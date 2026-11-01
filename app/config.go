package main

// 配置与密码管理。
//
// 配置文件（config.json）只保存少量运维信息：登录盐、密码哈希、LAN 网段。
// 业务设置（采集间隔/留存/告警阈值等）保存在 <data>/state.json，见 store.go。
//
// 密码算法：sha256(salt + password)，salt 为随机 16 字节 hex。
// 兼容部署脚本可能写入的明文 password 字段（首次加载时自动转成哈希并落盘）。

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

// Version 服务版本号（api.md / hello 帧使用）。
// 单一来源：编译期注入（-ldflags "-X main.buildVersion=…"）优先，其次内嵌的 version.txt。
var Version = AppVersion()

// 默认密码：部署脚本未生成配置时使用，首次启动会打印提示。
// 默认管理员密码。
// 必须与 deploy/install.sh 的 DEFAULT_PASSWORD 保持一致（guanlan2026），
// 否则配置文件缺失时会回退到另一个密码，导致登录失败。
// install.sh 写入 config.json 时用的是同一个值。
const defaultPassword = "guanlan2026"

// Config 进程级配置（来自命令行 flag + config.json）。
type Config struct {
	Addr    string // 监听地址，如 :8088
	WebDir  string // 前端目录，空 = 使用内嵌资源
	DataDir string // 数据目录

	Demo   bool // 演示模式：不读 /proc，不执行真实命令，生成合成数据
	DryRun bool // 干跑：所有外部命令只记录不执行（真机零风险验证）

	LANCIDR string // LAN 网段，默认 192.168.1.0/24

	Salt         string // 密码盐
	PasswordHash string // sha256(salt+pwd) hex
	ConfigPath   string // config.json 路径（用于回写密码）

	mu sync.Mutex
}

// fileConfig config.json 的持久化结构。
type fileConfig struct {
	Salt         string `json:"salt"`
	PasswordHash string `json:"passwordHash"`
	Password     string `json:"password,omitempty"` // 部署脚本可能写明文，加载后转为 hash
	LANCIDR      string `json:"lanCidr,omitempty"`
}

// defaultDataDir 返回默认数据目录：真机为 mmcblk2p4 分区，演示模式用本地目录。
func defaultDataDir(demo bool) string {
	if demo || runtime.GOOS == "windows" {
		return "tmpdata"
	}
	return "/mnt/mmcblk2p4/guanlan"
}

// LoadConfig 读取（或初始化）配置。
func LoadConfig(dataDir string, demo, dryRun bool) (*Config, error) {
	cfg := &Config{
		DataDir: dataDir,
		Demo:    demo,
		DryRun:  dryRun || demo,
		LANCIDR: "192.168.1.0/24",
	}
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return nil, fmt.Errorf("创建数据目录失败: %w", err)
	}

	candidates := make([]string, 0, 3)
	if p := strings.TrimSpace(os.Getenv("GUANLAN_CONFIG")); p != "" {
		candidates = append(candidates, p)
	}
	candidates = append(candidates, "/etc/guanlan/config.json")
	candidates = append(candidates, filepath.Join(dataDir, "config.json"))

	for _, p := range candidates {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			cfg.ConfigPath = p
			break
		}
	}
	if cfg.ConfigPath == "" {
		cfg.ConfigPath = filepath.Join(dataDir, "config.json")
	}

	created := false
	if data, err := os.ReadFile(cfg.ConfigPath); err == nil {
		var fc fileConfig
		if uerr := json.Unmarshal(data, &fc); uerr != nil {
			// 主文件损坏（改密/断电时被截断、手工编辑出错）：回退 config.json.bak，
			// 用备份内容继续启动并重写主文件（created=true 触发下方 saveFile 自愈）。
			bak, berr := os.ReadFile(cfg.ConfigPath + ".bak")
			var bfc fileConfig
			if berr != nil || json.Unmarshal(bak, &bfc) != nil {
				return nil, fmt.Errorf("解析配置文件 %s 失败: %w", cfg.ConfigPath, uerr)
			}
			logf("config.json 损坏（%v），已回退 config.json.bak", uerr)
			fc = bfc
			created = true
		}
		cfg.Salt = fc.Salt
		cfg.PasswordHash = fc.PasswordHash
		if fc.LANCIDR != "" {
			cfg.LANCIDR = fc.LANCIDR
		}
		// 兼容明文 password 字段
		if cfg.PasswordHash == "" && fc.Password != "" {
			if cfg.Salt == "" {
				cfg.Salt = randomHex(16)
			}
			cfg.PasswordHash = hashPassword(cfg.Salt, fc.Password)
			created = true
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("读取配置文件失败: %w", err)
	}

	if cfg.Salt == "" {
		cfg.Salt = randomHex(16)
		created = true
	}
	if cfg.PasswordHash == "" {
		cfg.PasswordHash = hashPassword(cfg.Salt, defaultPassword)
		created = true
	}
	if created {
		if err := cfg.saveFile(); err != nil {
			return nil, fmt.Errorf("写入配置文件失败: %w", err)
		}
	}
	return cfg, nil
}

// saveFile 原子写配置文件。
//
// 落盘顺序：备份现有有效配置到 config.json.bak → 写 tmp → fsync → close → rename。
// 相比「直接覆盖写」，掉电/被杀进程时不会留下半截 config.json（否则下次启动解析失败、
// 登录直接不可用）；最坏情况回退 .bak，配置（含密码）不丢。
func (c *Config) saveFile() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	fc := fileConfig{Salt: c.Salt, PasswordHash: c.PasswordHash, LANCIDR: c.LANCIDR}
	data, err := json.MarshalIndent(fc, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(c.ConfigPath), 0o755); err != nil {
		return err
	}
	// 只备份语法有效的旧配置（损坏的主文件不该覆盖掉好备份）；备份失败只记日志，不阻断保存。
	if old, rerr := os.ReadFile(c.ConfigPath); rerr == nil && len(old) > 0 && json.Valid(old) {
		if berr := writeFileSync(c.ConfigPath+".bak", old, 0o600); berr != nil {
			logf("写入 config.json.bak 失败: %v", berr)
		}
	}
	return writeFileSync(c.ConfigPath, data, 0o600)
}

// VerifyPassword 校验密码。
func (c *Config) VerifyPassword(pwd string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	want := c.PasswordHash
	got := hashPassword(c.Salt, pwd)
	return subtle.ConstantTimeCompare([]byte(want), []byte(got)) == 1
}

// SetPassword 校验旧密码后修改。
func (c *Config) SetPassword(oldPwd, newPwd string) error {
	if !c.VerifyPassword(oldPwd) {
		return errors.New("原密码不正确")
	}
	// 与前端保持一致的最短长度（前端 settings.js 同样按 8 位校验）
	if len(strings.TrimSpace(newPwd)) < 8 {
		return errors.New("新密码至少 8 位")
	}
	c.mu.Lock()
	c.PasswordHash = hashPassword(c.Salt, newPwd)
	c.mu.Unlock()
	return c.saveFile()
}

// UsingDefaultPassword 是否仍在使用默认密码（启动日志提示）。
func (c *Config) UsingDefaultPassword() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.PasswordHash == hashPassword(c.Salt, defaultPassword)
}

// hashPassword sha256(salt + password) 的 hex。
func hashPassword(salt, pwd string) string {
	sum := sha256.Sum256([]byte(salt + pwd))
	return hex.EncodeToString(sum[:])
}

// randomHex 生成 n 字节随机数的 hex 串。
func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand 失败属于极端情况，退化仍保证不崩溃
		for i := range b {
			b[i] = byte(i*31 + 7)
		}
	}
	return hex.EncodeToString(b)
}
