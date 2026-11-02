package main

// 配置与密码管理。
//
// 配置文件（config.json）只保存少量运维信息：登录盐、密码哈希、LAN 网段。
// 业务设置（采集间隔/留存/告警阈值等）保存在 <data>/state.json，见 store.go。
//
// LAN 网段不再写死：config.json 里有 lanCidr 就用它（运维显式配置优先），
// 没有就按本机网卡自动探测（见 detectLANCIDR），全部探测失败才回退 192.168.1.0/24。
// 默认数据目录同样自动探测持久分区（GUANLAN_DATA > /mnt 下的可写挂载点 > /etc/guanlan/data）。
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
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
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

	LANCIDR string // LAN 网段：config.json 的 lanCidr 优先，否则自动探测，最后回退 192.168.1.0/24

	// lanCIDRAuto 为 true 表示 LANCIDR 来自自动探测或兜底，
	// saveFile 不会把它写进 config.json（换网段后下次启动仍能自适应）。
	lanCIDRAuto bool

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

// ---------------- 默认数据目录：持久分区自动探测 ----------------

const (
	// fallbackLANCIDR 是 LAN 网段探测全部失败时的最后兜底（仅在网卡信息不可得时使用）。
	fallbackLANCIDR = "192.168.1.0/24"

	// dataDirMinFreeBytes 持久分区最低可用空间：低于 200MB 的分区
	// 存不下历史流量库（7d/8d 分钟桶 + 威胁库），换下一个候选。
	dataDirMinFreeBytes = 200 << 20

	// overlayDataDir 是 /mnt 下没有可用持久分区时的 overlay 兜底目录。
	overlayDataDir = "/etc/guanlan/data"
)

// defaultDataDir 返回默认数据目录。
//
// 优先级（命令行 -data 与 config.json 的 dataDir 在调用方更早已生效）：
//  1. 环境变量 GUANLAN_DATA（部署/运维显式指定，原样使用）；
//  2. 演示模式 / Windows：本地 ./tmpdata（不碰真机路径）；
//  3. /mnt 下可写、空间 ≥200MB 的真实文件系统挂载点（优先名字含
//     mmcblk/sd/nvme/ssd 的存储卡/NVMe，其次任意挂载点；已有 guanlan
//     数据目录的挂载点排最前，保证升级后不丢历史数据）；
//  4. /etc/guanlan/data（overlay 兜底，任何路由器都有）。
//
// 探测过程不假设分区名（不同机型是 mmcblk2p4 / sda1 / nvme0n1p1 …），
// 探测失败时回退到 overlay 目录，保证仍能启动。
func defaultDataDir(demo bool) string {
	if p := strings.TrimSpace(os.Getenv("GUANLAN_DATA")); p != "" {
		return p
	}
	if demo || runtime.GOOS == "windows" {
		return "tmpdata"
	}
	if root := probePersistentMount("/proc/mounts", "/mnt"); root != "" {
		return filepath.Join(root, "guanlan")
	}
	return overlayDataDir
}

// mountCandidate /mnt 下的一个候选挂载点。
type mountCandidate struct {
	path      string
	preferred bool // 名字像存储卡/NVMe/SSD
	hasData   bool // 已经存在 guanlan 数据目录
}

// probePersistentMount 从 mountsFile（/proc/mounts 格式）里挑一个可用的持久挂载点。
//
// 只接受 root（/mnt）本身或 root 之下的真实文件系统挂载点：
// 跳过 tmpfs/overlay/squashfs 等伪文件系统与只读挂载，写测试失败或空间不足的也跳过。
// 排序：已有 guanlan 数据目录 > 名字像存储卡的 > 其它；最后真正创建 <挂载点>/guanlan
// 并复查可写，成功才返回。全部失败返回 ""（调用方回退 overlay 目录）。
func probePersistentMount(mountsFile, root string) string {
	data, err := os.ReadFile(mountsFile)
	if err != nil {
		return ""
	}
	seen := make(map[string]bool)
	var cands []mountCandidate
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		mp := unescapeMountField(fields[1])
		// 用 filepath.Rel 判「root 本身或 root 之下」，避免手工拼分隔符在
		// 非 Linux 布局/测试环境下失效（生产只在 Linux 走这里）。
		rel, rerr := filepath.Rel(root, mp)
		if rerr != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			continue
		}
		if seen[mp] {
			continue
		}
		seen[mp] = true
		if !persistentFsType(fields[2]) || mountReadOnly(fields[3]) {
			continue
		}
		if !dirWritable(mp) {
			continue
		}
		// 空间检查：df 不可用时只保留「可写」这一硬条件（写失败已排除只读/无权限）。
		if free, ok := freeBytesViaDF(mp); ok && free < dataDirMinFreeBytes {
			logf("跳过数据目录候选 %s：可用空间不足 200MB", mp)
			continue
		}
		cands = append(cands, mountCandidate{
			path:      mp,
			preferred: storageNameHint(mp),
			hasData:   isGuanlanDataMount(mp),
		})
	}
	// 稳定排序：已有数据 > 存储卡命名 > /proc/mounts 原始顺序。
	sort.SliceStable(cands, func(i, j int) bool {
		if cands[i].hasData != cands[j].hasData {
			return cands[i].hasData
		}
		return cands[i].preferred && !cands[j].preferred
	})
	for _, c := range cands {
		dir := filepath.Join(c.path, "guanlan")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			continue
		}
		if !dirWritable(dir) {
			continue
		}
		return c.path
	}
	return ""
}

// persistentFsType 判断挂载类型是否可能持久保存数据（排除伪文件系统/只读镜像）。
func persistentFsType(fs string) bool {
	switch strings.ToLower(strings.TrimSpace(fs)) {
	case "proc", "sysfs", "devtmpfs", "devpts", "tmpfs", "ramfs", "rootfs",
		"overlay", "squashfs", "cgroup", "cgroup2", "debugfs", "tracefs",
		"securityfs", "pstore", "bpf", "mqueue", "hugetlbfs", "configfs",
		"fusectl", "autofs", "nsfs", "efivarfs", "binfmt_misc", "rpc_pipefs":
		return false
	}
	return true
}

// mountReadOnly 判断挂载选项里是否有 ro。
func mountReadOnly(opts string) bool {
	for _, o := range strings.Split(opts, ",") {
		if strings.TrimSpace(o) == "ro" {
			return true
		}
	}
	return false
}

// dirWritable 用「建临时文件再删除」验证目录可写。
func dirWritable(dir string) bool {
	f, err := os.CreateTemp(dir, ".guanlan-probe-*")
	if err != nil {
		return false
	}
	name := f.Name()
	_ = f.Close()
	_ = os.Remove(name)
	return true
}

// storageNameHint 判断挂载点名是否像存储卡/NVMe/SSD（不同机型命名不同，只作排序偏好）。
func storageNameHint(mountpoint string) bool {
	name := strings.ToLower(filepath.Base(mountpoint))
	for _, hint := range []string{"mmcblk", "sd", "nvme", "ssd"} {
		if strings.Contains(name, hint) {
			return true
		}
	}
	return false
}

// isGuanlanDataMount 判断挂载点下是否已有 guanlan 数据目录（升级/重启时优先复用）。
func isGuanlanDataMount(mountpoint string) bool {
	st, err := os.Stat(filepath.Join(mountpoint, "guanlan"))
	return err == nil && st.IsDir()
}

// freeBytesViaDF 用 `df` 查询路径所在文件系统的可用字节数。
// 纯 Go 标准库没有跨平台 statfs，df 在 OpenWrt(busybox)/桌面上都有；
// 先试 POSIX `-Pk`，老 busybox 不支持 -P 时退化到 `-k`。
// 查询失败返回 ok=false，由调用方按「空间未知」处理。
func freeBytesViaDF(path string) (int64, bool) {
	out, err := exec.Command("df", "-Pk", path).Output()
	if err != nil {
		out, err = exec.Command("df", "-k", path).Output()
		if err != nil {
			return 0, false
		}
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) < 2 {
		return 0, false
	}
	fields := strings.Fields(lines[len(lines)-1])
	if len(fields) < 4 {
		return 0, false
	}
	kb, err := strconv.ParseInt(fields[3], 10, 64)
	if err != nil || kb < 0 {
		return 0, false
	}
	return kb * 1024, true
}

// unescapeMountField 还原 /proc/mounts 里的转义。
// 内核只对空格/制表/换行/反斜杠做八进制转义（\040 \011 \012 \134），
// 其余反斜杠按原样保留 —— 否则非 Linux 路径（含 \001 之类）会被误转义。
func unescapeMountField(s string) string {
	if !strings.Contains(s, "\\") {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			switch s[i+1 : i+4] {
			case "040":
				b.WriteByte(' ')
				i += 3
				continue
			case "011":
				b.WriteByte('\t')
				i += 3
				continue
			case "012":
				b.WriteByte('\n')
				i += 3
				continue
			case "134":
				b.WriteByte('\\')
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// ---------------- LAN 网段自动探测 ----------------

// detectLANCIDR 探测本机 LAN 网段；探测不到返回 ""（调用方回退 fallbackLANCIDR）。
//
// 优先级：br-lan* > br0 > lan* > 其它桥（br*）> 首个带私网 IPv4 的非虚拟接口。
// 排除 loopback/docker/veth/zt/tailscale/tun/wg/ppp/wan/ifb 等虚拟或外网接口，
// 只接受私网（含 CGNAT 100.64/10）地址，避免把 WAN 公网口或 ZeroTier 网段当成 LAN。
// 接口名只是排序偏好：不认识名字（x86_64 的 enp1s0、单网口 eth0 扁平网络等）时
// 仍能靠「带私网 IPv4」选出来。
func detectLANCIDR() string {
	ifs, err := net.Interfaces()
	if err != nil {
		return ""
	}
	// 默认路由出口通常是 WAN；名字不像 LAN 桥的接口（eth0/enp1s0 等）降权，
	// 避免双网口 x86 上把私网 WAN 口当成 LAN。唯一候选时仍会被选中（单网口扁平网络）。
	defDev := defaultRouteDevFromProc("/proc/net/route")
	type cand struct {
		cidr  string
		score int
	}
	var cands []cand
	for _, ifi := range ifs {
		name := ifi.Name
		if virtualIfaceName(name) {
			continue
		}
		up := ifi.Flags&net.FlagUp != 0
		addrs, err := ifi.Addrs()
		if err != nil {
			continue
		}
		for _, ad := range addrs {
			ipn, ok := ad.(*net.IPNet)
			if !ok {
				continue
			}
			v4 := ipn.IP.To4()
			if v4 == nil || v4.IsLoopback() || v4.IsLinkLocalUnicast() {
				continue
			}
			ones, bits := ipn.Mask.Size()
			if bits != 32 {
				continue
			}
			addr := netip.AddrFrom4([4]byte{v4[0], v4[1], v4[2], v4[3]})
			if !isPrivateIPv4(addr) {
				continue // 公网地址是 WAN，不是 LAN
			}
			score := lanIfaceNameScore(name)
			if defDev != "" && name == defDev && score <= 50 {
				score -= 40 // 默认路由出口 + 通用网卡名：更像 WAN
			}
			if up {
				score += 5
			}
			cands = append(cands, cand{
				cidr:  fmt.Sprintf("%s/%d", v4.Mask(ipn.Mask).String(), ones),
				score: score,
			})
		}
	}
	if len(cands) == 0 {
		return ""
	}
	sort.SliceStable(cands, func(i, j int) bool { return cands[i].score > cands[j].score })
	return cands[0].cidr
}

// defaultRouteDevFromProc 从 /proc/net/route 读默认路由出口（Linux；其它平台返回空）。
// 格式：Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT，
// 默认路由是 Destination=00000000 且 Mask=00000000 的那一行。
func defaultRouteDevFromProc(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 8 {
			continue
		}
		if fields[1] == "00000000" && fields[7] == "00000000" {
			return fields[0]
		}
	}
	return ""
}

// lanIfaceNameScore 按接口名给 LAN 候选打分（只是偏好，不认识的名字也有基础分）。
func lanIfaceNameScore(name string) int {
	n := strings.ToLower(strings.TrimSpace(name))
	switch {
	case n == "br-lan" || strings.HasPrefix(n, "br-lan."):
		return 100
	case n == "br0":
		return 95
	case strings.HasPrefix(n, "lan"):
		return 90
	case strings.HasPrefix(n, "br"):
		return 85
	}
	return 50
}

// isPrivateIPv4 判断 IPv4 是否私网/回环/链路本地/CGNAT（路由器 LAN 只会是这些段）。
func isPrivateIPv4(addr netip.Addr) bool {
	if !addr.Is4() {
		return false
	}
	if addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() {
		return true
	}
	// 100.64.0.0/10（CGNAT）：部分路由器/运营商级 NAT 会把它当 LAN 段。
	b := addr.As4()
	return b[0] == 100 && b[1] >= 64 && b[1] <= 127
}

// LoadConfig 读取（或初始化）配置。
func LoadConfig(dataDir string, demo, dryRun bool) (*Config, error) {
	cfg := &Config{
		DataDir: dataDir,
		Demo:    demo,
		DryRun:  dryRun || demo,
		// LAN 网段留空：config.json 的 lanCidr 优先，其次自动探测，最后才回退。
		LANCIDR: "",
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
	// LAN 网段：配置文件里显式写了就用它；没写则按本机网卡自动探测；
	// 探测失败才回退 192.168.1.0/24（仅兜底，不写回 config.json）。
	if cfg.LANCIDR == "" {
		if detected := detectLANCIDR(); detected != "" {
			cfg.LANCIDR = detected
			cfg.lanCIDRAuto = true
			logf("LAN 网段未配置，已自动探测: %s", cfg.LANCIDR)
		}
	}
	if cfg.LANCIDR == "" {
		cfg.LANCIDR = fallbackLANCIDR
		cfg.lanCIDRAuto = true
		logf("LAN 网段探测失败，使用兜底值 %s（可在 /etc/guanlan/config.json 配置 lanCidr）", cfg.LANCIDR)
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
	fc := fileConfig{Salt: c.Salt, PasswordHash: c.PasswordHash}
	// 自动探测出来的 LAN 网段不落盘（换网段后下次启动能自适应）；
	// 配置文件里显式配置的 lanCidr 原样保留。
	if !c.lanCIDRAuto {
		fc.LANCIDR = c.LANCIDR
	}
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
