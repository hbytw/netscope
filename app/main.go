package main

// 进程入口：flag 解析、组件装配、采集/推送/巡检循环、HTTP 服务、优雅退出。
//
// 运行形态：
//   guanlan -addr :8088 -data /mnt/<存储>/guanlan            （路由器真机，默认自动探测持久分区）
//   guanlan -addr 127.0.0.1:8088 -web .\app\web -data tmpdata -demo   （Windows 本地联调）
//   guanlan -dry-run ...                                     （真机零风险验证：命令只记录不执行）

import (
	"bytes"
	"context"
	_ "embed"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// ---------------- 版本号（单一来源：app/version.txt） ----------------

// buildVersion 编译期注入点：go build -ldflags "-X main.buildVersion=1.2.3"。
// 未注入时回退到内嵌的 version.txt（该文件是版本号的唯一权威来源）。
var buildVersion string

//go:embed version.txt
var versionFile string

// AppVersion 返回当前版本号：编译期注入优先，其次内嵌的 version.txt。
func AppVersion() string {
	if v := strings.TrimSpace(buildVersion); v != "" {
		return v
	}
	if v := strings.TrimSpace(versionFile); v != "" {
		return v
	}
	return "0.0.0-dev"
}

// App 应用根对象（所有组件共享）。
type App struct {
	cfg *Config

	store    *Store
	agg      *Agg
	devs     *DeviceMgr
	ct       *ConnEngine
	dns      *DNSResolver
	sys      *SysInfo
	sec      *Security
	enf      *Enforcer
	hub      *Hub
	sessions *Sessions
	login    *LoginGuard
	webFS    fs.FS
	demo     *Demo

	started time.Time
	stop    chan struct{}
	wg      sync.WaitGroup

	execMu   sync.Mutex
	dnsTapMu sync.Mutex
	switchMu sync.Mutex // 设置补丁「读—改—写」串行化，避免并发丢更新

	// 开关动作注入点（单测替换以模拟失败；nil = 默认实现）
	dnsTapApply          func(enabled bool) error
	deviceControlRestore func() error

	scaleLogN int
	scaleInit bool // 校准系数是否已首次取值（Scale() 未初始化时返回 1，无法靠它判断）
	pidPath   string

	// 命令记录（demo/dry-run 下便于单测断言「开关撤销流程」调用了哪些命令）
	cmdMu  sync.Mutex
	cmdLog []string

	// 接口/拓扑缓存（10s 级缓存，避免每次 API 都 fork ip/ss 命令）
	ifMu    sync.Mutex
	ifaces  []ifaceInfo
	ifAt    int64
	topoMu  sync.Mutex
	topo    topologyResp
	topoAt  int64
	topoRx  map[string]int64
	topoTx  map[string]int64
	topoRAt int64
	// topoRate 接口速率差分结果（采集循环按固定 2s 节拍写入，拓扑读路径只读快照）
	topoRate map[string][2]int64
	proxyMu  sync.Mutex
	proxyUp  bool
	proxyAt  int64
	// proxyTool 缓存可用的监听端口查询工具：ss 或 netstat（空=尚未探测，"none"=都不可用）。
	// 有些 OpenWrt 固件不带 ss，若每轮都先试 ss 就会每 18 秒刷一条 "exec 失败" 日志。
	proxyTool string

	// 本机/网关保护集合（防止误封路由器自身导致断网）
	protMu  sync.Mutex
	protIPs map[string]bool
	protAt  int64
}

// webFS 实际类型是 fs.FS；为可读性在 NewApp 中赋值（见 assets.go）。
func NewApp(cfg *Config) *App {
	a := &App{
		cfg:      cfg,
		started:  time.Now(),
		stop:     make(chan struct{}),
		sessions: NewSessions(),
		login:    NewLoginGuard(),
	}
	a.store = NewStore(cfg.DataDir)
	maxBuckets := 1500 // ≈24h
	if cfg.Demo {
		maxBuckets = 12000 // ≈8 天，演示模式支持 7d 查询
	}
	a.agg = NewAgg(maxBuckets)
	a.ct = NewConnEngine(cfg.LANCIDR)
	a.ct.SetSelfIPs(localIPv4s())
	a.devs = NewDeviceMgr(a)
	a.dns = NewDNSResolver(a)
	a.sys = NewSysInfo(a, cfg.Demo)
	a.hub = NewHub(2000)
	a.sec = NewSecurity(a)
	a.enf = NewEnforcer(a)
	a.agg.SetSink(func(b *Bucket) {
		// 历史统计开关关闭时不落盘（1min 桶仍保留在内存中用于实时曲线）
		s := a.store.Settings()
		if !s.Enabled || !s.Collect || !s.History {
			return
		}
		if err := a.store.AppendTrafficBucket(b); err != nil {
			logf("写入分钟流量失败: %v", err)
		}
	})
	if cfg.Demo {
		a.demo = NewDemo(a)
	}
	return a
}

// logf 统一日志（procd 收集 stdout）。
func logf(format string, args ...interface{}) {
	log.Printf(format, args...)
}

// logDebug 控制是否输出调试日志，默认关闭，用环境变量 GUANLAN_DEBUG=1 打开。
//
// 为什么需要这个开关：
// 采集/拓扑/设备刷新每 2~10 秒就会执行一批 shell 命令（ip/ss/df/ping），
// 每成功一条都打一行 "exec: ..." —— 实测每 10 秒约 4 行、一小时 1400+ 行。
// 后果是把真正重要的告警和故障信息挤掉：等到需要排查问题时，
// 日志缓冲区里全是 exec 噪声，故障现场早就被冲没了。
//
// 所以「命令执行成功」属于调试信息，不是运行日志；默认不输出。
// 需要排查具体命令时要打开：GUANLAN_DEBUG=1 /etc/init.d/guanlan restart
var logDebug = os.Getenv("GUANLAN_DEBUG") == "1"

// logDebugf 只在调试模式下输出。
func logDebugf(format string, args ...interface{}) {
	if !logDebug {
		return
	}
	log.Printf("[debug] "+format, args...)
}

// collectIntervalSec 采集间隔（可在设置页动态调整）。
func (a *App) collectIntervalSec() int {
	v := a.store.Settings().CollectIntervalSec
	if v < 1 {
		v = 2
	}
	if v > 60 {
		v = 60
	}
	return v
}

// ---------------- 开关（两级：总开关 + 功能开关） ----------------

// settings 返回设置快照。
func (a *App) settings() Settings { return a.store.Settings() }

// dataActive 采集链路是否生效（总开关 + 采集开关）。
func (a *App) dataActive() bool {
	s := a.settings()
	return s.Enabled && s.Collect
}

// deviceControlOn 设备管控（断网/限速）是否允许下发。
func (a *App) deviceControlOn() bool {
	s := a.settings()
	return s.Enabled && s.DeviceControl
}

// domainBlockOn 域名封堵是否允许下发。
func (a *App) domainBlockOn() bool {
	s := a.settings()
	return s.Enabled && s.Collect && s.DomainBlock
}

// policyEngineOn 定时策略引擎是否工作。
func (a *App) policyEngineOn() bool {
	s := a.settings()
	return s.Enabled && s.DeviceControl && s.Schedule
}

// alertsOn 安全研判是否工作。
func (a *App) alertsOn() bool {
	s := a.settings()
	return s.Enabled && s.Alerts
}

// recordCmd 记录外部命令（仅 demo / dry-run，便于单测断言与审计）。
func (a *App) recordCmd(cmd string) {
	a.cmdMu.Lock()
	if len(a.cmdLog) < 1000 {
		a.cmdLog = append(a.cmdLog, cmd)
	}
	a.cmdMu.Unlock()
}

// recordedCommands 返回已记录的外部命令（测试用）。
func (a *App) recordedCommands() []string {
	a.cmdMu.Lock()
	defer a.cmdMu.Unlock()
	out := make([]string, len(a.cmdLog))
	copy(out, a.cmdLog)
	return out
}

// switchError 开关变更错误（带 HTTP 状态码）。
type switchError struct {
	status int
	msg    string
}

func (e *switchError) Error() string { return e.msg }

func badSetting(msg string) error { return &switchError{status: 400, msg: msg} }

// ApplySwitchPatch 应用设置补丁（开关 + 阈值），返回新设置与本次实际动作。
// 开关变更顺序：先撤销（安全），再启用；dnsTap 变更失败会回滚且不落库。
func (a *App) ApplySwitchPatch(patch settingsPatch) (Settings, []string, []string, error) {
	// 串行化「读—改—写」全过程：并发 PUT 会互相覆盖（用旧快照全量覆盖 Settings）
	a.switchMu.Lock()
	defer a.switchMu.Unlock()

	cur := a.store.Settings()
	next := cur
	if patch.Enabled != nil {
		next.Enabled = *patch.Enabled
	}
	if patch.Collect != nil {
		next.Collect = *patch.Collect
	}
	if patch.DNSTap != nil {
		next.DNSTap = *patch.DNSTap
	}
	if patch.DeviceControl != nil {
		next.DeviceControl = *patch.DeviceControl
	}
	if patch.DomainBlock != nil {
		next.DomainBlock = *patch.DomainBlock
	}
	if patch.Schedule != nil {
		next.Schedule = *patch.Schedule
	}
	if patch.Alerts != nil {
		next.Alerts = *patch.Alerts
	}
	if patch.History != nil {
		next.History = *patch.History
	}
	if patch.HTTPTap != nil {
		next.HTTPTap = *patch.HTTPTap
	}
	if patch.Timezone != nil {
		// 定时策略时区：必须是合法 IANA 名称（如 Asia/Shanghai）。
		// 非法值会导致策略时段静默偏移，故直接拒绝而不是回退默认。
		tz := strings.TrimSpace(*patch.Timezone)
		if tz == "" || len(tz) > 64 {
			return cur, nil, nil, badSetting("时区名不能为空且不超过 64 字符")
		}
		if _, err := time.LoadLocation(tz); err != nil {
			return cur, nil, nil, badSetting("时区名无效：" + tz + "（示例 Asia/Shanghai）")
		}
		next.Timezone = tz
	}
	if patch.CollectIntervalSec != nil {
		v := *patch.CollectIntervalSec
		if v < 1 || v > 60 {
			return cur, nil, nil, badSetting("采集间隔范围 1~60 秒")
		}
		next.CollectIntervalSec = v
	}
	if patch.RetentionDays != nil {
		v := *patch.RetentionDays
		if v < 1 || v > 90 {
			return cur, nil, nil, badSetting("留存天数范围 1~90")
		}
		next.RetentionDays = v
	}
	if patch.Alert != nil {
		if patch.Alert.Enable != nil {
			next.Alert.Enable = *patch.Alert.Enable
		}
		if patch.Alert.ScanPorts != nil {
			v := *patch.Alert.ScanPorts
			if v < 3 || v > 200 {
				return cur, nil, nil, badSetting("端口扫描阈值范围 3~200")
			}
			next.Alert.ScanPorts = v
		}
		if patch.Alert.TrafficMbPerHour != nil {
			v := *patch.Alert.TrafficMbPerHour
			if v < 10 || v > 100000 {
				return cur, nil, nil, badSetting("流量异常阈值范围 10~100000 MB")
			}
			next.Alert.TrafficMbPerHour = v
		}
		if patch.Alert.ThreatUpdateHours != nil {
			v := *patch.Alert.ThreatUpdateHours
			if v < 1 || v > 168 {
				return cur, nil, nil, badSetting("威胁情报更新间隔范围 1~168 小时")
			}
			next.Alert.ThreatUpdateHours = v
		}
	}
	// 依赖关系：关闭依赖项会自动关闭被依赖项
	normalizeSwitches(&next)

	// 开关变更：执行动作；任一动作失败时立即回滚已执行的动作，
	// 保证「落库状态 == 路由器实际状态」（不会出现界面显示生效、实际已撤销）。
	res := a.applySwitchTransitions(cur, next)
	if res.Err != nil {
		return a.handleSwitchFailure(cur, next, res)
	}
	applied, revoked := res.Applied, res.Revoked
	out := a.store.UpdateSettings(func(s *Settings) { *s = next })
	// 仅当开关相关补丁变化时才重下发规则/策略恢复，避免修改告警参数（如更新间隔）时也做全量 reconcile
	switchPatch := patch.Enabled != nil || patch.DeviceControl != nil || patch.Schedule != nil
	if switchPatch && out.Enabled && out.DeviceControl {
		// 设备管控开启时：先从 store 恢复持久化的封禁/限速记录，再立即评估一次策略（不必等 15s）
		a.enf.RestoreFromStore()
		if out.Schedule {
			a.enf.ReconcilePolicies(time.Now())
		}
	}
	if switchPatch && a.cfg.Demo && a.demo != nil && out.Enabled && out.Collect {
		a.demo.ensureSeed()
	}
	// 采集链路开启/恢复后，同步多网段识别（zt/vpn 设备与流向）
	if switchPatch && out.Enabled && out.Collect {
		a.syncConnNets()
	}
	// 手工封禁域名跟随开关恢复下发（域名封堵/总开关/采集开启后立即生效，不等 15s 轮询）。
	// 必须放在 UpdateSettings 之后：ApplyManualDomains 内部按「落库后」的开关状态判定。
	if switchPatch || patch.DomainBlock != nil || patch.Collect != nil {
		a.enf.ApplyManualDomains()
	}
	// 明文 HTTP URL 抓取：跟随 httpTap 开关即时启停（失败只记日志，不影响开关本身）
	if patch.HTTPTap != nil || (switchPatch && !out.Enabled) {
		if out.Enabled && out.Collect && out.HTTPTap {
			if err := a.StartHTTPTap(); err != nil {
				logf("HTTP 明文 URL 抓取启动失败: %v", err)
			}
		} else {
			a.StopHTTPTap()
		}
	}
	return out, applied, revoked, nil
}

// ---------------- 开关变更：可逆动作 + 失败回滚 ----------------
//
// 设计要点（修复「先撤销、后启用」导致的状态背离）：
//
//	原实现：撤销 deviceControl 成功 → 启用 dnsTap 失败 → 返回错误且不落库，
//	此时 store 仍显示 deviceControl=true，但 iptables/tc 已被撤销，
//	界面显示「生效」而实际无规则（状态背离）。
//
//	现实现：每个动作都配有反向动作（revert）。任一动作失败时按相反顺序回滚
//	已执行的动作：
//	  - 全部回滚成功 → 路由器实际状态 == 旧设置 → 不落库（设置保持旧值）；
//	  - 存在回滚失败 → 部分成功 → 按路由器实际状态落库，并在错误信息中标注
//	    「部分成功」，前端可如实提示。
//
//	两种情况都保证：ApplySwitchPatch 返回的设置 == 路由器实际状态。

// switchStep 开关变更中的单个原子动作。
type switchStep struct {
	key    string       // 对应 Settings 字段（回滚失败时用于校正落库值）
	label  string       // 中文短名（错误信息用）
	turnOn bool         // 动作目标状态：true=启用，false=撤销
	desc   string       // 完成后的中文描述（写入 applied / revoked）
	run    func() error // 执行动作（返回 error 表示动作失败）
	revert func() error // 反向动作：恢复旧状态（nil = 无需恢复）
}

// switchFailure 一个未能回滚的动作（实际状态无法恢复 → 需按实际状态落库）。
type switchFailure struct {
	Key   string
	Label string
}

// switchRunResult 开关动作执行结果。
type switchRunResult struct {
	Applied []string        // 已生效动作描述
	Revoked []string        // 已撤销动作描述
	Err     error           // 首个失败动作的错误（nil = 全部成功）
	Failed  string          // 失败动作对应的设置字段
	Undone  []switchFailure // 回滚失败的动作（实际状态未能恢复）
}

// runSwitchSteps 顺序执行开关动作，并在失败时回滚已执行的动作。
//
// 失败动作本身不回滚：各动作的失败路径自行负责清理（如 ApplyDNSTap 内部
// 已反做还原），此处只回滚「此前已成功执行」的动作。
func runSwitchSteps(steps []switchStep) switchRunResult {
	var res switchRunResult
	done := make([]switchStep, 0, len(steps))
	for _, st := range steps {
		if st.run != nil {
			if err := st.run(); err != nil {
				res.Err = err
				res.Failed = st.key
				// 回滚已执行的动作（逆序：后撤销的先恢复）
				for i := len(done) - 1; i >= 0; i-- {
					d := done[i]
					if d.revert == nil {
						continue
					}
					if rerr := d.revert(); rerr != nil {
						logf("开关回滚失败: %s: %v", d.label, rerr)
						res.Undone = append(res.Undone, switchFailure{Key: d.key, Label: d.label})
					}
				}
				return res
			}
		}
		done = append(done, st)
		if st.turnOn {
			res.Applied = append(res.Applied, st.desc)
		} else {
			res.Revoked = append(res.Revoked, st.desc)
		}
	}
	return res
}

// applySwitchTransitions 执行实际启停动作并给出中文描述。
//
// 顺序：先撤销（安全），再启用；任一动作失败时自动回滚已撤销项。
func (a *App) applySwitchTransitions(old, next Settings) switchRunResult {
	// 撤销前的管控层快照（回滚时精确还原域名封堵 / 策略命中状态）
	snap := a.enf.snapshotEnforce()

	var steps []switchStep

	// 1) 撤销（先关闭，保证不残留规则）
	if old.DNSTap && !next.DNSTap {
		steps = append(steps, switchStep{
			key: "dnsTap", label: "DNS 日志旁挂", turnOn: false,
			desc:   "已关闭 dnsmasq 日志旁挂并还原 UCI 选项",
			run:    func() error { return a.applyDNSTapSwitch(false) },
			revert: func() error { return a.applyDNSTapSwitch(true) },
		})
	}
	if old.DeviceControl && !next.DeviceControl {
		steps = append(steps, switchStep{
			key: "deviceControl", label: "设备管控", turnOn: false,
			desc:   "已撤销 UBM_FWD/UBM_IN 断网规则并清理 tc 限速配置",
			run:    func() error { a.enf.RevokeDeviceControl(); return nil },
			revert: func() error { return a.restoreDeviceControl(snap) },
		})
	}
	if old.DomainBlock && !next.DomainBlock {
		steps = append(steps, switchStep{
			key: "domainBlock", label: "域名封堵", turnOn: false,
			desc:   "已销毁 ipset ubm_block 并删除域名拦截规则",
			run:    func() error { a.enf.RevokeDomainBlock(); return nil },
			revert: func() error { return a.restoreDomainBlock(snap) },
		})
	}
	if old.Enabled && !next.Enabled {
		steps = append(steps, switchStep{
			key: "enabled", label: "系统总开关", turnOn: false,
			desc:   "系统总开关已关闭：全部采集与管控静默，已撤销全部下发规则",
			run:    func() error { a.enf.RevokeAll(); return nil },
			revert: func() error { return a.restoreAllControl(snap) },
		})
	}
	if old.Schedule && !next.Schedule {
		steps = append(steps, switchStep{
			key: "schedule", label: "定时策略", turnOn: false,
			desc: "已停止定时策略自动启停",
			run:  func() error { return nil },
		})
	}
	if old.Alerts && !next.Alerts {
		steps = append(steps, switchStep{
			key: "alerts", label: "安全告警研判", turnOn: false,
			desc: "已停止安全研判（历史事件保留）",
			run:  func() error { a.sec.ResetRuntime(); return nil },
		})
	}
	if old.History && !next.History {
		steps = append(steps, switchStep{
			key: "history", label: "历史流量落盘", turnOn: false,
			desc: "已停止历史流量落盘",
			run:  func() error { return nil },
		})
	}
	if old.Collect && !next.Collect {
		steps = append(steps, switchStep{
			key: "collect", label: "流量采集", turnOn: false,
			desc: "已停止流量采集并清空实时数据",
			run:  func() error { a.clearCollectedData(); return nil },
		})
	}

	// 2) 启用（dnsTap 先试：失败则回滚上面已撤销的项并保持旧设置）
	if !old.DNSTap && next.DNSTap {
		steps = append(steps, switchStep{
			key: "dnsTap", label: "DNS 日志旁挂", turnOn: true,
			desc:   "已开启 dnsmasq 日志旁挂（UCI + stop/start + 健康检查）",
			run:    func() error { return a.applyDNSTapSwitch(true) },
			revert: func() error { return a.applyDNSTapSwitch(false) },
		})
	}
	if !old.Enabled && next.Enabled {
		steps = append(steps, switchStep{
			key: "enabled", label: "系统总开关", turnOn: true,
			desc: "系统总开关已开启",
			run:  func() error { return nil },
		})
	}
	if !old.Collect && next.Collect {
		steps = append(steps, switchStep{
			key: "collect", label: "流量采集", turnOn: true,
			desc: "已启动流量采集",
			run:  func() error { return nil },
		})
	}
	if !old.DeviceControl && next.DeviceControl {
		steps = append(steps, switchStep{
			key: "deviceControl", label: "设备管控", turnOn: true,
			desc: "设备管控已启用",
			run:  func() error { return nil },
		})
	}
	if !old.DomainBlock && next.DomainBlock {
		steps = append(steps, switchStep{
			key: "domainBlock", label: "域名封堵", turnOn: true,
			desc: "域名封堵已启用",
			run:  func() error { return nil },
		})
	}
	if !old.Schedule && next.Schedule {
		steps = append(steps, switchStep{
			key: "schedule", label: "定时策略", turnOn: true,
			desc: "定时策略已启用",
			run:  func() error { return nil },
		})
	}
	if !old.Alerts && next.Alerts {
		steps = append(steps, switchStep{
			key: "alerts", label: "安全告警研判", turnOn: true,
			desc: "安全告警研判已启用",
			run:  func() error { return nil },
		})
	}
	if !old.History && next.History {
		steps = append(steps, switchStep{
			key: "history", label: "历史流量落盘", turnOn: true,
			desc: "历史统计已启用",
			run:  func() error { return nil },
		})
	}
	return runSwitchSteps(steps)
}

// handleSwitchFailure 处理开关动作失败。
//
// 能全部回滚 → 路由器实际状态与旧设置一致 → 不落库（保持旧设置）；
// 不能全部回滚（部分成功）→ 按路由器实际状态落库，并在错误信息中标注「部分成功」。
func (a *App) handleSwitchFailure(cur, next Settings, res switchRunResult) (Settings, []string, []string, error) {
	if len(res.Undone) == 0 {
		// 已撤销的开关全部恢复 → 系统状态 == 旧设置 → 不落库
		msg := "（已回滚到操作前状态：设置与路由器实际状态一致）"
		if len(res.Applied) == 0 && len(res.Revoked) == 0 {
			msg = "（未做任何变更：设置与路由器实际状态一致）"
		}
		return cur, res.Applied, res.Revoked, &switchError{
			status: 500,
			msg:    fmt.Sprintf("%v%s", res.Err, msg),
		}
	}
	// 部分成功：把实际生效的状态落库（设置必须与路由器实际状态一致）
	names := make([]string, 0, len(res.Undone))
	effective := cur
	for _, f := range res.Undone {
		names = append(names, f.Label)
		applySwitchKey(&effective, f.Key, next)
	}
	normalizeSwitches(&effective)
	out := a.store.UpdateSettings(func(s *Settings) { *s = effective })
	logf("开关变更部分成功：%s 未能恢复，已按路由器实际状态落库", strings.Join(names, "、"))
	return out, res.Applied, res.Revoked, &switchError{
		status: 500,
		msg: fmt.Sprintf("%v；部分成功：%s 未能恢复，已按路由器实际状态记录（请刷新页面确认）",
			res.Err, strings.Join(names, "、")),
	}
}

// applySwitchKey 按字段名把「目标设置」的值写入 s（部分成功时校正落库值）。
func applySwitchKey(s *Settings, key string, ref Settings) {
	switch key {
	case "enabled":
		s.Enabled = ref.Enabled
	case "collect":
		s.Collect = ref.Collect
	case "dnsTap":
		s.DNSTap = ref.DNSTap
	case "deviceControl":
		s.DeviceControl = ref.DeviceControl
	case "domainBlock":
		s.DomainBlock = ref.DomainBlock
	case "schedule":
		s.Schedule = ref.Schedule
	case "alerts":
		s.Alerts = ref.Alerts
	case "history":
		s.History = ref.History
	}
}

// applyDNSTapSwitch 执行 DNS 旁挂开关（单测可注入失败）。
func (a *App) applyDNSTapSwitch(enabled bool) error {
	if a.dnsTapApply != nil {
		return a.dnsTapApply(enabled)
	}
	return a.ApplyDNSTap(enabled)
}

// restoreDeviceControl 恢复设备管控（回滚用）。
//
// 撤销设备管控会清空内存中的管控状态并拆掉 iptables/tc 规则；
// 回滚时从 store 恢复持久化的断网/限速记录并重新下发规则，使实际状态回到操作前。
//
// 恢复后自检规则是否真的在位（防火墙重载会静默冲刷自有链）：
// 自检失败先重试一次，仍失败则如实上报（进入「部分成功」分支，按实际状态落库）。
func (a *App) restoreDeviceControl(snap enforceSnapshot) error {
	if a.deviceControlRestore != nil {
		return a.deviceControlRestore()
	}
	a.enf.restorePolicyState(snap)
	a.enf.RestoreFromStore()
	if err := a.verifyDeviceControl(); err != nil {
		logf("设备管控回滚自检失败，重试一次: %v", err)
		a.enf.restorePolicyState(snap)
		a.enf.RestoreFromStore()
		if err2 := a.verifyDeviceControl(); err2 != nil {
			return fmt.Errorf("设备管控回滚失败: %w", err2)
		}
	}
	return nil
}

// verifyDeviceControl 校验管控规则是否真的在位（回滚后自检）。
//
// dry-run/demo 下只记录命令不执行，无法核验系统状态，此时不做校验。
func (a *App) verifyDeviceControl() error {
	out, ok := a.enf.iptablesDump()
	if !ok {
		return nil // 无法核验 → 视为成功
	}
	if !a.enf.rulesPresent(out) {
		return errors.New("iptables 自有链或管控规则缺失")
	}
	return nil
}

// restoreDomainBlock 恢复域名封堵（回滚用）：按快照重新下发 ipset 与拦截规则。
func (a *App) restoreDomainBlock(snap enforceSnapshot) error {
	return a.enf.restoreDomains(snap)
}

// restoreAllControl 恢复总开关撤销前的全部管控（回滚用）。
//
// 域名封堵由「域名封堵」开关自己的回滚步骤单独恢复（各自独立判定成败，
// 避免重复恢复导致「明明恢复了却报失败」的假象）。
func (a *App) restoreAllControl(snap enforceSnapshot) error {
	return a.restoreDeviceControl(snap)
}

// ---------------- 管控层快照（开关回滚用） ----------------
//
// RevokeDeviceControl / RevokeDomainBlock / RevokeAll 会清空 Enforcer 内存中的
// 管控状态（断网/限速/域名封堵/策略命中）且不可逆。为支持失败回滚，这里在撤销前
// 做快照，回滚时精确还原：无需重新解析域名，也不会让策略命中数重复累加。
//
// 说明：这些方法定义在 main.go —— 本模块只允许改动 main.go（enforce.go 归其它模块维护）。

// enforceSnapshot 管控层可恢复状态快照。
type enforceSnapshot struct {
	domains       map[string]bool     // 已下发的域名封堵集合
	domainIPs     map[string][]uint32 // 域名 → 已解析 IP（回滚时免去重新解析）
	policyActive  map[string]bool     // 已命中的策略集合
	manualDomains map[string]bool     // 手工封禁域名镜像（回滚后策略下发不会丢手工封禁）
}

// snapshotEnforce 快照当前管控状态（撤销动作前调用）。
func (e *Enforcer) snapshotEnforce() enforceSnapshot {
	e.mu.Lock()
	defer e.mu.Unlock()
	snap := enforceSnapshot{
		domains:       copyBoolMap(e.dnsDomains),
		domainIPs:     make(map[string][]uint32, len(e.domainIPs)),
		policyActive:  copyBoolMap(e.policyActive),
		manualDomains: copyBoolMap(e.manualDomains),
	}
	for d, ips := range e.domainIPs {
		snap.domainIPs[d] = append([]uint32(nil), ips...)
	}
	return snap
}

// restorePolicyState 还原策略命中状态（回滚用）。
//
// 撤销设备管控/总开关会清空 policyActive；若不回原，回滚后的下一轮策略评估会
// 把同一批策略当成「新命中」，重复累加命中数并重复推送命中事件。
func (e *Enforcer) restorePolicyState(snap enforceSnapshot) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.policyActive = copyBoolMap(snap.policyActive)
}

// restoreDomains 用快照还原域名封堵状态并重新下发 ipset 与拦截规则（回滚用）。
func (e *Enforcer) restoreDomains(snap enforceSnapshot) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	// 先还原已解析的域名 IP 缓存：回滚时无需重新解析（DNS 不可用也能还原）
	e.domainIPs = make(map[string][]uint32, len(snap.domainIPs))
	for d, ips := range snap.domainIPs {
		e.domainIPs[d] = append([]uint32(nil), ips...)
	}
	e.dnsDomains = map[string]bool{}
	e.dnsDesired = map[string]bool{}
	e.pending = map[string]int64{}
	// 手工封禁镜像随快照还原：否则回滚后的下一次策略下发会把手工域从期望集合里丢掉
	e.manualDomains = copyBoolMap(snap.manualDomains)
	if len(snap.domains) == 0 {
		return nil
	}
	if _, err := e.applyDomainState(copyBoolMap(snap.domains)); err != nil {
		return fmt.Errorf("回滚域名封堵失败: %w", err)
	}
	// applyDomainState 重建规则时 dnsDomains 尚未提交（enforce.go 的既有顺序），
	// 这里再重建一次，确保 ipset 匹配规则被补上。
	if _, err := e.rebuildDeviceRules(); err != nil {
		return fmt.Errorf("回滚域名封堵规则失败: %w", err)
	}
	return nil
}

// clearCollectedData 清空运行时采集数据（关闭采集时回到空状态）。
func (a *App) clearCollectedData() {
	a.agg.Clear()
	a.devs.Clear()
	a.dns.Clear()
	a.ct.Reset()
}

// ---------------- 外部命令执行 ----------------

// shell 执行 shell 命令（/bin/sh -c），全局串行；-dry-run / -demo 只记录不执行。
// 默认 60s 超时，供管控类命令（iptables/tc/uci 等）使用。
func (a *App) shell(cmd string) (string, error) {
	return a.shellTimeout(cmd, 60*time.Second)
}

// shellTimeout 执行 shell 命令并指定超时（timeout<=0 视为 60s）。
//
// 超时预算必须在拿到 execMu 之后再开始计时：排队等锁的时间不计入超时，
// 否则并发调用一多，命令还没执行就被判定超时。
// 采集类命令（ip/ss/df 等）应传 2~3s：一条慢命令若按 60s 跑，
// 会占住 execMu 把采集/拓扑一起冻结；管控类命令保持长超时。
func (a *App) shellTimeout(cmd string, timeout time.Duration) (string, error) {
	if a.cfg.DryRun || a.cfg.Demo {
		a.recordCmd(cmd)
		logf("[dry-run] %s", cmd)
		return "", nil
	}
	a.execMu.Lock()
	defer a.execMu.Unlock()
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	c := exec.CommandContext(ctx, "/bin/sh", "-c", cmd)
	var buf bytes.Buffer
	c.Stdout = &buf
	c.Stderr = &buf
	err := c.Run()
	out := strings.TrimSpace(buf.String())
	if err != nil {
		logf("exec 失败: %s => %v: %s", cmd, err, out)
		return out, fmt.Errorf("%v: %s", err, out)
	}
	logDebugf("exec: %s", cmd)
	return out, nil
}

// shellInput 带 stdin 的命令（iptables-restore 用）。
func (a *App) shellInput(cmd, input string) (string, error) {
	if a.cfg.DryRun || a.cfg.Demo {
		a.recordCmd(cmd)
		logf("[dry-run] %s <<< (%d bytes)", cmd, len(input))
		return "", nil
	}
	a.execMu.Lock()
	defer a.execMu.Unlock()
	// 超时预算必须在拿到 execMu 之后再开始计时：
	// 排队等锁的时间不计入超时，否则并发调用一多，命令还没执行就被判定超时。
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	c := exec.CommandContext(ctx, "/bin/sh", "-c", cmd)
	c.Stdin = strings.NewReader(input)
	var buf bytes.Buffer
	c.Stdout = &buf
	c.Stderr = &buf
	err := c.Run()
	out := strings.TrimSpace(buf.String())
	if err != nil {
		logf("exec(stdin) 失败: %s => %v: %s", cmd, err, out)
		return out, fmt.Errorf("%v: %s", err, out)
	}
	logDebugf("exec(stdin): %s", cmd)
	return out, nil
}

// shellQuiet 忽略错误的命令（恢复/清理路径）。
func (a *App) shellQuiet(cmd string) {
	if _, err := a.shell(cmd); err != nil {
		logf("命令失败（忽略）: %s: %v", cmd, err)
	}
}

// shellQuietOutput 执行并返回输出，忽略错误。
//
// 可选 timeout：采集类调用（ip/ss/df 等）传 2~3s，慢命令最多冻结 2~3s 而不是 60s；
// 不传（或传 <=0）保持默认 60s，管控类调用无需改动。
// 用变参兼容既有调用方，其它模块可按需逐个迁移到短超时。
func (a *App) shellQuietOutput(cmd string, timeout ...time.Duration) (string, error) {
	if len(timeout) > 0 {
		return a.shellTimeout(cmd, timeout[0])
	}
	return a.shellTimeout(cmd, 60*time.Second)
}

// iptablesSnapshot 保存当前 iptables 规则快照（回滚用）。
func (a *App) iptablesSnapshot() string {
	if a.cfg.Demo || a.cfg.DryRun {
		return ""
	}
	out, err := a.shell("iptables-save 2>/dev/null")
	if err != nil {
		logf("iptables-save 失败，无法生成回滚快照: %v", err)
		return ""
	}
	return out
}

// iptablesSnapshotComplete 校验快照完整性。
//
// iptables-save 的输出按表分段：每段以 "*<表名>" 开头、以 "COMMIT" 结尾。
// 快照若被截断（例如保存过程中进程被杀），某段就缺少 COMMIT —— 此时绝不能
// 拿去做整表恢复，否则 iptables-restore 会把防火墙/NAT 表清空，路由器直接断网。
func iptablesSnapshotComplete(snapshot string) bool {
	s := strings.TrimSpace(snapshot)
	if s == "" {
		return false
	}
	for _, table := range []string{"filter", "mangle", "nat", "raw"} {
		head := "*" + table
		i := strings.Index(s, head+"\n")
		if i < 0 {
			return false
		}
		rest := s[i+len(head)+1:]
		commit := strings.Index(rest, "\nCOMMIT")
		if commit < 0 {
			return false
		}
		// 下一张表出现在 COMMIT 之前 → 本段被截断
		if next := strings.Index(rest, "\n*"); next >= 0 && next < commit {
			return false
		}
	}
	return strings.HasSuffix(s, "COMMIT")
}

// cleanupOwnChains 只清理本项目自有的 UBM_* 链及其跳转，其余规则原样保留。
// 复用管控层的 teardownIptables（同时复位 chainsReady，避免下次下发时链已不存在）。
func (a *App) cleanupOwnChains() {
	if a.enf != nil {
		if err := a.enf.teardownIptables(); err != nil {
			logf("清理 iptables 自有链失败: %v", err)
		}
		return
	}
	a.shellQuiet(strings.Join([]string{
		"iptables -F UBM_FWD 2>/dev/null",
		"iptables -F UBM_IN 2>/dev/null",
		"iptables -D FORWARD -j UBM_FWD 2>/dev/null",
		"iptables -D INPUT -j UBM_IN 2>/dev/null",
		"iptables -X UBM_FWD 2>/dev/null",
		"iptables -X UBM_IN 2>/dev/null",
	}, "; "))
}

// restoreIptables 用快照回滚 iptables（失败保护版）。
//
// 绝不使用「整表 flush + restore」的裸 iptables-restore 回滚：
// 快照被截断或命令中途被杀都会把防火墙/NAT 表清空 —— 路由器直接断网。
// 这里分两步：
//  1. 快照完整时用 iptables-restore --noflush 增量恢复（不清空既有表）；
//  2. 快照不完整或增量恢复失败时，只清理本项目自有的 UBM_* 链，其余规则原样保留。
func (a *App) restoreIptables(snapshot string) {
	if snapshot == "" || a.cfg.Demo || a.cfg.DryRun {
		return
	}
	if iptablesSnapshotComplete(snapshot) {
		logf("回滚 iptables 规则（iptables-restore --noflush，不清空既有表）")
		if _, err := a.shellInput("iptables-restore --noflush", snapshot); err == nil {
			return
		} else {
			logf("iptables 增量回滚失败，转为只清理本项目自有链: %v", err)
		}
	} else {
		logf("iptables 快照不完整（可能被截断），跳过整表恢复，只清理本项目自有链")
	}
	a.cleanupOwnChains()
}

// cleanupStaleDeviceMeta 清理历史 state 中累积的非内网设备（公网/docker 邻居等）。
// 只删除既无别名/分组、也无封禁/限速/隐藏状态的元数据，避免误删用户配置。
func (a *App) cleanupStaleDeviceMeta() {
	metas := a.store.AllDeviceMeta()
	removed := 0
	for ip, m := range metas {
		if m.Blocked || m.Hidden ||
			m.LimitKbps.Down > 0 || m.LimitKbps.Up > 0 {
			continue
		}
		if _, internal := a.networkForIP(ip); internal {
			continue
		}
		if m.Alias != "" || m.Group != "" {
			continue // 用户手工配置过的保留
		}
		a.store.DeleteDeviceMeta(ip)
		removed++
	}
	if removed > 0 {
		logf("已清理 %d 条历史外网设备元数据", removed)
	}
}

// ---------------- 采集 ----------------

// collectOnce 执行一轮采集：conntrack → 差分 → 聚合 → 设备速率 → 系统指标。
func (a *App) collectOnce() {
	// 总开关或采集开关关闭时立即返回：不读 /proc、不做任何聚合
	if !a.dataActive() {
		return
	}
	now := nowUnix()
	interval := a.collectIntervalSec()

	if a.cfg.Demo && a.demo != nil {
		lines := a.demo.Lines(now, int64(interval))
		if _, err := a.ct.Collect(strings.NewReader(lines), now, a.onDelta, a.onGone); err != nil {
			logf("演示流量生成失败: %v", err)
		}
	} else {
		if _, err := a.ct.CollectFile(conntrackPath, now, a.onDelta, a.onGone); err != nil {
			if now%60 == 0 {
				logf("读取 conntrack 失败: %v", err)
			}
		}
	}
	rates := a.agg.Tick(int64(interval), now)
	a.devs.ApplyRates(rates, now)
	a.sys.Sample(int64(interval))
	// 接口计数固定节拍采样：拓扑节点速率不再依赖前端轮询频率的窗口均值
	a.sampleIfaceCounters(now)
	a.updateScale()
	if a.cfg.Demo && a.demo != nil {
		a.demo.Tick(now)
	}
}

// updateScale 用物理接口速率校准 conntrack 归因统计。
//
// conntrack 差分在 UDP 打洞/端口复用场景下会重复计入，绝对值不可信
// （实测可虚高 10~1000 倍）；但它给出的「各类/各设备/各域名的相对比例」仍然可用。
// 这里以物理单方向总量（SysSnapshot.PhysTotalBps）为总量基准，算出比例系数并交给 Agg，
// 使所有对外显示的速率都锚定在物理真实量级上。
//
// 口径说明（否则校准结果系统性偏 ~2 倍）：
//   - conntrack 是「每连接一次计数」：ct = raw.Up + raw.Down，每个字节在其方向上计一次；
//   - 旁路由形态下 br-lan 是中转桥，NetUp+NetDown 这类「进出合计」每字节计两次
//     （RX≈TX≈总流量），与 ct 不同量纲 —— 不能直接相除；
//   - PhysTotalBps 已按单方向口径给出：有真 WAN 取 WAN RX+TX，无 WAN 取 (RX+TX)/2，
//     与 ct 同量纲，f = phys/ct 才是真实校准系数。
func (a *App) updateScale() {
	sys := a.sys.Snapshot()
	phys := sys.PhysTotalBps
	if phys <= 0 {
		return
	}
	// 取未经校准的 conntrack 速率（LastRates 已缩放，这里用 Agg 内部原始值）
	raw := a.agg.RawRates()
	ct := raw.DownBps + raw.UpBps
	if ct <= 0 {
		return // conntrack 本周期无数据：保持上一系数
	}
	f := float64(phys) / float64(ct)
	if f <= 0.0001 {
		return
	}
	var next float64
	if a.scaleInit {
		// 平滑，避免系数抖动导致显示跳变
		old := a.agg.Scale()
		if old <= 0 {
			old = f
		} else {
			old = 0.7*old + 0.3*f
		}
		next = old
	} else {
		// 首次直接取值：Scale() 未初始化时返回 1 而非 0，靠 old<=0 判断「未设置」
		// 永远不成立（旧逻辑因此只能从 1 慢慢逼近，约 40s 收敛）。
		// scaleInit 只在本 App 内标记首个可用系数，直接 SetScale(f) 立即锚定。
		next = f
		a.scaleInit = true
	}
	a.agg.SetScale(next)
	a.scaleLogN++
	if a.scaleLogN%30 == 1 {
		logDebugf("[scale] 物理(单向)=%.2f Mbps conntrack=%.2f Mbps 系数=%.6f", float64(phys)/1e6, float64(ct)/1e6, next)
	}
}

// currentFlowContext 读取 DNS 模块当前持有的流向上下文（回填用）。
//
// 说明：DNSResolver 的上下文发布方法（onFlowContext）定义在 dns.go（其它模块维护），
// 本文件只补一个读取方法，保证「设备级 DNS 回退」使用的上下文始终是当前连接，
// 不依赖采集侧发布/清理的隐式时序。
func (d *DNSResolver) currentFlowContext() FlowContext {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.flowCtx
}

// onDelta 处理一条 conntrack 增量：域名归因 → 聚合 → 设备累计 → 连接明细 → 研判。
func (a *App) onDelta(d FlowDelta) {
	now := nowUnix()
	// 非设备流量（本机 / docker0 等）：
	//
	// 这类记录与「设备侧记录」是同一份用户流量的另一条 conntrack 条目
	//（例：客户端→目标的 TPROXY 记录 与 路由器(xray)→上游的出口记录），
	// 若同时计入 path，会让 direct/proxy 链路流量翻倍，与「互联网节点 = 链路之和」
	// 的口径自相矛盾（实测链路值放大千倍）。
	// 因此本机流量只保留在连接层展示，不计入 path 链路、不计入全局总量。
	if d.DeviceIP == "" {
		return
	}
	deviceName := ""
	if st, ok := a.devs.State(d.DeviceIP); ok {
		deviceName = displayName(st.Hostname, d.DeviceIP)
	}
	domain, cat, label, ok := a.dns.Attribute(d.DstIP, now)
	if !ok {
		// 连接域名回退：短 TTL 未命中时查 6h 长 TTL 反查索引（dnsTap 关闭/日志断档时仍尽量可读）
		if d2, c2, l2, ok2 := a.dns.ReverseLookup(d.DstIP, now); ok2 {
			domain, cat, label, ok = d2, c2, l2, true
		}
	}
	if !ok && d.Path == "proxy" {
		// 设备级回退：走代理时 dst 是代理服务器/隧道出口 IP，无法按目的 IP 归因；
		// 用该设备最近一次 DNS 查询（如 www.youtube.com）归类，解决代理流量 100% other。
		//
		// 流向限制在此显式判定（只对 proxy 连接生效）：直连/内网连接若也回退，
		// 会把裸 IP 流量误挂到上一次查询的域名上。
		// 同时把本条连接的上下文（d.Path / d.DstIP / d.DPort 等）显式发布给 DNS 模块，
		// 使 DNS 侧的「仅代理连接生效」判断看到的就是当前连接，而不是采集侧
		// 隐式发布、可能陈旧的上下文；调用后恢复原上下文，不影响采集节奏。
		prev := a.dns.currentFlowContext()
		a.dns.onFlowContext(FlowContext{
			DeviceIP: d.DeviceIP,
			DstIP:    d.DstIP,
			SPort:    d.SPort,
			DPort:    d.DPort,
			Proto:    d.Proto,
			Path:     d.Path,
		})
		d2, c2, l2, ok2 := a.dns.RecentForDevice(d.DeviceIP, now)
		a.dns.onFlowContext(prev)
		if ok2 {
			domain, cat, label, ok = d2, c2, l2, true
		}
	}
	if !ok {
		cat = classifyPort(d.Proto, d.DPort)
	}
	// 代理隧道端口归因失败时至少归 web，不再落入 other
	if cat == "other" && d.Path == "proxy" {
		cat = "web"
	}
	// 开源威胁情报：恶意域名 / 恶意 IP（走代理时隧道内目标不可见，dst=代理服务器通常不在库中）
	if domain != "" {
		if tr, ok := ThreatDomainLookup(domain); ok && a.sec != nil {
			a.sec.OnThreatDomain(domain, d.DeviceIP, tr, now)
		}
	}
	if tr, ok := ThreatIPLookup(d.DstIP); ok && a.sec != nil {
		a.sec.OnThreatIP(d.DstIP, d.DeviceIP, tr, now)
	}
	appName := label
	if appName == "" && domain != "" {
		appName = domain
	}
	// 连接明细始终维护（含首帧 baseline），便于 /api/traffic/conns 展示
	a.agg.UpsertConn(ConnUpdate{
		Key: d.Key, Proto: d.Proto, SrcIP: d.DeviceIP, SrcPort: d.SPort,
		DstIP: d.DstIP, DstPort: d.DPort, DeviceIP: d.DeviceIP, State: d.State,
		UpBytes: d.TotalUp, DownBytes: d.TotalDown, StartedAt: d.Started, Now: now,
		Domain: domain, App: appName, Category: cat, Path: d.Path, Iface: d.Iface,
		DeviceName: deviceName,
	})
	if d.Baseline || (d.UpDelta == 0 && d.DownDelta == 0) {
		return
	}
	a.agg.AddDelta(d.DeviceIP, d.DstIP, cat, domain, d.UpDelta, d.DownDelta, now)
	a.agg.AddPathBytes(d.Path, d.UpDelta, d.DownDelta)
	a.devs.NoteTraffic(d.DeviceIP, d.UpDelta, d.DownDelta, now)
	if domain != "" {
		a.dns.AddBytes(domain, d.UpDelta, d.DownDelta, d.DeviceIP, now)
		// 记录该域名实际使用的目的端口，用于把「域名」还原成 scheme://host:port 的完整 URL。
		// 只采信「设备主动发起、非 TPROXY 改写、非临时端口」的记录：
		//   · Inbound 连接的方向被交换过，DPort 是对端的临时端口（如 46423），不可用；
		//   · TPROXY 记录的 SPort 是 16384 特征端口，DPort 是改写后的端口，不可用；
		//   · >=32768 基本都是临时端口，不是服务端口。
		if !d.Inbound && d.SPort != 16384 && d.DPort > 0 && d.DPort < 32768 {
			a.dns.AddPort(domain, d.DPort)
		}
	}
	a.sec.OnFlow(d, now, isForeignIP(d.DstIP))
}

// onGone conntrack 条目消失：删除连接明细。
func (a *App) onGone(key string) {
	a.agg.DropConn(key)
}

// ---------------- 后台循环 ----------------

// runCollector 采集循环（动态间隔，time.Timer，无忙等）。
func (a *App) runCollector() {
	defer a.wg.Done()
	for {
		interval := time.Duration(a.collectIntervalSec()) * time.Second
		timer := time.NewTimer(interval)
		select {
		case <-timer.C:
			if !a.dataActive() {
				continue // 总开关/采集开关关闭：直接跳过，不读任何文件
			}
			func() {
				defer func() {
					if rec := recover(); rec != nil {
						logf("采集协程 panic: %v", rec)
					}
				}()
				a.collectOnce()
			}()
		case <-a.stop:
			timer.Stop()
			return
		}
	}
}

// runSSE 每 2s 推送一帧 tick（默认增量，每 10 帧全量）。
func (a *App) runSSE() {
	defer a.wg.Done()
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	last := map[string]tickDevice{}
	frame := 0
	for {
		select {
		case <-ticker.C:
			// 单帧 panic 只丢这一帧，不拖垮进程也不终止推送循环
			func() {
				defer func() {
					if rec := recover(); rec != nil {
						logf("SSE 推送 panic: %v", rec)
					}
				}()
				frame++
				full := frame%10 == 1
				a.hub.Broadcast("tick", a.buildTick(nowUnix(), full, last))
			}()
		case <-a.stop:
			return
		}
	}
}

// runDeviceRefresh 每 10s 合并租约/邻居表。
func (a *App) runDeviceRefresh() {
	defer a.wg.Done()
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if !a.dataActive() {
				continue // 采集关闭时不读 dhcp.leases / ip neigh
			}
			func() {
				defer func() {
					if rec := recover(); rec != nil {
						logf("设备刷新 panic: %v", rec)
					}
				}()
				a.syncConnNets() // 接口/路由可能变化（zt up/down、vpn 启停），10s 同步一次
				a.devs.Refresh(nowUnix())
			}()
		case <-a.stop:
			return
		}
	}
}

// runSecurity 每 5s 研判一次。
func (a *App) runSecurity() {
	defer a.wg.Done()
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if !a.alertsOn() {
				continue // 告警开关关闭：不做研判、不产生新事件
			}
			func() {
				defer func() {
					if rec := recover(); rec != nil {
						logf("研判协程 panic: %v", rec)
					}
				}()
				a.sec.Analyze(nowUnix())
			}()
		case <-a.stop:
			return
		}
	}
}

// runPolicies 每 15s 评估一次策略。
func (a *App) runPolicies() {
	defer a.wg.Done()
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if !a.policyEngineOn() {
				continue // 定时策略开关关闭：不自动启停任何规则
			}
			func() {
				defer func() {
					if rec := recover(); rec != nil {
						logf("策略评估 panic: %v", rec)
					}
				}()
				a.enf.ReconcilePolicies(time.Now())
			}()
		case <-a.stop:
			return
		}
	}
}

// runStateSaver 每 30s 合并写 state.json（脏标记），并定期清理旧流量文件。
func (a *App) runStateSaver() {
	defer a.wg.Done()
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	purgeTicker := time.NewTicker(time.Hour)
	defer purgeTicker.Stop()
	for {
		select {
		case <-ticker.C:
			func() {
				defer func() {
					if rec := recover(); rec != nil {
						logf("状态保存 panic: %v", rec)
					}
				}()
				if err := a.store.SaveIfDirty(); err != nil {
					logf("保存 state.json 失败: %v", err)
				}
			}()
		case <-purgeTicker.C:
			func() {
				defer func() {
					if rec := recover(); rec != nil {
						logf("流量清理 panic: %v", rec)
					}
				}()
				a.store.PurgeOldTraffic(a.store.Settings().RetentionDays)
			}()
		case <-a.stop:
			return
		}
	}
}

// runThreatUpdater 威胁情报库定时自动更新（间隔可配置：alert.threatUpdateHours，默认 6h）。
// 独立 goroutine，不与采集/SSE 抢锁；更新失败保留旧库。
func (a *App) runThreatUpdater() {
	defer a.wg.Done()
	for {
		timer := time.NewTimer(a.threatUpdateHours())
		select {
		case <-timer.C:
			// 更新类 panic 只丢这一轮，不拖垮进程也不终止更新循环
			func() {
				defer func() {
					if rec := recover(); rec != nil {
						logf("威胁情报更新 panic: %v", rec)
					}
				}()
				res := a.updateThreatsNow()
				if !res.Ok {
					logf("威胁情报库定时更新失败（保留旧库）: %v", res.Errors)
					return
				}
				logf("威胁情报库定时更新完成：域名 %d、IP %d", res.Domains, res.IPs)
			}()
		case <-a.stop:
			timer.Stop()
			return
		}
	}
}

// threatUpdateHours 自动更新间隔（读取设置，范围 1~168h，默认 6h）。
func (a *App) threatUpdateHours() time.Duration {
	h := 6
	if a.store != nil {
		if v := a.store.Settings().Alert.ThreatUpdateHours; v >= 1 && v <= 168 {
			h = v
		}
	}
	return time.Duration(h) * time.Hour
}

// updateThreatsNow 手动/定时更新入口（demo 模式 mock 不改数据）。
func (a *App) updateThreatsNow() UpdateResult {
	return UpdateThreats(a.store.Dir(), a.cfg.Demo)
}

// emitEvent 事件落库 + SSE alert 推送。
func (a *App) emitEvent(ev Event) {
	saved := a.store.AddEvent(ev)
	if a.hub != nil {
		a.hub.Broadcast("alert", saved)
	}
}

// ---------------- 启动 / 退出 ----------------

// withRequestTimeout 给非流式请求加整体处理超时（兜底慢 handler 长期占用 goroutine/fd）。
//
// 为什么不设全局 WriteTimeout：/api/stream 是长连接（服务端持续 flush），
// 全局写超时到点会把 SSE 掐断。因此按路径分流：
//   - /api/stream 原样透传（保留 http.Flusher 等接口）；
//   - 其余路径套 http.TimeoutHandler：超时后写 503 并结束 handler，
//     即使 handler 内部卡住也不会一直占着连接。
func (a *App) withRequestTimeout(next http.Handler, d time.Duration) http.Handler {
	limited := http.TimeoutHandler(next, d, "请求处理超时")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/stream") {
			next.ServeHTTP(w, r)
			return
		}
		limited.ServeHTTP(w, r)
	})
}

// Run 启动全部组件并阻塞直到收到退出信号。
func (a *App) Run() error {
	if err := a.store.Load(); err != nil {
		logf("加载状态失败（使用默认值继续）: %v", err)
	}
	a.store.PurgeOldTraffic(a.store.Settings().RetentionDays)
	// 威胁情报库：优先加载 <data>/threats.json（更新后的完整列表），无/损坏则用内置静态库
	if err := LoadThreats(threatStorePath(a.store.Dir())); err != nil {
		logf("加载威胁情报库文件失败（使用内置静态库）: %v", err)
	}

	// demo 模式默认全开，方便前端联调；真实模式默认全部关闭（不影响路由器现有功能）
	if a.cfg.Demo {
		s := a.store.Settings()
		if !s.Enabled && !s.Collect && !s.DNSTap && !s.DeviceControl &&
			!s.DomainBlock && !s.Schedule && !s.Alerts && !s.History {
			a.store.UpdateSettings(func(st *Settings) {
				st.Enabled = true
				st.Collect = true
				st.DNSTap = true
				st.DeviceControl = true
				st.DomainBlock = true
				st.Schedule = true
				st.Alerts = true
				st.History = true
			})
			logf("演示模式：默认启用全部开关（可在设置中关闭）")
		}
	}

	// 载入最近 24h 分钟桶（仅在采集 + 历史统计开启时）
	settings := a.store.Settings()
	if settings.Enabled && settings.Collect && settings.History {
		now := nowUnix()
		history := a.store.LoadTrafficBuckets(now-86400, now)
		if len(history) > 0 {
			a.agg.LoadHistory(history)
			logf("已载入历史流量桶 %d 个", len(history))
		}
	}

	// 先确定 DNS 日志路径：dnsmasq 若跑在 ujail 沙箱里，默认 /tmp/guanlan 在 jail 内不可见，
	// 必须改用 jail 里 rw 挂载的 /var/run/dnsmasq（见 resolveDNSLogPath）。
	a.resolveDNSLogPath()
	if a.cfg.Demo && a.demo != nil {
		a.demo.Init()
		logf("演示模式：已生成合成设备/策略/域名/历史流量/事件")
	} else {
		a.startupDNS()
	}

	// 清理历史 state 中累积的外网/非内网设备元数据（用户真机反馈：页面出现大量外网 IP）
	if !a.cfg.Demo {
		a.cleanupStaleDeviceMeta()
	}
	// 从 store 恢复持久化封禁/限速记录（含本机/网关保护过滤），管控开关开启时会重新下发规则
	a.enf.RestoreFromStore()
	// 加载告警白名单（加白的事件类型+目标不再产生新事件）
	a.sec.RestoreWhitelist()
	// 初始化 conntrack 多网段识别（LAN + zt/vpn 本地接口 + zt/vpn 远端路由）
	a.syncConnNets()
	// 手工封禁域名恢复下发（domainBlock 开关开启时；关闭时内部直接跳过）
	if a.enf.ApplyManualDomains() {
		logf("已恢复手工封禁域名 %d 条", len(a.store.DomainBlocks()))
	}
	// 明文 HTTP URL 抓取（可选开关，默认关闭）：只在开启且采集生效时启动
	if s := a.store.Settings(); s.Enabled && s.Collect && s.HTTPTap {
		if err := a.StartHTTPTap(); err != nil {
			logf("HTTP 明文 URL 抓取启动失败（不影响其它功能）: %v", err)
		}
	}

	a.hub.SetInitial(func() interface{} {
		return a.buildTick(nowUnix(), true, nil)
	})
	a.checkSingleInstance()

	a.wg.Add(7)
	go a.runCollector()
	go a.runSSE()
	go a.runDeviceRefresh()
	go a.runSecurity()
	go a.runPolicies()
	go a.runStateSaver()
	go a.runThreatUpdater()
	if !a.cfg.Demo && !a.cfg.DryRun {
		a.wg.Add(1)
		go func() {
			defer a.wg.Done()
			// runDNSTailer 的循环体在 dns.go（其它模块维护），这里兜底：
			// 它 panic 时记录日志而不是带走整个进程（代价是该协程停止，
			// procd 不会重启；相比进程崩溃导致全部服务中断更可控）
			defer func() {
				if rec := recover(); rec != nil {
					logf("DNS 日志采集 panic: %v", rec)
				}
			}()
			a.runDNSTailer()
		}()
	} else {
		logf("演示/干跑模式：不启动 DNS 日志采集")
	}

	srv := &http.Server{
		Addr:              a.cfg.Addr,
		Handler:           a.withRequestTimeout(a.Handler(), 30*time.Second),
		ReadHeaderTimeout: 10 * time.Second,
		// ReadTimeout 约束「读完整个请求」（含 body）：慢连接不能长期占住 goroutine 与 fd
		//（N1 fd 预算小，几个慢客户端就能把连接槽吃满）。
		// 刻意不设全局 WriteTimeout：/api/stream 是长连接，全局写超时到点会掐断 SSE。
		ReadTimeout: 15 * time.Second,
		IdleTimeout: 60 * time.Second,
	}
	errCh := make(chan error, 1)
	go func() {
		logf("观澜 NetScope %s 启动：http://%s（数据目录 %s，demo=%v，dry-run=%v）",
			AppVersion(), a.cfg.Addr, a.cfg.DataDir, a.cfg.Demo, a.cfg.DryRun)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	select {
	case sig := <-sigCh:
		logf("收到退出信号 %v，开始优雅退出", sig)
	case err := <-errCh:
		logf("HTTP 服务异常退出: %v", err)
	}
	close(a.stop)
	// 先关闭 SSE 广播（结束活跃的流式连接），再关闭 HTTP 服务，
	// 否则 Shutdown 会一直等 SSE handler 结束，白白耗尽 5 秒超时。
	a.hub.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
	// 停止明文 HTTP 抓包（释放 AF_PACKET 套接字）
	a.StopHTTPTap()
	if err := a.store.Save(); err != nil {
		logf("退出前保存状态失败: %v", err)
	}
	a.removePid()
	done := make(chan struct{})
	go func() { a.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		logf("部分协程未在 3s 内退出，强制结束")
	}
	// 释放按 *App 挂载的采集缓存：注册表是包级 sync.Map，不删会让每个 App
	// （进程退出/单测反复 NewApp）永久留一份缓存。
	a.releaseCmdCache()
	logf("观澜 NetScope 已退出")
	return nil
}

// startupDNS 真机启动：确保日志目录、检查旁挂配置（只读，不做任何写操作）。
func (a *App) startupDNS() {
	settings := a.store.Settings()
	if !settings.Enabled || !settings.DNSTap {
		logf("DNS 旁挂未启用（总开关/采集开关/DNS 开关关闭），跳过 DNS 日志相关初始化")
		return
	}
	if err := os.MkdirAll(dnsLogDir, 0o755); err != nil {
		logf("创建 DNS 日志目录失败: %v", err)
	}
	if a.DNSTapEnabled() {
		logf("DNS 旁挂已配置：%s", dnsLogPath)
		return
	}
	if os.Getenv("GUANLAN_DNS_TAP_AUTO") == "1" {
		logf("检测到 DNS 旁挂未配置，按 GUANLAN_DNS_TAP_AUTO=1 自动启用")
		if err := a.ApplyDNSTap(true); err != nil {
			logf("自动启用 DNS 旁挂失败: %v", err)
		}
		return
	}
	logf("提示：DNS 旁挂尚未配置。请在设置页开启 dnsTap（会短暂重启 dnsmasq），" +
		"或设置环境变量 GUANLAN_DNS_TAP_AUTO=1 允许启动时自动启用")
}

// checkSingleInstance 单实例锁（/tmp/guanlan.pid，仅 Linux 真机）。
//
// pid 文件位于 /tmp（sticky 目录，任何本地用户可写），内容绝不能拼进 shell 命令：
// 先用 strconv 校验为纯数字，再用 /proc/<pid> + signal 0 判活，全程不走 shell。
func (a *App) checkSingleInstance() {
	if a.cfg.Demo || a.cfg.DryRun || runtime.GOOS != "linux" {
		return
	}
	pidPath := "/tmp/guanlan.pid"
	a.pidPath = pidPath
	if b, err := os.ReadFile(pidPath); err == nil {
		raw := strings.TrimSpace(string(b))
		if raw != "" {
			pid, perr := strconv.Atoi(raw)
			switch {
			case perr != nil || pid <= 0:
				// 内容不是合法 pid：按垃圾文件处理，绝不当作命令执行
				logf("pid 文件内容非法（%q），已按残留处理", raw)
			case processAlive(pid):
				log.Fatalf("检测到已有观澜实例在运行（pid %d），本次启动退出", pid)
			default:
				logf("清理残留 pid 文件（pid %d 已不存在）", pid)
			}
		}
	}
	if err := os.WriteFile(pidPath, []byte(strconv.Itoa(os.Getpid())), 0o644); err != nil {
		logf("写入 pid 文件失败: %v", err)
	}
}

// processAlive 判断 pid 对应的进程是否存在（不走 shell，避免命令注入）。
// 优先用 signal 0 探测；EPERM 表示进程存在但无权限，同样视为存活。
func processAlive(pid int) bool {
	if proc, err := os.FindProcess(pid); err == nil {
		err = proc.Signal(syscall.Signal(0))
		if err == nil {
			return true
		}
		if errors.Is(err, os.ErrPermission) {
			return true
		}
	}
	// 兜底：Linux 上 /proc/<pid> 存在即代表进程存在
	_, err := os.Stat("/proc/" + strconv.Itoa(pid))
	return err == nil
}

func (a *App) removePid() {
	if a.pidPath == "" {
		return
	}
	_ = os.Remove(a.pidPath)
}

// ---------------- 通用工具 ----------------

func nowUnix() int64 { return time.Now().Unix() }

func readAll(r io.Reader) ([]byte, error) { return io.ReadAll(r) }

func fmtSscan(s string, v ...interface{}) (int, error) { return fmt.Sscan(s, v...) }

func parseFloat(s string) (float64, error) { return strconv.ParseFloat(strings.TrimSpace(s), 64) }

func parseInt64(s string) (int64, error) { return strconv.ParseInt(strings.TrimSpace(s), 10, 64) }

func parseUint64(s string) (uint64, error) { return strconv.ParseUint(strings.TrimSpace(s), 10, 64) }

func trimSpaceBytes(b []byte) []byte { return bytes.TrimSpace(b) }

func goGOARCH() string { return runtime.GOARCH }

// main 解析 flag 并启动服务。
// localIPv4s 返回本机所有接口的 IPv4 地址（路由器自身）。
// 用于把本机出站流量（如 xray 透明代理出口）从「设备」统计中排除。
func localIPv4s() []uint32 {
	var out []uint32
	ifs, err := net.Interfaces()
	if err != nil {
		return out
	}
	for _, ifi := range ifs {
		addrs, err := ifi.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			if v4 := ipn.IP.To4(); v4 != nil {
				var b [4]byte
				copy(b[:], v4)
				out = append(out, ip4ToUint32(b))
			}
		}
	}
	return out
}

func main() {
	addr := flag.String("addr", ":8088", "监听地址")
	webDir := flag.String("web", "", "前端资源目录（空=使用内嵌资源）")
	dataDir := flag.String("data", "", "数据目录（默认自动探测 /mnt 下持久分区，兜底 /etc/guanlan/data；演示模式 ./tmpdata）")
	demo := flag.Bool("demo", false, "演示模式：不读 /proc、不执行命令，生成合成数据")
	dryRun := flag.Bool("dry-run", false, "干跑模式：所有外部命令只记录不执行（可用 GL_DRYRUN=1）")
	flag.Parse()

	log.SetFlags(log.LstdFlags)
	log.SetOutput(os.Stdout)

	dd := strings.TrimSpace(*dataDir)
	if dd == "" {
		dd = defaultDataDir(*demo)
	}
	dd = filepath.Clean(dd)
	dr := *dryRun || os.Getenv("GL_DRYRUN") == "1"

	cfg, err := LoadConfig(dd, *demo, dr)
	if err != nil {
		log.Fatalf("初始化配置失败: %v", err)
	}
	cfg.Addr = *addr
	cfg.WebDir = *webDir

	logf("观澜 NetScope %s（域名规则 %d 条，黑名单 %d 个，OUI %d 条）",
		AppVersion(), DomainRuleCount(), BlockedDomainCount(), OUIEntryCount())
	if cfg.UsingDefaultPassword() {
		logf("提示：当前仍使用默认密码，请在设置页及时修改")
	}
	a := NewApp(cfg)
	// 前端资源：内嵌或开发目录
	a.webFS = buildWebFS(cfg.WebDir)

	if err := a.Run(); err != nil {
		log.Fatalf("服务异常退出: %v", err)
	}
}
