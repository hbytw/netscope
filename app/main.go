package main

// 进程入口：flag 解析、组件装配、采集/推送/巡检循环、HTTP 服务、优雅退出。
//
// 运行形态：
//   guanlan -addr :8088 -data /mnt/mmcblk2p4/guanlan          （路由器真机）
//   guanlan -addr 127.0.0.1:8088 -web .\app\web -data tmpdata -demo   （Windows 本地联调）
//   guanlan -dry-run ...                                     （真机零风险验证：命令只记录不执行）

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
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
	pidPath  string

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
	proxyMu sync.Mutex
	proxyUp bool
	proxyAt int64

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

	applied, revoked, err := a.applySwitchTransitions(cur, next)
	if err != nil {
		return cur, applied, revoked, err
	}
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
	return out, applied, revoked, nil
}

// applySwitchTransitions 执行实际启停动作并给出中文描述。
func (a *App) applySwitchTransitions(old, next Settings) ([]string, []string, error) {
	var applied, revoked []string

	// 1) 撤销（先关闭，保证不残留规则）
	if old.DNSTap && !next.DNSTap {
		if err := a.ApplyDNSTap(false); err != nil {
			return applied, revoked, &switchError{status: 500, msg: err.Error()}
		}
		revoked = append(revoked, "已关闭 dnsmasq 日志旁挂并还原 UCI 选项")
	}
	if old.DeviceControl && !next.DeviceControl {
		a.enf.RevokeDeviceControl()
		revoked = append(revoked, "已撤销 UBM_FWD/UBM_IN 断网规则并清理 tc 限速配置")
	}
	if old.DomainBlock && !next.DomainBlock {
		a.enf.RevokeDomainBlock()
		revoked = append(revoked, "已销毁 ipset ubm_block 并删除域名拦截规则")
	}
	if old.Enabled && !next.Enabled {
		a.enf.RevokeAll()
		revoked = append(revoked, "系统总开关已关闭：全部采集与管控静默，已撤销全部下发规则")
	}
	if old.Schedule && !next.Schedule {
		revoked = append(revoked, "已停止定时策略自动启停")
	}
	if old.Alerts && !next.Alerts {
		a.sec.ResetRuntime()
		revoked = append(revoked, "已停止安全研判（历史事件保留）")
	}
	if old.History && !next.History {
		revoked = append(revoked, "已停止历史流量落盘")
	}
	if old.Collect && !next.Collect {
		a.clearCollectedData()
		revoked = append(revoked, "已停止流量采集并清空实时数据")
	}

	// 2) 启用（dnsTap 先试，失败则不落库）
	if !old.DNSTap && next.DNSTap {
		if err := a.ApplyDNSTap(true); err != nil {
			return applied, revoked, &switchError{status: 500, msg: err.Error()}
		}
		applied = append(applied, "已开启 dnsmasq 日志旁挂（UCI + stop/start + 健康检查）")
	}
	if !old.Enabled && next.Enabled {
		applied = append(applied, "系统总开关已开启")
	}
	if !old.Collect && next.Collect {
		applied = append(applied, "已启动流量采集")
	}
	if !old.DeviceControl && next.DeviceControl {
		applied = append(applied, "设备管控已启用")
	}
	if !old.DomainBlock && next.DomainBlock {
		applied = append(applied, "域名封堵已启用")
	}
	if !old.Schedule && next.Schedule {
		applied = append(applied, "定时策略已启用")
	}
	if !old.Alerts && next.Alerts {
		applied = append(applied, "安全告警研判已启用")
	}
	if !old.History && next.History {
		applied = append(applied, "历史统计已启用")
	}
	return applied, revoked, nil
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
func (a *App) shell(cmd string) (string, error) {
	if a.cfg.DryRun || a.cfg.Demo {
		a.recordCmd(cmd)
		logf("[dry-run] %s", cmd)
		return "", nil
	}
	a.execMu.Lock()
	defer a.execMu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
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
	logf("exec: %s", cmd)
	return out, nil
}

// shellInput 带 stdin 的命令（iptables-restore 用）。
func (a *App) shellInput(cmd, input string) (string, error) {
	if a.cfg.DryRun || a.cfg.Demo {
		a.recordCmd(cmd)
		logf("[dry-run] %s <<< (%d bytes)", cmd, len(input))
		return "", nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	a.execMu.Lock()
	defer a.execMu.Unlock()
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
	logf("exec(stdin): %s", cmd)
	return out, nil
}

// shellQuiet 忽略错误的命令（恢复/清理路径）。
func (a *App) shellQuiet(cmd string) {
	if _, err := a.shell(cmd); err != nil {
		logf("命令失败（忽略）: %s: %v", cmd, err)
	}
}

// shellQuietOutput 执行并返回输出，忽略错误。
func (a *App) shellQuietOutput(cmd string) (string, error) {
	return a.shell(cmd)
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

// restoreIptables 用快照恢复 iptables（失败记录告警）。
func (a *App) restoreIptables(snapshot string) {
	if snapshot == "" || a.cfg.Demo || a.cfg.DryRun {
		return
	}
	logf("回滚 iptables 规则（iptables-restore）")
	if _, err := a.shellInput("iptables-restore", snapshot); err != nil {
		logf("iptables 回滚失败，请检查: %v", err)
	}
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
	if a.cfg.Demo && a.demo != nil {
		a.demo.Tick(now)
	}
}

// onDelta 处理一条 conntrack 增量：域名归因 → 聚合 → 设备累计 → 连接明细 → 研判。
func (a *App) onDelta(d FlowDelta) {
	now := nowUnix()
	// 非设备流量（本机 / docker0 等）：只计入链路 path 流量，不进连接表与设备统计
	if d.DeviceIP == "" {
		if d.Baseline || (d.UpDelta == 0 && d.DownDelta == 0) {
			return
		}
		a.agg.AddPathBytes(d.Path, d.UpDelta, d.DownDelta)
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
	if !ok {
		// 设备级回退：走代理时 dst 是代理服务器 IP，无法按目的 IP 归因；
		// 用该设备最近一次 DNS 查询（如 www.youtube.com）归类，解决代理流量 100% other。
		if d2, c2, l2, ok2 := a.dns.RecentForDevice(d.DeviceIP, now); ok2 {
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
			frame++
			full := frame%10 == 1
			a.hub.Broadcast("tick", a.buildTick(nowUnix(), full, last))
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
			if err := a.store.SaveIfDirty(); err != nil {
				logf("保存 state.json 失败: %v", err)
			}
		case <-purgeTicker.C:
			a.store.PurgeOldTraffic(a.store.Settings().RetentionDays)
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
			res := a.updateThreatsNow()
			if !res.Ok {
				logf("威胁情报库定时更新失败（保留旧库）: %v", res.Errors)
				continue
			}
			logf("威胁情报库定时更新完成：域名 %d、IP %d", res.Domains, res.IPs)
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
			a.runDNSTailer()
		}()
	} else {
		logf("演示/干跑模式：不启动 DNS 日志采集")
	}

	srv := &http.Server{
		Addr:              a.cfg.Addr,
		Handler:           a.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	errCh := make(chan error, 1)
	go func() {
		logf("观澜 NetScope %s 启动：http://%s（数据目录 %s，demo=%v，dry-run=%v）",
			Version, a.cfg.Addr, a.cfg.DataDir, a.cfg.Demo, a.cfg.DryRun)
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
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
	a.hub.Close()
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
func (a *App) checkSingleInstance() {
	if a.cfg.Demo || a.cfg.DryRun || runtime.GOOS != "linux" {
		return
	}
	pidPath := "/tmp/guanlan.pid"
	a.pidPath = pidPath
	if b, err := os.ReadFile(pidPath); err == nil {
		pid := strings.TrimSpace(string(b))
		if pid != "" {
			out, err := exec.Command("/bin/sh", "-c", "kill -0 "+pid+" 2>/dev/null").CombinedOutput()
			_ = out
			if err == nil {
				log.Fatalf("检测到已有观澜实例在运行（pid %s），本次启动退出", pid)
			}
			logf("清理残留 pid 文件（pid %s 已不存在）", pid)
		}
	}
	if err := os.WriteFile(pidPath, []byte(strconv.Itoa(os.Getpid())), 0o644); err != nil {
		logf("写入 pid 文件失败: %v", err)
	}
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
func main() {
	addr := flag.String("addr", ":8088", "监听地址")
	webDir := flag.String("web", "", "前端资源目录（空=使用内嵌资源）")
	dataDir := flag.String("data", "", "数据目录（默认 /mnt/mmcblk2p4/guanlan；演示模式默认 ./tmpdata）")
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
		Version, DomainRuleCount(), BlockedDomainCount(), OUIEntryCount())
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
