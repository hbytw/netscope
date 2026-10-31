package main

// 执行层：iptables 封禁、tc 限速、ipset 域名封堵、策略引擎。
//
// 安全原则（用户正在使用该路由器）：
//   - iptables 只写自有链 UBM_FWD / UBM_IN，绝不修改/删除他人链；
//     修改前用 iptables-save 快照，任何一步失败立即 iptables-restore 回滚。
//   - tc 限速默认关闭；应用失败删除本次创建的 qdisc 回滚，绝不留下坏掉的 br-lan 队列。
//   - 域名封堵不走 dnsmasq，改为域名解析成 IP 写 ipset（ubm_block），
//     iptables 链内 `-m set --match-set ubm_block dst -j DROP`；解析失败进入待重试队列。
//   - 所有外部命令经 App.shell 串行执行；-demo / -dry-run 只记录不执行。

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// errSwitchOff 对应功能开关未开启时的统一错误（API 返回 400）。
var errSwitchOff = errors.New("对应功能开关未启用，请在设置中开启（或开启总开关）")

// errProtectedIP 本机/网关/关键内网地址保护：禁止封禁或限速，避免把路由器自己断网。
var errProtectedIP = errors.New("不能封禁本机/网关/关键内网地址，已拒绝")

const (
	chainFwd  = "UBM_FWD"
	chainIn   = "UBM_IN"
	ipsetName = "ubm_block"
)

// EnforceStatus /api/enforce/status 契约。
type EnforceStatus struct {
	IPTablesRules     int  `json:"iptablesRules"`
	TcDevices         int  `json:"tcDevices"`
	DNSBlockedDomains int  `json:"dnsBlockedDomains"`
	ActivePolicies    int  `json:"activePolicies"`
	DNSTap            bool `json:"dnsTap"`
}

// BlockEntry 封禁/限速记录（/api/enforce/blocks 展示用）。
type BlockEntry struct {
	IP       string `json:"ip"`
	Type     string `json:"type"` // device / dst / limit
	Reason   string `json:"reason"`
	At       int64  `json:"at"`
	DownKbps int    `json:"downKbps"`
	UpKbps   int    `json:"upKbps"`
}

// Enforcer 管控执行器。
type Enforcer struct {
	app *App
	mu  sync.Mutex

	blocked    map[string]bool
	blockedAt  map[string]int64
	dstBlocks  map[string]bool
	dstAt      map[string]int64
	limits     map[string]LimitKbps
	limitsAt   map[string]int64
	dnsDomains map[string]bool
	domainIPs  map[string][]uint32
	pending    map[string]int64 // 待重试域名 -> 下次重试时间

	policyActive map[string]bool

	tcRootOwned    bool
	tcIngressOwned bool
	tcIfbRootOwned bool
	ifbOwned       bool
	chainsReady    bool
}

// NewEnforcer 创建执行器（初始全部关闭）。
func NewEnforcer(a *App) *Enforcer {
	return &Enforcer{
		app:          a,
		blocked:      map[string]bool{},
		blockedAt:    map[string]int64{},
		dstBlocks:    map[string]bool{},
		dstAt:        map[string]int64{},
		limits:       map[string]LimitKbps{},
		limitsAt:     map[string]int64{},
		dnsDomains:   map[string]bool{},
		domainIPs:    map[string][]uint32{},
		pending:      map[string]int64{},
		policyActive: map[string]bool{},
	}
}

// ---------------- iptables ----------------

// ensureChains 创建自有链并挂到 FORWARD/INPUT 首位（幂等）。
func (e *Enforcer) ensureChains() error {
	if e.chainsReady {
		return nil
	}
	cmd := strings.Join([]string{
		"iptables -N UBM_FWD 2>/dev/null",
		"iptables -N UBM_IN 2>/dev/null",
		"iptables -C FORWARD -j UBM_FWD 2>/dev/null || iptables -I FORWARD 1 -j UBM_FWD",
		"iptables -C INPUT -j UBM_IN 2>/dev/null || iptables -I INPUT 1 -j UBM_IN",
	}, "; ")
	if _, err := e.app.shell(cmd); err != nil {
		return fmt.Errorf("初始化 iptables 自有链失败: %w", err)
	}
	e.chainsReady = true
	return nil
}

// rebuildDeviceRules 用当前状态完整重建自有链（幂等，天然可回滚）。
func (e *Enforcer) rebuildDeviceRules() ([]string, error) {
	var applied []string
	if err := e.ensureChains(); err != nil {
		return applied, err
	}
	cmds := []string{
		"iptables -F UBM_FWD 2>/dev/null",
		"iptables -F UBM_IN 2>/dev/null",
	}
	ips := sortedKeysBool(e.blocked)
	for _, ip := range ips {
		cmds = append(cmds,
			fmt.Sprintf("iptables -A UBM_FWD -s %s -m comment --comment guanlan -j DROP", ip),
			fmt.Sprintf("iptables -A UBM_IN -s %s -p udp --dport 53 -m comment --comment guanlan -j DROP", ip))
	}
	for _, ip := range sortedKeysBool(e.dstBlocks) {
		cmds = append(cmds, fmt.Sprintf("iptables -A UBM_FWD -d %s -m comment --comment guanlan -j DROP", ip))
	}
	if len(e.dnsDomains) > 0 {
		cmds = append(cmds,
			"ipset create ubm_block hash:ip -exist",
			"iptables -C UBM_FWD -m set --match-set ubm_block dst -m comment --comment guanlan -j DROP 2>/dev/null || iptables -A UBM_FWD -m set --match-set ubm_block dst -m comment --comment guanlan -j DROP")
	}
	for _, c := range cmds {
		if _, err := e.app.shell(c); err != nil {
			return applied, fmt.Errorf("下发 iptables 规则失败（%s）: %w", c, err)
		}
	}
	applied = append(applied, cmds...)
	return applied, nil
}

// ---------------- tc 限速 ----------------

// classMinor 设备 IP -> tc class minor（/24 用末位，其他用哈希）。
func classMinor(ip string) int {
	if v, ok := parseIPv4Str(ip); ok {
		return 100 + int(v&0xff)
	}
	h := uint32(2166136261)
	for i := 0; i < len(ip); i++ {
		h ^= uint32(ip[i])
		h *= 16777619
	}
	return 100 + int(h%40000)
}

// rebuildTC 按当前 limits 重建限速配置。
func (e *Enforcer) rebuildTC() ([]string, error) {
	var applied []string
	if len(e.limits) == 0 {
		e.teardownTC(true)
		return applied, nil
	}
	cmds := []string{}
	// 下行：br-lan 出口 htb
	if !e.tcRootOwned {
		cmds = append(cmds, "tc qdisc add dev br-lan root handle 1: htb default 1")
	}
	cmds = append(cmds,
		"tc class replace dev br-lan parent 1: classid 1:1 htb rate 1000000kbit ceil 1000000kbit",
		"tc filter del dev br-lan parent 1: prio 10 2>/dev/null")
	downIPs := make([]string, 0, len(e.limits))
	for ip, l := range e.limits {
		if l.Down > 0 {
			downIPs = append(downIPs, ip)
		}
	}
	sort.Strings(downIPs)
	for _, ip := range downIPs {
		l := e.limits[ip]
		minor := classMinor(ip)
		cmds = append(cmds,
			fmt.Sprintf("tc class replace dev br-lan parent 1: classid 1:%d htb rate %dkbit ceil %dkbit", minor, l.Down, l.Down),
			fmt.Sprintf("tc filter add dev br-lan parent 1: protocol ip prio 10 u32 match ip dst %s/32 flowid 1:%d", ip, minor))
	}
	// 上行：ifb0
	upIPs := make([]string, 0, len(e.limits))
	for ip, l := range e.limits {
		if l.Up > 0 {
			upIPs = append(upIPs, ip)
		}
	}
	sort.Strings(upIPs)
	if len(upIPs) > 0 {
		if !e.ifbOwned {
			cmds = append(cmds, "ip link add ifb0 type ifb 2>/dev/null; ip link set ifb0 up")
		}
		if !e.tcIngressOwned {
			cmds = append(cmds, "tc qdisc add dev br-lan handle ffff: ingress 2>/dev/null")
		}
		if !e.tcIfbRootOwned {
			cmds = append(cmds, "tc qdisc add dev ifb0 root handle 2: htb default 1 2>/dev/null")
		}
		cmds = append(cmds,
			"tc class replace dev ifb0 parent 2: classid 2:1 htb rate 1000000kbit ceil 1000000kbit",
			"tc filter del dev br-lan parent ffff: prio 11 2>/dev/null",
			"tc filter del dev ifb0 parent 2: prio 11 2>/dev/null")
		for _, ip := range upIPs {
			l := e.limits[ip]
			minor := classMinor(ip)
			cmds = append(cmds,
				fmt.Sprintf("tc filter add dev br-lan parent ffff: protocol ip prio 11 u32 match ip src %s/32 action mirred egress redirect dev ifb0", ip),
				fmt.Sprintf("tc class replace dev ifb0 parent 2: classid 2:%d htb rate %dkbit ceil %dkbit", minor, l.Up, l.Up),
				fmt.Sprintf("tc filter add dev ifb0 parent 2: protocol ip prio 11 u32 match ip dst %s/32 flowid 2:%d", ip, minor))
		}
	}
	for _, c := range cmds {
		if _, err := e.app.shell(c); err != nil {
			// 回滚：删除本次创建的队列，绝不留下坏队列
			e.teardownTC(true)
			return applied, fmt.Errorf("下发 tc 限速失败（%s）: %w", c, err)
		}
		applied = append(applied, c)
		// 记录创建成功
		switch {
		case strings.HasPrefix(c, "tc qdisc add dev br-lan root"):
			e.tcRootOwned = true
		case strings.Contains(c, "handle ffff: ingress"):
			e.tcIngressOwned = true
		case strings.HasPrefix(c, "tc qdisc add dev ifb0 root"):
			e.tcIfbRootOwned = true
		case strings.HasPrefix(c, "ip link add ifb0"):
			e.ifbOwned = true
		}
	}
	return applied, nil
}

// teardownTC 清理限速配置。force=true 时无条件尝试删除（reset 用）。
func (e *Enforcer) teardownTC(force bool) {
	if force || e.tcRootOwned {
		e.app.shellQuiet("tc qdisc del dev br-lan root 2>/dev/null")
		e.tcRootOwned = false
	}
	if force || e.tcIngressOwned {
		e.app.shellQuiet("tc qdisc del dev br-lan handle ffff: ingress 2>/dev/null")
		e.tcIngressOwned = false
	}
	if force || e.tcIfbRootOwned {
		e.app.shellQuiet("tc qdisc del dev ifb0 root 2>/dev/null")
		e.tcIfbRootOwned = false
	}
	if force || e.ifbOwned {
		e.app.shellQuiet("ip link del ifb0 2>/dev/null")
		e.ifbOwned = false
	}
}

// teardownIptables 清空自有链（uninstall/reset 用），不碰他人规则。
func (e *Enforcer) teardownIptables() error {
	cmd := strings.Join([]string{
		"iptables -F UBM_FWD 2>/dev/null",
		"iptables -F UBM_IN 2>/dev/null",
		"iptables -D FORWARD -j UBM_FWD 2>/dev/null",
		"iptables -D INPUT -j UBM_IN 2>/dev/null",
		"iptables -X UBM_FWD 2>/dev/null",
		"iptables -X UBM_IN 2>/dev/null",
		"iptables -F UBM_FWD 2>/dev/null",
	}, "; ")
	if _, err := e.app.shell(cmd); err != nil {
		return fmt.Errorf("清理 iptables 自有链失败: %w", err)
	}
	e.chainsReady = false
	return nil
}

// ---------------- 状态应用（带回滚） ----------------

// applyDeviceState 应用「断网设备 / 封禁目标 IP / 限速」期望状态；失败回滚到旧状态。
// 同时维护各条目的首次下发时间（封禁列表展示用）。
func (e *Enforcer) applyDeviceState(blocked, dst map[string]bool, limits map[string]LimitKbps) ([]string, error) {
	oldBlocked, oldDst, oldLimits := e.blocked, e.dstBlocks, e.limits
	if mapsEqualBool(oldBlocked, blocked) && mapsEqualBool(oldDst, dst) && mapsEqualLimit(oldLimits, limits) {
		return nil, nil
	}
	now := nowUnix()
	for ip := range blocked {
		if e.blockedAt[ip] == 0 {
			e.blockedAt[ip] = now
		}
	}
	for ip := range e.blockedAt {
		if !blocked[ip] {
			delete(e.blockedAt, ip)
		}
	}
	for ip := range dst {
		if e.dstAt[ip] == 0 {
			e.dstAt[ip] = now
		}
	}
	for ip := range e.dstAt {
		if !dst[ip] {
			delete(e.dstAt, ip)
		}
	}
	for ip := range limits {
		if e.limitsAt[ip] == 0 {
			e.limitsAt[ip] = now
		}
	}
	for ip := range e.limitsAt {
		if _, ok := limits[ip]; !ok {
			delete(e.limitsAt, ip)
		}
	}
	snapshot := e.app.iptablesSnapshot()
	e.blocked, e.dstBlocks, e.limits = blocked, dst, limits
	var applied []string
	rules, err := e.rebuildDeviceRules()
	applied = append(applied, rules...)
	if err == nil {
		var tcApplied []string
		tcApplied, err = e.rebuildTC()
		applied = append(applied, tcApplied...)
	}
	if err != nil {
		e.blocked, e.dstBlocks, e.limits = oldBlocked, oldDst, oldLimits
		e.app.restoreIptables(snapshot)
		if _, rerr := e.rebuildDeviceRules(); rerr != nil {
			logf("回滚 iptables 失败: %v", rerr)
		}
		if _, rerr := e.rebuildTC(); rerr != nil {
			logf("回滚 tc 失败: %v", rerr)
		}
		return applied, fmt.Errorf("管控下发失败，已回滚: %w", err)
	}
	return applied, nil
}

// SetBlocked 手动断网/恢复（API 调用；策略引擎也复用）。
func (e *Enforcer) SetBlocked(ip string, blocked bool) ([]string, error) {
	if !e.app.deviceControlOn() {
		return nil, errSwitchOff
	}
	if blocked && e.app.isProtectedIP(ip) {
		return nil, errProtectedIP
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.blocked[ip] == blocked {
		return nil, nil
	}
	desired := copyBoolMap(e.blocked)
	if blocked {
		desired[ip] = true
	} else {
		delete(desired, ip)
	}
	dst := copyBoolMap(e.dstBlocks)
	limits := copyLimitMap(e.limits)
	applied, err := e.applyDeviceState(desired, dst, limits)
	if err != nil {
		return applied, err
	}
	if blocked {
		return []string{
			fmt.Sprintf("iptables -A UBM_FWD -s %s -j DROP", ip),
			fmt.Sprintf("iptables -A UBM_IN -s %s -p udp --dport 53 -j DROP", ip),
		}, nil
	}
	return []string{
		fmt.Sprintf("iptables -D UBM_FWD -s %s -j DROP", ip),
		fmt.Sprintf("iptables -D UBM_IN -s %s -p udp --dport 53 -j DROP", ip),
	}, nil
}

// SetLimit 手动限速（0,0 取消）。
func (e *Enforcer) SetLimit(ip string, down, up int) ([]string, error) {
	if !e.app.deviceControlOn() {
		return nil, errSwitchOff
	}
	if (down > 0 || up > 0) && e.app.isProtectedIP(ip) {
		return nil, errProtectedIP
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	desired := copyLimitMap(e.limits)
	if down <= 0 && up <= 0 {
		delete(desired, ip)
	} else {
		desired[ip] = LimitKbps{Down: down, Up: up}
	}
	blocked := copyBoolMap(e.blocked)
	dst := copyBoolMap(e.dstBlocks)
	applied, err := e.applyDeviceState(blocked, dst, desired)
	if err != nil {
		return applied, err
	}
	minor := classMinor(ip)
	if down <= 0 && up <= 0 {
		return []string{fmt.Sprintf("tc class del dev br-lan classid 1:%d", minor)}, nil
	}
	out := []string{}
	if down > 0 {
		out = append(out, fmt.Sprintf("tc class replace dev br-lan parent 1: classid 1:%d htb rate %dkbit", minor, down))
	}
	if up > 0 {
		out = append(out, fmt.Sprintf("tc class replace dev ifb0 parent 2: classid 2:%d htb rate %dkbit", minor, up))
	}
	return out, nil
}

// BlockDst 封禁某个目标 IP（连接明细里的「封目标」）。
func (e *Enforcer) BlockDst(ip string) ([]string, error) {
	if !e.app.deviceControlOn() {
		return nil, errSwitchOff
	}
	if e.app.isProtectedIP(ip) {
		return nil, errProtectedIP
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.dstBlocks[ip] {
		return nil, nil
	}
	desired := copyBoolMap(e.dstBlocks)
	desired[ip] = true
	applied, err := e.applyDeviceState(copyBoolMap(e.blocked), desired, copyLimitMap(e.limits))
	if err != nil {
		return applied, fmt.Errorf("封禁目标 IP 失败，已回滚: %w", err)
	}
	if e.app.store != nil {
		e.app.store.PutDstBlock(ip, nowUnix())
	}
	return []string{fmt.Sprintf("iptables -A UBM_FWD -d %s -j DROP", ip)}, nil
}

// UnblockDst 解封目标 IP（误操作恢复用）。
func (e *Enforcer) UnblockDst(ip string) ([]string, error) {
	if !e.app.deviceControlOn() {
		return nil, errSwitchOff
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.dstBlocks[ip] {
		return nil, nil
	}
	desired := copyBoolMap(e.dstBlocks)
	delete(desired, ip)
	applied, err := e.applyDeviceState(copyBoolMap(e.blocked), desired, copyLimitMap(e.limits))
	if err != nil {
		return applied, err
	}
	if e.app.store != nil {
		e.app.store.DeleteDstBlock(ip)
	}
	return []string{fmt.Sprintf("iptables -D UBM_FWD -d %s -j DROP", ip)}, nil
}

// IsBlocked 该 IP 是否处于设备断网状态。
func (e *Enforcer) IsBlocked(ip string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.blocked[ip]
}

// IsDstBlocked 该 IP 是否被作为目标封禁。
func (e *Enforcer) IsDstBlocked(ip string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.dstBlocks[ip]
}

// IsLimited 该 IP 是否被限速。
func (e *Enforcer) IsLimited(ip string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	l, ok := e.limits[ip]
	return ok && (l.Down > 0 || l.Up > 0)
}

// BlockedIPs 已断网设备 IP（排序）。
func (e *Enforcer) BlockedIPs() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return sortedKeysBool(e.blocked)
}

// DstBlockedIPs 已封禁目标 IP（排序）。
func (e *Enforcer) DstBlockedIPs() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return sortedKeysBool(e.dstBlocks)
}

// Limits 当前限速表拷贝。
func (e *Enforcer) Limits() map[string]LimitKbps {
	e.mu.Lock()
	defer e.mu.Unlock()
	return copyLimitMap(e.limits)
}

// Blocks 返回封禁/限速记录列表（供 GET /api/enforce/blocks）。
func (e *Enforcer) Blocks() []BlockEntry {
	e.mu.Lock()
	blocked := copyBoolMap(e.blocked)
	blockedAt := make(map[string]int64, len(e.blockedAt))
	for ip, at := range e.blockedAt {
		blockedAt[ip] = at
	}
	dst := copyBoolMap(e.dstBlocks)
	dstAt := make(map[string]int64, len(e.dstAt))
	for ip, at := range e.dstAt {
		dstAt[ip] = at
	}
	limits := copyLimitMap(e.limits)
	limitsAt := make(map[string]int64, len(e.limitsAt))
	for ip, at := range e.limitsAt {
		limitsAt[ip] = at
	}
	e.mu.Unlock()

	metas := map[string]DeviceMeta{}
	if e.app.store != nil {
		metas = e.app.store.AllDeviceMeta()
	}
	entries := make([]BlockEntry, 0, len(blocked)+len(dst)+len(limits))
	for ip := range blocked {
		reason := "策略断网"
		at := blockedAt[ip]
		if m, ok := metas[ip]; ok && m.Blocked {
			reason = "手动断网"
			if m.BlockedAt > 0 {
				at = m.BlockedAt
			}
		}
		entries = append(entries, BlockEntry{IP: ip, Type: "device", Reason: reason, At: at})
	}
	for ip := range dst {
		entries = append(entries, BlockEntry{IP: ip, Type: "dst", Reason: "封禁目标 IP", At: dstAt[ip]})
	}
	for ip, l := range limits {
		at := limitsAt[ip]
		if m, ok := metas[ip]; ok && m.LimitAt > 0 {
			at = m.LimitAt
		}
		entries = append(entries, BlockEntry{
			IP: ip, Type: "limit", Reason: "手动限速", At: at,
			DownKbps: l.Down, UpKbps: l.Up,
		})
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Type != entries[j].Type {
			return entries[i].Type < entries[j].Type
		}
		return entries[i].IP < entries[j].IP
	})
	return entries
}

// RestoreFromStore 从 store 恢复持久化的断网/限速/目标封禁状态（重启不丢）。
// 仅在设备管控开关开启时才真正下发规则；否则只恢复内存状态供展示。
func (e *Enforcer) RestoreFromStore() {
	if e.app.store == nil {
		return
	}
	// 未启用设备管控时不做任何读取/下发（总开关关闭时保持绝对静默）；
	// 待用户在设置中开启设备管控后再恢复记录并下发规则。
	if !e.app.deviceControlOn() {
		return
	}
	metas := e.app.store.AllDeviceMeta()
	blocked := map[string]bool{}
	blockedAt := map[string]int64{}
	limits := map[string]LimitKbps{}
	limitsAt := map[string]int64{}
	for ip, m := range metas {
		if m.Blocked {
			if e.app.isProtectedIP(ip) {
				// 历史误封本机/网关记录：清理，不再恢复
				e.app.store.UpdateDeviceMeta(ip, func(meta *DeviceMeta) {
					meta.Blocked = false
					meta.BlockedAt = 0
				})
				logf("忽略并清理受保护 IP 的断网记录: %s", ip)
			} else {
				blocked[ip] = true
				if m.BlockedAt > 0 {
					blockedAt[ip] = m.BlockedAt
				}
			}
		}
		if m.LimitKbps.Down > 0 || m.LimitKbps.Up > 0 {
			if e.app.isProtectedIP(ip) {
				e.app.store.UpdateDeviceMeta(ip, func(meta *DeviceMeta) {
					meta.LimitKbps = LimitKbps{}
					meta.LimitAt = 0
				})
				logf("忽略并清理受保护 IP 的限速记录: %s", ip)
			} else {
				limits[ip] = m.LimitKbps
				if m.LimitAt > 0 {
					limitsAt[ip] = m.LimitAt
				}
			}
		}
	}
	dst := map[string]bool{}
	dstAt := map[string]int64{}
	for ip, at := range e.app.store.DstBlocks() {
		if e.app.isProtectedIP(ip) {
			e.app.store.DeleteDstBlock(ip)
			logf("忽略并清理受保护 IP 的目标封禁记录: %s", ip)
			continue
		}
		dst[ip] = true
		dstAt[ip] = at
	}
	e.mu.Lock()
	e.blocked, e.blockedAt = blocked, blockedAt
	e.dstBlocks, e.dstAt = dst, dstAt
	e.limits, e.limitsAt = limits, limitsAt
	e.mu.Unlock()

	// 管控开关已开启（函数开头已检查），直接下发恢复规则
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, err := e.rebuildDeviceRules(); err != nil {
		logf("恢复持久化封禁规则失败: %v", err)
		return
	}
	if _, err := e.rebuildTC(); err != nil {
		logf("恢复持久化限速规则失败: %v", err)
	}
}

// ---------------- 域名封堵（ipset） ----------------

// applyDomainState 应用域名封堵期望集合（解析 -> ipset）。
func (e *Enforcer) applyDomainState(desired map[string]bool) ([]string, error) {
	if mapsEqualBool(e.dnsDomains, desired) && len(e.pending) == 0 {
		return nil, nil
	}
	var applied []string
	now := nowUnix()
	// 解析新增域名
	for d := range desired {
		if e.dnsDomains[d] {
			continue
		}
		ips := e.app.ResolveDomain(d)
		if len(ips) == 0 {
			if _, ok := e.pending[d]; !ok {
				e.pending[d] = now + 60
			}
			logf("域名 %s 解析失败，稍后重试封堵", d)
			continue
		}
		parsed := make([]uint32, 0, len(ips))
		for _, s := range ips {
			if v, ok := parseIPv4Str(s); ok {
				parsed = append(parsed, v)
			}
		}
		e.domainIPs[d] = parsed
		delete(e.pending, d)
	}
	// 计算 ip 集合并与已下发集合比对
	wantIPs := map[uint32]bool{}
	for d := range desired {
		for _, ip := range e.domainIPs[d] {
			wantIPs[ip] = true
		}
	}
	oldIPs := map[uint32]bool{}
	for d := range e.dnsDomains {
		for _, ip := range e.domainIPs[d] {
			oldIPs[ip] = true
		}
	}
	newDomains := copyBoolMap(desired)
	e.dnsDomains = newDomains
	// 清理不再被引用的域名 IP
	for d := range oldIPs {
		_ = d
	}
	if len(wantIPs) > 0 {
		if _, err := e.app.shell("ipset create " + ipsetName + " hash:ip -exist"); err != nil {
			return applied, fmt.Errorf("创建 ipset 失败: %w", err)
		}
	}
	for ip := range wantIPs {
		if oldIPs[ip] {
			continue
		}
		cmd := fmt.Sprintf("ipset add %s %s -exist", ipsetName, ip4String(ip))
		if _, err := e.app.shell(cmd); err != nil {
			return applied, fmt.Errorf("写入 ipset 失败: %w", err)
		}
		applied = append(applied, cmd)
	}
	for ip := range oldIPs {
		if wantIPs[ip] {
			continue
		}
		cmd := fmt.Sprintf("ipset del %s %s -exist", ipsetName, ip4String(ip))
		if _, err := e.app.shell(cmd); err != nil {
			return applied, fmt.Errorf("移除 ipset 记录失败: %w", err)
		}
		applied = append(applied, cmd)
	}
	// 确保 iptables 规则存在
	if rules, err := e.rebuildDeviceRules(); err != nil {
		return applied, err
	} else {
		applied = append(applied, rules...)
	}
	// 清理已删除域名的解析缓存
	for d := range e.domainIPs {
		if !e.dnsDomains[d] {
			delete(e.domainIPs, d)
		}
	}
	return applied, nil
}

// retryPendingDomains 重试解析失败的域名。
func (e *Enforcer) retryPendingDomains(now int64) {
	if len(e.pending) == 0 {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	changed := false
	for d, next := range e.pending {
		if now < next {
			continue
		}
		ips := e.app.ResolveDomain(d)
		if len(ips) == 0 {
			e.pending[d] = now + 120
			continue
		}
		parsed := make([]uint32, 0, len(ips))
		for _, s := range ips {
			if v, ok := parseIPv4Str(s); ok {
				parsed = append(parsed, v)
			}
		}
		e.domainIPs[d] = parsed
		delete(e.pending, d)
		changed = true
	}
	if changed {
		desired := copyBoolMap(e.dnsDomains)
		if _, err := e.applyDomainState(desired); err != nil {
			logf("重试域名封堵失败: %v", err)
		}
	}
}

// ---------------- 策略引擎 ----------------

// ReconcilePolicies 每 15s 评估一次策略，下发/撤销对应规则。
// 仅当总开关 + 设备管控 + 定时策略三个开关都开启时才工作；
// 域名类封堵还需要 domainBlock 开关开启。
func (e *Enforcer) ReconcilePolicies(now time.Time) {
	if e.app.store == nil || e.app.devs == nil {
		return
	}
	if !e.app.policyEngineOn() {
		return
	}
	domainOn := e.app.domainBlockOn()
	pols := e.app.store.Policies()
	metas := e.app.store.AllDeviceMeta()
	devs := e.app.devs.States()
	ts := now.Unix()

	desiredBlocked := map[string]bool{}
	desiredLimits := map[string]LimitKbps{}
	desiredDst := map[string]bool{}
	desiredDomains := map[string]bool{}
	active := map[string]bool{}
	hitsToSend := map[string]string{} // policyID -> 首个目标设备

	// 手动封禁的目标 IP 来自 store 持久化记录（重启恢复）
	for ip := range e.app.store.DstBlocks() {
		desiredDst[ip] = true
	}

	for _, st := range devs {
		meta := metas[st.IP]
		if meta.Blocked {
			desiredBlocked[st.IP] = true
		}
		if meta.LimitKbps.Down > 0 || meta.LimitKbps.Up > 0 {
			desiredLimits[st.IP] = meta.LimitKbps
		}
		var matched []Policy
		allow := false
		for _, p := range pols {
			if !p.Enabled || !policyTargets(p, st.IP, meta.Group) || !scheduleActive(p.Schedule, now) {
				continue
			}
			matched = append(matched, p)
			active[p.ID] = true
			if p.Action == "allow" {
				allow = true
			}
		}
		if allow {
			continue
		}
		for _, p := range matched {
			switch p.Action {
			case "block":
				if len(p.Categories) == 0 && len(p.Domains) == 0 {
					desiredBlocked[st.IP] = true
				} else if domainOn {
					for _, cat := range p.Categories {
						for _, d := range DomainsForCategory(cat) {
							desiredDomains[d] = true
						}
					}
					for _, d := range p.Domains {
						if nd := normalizeDomainRule(d); nd != "" {
							desiredDomains[nd] = true
						}
					}
				}
			case "limit":
				desiredLimits[st.IP] = p.LimitKbps
			}
			if _, ok := hitsToSend[p.ID]; !ok {
				hitsToSend[p.ID] = st.IP
			}
		}
	}

	e.mu.Lock()
	if _, err := e.applyDeviceState(desiredBlocked, desiredDst, desiredLimits); err != nil {
		logf("策略下发失败: %v", err)
	}
	if domainOn {
		if _, err := e.applyDomainState(desiredDomains); err != nil {
			logf("域名封堵下发失败: %v", err)
		}
	}
	// 新命中策略：命中计数 +1 并产生事件
	for id := range active {
		if e.policyActive[id] {
			continue
		}
		e.app.store.IncrementPolicyHits(id)
		target := hitsToSend[id]
		var pol Policy
		for _, p := range pols {
			if p.ID == id {
				pol = p
				break
			}
		}
		if pol.ID != "" && e.app.sec != nil {
			name := ""
			if st, ok := e.app.devs.State(target); ok {
				name = st.Hostname
			}
			e.app.sec.OnPolicyHit(pol.ID, pol.Name, pol.Action, target, name, ts)
		}
	}
	e.policyActive = active
	e.mu.Unlock()

	e.retryPendingDomains(ts)
}

// policyTargets 判断策略是否作用于某设备。
func policyTargets(p Policy, ip, group string) bool {
	if p.Targets.All {
		return true
	}
	for _, t := range p.Targets.IPs {
		if t == ip {
			return true
		}
	}
	if group != "" {
		for _, g := range p.Targets.Groups {
			if g == group {
				return true
			}
		}
	}
	return false
}

// scheduleActive 判断当前时间是否在策略生效时段内。支持跨零点。
func scheduleActive(sc Schedule, now time.Time) bool {
	if len(sc.Days) > 0 {
		iso := int(now.Weekday())
		if iso == 0 {
			iso = 7
		}
		found := false
		for _, d := range sc.Days {
			if d == iso {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	start, ok1 := parseHHMM(sc.Start)
	end, ok2 := parseHHMM(sc.End)
	if !ok1 || !ok2 {
		return true // 时段时间不合法时视为全天
	}
	cur := now.Hour()*60 + now.Minute()
	if start == end {
		return true
	}
	if start < end {
		return cur >= start && cur < end
	}
	return cur >= start || cur < end
}

// parseHHMM 解析 "HH:MM" 为当日分钟数。
func parseHHMM(s string) (int, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, false
	}
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 {
		return 0, false
	}
	h, ok1 := atoiOK([]byte(strings.TrimSpace(parts[0])))
	m, ok2 := atoiOK([]byte(strings.TrimSpace(parts[1])))
	if !ok1 || !ok2 || h < 0 || h > 23 || m < 0 || m > 59 {
		return 0, false
	}
	return h*60 + m, true
}

// normalizeDomainRule 归一化域名规则（去 *. 前缀/空白）。
func normalizeDomainRule(d string) string {
	d = strings.ToLower(strings.TrimSpace(d))
	d = strings.TrimPrefix(d, "*.")
	d = strings.TrimPrefix(d, ".")
	if d == "" || strings.ContainsAny(d, " /") {
		return ""
	}
	return d
}

// ---------------- 状态 / 重置 ----------------

// Status 返回管控状态。
func (e *Enforcer) Status() EnforceStatus {
	e.mu.Lock()
	defer e.mu.Unlock()
	st := EnforceStatus{
		IPTablesRules:     len(e.blocked)*2 + len(e.dstBlocks),
		TcDevices:         len(e.limits),
		DNSBlockedDomains: len(e.dnsDomains),
		ActivePolicies:    len(e.policyActive),
	}
	if len(e.dnsDomains) > 0 {
		st.IPTablesRules++
	}
	if e.app.store != nil {
		st.DNSTap = e.app.store.Settings().DNSTap
	}
	return st
}

// BlockedDomains 当前实际封堵的域名明细（策略下发 + 手工列表，去重排序）。
// 供行为页展示；契约 §5 只有计数，此方法由只读补充端点 /api/enforce/dns 使用。
func (e *Enforcer) BlockedDomains() []string {
	e.mu.Lock()
	applied := make([]string, 0, len(e.dnsDomains))
	for d := range e.dnsDomains {
		applied = append(applied, d)
	}
	e.mu.Unlock()
	seen := map[string]bool{}
	out := make([]string, 0, len(applied)+8)
	if e.app.store != nil {
		for _, d := range e.app.store.DomainBlocks() {
			if !seen[d] {
				seen[d] = true
				out = append(out, d)
			}
		}
	}
	for _, d := range applied {
		if !seen[d] {
			seen[d] = true
			out = append(out, d)
		}
	}
	sort.Strings(out)
	return out
}

// Reset 清空全部管控并还原 DNS 拦截，返回 removed 描述列表。
func (e *Enforcer) Reset() ([]string, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	var removed []string
	snapshot := e.app.iptablesSnapshot()
	if err := e.teardownIptables(); err != nil {
		e.app.restoreIptables(snapshot)
		return removed, err
	}
	removed = append(removed, "iptables: UBM_FWD / UBM_IN 全部规则已清理")
	e.app.shellQuiet("ipset flush " + ipsetName + " 2>/dev/null; ipset destroy " + ipsetName + " 2>/dev/null")
	removed = append(removed, "ipset: ubm_block 已销毁")
	e.teardownTC(true)
	removed = append(removed, "tc: br-lan / ifb0 队列已清理")
	// 停用全部策略、清空手工管控状态与持久化记录，避免 15s 后又被重新下发
	if e.app.store != nil {
		pols := e.app.store.Policies()
		for _, p := range pols {
			e.app.store.SetPolicyEnabled(p.ID, false)
		}
		if len(pols) > 0 {
			removed = append(removed, fmt.Sprintf("策略: 已停用 %d 条策略", len(pols)))
		}
		metas := e.app.store.AllDeviceMeta()
		for ip, m := range metas {
			if !m.Blocked && m.LimitKbps.Down == 0 && m.LimitKbps.Up == 0 {
				continue
			}
			e.app.store.UpdateDeviceMeta(ip, func(meta *DeviceMeta) {
				meta.Blocked = false
				meta.BlockedAt = 0
				meta.LimitKbps = LimitKbps{}
				meta.LimitAt = 0
			})
		}
		e.app.store.ClearDstBlocks()
	}
	e.blocked = map[string]bool{}
	e.blockedAt = map[string]int64{}
	e.dstBlocks = map[string]bool{}
	e.dstAt = map[string]int64{}
	e.limits = map[string]LimitKbps{}
	e.limitsAt = map[string]int64{}
	e.dnsDomains = map[string]bool{}
	e.domainIPs = map[string][]uint32{}
	e.pending = map[string]int64{}
	e.policyActive = map[string]bool{}
	removed = append(removed, "设备: 断网/限速/目标封禁状态与持久化记录已全部恢复")
	return removed, nil
}

// ---------------- 开关撤销（关闭功能时回到"从未开启"状态） ----------------

// RevokeDeviceControl 撤销全部设备管控：iptables 自有链 + tc 配置，清空管控状态。
// 只操作自有链，不触碰 passwall/docker 等他人规则。
func (e *Enforcer) RevokeDeviceControl() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := e.teardownIptables(); err != nil {
		logf("撤销 iptables 管控规则失败: %v", err)
	}
	e.teardownTC(true)
	e.blocked = map[string]bool{}
	e.blockedAt = map[string]int64{}
	e.dstBlocks = map[string]bool{}
	e.dstAt = map[string]int64{}
	e.limits = map[string]LimitKbps{}
	e.limitsAt = map[string]int64{}
	e.policyActive = map[string]bool{}
	logf("已撤销设备管控：iptables 自有链与 tc 配置已清理")
}

// RevokeDomainBlock 撤销域名封堵：销毁 ipset 并移除链内引用规则。
func (e *Enforcer) RevokeDomainBlock() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.app.shellQuiet("ipset flush " + ipsetName + " 2>/dev/null; ipset destroy " + ipsetName + " 2>/dev/null")
	e.dnsDomains = map[string]bool{}
	e.domainIPs = map[string][]uint32{}
	e.pending = map[string]int64{}
	if e.chainsReady {
		if _, err := e.rebuildDeviceRules(); err != nil {
			logf("移除域名封堵 iptables 规则失败: %v", err)
		}
	}
	logf("已撤销域名封堵：ipset ubm_block 已销毁")
}

// RevokeAll 总开关关闭时调用：撤销全部已下发的系统变更。
func (e *Enforcer) RevokeAll() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := e.teardownIptables(); err != nil {
		logf("撤销 iptables 规则失败: %v", err)
	}
	e.teardownTC(true)
	e.app.shellQuiet("ipset flush " + ipsetName + " 2>/dev/null; ipset destroy " + ipsetName + " 2>/dev/null")
	e.blocked = map[string]bool{}
	e.blockedAt = map[string]int64{}
	e.dstBlocks = map[string]bool{}
	e.dstAt = map[string]int64{}
	e.limits = map[string]LimitKbps{}
	e.limitsAt = map[string]int64{}
	e.dnsDomains = map[string]bool{}
	e.domainIPs = map[string][]uint32{}
	e.pending = map[string]int64{}
	e.policyActive = map[string]bool{}
	logf("系统级撤销完成：iptables / tc / ipset 均已恢复")
}

// ---------------- 小工具 ----------------

func sortedKeysBool(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func copyBoolMap(m map[string]bool) map[string]bool {
	out := make(map[string]bool, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func copyLimitMap(m map[string]LimitKbps) map[string]LimitKbps {
	out := make(map[string]LimitKbps, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func mapsEqualBool(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

func mapsEqualLimit(a, b map[string]LimitKbps) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}
