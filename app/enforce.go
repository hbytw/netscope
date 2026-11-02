package main

// 执行层：iptables 封禁、tc 限速、ipset 域名封堵、策略引擎。
//
// 安全原则（用户正在使用该路由器）：
//   - iptables 只写自有链 UBM_FWD / UBM_IN，绝不修改/删除他人链；
//     修改前用 iptables-save 快照，任何一步失败立即 iptables-restore 回滚。
//   - tc 限速默认关闭；应用失败删除本次创建的 qdisc 回滚，绝不留下坏掉的 LAN 队列。
//     限速的出接口不写死：用拓扑探测到的 LAN 接口名（见 Enforcer.lanDev），
//     探测不到内网桥/网口时整轮跳过限速并在状态里标记原因，不对不存在的接口下发命令。
//   - 域名封堵不走 dnsmasq，改为域名解析成 IP 写 ipset（ubm_block），
//     iptables 链内 `-m set --match-set ubm_block dst -j DROP`；解析失败进入待重试队列。
//   - 所有外部命令经 App.shell 串行执行；-demo / -dry-run 只记录不执行。

import (
	"errors"
	"fmt"
	"os"
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

	// tcHandleRoot / tcHandleIfb 本程序创建的 tc 根队列句柄。
	// 刻意避开用户自有 QoS 常用句柄（luci-app-sqm 一般用 1:），
	// 删除时按句柄比对，确保不会误删用户自己的队列。
	tcHandleRoot = "10:"
	tcHandleIfb  = "20:"
)

// EnforceStatus /api/enforce/status 契约。
type EnforceStatus struct {
	IPTablesRules     int    `json:"iptablesRules"`
	TcDevices         int    `json:"tcDevices"`
	DNSBlockedDomains int    `json:"dnsBlockedDomains"`
	ActivePolicies    int    `json:"activePolicies"`
	DNSTap            bool   `json:"dnsTap"`
	TcConflict        string `json:"tcConflict,omitempty"` // 非空：LAN 根队列归属用户 QoS / 未探测到 LAN 接口，已跳过限速下发
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
	dnsDesired map[string]bool  // 期望封堵的域名集合（含尚未解析成功的）
	pending    map[string]int64 // 待重试域名 -> 下次重试时间

	policyActive map[string]bool
	protWarned   map[string]bool // 已提示过的受保护策略目标（避免 15s 轮询刷日志）

	tcRootOwned    bool
	tcIngressOwned bool
	tcIfbRootOwned bool
	ifbOwned       bool
	tcLimited      map[string]bool // 本程序已下发 class/filter 的设备
	tcConflict     string          // 非空：根队列属于用户 QoS，已跳过限速下发（状态展示用）
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
		dnsDesired:   map[string]bool{},
		pending:      map[string]int64{},
		protWarned:   map[string]bool{},
		policyActive: map[string]bool{},
		tcLimited:    map[string]bool{},
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

// dryRunMode 演示/试运行模式：外部命令只记录不执行，无法核验系统状态。
func (e *Enforcer) dryRunMode() bool {
	return e.app == nil || e.app.cfg.Demo || e.app.cfg.DryRun
}

// lanDev 返回限速使用的 LAN 出口接口名。
//
// ok=false 表示没有可用的内网接口（未探测到 LAN 桥/网口，或探测到的名字在当前
// 系统里并不存在）：此时调用方必须安全跳过 tc 下发，而不是硬编码 br-lan 去操作
// 一个不存在的接口。dry-run/demo 下不做真实存在性校验（命令本来就不执行）。
func (e *Enforcer) lanDev() (string, bool) {
	if e.app == nil {
		return "", false
	}
	name, ok := e.app.detectedLanIface()
	if !ok {
		return "", false
	}
	if !e.dryRunMode() && !e.linkExists(name) {
		return "", false
	}
	return name, true
}

// iptablesDump 读取当前 iptables 规则表（供自有链/规则核对）。
// ok=false 表示无法核验（iptables 不可用 / 演示模式）。
func (e *Enforcer) iptablesDump() (string, bool) {
	if e.dryRunMode() {
		return "", false
	}
	out, err := e.app.shellQuietOutput("iptables -S 2>/dev/null")
	if err != nil {
		return "", false
	}
	return out, true
}

// chainsPresent 判断自有链是否存在于 iptables 规则表中。
func chainsPresent(out string) bool {
	return strings.Contains(out, "-N "+chainFwd) && strings.Contains(out, "-N "+chainIn)
}

// rulesPresent 判断当前期望的规则是否都还在（链存在 + 规则存在）。
// OpenWrt 防火墙重载（iptables-restore 冲刷整表）后链与规则会一起消失。
func (e *Enforcer) rulesPresent(out string) bool {
	if !chainsPresent(out) {
		return false // 自有链已被冲刷
	}
	fwd := iptablesChainRules(out, chainFwd)
	in := iptablesChainRules(out, chainIn)
	for _, ip := range sortedKeysBool(e.blocked) {
		// 断网规则在 UBM_FWD，DNS 拦截规则在 UBM_IN
		if !ruleHasIP(fwd, "-s ", ip) || !ruleHasIP(in, "-s ", ip) {
			return false
		}
	}
	for _, ip := range sortedKeysBool(e.dstBlocks) {
		if !ruleHasIP(fwd, "-d ", ip) {
			return false
		}
	}
	if len(e.dnsDomains) > 0 && !strings.Contains(out, "--match-set "+ipsetName+" dst") {
		return false
	}
	return true
}

// iptablesChainRules 从 `iptables -S` 输出中取出指定链的规则行。
func iptablesChainRules(out, chain string) []string {
	var rules []string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "-A "+chain+" ") {
			continue
		}
		rules = append(rules, line)
	}
	return rules
}

// ruleHasIP 判断链规则中是否存在指定源/目的 IP 的规则。
// iptables 会把单主机地址归一化成 /32，这里两种写法都匹配。
func ruleHasIP(rules []string, flag, ip string) bool {
	for _, r := range rules {
		if strings.Contains(r, flag+ip+"/32") || strings.Contains(r, flag+ip+" ") {
			return true
		}
	}
	return false
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
	// 合并为单条 sh -c 脚本一次 fork 下发（原先每条规则 fork 一次，规则多时开销线性增长）。
	// 失败可回滚：调用方（applyDeviceState）持有 iptables-save 快照，脚本任一步失败
	// 返回错误后立即 iptables-restore 回滚；成功后再用 iptables -S 逐项校验期望规则。
	script := "set -e\n" + strings.Join(cmds, "\n")
	if _, err := e.app.shell(script); err != nil {
		// 脚本失败可能伴随链被外部冲刷：清掉缓存，下一轮 ensureChains 重新创建。
		e.chainsReady = false
		return cmds, fmt.Errorf("下发 iptables 规则失败（批量脚本）: %w", err)
	}
	applied = append(applied, cmds...)
	// 逐项校验：脚本返回成功但规则被并发重载/内核拒绝时，仍要报失败交给上层回滚。
	if out, ok := e.iptablesDump(); ok && !e.rulesPresent(out) {
		e.chainsReady = false
		return applied, fmt.Errorf("下发 iptables 规则后校验失败：自有链或期望规则缺失")
	}
	return applied, nil
}

// ---------------- tc 限速 ----------------

// classMinor 设备 IP -> tc class minor（对完整 IP 做哈希，映射到 100..65535）。
// 注：不能用 IP 末位字节，否则跨网段同末位字节的设备会共用同一个 class（限速串到别的设备）。
func classMinor(ip string) int {
	h := uint32(2166136261)
	for i := 0; i < len(ip); i++ {
		h ^= uint32(ip[i])
		h *= 16777619
	}
	return 100 + int(h%65436) // 100..65535
}

// tcRootHandles 返回 dev 上各根队列的句柄集合（解析 tc qdisc show）。
// 用于判断某个队列是否由本程序创建（句柄 = tcHandleRoot/tcHandleIfb）。
func (e *Enforcer) tcRootHandles(dev string) map[string]bool {
	handles := map[string]bool{}
	if e.dryRunMode() {
		return handles
	}
	out, err := e.app.shellQuietOutput("tc qdisc show dev " + dev + " 2>/dev/null")
	if err != nil {
		return handles
	}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if !strings.Contains(line, " root ") {
			continue
		}
		fields := strings.Fields(line)
		for i, f := range fields {
			if f == "root" && i > 0 {
				handles[fields[i-1]] = true
			}
		}
	}
	return handles
}

// tcIngressExists 判断 dev 上是否已有 ingress 队列（用户 sqm 等可能自带，不能重复 add）。
func (e *Enforcer) tcIngressExists(dev string) bool {
	if e.dryRunMode() {
		return false
	}
	out, err := e.app.shellQuietOutput("tc qdisc show dev " + dev + " 2>/dev/null")
	if err != nil {
		return false
	}
	return strings.Contains(out, " ingress ")
}

// tcConflictReason 探测既有根队列归属，返回非空表示本轮应跳过 tc 下发。
//
// 判定口径：
//   - 先确认 LAN 出口接口真实可用（不同路由器是 br-lan/br0/br-guest/单网口 eth0）；
//     探测不到直接跳过，原因写入状态，绝不对不存在的接口下发命令；
//   - 内核自动创建的默认根队列句柄为 0:（pfifo_fast / fq_codel / noqueue），
//     可以被本程序替换，不算冲突；除此之外的非自有句柄（例如 luci-app-sqm 的 1:）
//     视为用户自建，一律不覆盖、不删除，整轮跳过 tc 下发。
func (e *Enforcer) tcConflictReason() string {
	if e.dryRunMode() {
		return ""
	}
	dev, ok := e.lanDev()
	if !ok {
		return "未探测到可用的 LAN 接口（无 br-lan/br0/br-* 等内网桥或网口），已跳过限速下发"
	}
	if h, conflict := tcRootConflict(e.tcRootHandles(dev), tcHandleRoot); conflict {
		return fmt.Sprintf("%s 根队列（%s）非本程序创建，与用户 QoS 冲突，已跳过限速下发", dev, h)
	}
	for _, l := range e.limits {
		if l.Up <= 0 {
			continue
		}
		if h, conflict := tcRootConflict(e.tcRootHandles("ifb0"), tcHandleIfb); conflict {
			return fmt.Sprintf("ifb0 根队列（%s）非本程序创建，与用户 QoS 冲突，已跳过限速下发", h)
		}
		break
	}
	return ""
}

// tcRootConflict 判断根队列句柄集合是否被非自有队列占用。
// 默认句柄 0: 是内核创建的初始队列，可替换，不计入冲突。
func tcRootConflict(handles map[string]bool, own string) (string, bool) {
	delete(handles, "0:")
	if len(handles) == 0 || handles[own] {
		return "", false
	}
	return strings.Join(sortedKeysBool(handles), ","), true
}

// rebuildTC 按当前 limits 重建限速配置。
// 根队列句柄固定为 tcHandleRoot/tcHandleIfb（与用户自有 QoS 常用句柄区分），
// 删除时按句柄比对，确保不误删 luci-app-sqm 等用户配置。
// 失败时不直接删除用户队列，由调用方用旧状态重新下发恢复。
//
// 出接口用探测到的 LAN 接口（dev），不写死 br-lan：单网口 / br0 / br-guest
// 等形态都能正确下发；探测不到可用 LAN 接口时整轮跳过并把原因写进 tcConflict。
func (e *Enforcer) rebuildTC() ([]string, error) {
	var applied []string
	if len(e.limits) == 0 {
		e.tcConflict = ""
		e.teardownTC(false)
		return applied, nil
	}
	// 下发前先探测既有根队列归属与 LAN 接口是否可用：
	// LAN 接口不存在，或 LC/ifb0 已被用户 QoS（如 luci-app-sqm）接管时
	// 不覆盖、不删除，整轮跳过并记录状态，避免 tc 下发整体失败或破坏用户队列。
	if msg := e.tcConflictReason(); msg != "" {
		if e.tcConflict != msg {
			e.tcConflict = msg
			logf("%s", msg)
		}
		return applied, nil
	}
	e.tcConflict = ""
	dev, ok := e.lanDev()
	if !ok {
		msg := "未探测到可用的 LAN 接口（无 br-lan/br0/br-* 等内网桥或网口），已跳过限速下发"
		if e.tcConflict != msg {
			e.tcConflict = msg
			logf("%s", msg)
		}
		return applied, nil
	}
	cmds := []string{}
	// 下行：LAN 出口 htb
	if !e.tcRootOwned {
		if e.tcRootHandles(dev)[tcHandleRoot] {
			e.tcRootOwned = true // 已存在且句柄一致，视为本程序创建
		} else {
			cmds = append(cmds, "tc qdisc add dev "+dev+" root handle "+tcHandleRoot+" htb default 1")
		}
	}
	cmds = append(cmds,
		"tc class replace dev "+dev+" parent "+tcHandleRoot+" classid "+tcHandleRoot+"1 htb rate 1000000kbit ceil 1000000kbit",
		"tc filter del dev "+dev+" parent "+tcHandleRoot+" prio 10 2>/dev/null")
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
			fmt.Sprintf("tc class replace dev %s parent %s classid %s%d htb rate %dkbit ceil %dkbit", dev, tcHandleRoot, tcHandleRoot, minor, l.Down, l.Down),
			fmt.Sprintf("tc filter add dev %s parent %s protocol ip prio 10 u32 match ip dst %s/32 flowid %s%d", dev, tcHandleRoot, ip, tcHandleRoot, minor))
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
			if e.linkExists("ifb0") {
				// 已存在（上次运行遗留或用户自建）：复用该设备，但撤销时不删除它
				logf("ifb0 已存在且非本程序创建：复用该设备，撤销时不会删除")
			} else {
				cmds = append(cmds, "ip link add ifb0 type ifb 2>/dev/null; ip link set ifb0 up")
			}
		}
		if !e.tcIngressOwned && !e.tcIngressExists(dev) {
			// 已有 ingress 队列（用户 sqm 等自带）时不重复添加，也不接管
			cmds = append(cmds, "tc qdisc add dev "+dev+" handle ffff: ingress")
		}
		if !e.tcIfbRootOwned {
			if e.tcRootHandles("ifb0")[tcHandleIfb] {
				e.tcIfbRootOwned = true
			} else {
				cmds = append(cmds, "tc qdisc add dev ifb0 root handle "+tcHandleIfb+" htb default 1")
			}
		}
		cmds = append(cmds,
			"tc class replace dev ifb0 parent "+tcHandleIfb+" classid "+tcHandleIfb+"1 htb rate 1000000kbit ceil 1000000kbit",
			"tc filter del dev "+dev+" parent ffff: prio 11 2>/dev/null",
			"tc filter del dev ifb0 parent "+tcHandleIfb+" prio 11 2>/dev/null")
		for _, ip := range upIPs {
			l := e.limits[ip]
			minor := classMinor(ip)
			cmds = append(cmds,
				fmt.Sprintf("tc filter add dev %s parent ffff: protocol ip prio 11 u32 match ip src %s/32 action mirred egress redirect dev ifb0", dev, ip),
				fmt.Sprintf("tc class replace dev ifb0 parent %s classid %s%d htb rate %dkbit ceil %dkbit", tcHandleIfb, tcHandleIfb, minor, l.Up, l.Up),
				fmt.Sprintf("tc filter add dev ifb0 parent %s protocol ip prio 11 u32 match ip dst %s/32 flowid %s%d", tcHandleIfb, ip, tcHandleIfb, minor))
		}
	}
	// 取消限速的设备：删除本程序创建的 class（只删自己下发的）
	for ip := range e.tcLimited {
		if _, ok := e.limits[ip]; ok {
			continue
		}
		e.app.shellQuiet(fmt.Sprintf("tc class del dev %s classid %s%d 2>/dev/null", dev, tcHandleRoot, classMinor(ip)))
		e.app.shellQuiet(fmt.Sprintf("tc class del dev ifb0 classid %s%d 2>/dev/null", tcHandleIfb, classMinor(ip)))
	}
	// 记录本轮限速设备（失败回滚时据此清理本次新增的 class）
	limited := make(map[string]bool, len(e.limits))
	for ip := range e.limits {
		limited[ip] = true
	}
	e.tcLimited = limited
	for _, c := range cmds {
		if _, err := e.app.shell(c); err != nil {
			// 失败：不误删用户自有队列，旧状态由调用方（applyDeviceState）重新下发恢复
			return applied, fmt.Errorf("下发 tc 限速失败（%s）: %w", c, err)
		}
		applied = append(applied, c)
		// 记录创建成功
		switch {
		case strings.HasPrefix(c, "tc qdisc add dev "+dev+" root"):
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

// teardownTC 清理限速配置。
// 只删除本程序创建的队列与 class（先用 tc qdisc show 比对句柄），
// 绝不误删用户自有 QoS（luci-app-sqm 等的 LAN 根队列 / ifb0）。
// LAN 接口探测不到时跳过所有针对 LAN 接口的命令（接口都不在了，无需也不该操作）。
func (e *Enforcer) teardownTC(force bool) {
	// force=true 用于"一键清空/撤销"场景；删除动作一律按句柄比对，
	// 不再像旧实现那样无条件删除 LAN 根队列与 ifb0。
	_ = force
	e.tcConflict = ""
	dev, hasDev := e.lanDev()
	// 本程序下发过的设备 class
	for ip := range e.tcLimited {
		if hasDev {
			e.app.shellQuiet(fmt.Sprintf("tc class del dev %s classid %s%d 2>/dev/null", dev, tcHandleRoot, classMinor(ip)))
		}
		e.app.shellQuiet(fmt.Sprintf("tc class del dev ifb0 classid %s%d 2>/dev/null", tcHandleIfb, classMinor(ip)))
	}
	e.tcLimited = map[string]bool{}
	// LAN 根队列：句柄一致（本程序的 10:）才删除
	if hasDev && (e.dryRunMode() || e.tcRootHandles(dev)[tcHandleRoot]) {
		e.app.shellQuiet("tc qdisc del dev " + dev + " root 2>/dev/null")
	}
	e.tcRootOwned = false
	// ingress 队列：只有本程序创建（用户自有的 ffff: ingress 不动）
	if e.tcIngressOwned && hasDev {
		e.app.shellQuiet("tc qdisc del dev " + dev + " handle ffff: ingress 2>/dev/null")
	}
	e.tcIngressOwned = false
	// ifb0 根队列：句柄一致（本程序的 20:）才删除
	if e.dryRunMode() || e.tcRootHandles("ifb0")[tcHandleIfb] {
		e.app.shellQuiet("tc qdisc del dev ifb0 root 2>/dev/null")
	}
	e.tcIfbRootOwned = false
	// ifb0 设备：只有本程序创建的才删除（用户自建的 ifb0 不动）
	if e.ifbOwned && (e.dryRunMode() || e.linkExists("ifb0")) {
		e.app.shellQuiet("ip link del ifb0 2>/dev/null")
	}
	e.ifbOwned = false
}

// linkExists 判断网卡是否存在（用于只删除本程序创建的 ifb0）。
func (e *Enforcer) linkExists(name string) bool {
	if e.dryRunMode() {
		return true
	}
	out, err := e.app.shellQuietOutput("ip link show " + name + " 2>/dev/null")
	if err != nil {
		return false
	}
	return strings.Contains(out, name)
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
//
// 每轮都会核对自有链与规则是否真实存在：OpenWrt 防火墙重载会用 iptables-restore
// 冲刷整表，若只比对内存状态，规则会静默失效且不再补发（界面却显示已生效）。
func (e *Enforcer) applyDeviceState(blocked, dst map[string]bool, limits map[string]LimitKbps) ([]string, error) {
	oldBlocked, oldDst, oldLimits := e.blocked, e.dstBlocks, e.limits
	same := mapsEqualBool(oldBlocked, blocked) && mapsEqualBool(oldDst, dst) && mapsEqualLimit(oldLimits, limits)
	if same {
		// 期望状态没变，但必须核对自有链与规则是否真实存在：
		// OpenWrt 防火墙重载会用 iptables-restore 冲刷整表，
		// 只比对内存状态会让断网/封禁规则静默失效（界面却显示已生效）。
		if out, ok := e.iptablesDump(); ok && !e.rulesPresent(out) {
			logf("检测到自有链或规则缺失（防火墙可能被重载），重新下发管控规则")
			e.chainsReady = false
			same = false
		}
	}
	if same && e.tcConflict != "" {
		// 上次因用户 QoS 冲突跳过：期望状态没变也要重新探测，
		// 用户撤销自有队列后自动恢复限速下发；仍冲突则保持早退，不做无谓下发。
		if e.tcConflictReason() == "" {
			logf("用户 QoS 冲突已解除，重新下发 tc 限速")
			e.tcConflict = ""
			same = false
		}
	}
	if same {
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
	dev, hasDev := e.lanDev()
	if !hasDev {
		// 未探测到 LAN 接口：applyDeviceState 已安全跳过 tc，这里只回显原因。
		return []string{"（未探测到可用 LAN 接口，已跳过 tc 限速下发）"}, nil
	}
	if down <= 0 && up <= 0 {
		return []string{fmt.Sprintf("tc class del dev %s classid %s%d", dev, tcHandleRoot, minor)}, nil
	}
	out := []string{}
	if down > 0 {
		out = append(out, fmt.Sprintf("tc class replace dev %s parent %s classid %s%d htb rate %dkbit", dev, tcHandleRoot, tcHandleRoot, minor, down))
	}
	if up > 0 {
		out = append(out, fmt.Sprintf("tc class replace dev ifb0 parent %s classid %s%d htb rate %dkbit", tcHandleIfb, tcHandleIfb, minor, up))
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

	// 策略引擎关闭（如关闭「定时策略」）时，此前策略下发的域名封堵不会被
	// ReconcilePolicies 清理（runPolicies 已跳过、开关切换处也没有域名撤销步骤）。
	// 开关切换落库后 ApplySwitchPatch 会调用本函数，这里补上域名单清理路径；
	// 引擎开启时本调用为空操作（域名仍由 ReconcilePolicies 按策略评估）。
	if !e.app.policyEngineOn() {
		e.revokePolicyDomains()
	}

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
//
// 内存状态（dnsDomains/domainIPs）只在 ipset 下发成功后才提交，
// 且只包含真正封堵成功的域名（解析失败/下发失败的域名留在 pending，
// 下一轮继续重试，不会因"状态相同"而永不重试）。
func (e *Enforcer) applyDomainState(desired map[string]bool) ([]string, error) {
	e.dnsDesired = copyBoolMap(desired)
	if mapsEqualBool(e.dnsDomains, desired) && len(e.pending) == 0 {
		return nil, nil
	}
	var applied []string
	now := nowUnix()
	// 解析需要新增的域名（失败项留在 pending 等待重试）
	resolved := make(map[string][]uint32, len(desired))
	for d := range desired {
		if ips, ok := e.domainIPs[d]; ok && len(ips) > 0 {
			resolved[d] = ips
			continue
		}
		if next, ok := e.pending[d]; ok && now < next {
			continue // 等待下一次重试
		}
		ips := e.app.ResolveDomain(d)
		parsed := make([]uint32, 0, len(ips))
		for _, s := range ips {
			if v, ok := parseIPv4Str(s); ok {
				parsed = append(parsed, v)
			}
		}
		if len(parsed) == 0 {
			e.pending[d] = now + 60
			logf("域名 %s 解析失败，稍后重试封堵", d)
			continue
		}
		resolved[d] = parsed
	}
	// 计算 ip 集合并与已下发集合比对
	wantIPs := map[uint32]bool{}
	for d := range desired {
		for _, ip := range resolved[d] {
			wantIPs[ip] = true
		}
	}
	oldIPs := map[uint32]bool{}
	for d := range e.dnsDomains {
		for _, ip := range e.domainIPs[d] {
			oldIPs[ip] = true
		}
	}
	// 下发 ipset（失败不提交内存状态，失败项放回 pending 供下一轮重试）。
	// 同一批次的 add/del 合并成一次 `ipset restore`，避免逐条 fork。
	if len(wantIPs) > 0 {
		if _, err := e.app.shell("ipset create " + ipsetName + " hash:ip -exist"); err != nil {
			e.markDomainsPending(desired, now)
			return applied, fmt.Errorf("创建 ipset 失败: %w", err)
		}
	}
	addIPs := make([]uint32, 0, len(wantIPs))
	for ip := range wantIPs {
		if !oldIPs[ip] {
			addIPs = append(addIPs, ip)
		}
	}
	delIPs := make([]uint32, 0, len(oldIPs))
	for ip := range oldIPs {
		if !wantIPs[ip] {
			delIPs = append(delIPs, ip)
		}
	}
	sort.Slice(addIPs, func(i, j int) bool { return addIPs[i] < addIPs[j] })
	sort.Slice(delIPs, func(i, j int) bool { return delIPs[i] < delIPs[j] })
	lines := make([]string, 0, len(addIPs)+len(delIPs))
	for _, ip := range addIPs {
		lines = append(lines, fmt.Sprintf("add %s %s", ipsetName, ip4String(ip)))
	}
	for _, ip := range delIPs {
		lines = append(lines, fmt.Sprintf("del %s %s", ipsetName, ip4String(ip)))
	}
	if len(lines) > 0 {
		// `-exist` 是 ipset 全局选项：忽略「重复添加/删除不存在条目」，
		// 其它错误（集合不存在、权限等）仍会让 restore 返回非零。
		script := "ipset -exist restore <<'EOF'\n" + strings.Join(lines, "\n") + "\nEOF"
		if _, err := e.app.shell(script); err != nil {
			e.markDomainsPending(desired, now)
			return applied, fmt.Errorf("写入 ipset 失败: %w", err)
		}
		applied = append(applied, lines...)
	}
	// 下发成功后才提交内存状态（只提交真正封堵成功的域名）。
	// 先提交再重建 iptables：rebuildDeviceRules 依据 dnsDomains 决定是否挂 match-set
	// 规则，若顺序反过来，首次封堵时 ipset 已写入但规则要等下一轮才补上。
	e.domainIPs = resolved
	e.dnsDomains = make(map[string]bool, len(resolved))
	for d := range desired {
		if len(resolved[d]) > 0 {
			e.dnsDomains[d] = true
			delete(e.pending, d)
		}
	}
	// 已不在期望集合里的域名不再重试
	for d := range e.pending {
		if !desired[d] {
			delete(e.pending, d)
		}
	}
	rules, err := e.rebuildDeviceRules()
	if err != nil {
		// ipset 已下发成功（解析没失败）：不把域名放回 pending，避免无意义重试；
		// 规则缺失由下一轮 applyDeviceState 的规则核对自动补发，这里如实返回错误。
		return applied, err
	}
	applied = append(applied, rules...)
	return applied, nil
}

// markDomainsPending 把尚未成功封堵的域名放回 pending（下一轮重试）。
func (e *Enforcer) markDomainsPending(desired map[string]bool, now int64) {
	for d := range desired {
		if e.dnsDomains[d] && len(e.domainIPs[d]) > 0 {
			continue // 已封堵成功
		}
		if _, ok := e.pending[d]; !ok {
			e.pending[d] = now + 60
		}
	}
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
		parsed := make([]uint32, 0, len(ips))
		for _, s := range ips {
			if v, ok := parseIPv4Str(s); ok {
				parsed = append(parsed, v)
			}
		}
		if len(parsed) == 0 {
			e.pending[d] = now + 120
			continue
		}
		e.domainIPs[d] = parsed
		delete(e.pending, d)
		changed = true
	}
	if changed {
		desired := copyBoolMap(e.dnsDesired)
		if len(desired) == 0 {
			desired = copyBoolMap(e.dnsDomains)
		}
		if _, err := e.applyDomainState(desired); err != nil {
			logf("重试域名封堵失败: %v", err)
		}
	}
}

// warnProtectedOnce 受保护目标（本机/网关/关键内网）被策略或持久化记录标记为
// 断网/限速/封禁时记日志：目标被跳过、规则不下发，必须让管理员知道有配置无效。
// 每个「动作+IP」只提示一次，避免 15s 轮询刷屏。
func (e *Enforcer) warnProtectedOnce(ip, action string) {
	key := action + "|" + ip
	e.mu.Lock()
	if e.protWarned == nil {
		e.protWarned = map[string]bool{}
	}
	if e.protWarned[key] {
		e.mu.Unlock()
		return
	}
	e.protWarned[key] = true
	e.mu.Unlock()
	logf("受保护地址 %s（本机/网关/关键内网）被标记为%s，已跳过下发以避免全网中断", ip, action)
}

// revokePolicyDomains 撤销策略引擎下发的域名封堵（策略引擎关闭时调用）。
//
// 背景：策略评估只在 policyEngineOn() 为真时运行，关闭「定时策略」后 runPolicies
// 不再调用 ReconcilePolicies，开关切换处也没有域名撤销步骤 —— 此前策略下发的域名
// 会一直留在 ipset 中持续生效（issue：关闭定时策略不撤销域名封堵）。
// dnsDomains 只包含策略下发的域名（手工封堵列表存 store.DomainBlocks，仅展示层合并、
// 不写 ipset —— 见 BlockedDomains），因此整体清空即为撤销策略域名。
// ipset 集合本身保留（仅 flush），待策略重新开启后由 applyDomainState 复用。
func (e *Enforcer) revokePolicyDomains() {
	e.mu.Lock()
	if len(e.dnsDomains) == 0 && len(e.dnsDesired) == 0 && len(e.pending) == 0 {
		e.mu.Unlock()
		return
	}
	e.dnsDomains = map[string]bool{}
	e.dnsDesired = map[string]bool{}
	e.domainIPs = map[string][]uint32{}
	e.pending = map[string]int64{}
	e.app.shellQuiet("ipset flush " + ipsetName + " 2>/dev/null")
	if e.chainsReady {
		// dnsDomains 已置空，重建后 UBM 链不再挂 match-set 规则
		//（rebuildDeviceRules 会先 -F 再按状态重挂）。
		if _, err := e.rebuildDeviceRules(); err != nil {
			e.mu.Unlock()
			logf("撤销策略域名封堵规则失败: %v", err)
			return
		}
	}
	e.mu.Unlock()
	logf("定时策略已关闭：策略下发的域名封堵已撤销")
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
		// 定时策略关闭后策略引擎不再评估，但此前策略下发的域名封堵若不清理
		// 会永久生效（runPolicies 不再调用本函数，开关切换处也不触发域名撤销）。
		// 这里补上收敛路径：撤销策略域名（手工封堵列表存 store，仅展示合并，不受影响）。
		e.revokePolicyDomains()
		return
	}
	// 定时策略时区换算：OpenWrt 默认 UTC，直接用本地字段评估会早 8 小时。
	// 时区取 settings.timezone（默认 Asia/Shanghai，可在 state.json 配置），
	// 设备无 tzdata 时回退固定 +08:00（见 scheduleLocation）。
	now = now.In(e.app.scheduleLocation())
	domainOn := e.app.domainBlockOn()
	pols := e.app.store.Policies()
	metas := e.app.store.AllDeviceMeta()
	devs := e.app.devs.States()
	ts := now.Unix()

	desiredBlocked := map[string]bool{}
	desiredLimits := map[string]LimitKbps{}
	desiredDst := map[string]bool{}
	desiredDomains := map[string]bool{}
	hitsToSend := map[string]string{} // policyID -> 首个实际生效的目标设备（仅 applied 集合）

	// 手动封禁的目标 IP 来自 store 持久化记录（重启恢复）
	for ip := range e.app.store.DstBlocks() {
		// 受保护地址（本机/网关/关键内网）即使有历史记录也不得下发，避免全网中断
		if e.app.isProtectedIP(ip) {
			e.warnProtectedOnce(ip, "目标封禁")
			continue
		}
		desiredDst[ip] = true
	}

	for _, st := range devs {
		// 【防线】策略引擎下发前必须过受保护地址过滤：
		// 「全部设备 + 断网/限速」策略若把上游网关或路由器本机纳入目标，
		// 会把整网出口 DROP 掉，造成全网中断。被保护的目标跳过并记日志。
		prot := e.app.isProtectedIP(st.IP)
		meta := metas[st.IP]
		if meta.Blocked {
			if prot {
				e.warnProtectedOnce(st.IP, "断网")
			} else {
				desiredBlocked[st.IP] = true
			}
		}
		if meta.LimitKbps.Down > 0 || meta.LimitKbps.Up > 0 {
			if prot {
				e.warnProtectedOnce(st.IP, "限速")
			} else {
				desiredLimits[st.IP] = meta.LimitKbps
			}
		}
		var matched []Policy
		allow := false
		for _, p := range pols {
			if !p.Enabled || !policyTargets(p, st.IP, meta.Group) || !scheduleActive(p.Schedule, now) {
				continue
			}
			matched = append(matched, p)
			if p.Action == "allow" {
				allow = true
			}
		}
		// allow 短路：本设备命中 allow 后不再应用任何 block/limit。
		// 这些策略只是 matched，没有实际下发，因此都不进入 applied（不计命中、不发事件）。
		if allow {
			continue
		}
		for _, p := range matched {
			appliedThis := false
			switch p.Action {
			case "block":
				if len(p.Categories) == 0 && len(p.Domains) == 0 {
					if prot {
						e.warnProtectedOnce(st.IP, "断网")
					} else {
						desiredBlocked[st.IP] = true
						appliedThis = true
					}
				} else if domainOn {
					for _, cat := range p.Categories {
						for _, d := range DomainsForCategory(cat) {
							desiredDomains[d] = true
							appliedThis = true
						}
					}
					for _, d := range p.Domains {
						if nd := normalizeDomainRule(d); nd != "" {
							desiredDomains[nd] = true
							appliedThis = true
						}
					}
				}
				// domainBlock 开关关闭：域名类 block 未下发 → 不计 applied
			case "limit":
				if prot {
					e.warnProtectedOnce(st.IP, "限速")
				} else {
					desiredLimits[st.IP] = p.LimitKbps
					appliedThis = true
				}
			}
			if appliedThis {
				if _, ok := hitsToSend[p.ID]; !ok {
					hitsToSend[p.ID] = st.IP
				}
			}
		}
	}

	// applied 集合 = 真正下发了动作的策略（allow 短路/开关降级/受保护目标跳过都不算）
	applied := make(map[string]bool, len(hitsToSend))
	for id := range hitsToSend {
		applied[id] = true
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
	// 新命中策略：只有 applied（实际下发）的才 +1 并产生事件
	for id := range applied {
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
	e.policyActive = applied
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

// 定时策略时区：默认 Asia/Shanghai（东八区）。
//
// 背景：OpenWrt 默认系统时区是 UTC，ReconcilePolicies 收到的 time.Now() 本地字段
// 比北京时间早 8 小时，用户设置的「22:00-06:00」会实际在 14:00 生效。
// 策略评估入口统一把 now 换算到该时区后再取 Hour/Weekday（见 ReconcilePolicies）。
//
// 解析优先级：环境变量 GUANLAN_TZ（运维/测试覆盖） > settings.timezone（默认
// Asia/Shanghai） > 内置默认。设备未安装 tzdata 时 LoadLocation 失败，回退固定
// +08:00 —— 中国大陆 1991 年后无夏令时，固定偏移与 Asia/Shanghai 语义等价。
const defaultScheduleTimezone = "Asia/Shanghai"

// scheduleTimezone 内置默认时区（settings/time 环境变量都不可用时的兜底）。
var scheduleTimezone = loadScheduleLocation(defaultScheduleTimezone)

// loadScheduleLocation 按 IANA 名加载时区，失败回退固定 +08:00。
func loadScheduleLocation(name string) *time.Location {
	if loc, err := time.LoadLocation(name); err == nil {
		return loc
	}
	return time.FixedZone("Asia/Shanghai", 8*3600)
}

// scheduleLocation 当前生效的定时策略时区（每次评估读取，设置修改后下一轮即生效）。
func (a *App) scheduleLocation() *time.Location {
	if tz := strings.TrimSpace(os.Getenv("GUANLAN_TZ")); tz != "" {
		return loadScheduleLocation(tz)
	}
	if a != nil && a.store != nil {
		if tz := strings.TrimSpace(a.store.Settings().Timezone); tz != "" {
			return loadScheduleLocation(tz)
		}
	}
	return scheduleTimezone
}

// scheduleActive 判断当前时间是否在策略生效时段内。支持跨零点。
//
// 时区基准：now 的本地字段即策略时段的解释时区。生产路径由 ReconcilePolicies
// 先把 time.Now() 换算到 scheduleLocation() 再传入；单测可直接构造 time.Local
// 时间传入，函数本身不做换算。
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
		TcConflict:        e.tcConflict,
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
	removed = append(removed, fmt.Sprintf("tc: %s / ifb0 队列已清理", e.app.LanIfaceName()))
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
	e.dnsDesired = map[string]bool{}
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
	e.dnsDesired = map[string]bool{}
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
	e.dnsDesired = map[string]bool{}
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
