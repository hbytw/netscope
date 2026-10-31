package main

// 研判层：端口扫描 / 高危端口外联 / 黑名单域名 / DNS 隧道 / 流量异常 / 设备事件 / 策略命中。
//
// 去重：同一类型 + 同一设备 + 同一目标（域名/IP/端口）10 分钟内只产生一条事件；
//       高等级事件（critical）不会被同窗口内的低等级事件抑制。
// 风险分：按设备聚合的近 1 小时滑动窗口加权（critical 0.4 / warn 0.2 / info 0.05），封顶 1.0；
//         不受 store 事件表 500 条上限影响，窗口内无事件的设备风险显式清零。
// 事件写到 store（最多 500 条）并通过 SSE alert 实时推送；告警开关关闭时不产生任何事件。

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"
)

var badPorts = map[int]bool{23: true, 445: true, 3389: true, 1433: true, 5900: true, 6379: true, 11211: true}

type hourAgg struct {
	Hour      int64
	UpTotal   int64
	ForeignUp int64
	DownTotal int64
	Sent      bool
}

type riskReason struct {
	Type   string
	Count  int
	LastTs int64
}

// dedupeEntry 去重记录：最近一次事件时间 + 事件等级。
type dedupeEntry struct {
	Ts   int64
	Rank int // critical 3 / warn 2 / info 1
}

// riskEvent 风险滑动窗口内的一次事件（按设备聚合）。
type riskEvent struct {
	Ts     int64
	Type   string
	Weight float64
}

const (
	// riskWindowSec 风险分统计窗口（近 1 小时）。
	riskWindowSec = 3600
	// riskWindowMax 单设备窗口内最多保留的事件数（超出丢弃最旧）。
	riskWindowMax = 200
	// netsCacheSec ZeroTier/VPN 网段快照缓存时长。
	netsCacheSec = 10
)

// Security 研判器。
type Security struct {
	app *App

	mu         sync.Mutex
	scan       map[string]map[int]int64 // 设备 -> 目的端口 -> 首次出现时间
	dedupe     map[string]dedupeEntry   // 去重键（type|设备|目标） -> 最近事件
	hourly     map[string]*hourAgg
	risk       map[string]float64
	reasons    map[string]map[string]*riskReason
	riskWin    map[string][]riskEvent // 设备 -> 近 1 小时事件（风险滑动窗口）
	riskSeeded bool                   // 风险窗口是否已用 store 历史事件初始化
	level      string

	netMu  sync.Mutex
	nets   []ipNet // ZeroTier/VPN 网段快照
	netsAt int64

	wlMu sync.RWMutex
	wl   map[string]bool // 告警白名单：type|target -> true
}

// NewSecurity 创建研判器。
func NewSecurity(a *App) *Security {
	return &Security{
		app:     a,
		scan:    map[string]map[int]int64{},
		dedupe:  map[string]dedupeEntry{},
		hourly:  map[string]*hourAgg{},
		risk:    map[string]float64{},
		reasons: map[string]map[string]*riskReason{},
		riskWin: map[string][]riskEvent{},
		level:   "low",
		wl:      map[string]bool{},
	}
}

// RestoreWhitelist 从 store 重新加载白名单索引（启动/加白/取消后调用）。
func (s *Security) RestoreWhitelist() {
	set := map[string]bool{}
	if s.app != nil && s.app.store != nil {
		set = s.app.store.WhitelistKeySet()
	}
	s.wlMu.Lock()
	s.wl = set
	s.wlMu.Unlock()
}

// whitelisted 判断事件是否命中白名单（同 type + 同设备/域名/目标）。
func (s *Security) whitelisted(ev Event) bool {
	targets := eventTargets(ev)
	if len(targets) == 0 {
		return false
	}
	s.wlMu.RLock()
	defer s.wlMu.RUnlock()
	for _, t := range targets {
		if s.wl[wlKey(ev.Type, t)] {
			return true
		}
	}
	return false
}

// eventTargets 提取事件的可加白目标：设备 IP + 域名/目标 IP（来自 evidence）。
func eventTargets(ev Event) []string {
	out := make([]string, 0, 3)
	seen := map[string]bool{}
	add := func(v string) {
		v = strings.TrimSpace(v)
		if v == "" || seen[v] {
			return
		}
		seen[v] = true
		out = append(out, v)
	}
	add(ev.DeviceIP)
	for _, k := range []string{"domain", "dstIp", "target", "ip"} {
		if v, ok := ev.Evidence[k].(string); ok {
			add(v)
		}
	}
	return out
}

// OnFlow 处理一条 conntrack 增量。
func (s *Security) OnFlow(d FlowDelta, now int64, dstForeign bool) {
	if d.Baseline || d.DeviceIP == "" {
		return
	}
	s.mu.Lock()
	// 流量异常累计（只统计出公网的流量）
	if d.UpDelta > 0 || d.DownDelta > 0 {
		h := s.hourly[d.DeviceIP]
		hour := now / 3600 * 3600
		if h == nil || h.Hour != hour {
			h = &hourAgg{Hour: hour}
			s.hourly[d.DeviceIP] = h
		}
		if !isPrivateOrCGNAT(d.DstIP) {
			h.UpTotal += d.UpDelta
			h.DownTotal += d.DownDelta
			if dstForeign {
				h.ForeignUp += d.UpDelta
			}
		}
	}
	// 端口扫描：只统计「直连公网目的」的新连接。
	// 排除口径（与事件文案保持一致）：
	//   - 流向非 direct（proxy / ZeroTier / VPN / 内网）；
	//   - 目的地址为内网或 CGNAT(100.64.0.0/10)；
	//   - 目的地址落在 ZeroTier/VPN 网段（接口网段 + 经虚拟接口可达的远端路由网段）；
	//   - ZeroTier 控制端口 9993/9994。
	// ZeroTier 是 P2P：设备会同时连接多个 ZT 对等体的不同端口（9993 + 随机端口），
	// 若把这些也算进来会误判为端口扫描，因此这里仅对直连公网目的计数。
	scanFlow := d.New && scanPathDirect(d.Path) &&
		!isPrivateOrCGNAT(d.DstIP) &&
		!s.isVirtualDst(d.DstIP, now) &&
		d.DPort != 9993 && d.DPort != 9994
	if scanFlow {
		if s.scan[d.DeviceIP] == nil {
			s.scan[d.DeviceIP] = map[int]int64{}
		}
		m := s.scan[d.DeviceIP]
		if _, ok := m[d.DPort]; !ok {
			m[d.DPort] = now
		}
		// 窗口外清理 + 上限控制
		for p, ts := range m {
			if now-ts > 60 {
				delete(m, p)
			}
		}
		if len(m) > 300 {
			m = map[int]int64{}
			s.scan[d.DeviceIP] = m
		}
	}
	s.mu.Unlock()

	// 以下判断在锁外做（emit 会拿 store/hub 锁）
	if !d.New {
		return
	}
	if scanFlow {
		s.mu.Lock()
		portCount := len(s.scan[d.DeviceIP])
		ports := make([]int, 0, len(s.scan[d.DeviceIP]))
		for p := range s.scan[d.DeviceIP] {
			ports = append(ports, p)
		}
		s.mu.Unlock()
		sort.Ints(ports)
		threshold := s.scanPortsThreshold()
		if portCount >= threshold {
			// 端口列表限前 20 个，供前端"判定依据"展示
			limit := len(ports)
			if limit > 20 {
				limit = 20
			}
			portList := make([]int, 0, limit)
			portList = append(portList, ports[:limit]...)
			sample := make([]string, 0, 20)
			for _, p := range portList {
				sample = append(sample, fmt.Sprintf("%d", p))
			}
			s.emit(Event{
				Ts: now, Severity: "warn", Type: "port_scan",
				Title: "疑似端口扫描：" + d.DeviceIP,
				Detail: fmt.Sprintf("60 秒内新连接 %d 个不同公网端口（阈值 %d；仅统计直连公网目的，"+
					"已排除代理/ZeroTier/VPN/内网流向、内网与 CGNAT 地址）",
					portCount, threshold),
				DeviceIP:   d.DeviceIP,
				DeviceName: s.deviceName(d.DeviceIP),
				Evidence: map[string]interface{}{
					"ports": portCount, "portList": portList, "windowSec": 60,
					"threshold": threshold, "sample": sample,
					"excluded": "仅统计直连（path=direct）公网目的；代理/ZeroTier/VPN/内网流向、" +
						"内网与 CGNAT(100.64.0.0/10) 地址、ZeroTier/VPN 网段与 9993/9994 控制端口均不计入",
				},
			})
		}
	}
	if badPorts[d.DPort] && !isPrivateOrCGNAT(d.DstIP) {
		s.emit(Event{
			Ts: now, Severity: "info", Type: "bad_port",
			Title:      "高危端口外联：" + d.DeviceIP,
			Detail:     fmt.Sprintf("设备主动外联 %s:%d（高危端口）", d.DstIP, d.DPort),
			DeviceIP:   d.DeviceIP,
			DeviceName: s.deviceName(d.DeviceIP),
			Evidence:   map[string]interface{}{"port": d.DPort, "dstIp": d.DstIP},
		})
	}
}

func (s *Security) scanPortsThreshold() int {
	n := 20
	if s.app != nil && s.app.store != nil {
		if v := s.app.store.Settings().Alert.ScanPorts; v > 0 {
			n = v
		}
	}
	return n
}

// scanPathDirect 判断连接流向是否可能构成端口扫描。
// 只有直连（path=direct）或流向未知（空）才计入；
// proxy / ZeroTier / VPN / 内网（lan）流向一律排除（这些流量多端口属正常行为）。
func scanPathDirect(path string) bool {
	switch path {
	case "", "direct":
		return true
	}
	return false
}

// isPrivateOrCGNAT 判断是否内网地址（RFC1918 / CGNAT 100.64.0.0/10 / 回环 / 链路本地）。
// 注：conntrack.go 的 isPrivateIPStr 只含 RFC1918 等，CGNAT 在研判层补齐，
// 否则 100.64.x.x（运营商级 NAT）会被当成公网目的而误判。
func isPrivateOrCGNAT(s string) bool {
	if isPrivateIPStr(s) {
		return true
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil || !addr.Is4() {
		return false
	}
	v := addr.As4()
	return v[0] == 100 && v[1] >= 64 && v[1] <= 127
}

// isVirtualDst 判断目的 IP 是否落在 ZeroTier/VPN 网段。
func (s *Security) isVirtualDst(ip string, now int64) bool {
	v, ok := parseIPv4Str(strings.TrimSpace(ip))
	if !ok {
		return false
	}
	for _, n := range s.virtualNets(now) {
		if v&n.mask == n.net {
			return true
		}
	}
	return false
}

// virtualNets ZeroTier/VPN 网段快照（10s 缓存，避免每条流量都解析路由表）。
// 网段来源：虚拟接口自身网段 + 经虚拟接口可达的远端路由网段。
func (s *Security) virtualNets(now int64) []ipNet {
	s.netMu.Lock()
	defer s.netMu.Unlock()
	if s.netsAt > 0 && now-s.netsAt < netsCacheSec {
		return s.nets
	}
	var nets []ipNet
	if s.app != nil {
		for _, f := range s.app.interfaces() {
			if f.CIDR == "" {
				continue
			}
			switch f.Network {
			case "zerotier", "vpn":
				if n, ok := ipNetFromCIDR(f.CIDR, f.Network, f.Name); ok {
					nets = append(nets, n)
				}
			}
		}
		for _, line := range s.app.routeLines() {
			fields := strings.Fields(line)
			if len(fields) < 3 || fields[0] == "default" || strings.Contains(fields[0], ":") {
				continue
			}
			cidr := fields[0]
			if !strings.Contains(cidr, "/") {
				continue
			}
			dev := ""
			for i := 0; i < len(fields)-1; i++ {
				if fields[i] == "dev" {
					dev = fields[i+1]
					break
				}
			}
			if dev == "" {
				continue
			}
			kind, _ := ifaceKind(dev)
			if kind != "zerotier" && kind != "vpn" {
				continue
			}
			if n, ok := ipNetFromCIDR(cidr, kind, dev); ok {
				nets = append(nets, n)
			}
		}
	}
	s.nets = nets
	s.netsAt = now
	return nets
}

// OnBlacklistDomain 命中内置黑名单域名。
func (s *Security) OnBlacklistDomain(domain, devIP, kind string, now int64) {
	sev := "warn"
	if kind == "mining" {
		sev = "critical"
	}
	s.emit(Event{
		Ts: now, Severity: sev, Type: "blacklist_domain",
		Title:      "命中黑名单域名：" + domain,
		Detail:     fmt.Sprintf("设备 %s 访问%s（%s）", devIP, blockKindLabel(kind), domain),
		DeviceIP:   devIP,
		DeviceName: s.deviceName(devIP),
		Evidence:   map[string]interface{}{"domain": domain, "category": kind},
	})
}

// OnNewDevice 新设备入网。
func (s *Security) OnNewDevice(ip, name string, now int64) {
	s.emit(Event{
		Ts: now, Severity: "info", Type: "new_device",
		Title:    "新设备入网：" + name,
		Detail:   fmt.Sprintf("发现设备 %s（%s）接入局域网", name, ip),
		DeviceIP: ip, DeviceName: name,
		Evidence: map[string]interface{}{"ip": ip},
	})
}

// OnDeviceOnline 设备上线。
func (s *Security) OnDeviceOnline(ip, name string, now int64) {
	s.emit(Event{
		Ts: now, Severity: "info", Type: "device_online",
		Title:    "设备上线：" + name,
		Detail:   fmt.Sprintf("设备 %s（%s）重新上线", name, ip),
		DeviceIP: ip, DeviceName: name,
		Evidence: map[string]interface{}{"ip": ip},
	})
}

// OnDeviceOffline 设备离线。
func (s *Security) OnDeviceOffline(ip, name string, now int64) {
	s.emit(Event{
		Ts: now, Severity: "info", Type: "device_offline",
		Title:    "设备离线：" + name,
		Detail:   fmt.Sprintf("设备 %s（%s）已离线", name, ip),
		DeviceIP: ip, DeviceName: name,
		Evidence: map[string]interface{}{"ip": ip},
	})
}

// OnPolicyHit 策略命中。
func (s *Security) OnPolicyHit(policyID, policyName, action, ip, name string, now int64) {
	s.emit(Event{
		Ts: now, Severity: "info", Type: "policy_hit",
		Title:    "策略命中：" + policyName,
		Detail:   fmt.Sprintf("策略「%s」对设备 %s 生效（动作：%s）", policyName, name, action),
		DeviceIP: ip, DeviceName: name,
		Evidence: map[string]interface{}{"policyId": policyID, "policyName": policyName, "action": action},
	})
}

// OnThreatDomain 命中开源威胁情报库的恶意域名（C2/钓鱼/矿池/恶意软件等）。
func (s *Security) OnThreatDomain(domain, devIP string, tr ThreatRule, now int64) {
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return
	}
	s.emit(Event{
		Ts: now, Severity: threatSeverity(tr.Kind), Type: "blacklist_domain",
		Title:      "命中高危域名：" + domain,
		Detail:     fmt.Sprintf("命中%s（来源 %s）", threatKindLabel(tr.Kind), tr.Source),
		DeviceIP:   devIP,
		DeviceName: s.deviceName(devIP),
		Evidence: map[string]interface{}{
			"domain": domain, "kind": string(tr.Kind), "source": tr.Source,
		},
	})
}

// OnThreatIP 连接命中开源威胁情报库的恶意 IP/CIDR（C2/僵尸网络/恶意服务器）。
func (s *Security) OnThreatIP(ip, devIP string, tr ThreatRule, now int64) {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return
	}
	s.emit(Event{
		Ts: now, Severity: threatSeverity(tr.Kind), Type: "bad_ip",
		Title:      "连接高危 IP：" + ip,
		Detail:     fmt.Sprintf("命中%s：%s", threatKindLabel(tr.Kind), tr.Source),
		DeviceIP:   devIP,
		DeviceName: s.deviceName(devIP),
		Evidence: map[string]interface{}{
			"ip": ip, "kind": string(tr.Kind), "source": tr.Source,
		},
	})
}

// emit 去重后落库并推送（统一事件出口）。
// 告警开关关闭时不产生任何事件（契约：alerts 关闭 → 不做研判、不产生事件），
// 数据面（流量/DNS/设备上下线）同样受此开关约束。
func (s *Security) emit(ev Event) bool {
	if ev.Evidence == nil {
		ev.Evidence = map[string]interface{}{}
	}
	// 告警开关：关闭后不再产生/推送任何事件
	if !s.alertsEnabled() {
		return false
	}
	// 告警白名单：同 type + 同设备/域名/目标 → 不再产生新事件（历史事件保留）
	if s.whitelisted(ev) {
		return false
	}
	// 去重键含目标（域名/IP/端口）：同一设备访问不同恶意目标应各自产生事件
	key := ev.Type + "|" + ev.DeviceIP + "|" + eventTargetKey(ev)
	if ev.DeviceIP == "" {
		key = ev.Type + "|" + ev.Title + "|" + eventTargetKey(ev)
	}
	rank := severityRank(ev.Severity)
	s.mu.Lock()
	if last, ok := s.dedupe[key]; ok && ev.Ts-last.Ts < 600 {
		// 同窗口内低等级事件不抑制高等级事件（critical 不被 warn 压掉）
		if rank <= last.Rank {
			s.mu.Unlock()
			return false
		}
	}
	s.dedupe[key] = dedupeEntry{Ts: ev.Ts, Rank: rank}
	// 去重表上限
	if len(s.dedupe) > 2000 {
		for k, e := range s.dedupe {
			if ev.Ts-e.Ts > 600 {
				delete(s.dedupe, k)
			}
		}
	}
	s.mu.Unlock()
	if s.app != nil {
		s.app.emitEvent(ev)
		s.addRiskEvent(ev)
	}
	return true
}

// alertsEnabled 统一告警开关判断（事件出口统一把关）。
//   - alert.enable：设置页「启用安全告警」，关闭即不产生任何事件；
//   - alerts：安全告警功能开关（依赖总开关与采集开关），关闭同样不产生事件。
//
// 总开关未启用时不额外限制（此时不会有采集数据，保留演示/单测路径行为）。
func (s *Security) alertsEnabled() bool {
	if s.app == nil || s.app.store == nil {
		return true
	}
	st := s.app.store.Settings()
	if !st.Alert.Enable {
		return false
	}
	if st.Enabled && !st.Alerts {
		return false
	}
	return true
}

// severityRank 事件等级（critical 3 / warn 2 / info 1）。
func severityRank(sev string) int {
	switch sev {
	case "critical":
		return 3
	case "warn":
		return 2
	default:
		return 1
	}
}

// severityWeight 事件风险权重（critical 0.4 / warn 0.2 / info 0.05）。
func severityWeight(sev string) float64 {
	switch sev {
	case "critical":
		return 0.4
	case "warn":
		return 0.2
	default:
		return 0.05
	}
}

// eventTargetKey 事件去重目标：域名 / 目标 IP / 端口。
// 没有目标信息的事件（如端口扫描按设备聚合）返回空串，保持按设备去重。
func eventTargetKey(ev Event) string {
	parts := make([]string, 0, 3)
	for _, k := range []string{"domain", "dstIp", "target", "ip"} {
		if v, ok := ev.Evidence[k].(string); ok {
			if v = strings.TrimSpace(v); v != "" {
				parts = append(parts, k+"="+v)
			}
		}
	}
	switch p := ev.Evidence["port"].(type) {
	case int:
		parts = append(parts, fmt.Sprintf("port=%d", p))
	case float64:
		parts = append(parts, fmt.Sprintf("port=%d", int(p)))
	}
	return strings.Join(parts, ",")
}

// Analyze 周期性研判（每 5s）：流量异常、DNS 隧道、风险分。
func (s *Security) Analyze(now int64) {
	if s.app == nil {
		return
	}
	if s.alertsEnabled() {
		s.checkAnomaly(now)
		s.checkDNSTunnel(now)
	}
	s.updateRisk(now)
	if s.app.dns != nil {
		s.app.dns.Cleanup(now)
	}
	s.prune(now)
}

// checkAnomaly 单设备 1 小时上传超阈值且境外目的占比明显。
func (s *Security) checkAnomaly(now int64) {
	limitMb := int64(500)
	if s.app.store != nil {
		if v := s.app.store.Settings().Alert.TrafficMbPerHour; v > 0 {
			limitMb = int64(v)
		}
	}
	limit := limitMb * 1024 * 1024
	s.mu.Lock()
	type hit struct {
		dev     string
		upMb    int64
		foreign int64
	}
	var hits []hit
	for dev, h := range s.hourly {
		if h.Sent || h.UpTotal < limit {
			continue
		}
		// 要求境外目的占上传量的一定比例，避免内网备份误报
		if h.ForeignUp < limit/3 {
			continue
		}
		h.Sent = true
		hits = append(hits, hit{dev, h.UpTotal / (1024 * 1024), h.ForeignUp / (1024 * 1024)})
	}
	s.mu.Unlock()
	for _, h := range hits {
		s.emit(Event{
			Ts: now, Severity: "warn", Type: "traffic_anomaly",
			Title:      "流量异常：" + h.dev,
			Detail:     fmt.Sprintf("1 小时内上传 %d MB，其中境外目的约 %d MB", h.upMb, h.foreign),
			DeviceIP:   h.dev,
			DeviceName: s.deviceName(h.dev),
			Evidence:   map[string]interface{}{"upMb": h.upMb, "foreignMb": h.foreign, "windowSec": 3600},
		})
	}
}

// checkDNSTunnel 使用 DNS 解析器的 TXT 统计做隧道嫌疑研判。
func (s *Security) checkDNSTunnel(now int64) {
	if s.app.dns == nil {
		return
	}
	for _, sus := range s.app.dns.SuspectTXT(now) {
		dev := sus.SrcIP
		s.emit(Event{
			Ts: now, Severity: "warn", Type: "dns_tunnel",
			Title:      "DNS 隧道嫌疑：" + sus.Domain,
			Detail:     fmt.Sprintf("60 秒内 TXT 查询 %d 次，子域标签平均长度 %.0f", sus.Count, sus.AvgLabel),
			DeviceIP:   dev,
			DeviceName: s.deviceName(dev),
			Evidence:   map[string]interface{}{"domain": sus.Domain, "count": sus.Count, "avgLabelLen": int(sus.AvgLabel)},
		})
	}
}

// addRiskEvent 记录一条事件到设备风险滑动窗口（近 1 小时）。
func (s *Security) addRiskEvent(ev Event) {
	if ev.DeviceIP == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	win := append(s.riskWin[ev.DeviceIP], riskEvent{
		Ts:     ev.Ts,
		Type:   ev.Type,
		Weight: severityWeight(ev.Severity),
	})
	// 单设备窗口上限（超出丢弃最旧）
	if len(win) > riskWindowMax {
		win = win[len(win)-riskWindowMax:]
	}
	s.riskWin[ev.DeviceIP] = win
}

// seedRiskWindow 首次运行时用 store 中的历史事件初始化风险窗口（重启后风险不丢）。
func (s *Security) seedRiskWindow(now int64) {
	if s.app == nil || s.app.store == nil {
		return
	}
	events, _ := s.app.store.Events(500, "", "", "all")
	cut := now - riskWindowSec
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range events {
		if e.Ts < cut || e.DeviceIP == "" {
			continue
		}
		s.riskWin[e.DeviceIP] = append(s.riskWin[e.DeviceIP], riskEvent{
			Ts:     e.Ts,
			Type:   e.Type,
			Weight: severityWeight(e.Severity),
		})
	}
	s.riskSeeded = true
}

// updateRisk 依据近 1 小时事件重算设备风险与全局等级。
// 风险来自「按设备聚合的滑动窗口」（内存），不再受 store 事件表 500 条上限影响；
// 本轮窗口内已无事件的设备风险显式置零（表外设备不再残留旧分）。
func (s *Security) updateRisk(now int64) {
	if s.app == nil {
		return
	}
	s.mu.Lock()
	seeded := s.riskSeeded
	s.mu.Unlock()
	if !seeded {
		s.seedRiskWindow(now)
	}
	cut := now - riskWindowSec
	s.mu.Lock()
	risk := map[string]float64{}
	reasons := map[string]map[string]*riskReason{}
	prev := s.risk
	hasCritical := false
	for dev, win := range s.riskWin {
		kept := make([]riskEvent, 0, len(win))
		rm := map[string]*riskReason{}
		sum := 0.0
		for _, ev := range win {
			if ev.Ts < cut {
				continue
			}
			kept = append(kept, ev)
			sum += ev.Weight
			r := rm[ev.Type]
			if r == nil {
				r = &riskReason{Type: ev.Type}
				rm[ev.Type] = r
			}
			r.Count++
			if ev.Ts > r.LastTs {
				r.LastTs = ev.Ts
			}
			if ev.Weight >= 0.4 {
				hasCritical = true
			}
		}
		if len(kept) == 0 {
			// 窗口内已无事件：删除并清零
			delete(s.riskWin, dev)
			continue
		}
		s.riskWin[dev] = kept
		if sum > 1 {
			sum = 1
		}
		risk[dev] = sum
		reasons[dev] = rm
	}
	// 上一轮有风险、本轮窗口已空 → 显式置零
	for dev := range prev {
		if _, ok := risk[dev]; !ok {
			risk[dev] = 0
			reasons[dev] = nil
		}
	}
	maxRisk := 0.0
	for _, v := range risk {
		if v > maxRisk {
			maxRisk = v
		}
	}
	level := "low"
	if maxRisk >= 0.75 || hasCritical {
		level = "high"
	} else if maxRisk >= 0.35 {
		level = "guard"
	}
	s.risk = risk
	s.reasons = reasons
	s.level = level
	s.mu.Unlock()
	// 同步到设备状态（风险清零也要下发，避免界面残留旧分）
	if s.app.devs != nil {
		for dev, v := range risk {
			s.app.devs.SetRisk(dev, v)
		}
	}
}

// prune 清理过期的扫描窗口与小时累计。
func (s *Security) prune(now int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for dev, m := range s.scan {
		for p, ts := range m {
			if now-ts > 120 {
				delete(m, p)
			}
		}
		if len(m) == 0 {
			delete(s.scan, dev)
		}
	}
	for dev, h := range s.hourly {
		if now-h.Hour > 2*3600 {
			delete(s.hourly, dev)
		}
	}
	if len(s.dedupe) > 3000 {
		for k, e := range s.dedupe {
			if now-e.Ts > 600 {
				delete(s.dedupe, k)
			}
		}
	}
}

// Level 当前全局风险等级。
func (s *Security) Level() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.level == "" {
		return "low"
	}
	return s.level
}

// RiskDevices 风险设备列表（供 /api/security/risk）。
type RiskDevice struct {
	IP      string
	Name    string
	Risk    float64
	Reasons []riskReason
}

// RiskDevices 返回风险分 > 0.1 的设备。
func (s *Security) RiskDevices() []RiskDevice {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]RiskDevice, 0, len(s.risk))
	for ip, r := range s.risk {
		if r < 0.1 {
			continue
		}
		reasons := make([]riskReason, 0, len(s.reasons[ip]))
		for _, rr := range s.reasons[ip] {
			reasons = append(reasons, *rr)
		}
		sort.Slice(reasons, func(i, j int) bool { return reasons[i].Count > reasons[j].Count })
		out = append(out, RiskDevice{IP: ip, Name: s.deviceName(ip), Risk: mathRound2(r), Reasons: reasons})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Risk > out[j].Risk })
	return out
}

func (s *Security) deviceName(ip string) string {
	if s.app != nil && s.app.devs != nil {
		if st, ok := s.app.devs.State(ip); ok && st.Hostname != "" {
			return st.Hostname
		}
	}
	return ip
}

func mathRound2(v float64) float64 {
	return float64(int(v*100+0.5)) / 100
}

// EmitForTest 供 demo/测试直接投递事件。
func (s *Security) EmitForTest(ev Event) {
	if s.app != nil {
		ev.Ts = time.Now().Unix()
		s.emit(ev)
	}
}

// ResetRuntime 清空研判运行时状态（关闭告警开关时调用，历史事件保留在 store）。
func (s *Security) ResetRuntime() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.scan = map[string]map[int]int64{}
	s.dedupe = map[string]dedupeEntry{}
	s.hourly = map[string]*hourAgg{}
	s.risk = map[string]float64{}
	s.reasons = map[string]map[string]*riskReason{}
	s.riskWin = map[string][]riskEvent{}
	s.riskSeeded = false
	s.level = "low"
}
