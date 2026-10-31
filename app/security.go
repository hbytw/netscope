package main

// 研判层：端口扫描 / 高危端口外联 / 黑名单域名 / DNS 隧道 / 流量异常 / 设备事件 / 策略命中。
//
// 去重：同一类型 + 同一设备 10 分钟内只产生一条事件。
// 风险分：近 1 小时事件加权（critical 0.4 / warn 0.2 / info 0.05），封顶 1.0。
// 事件写到 store（最多 500 条）并通过 SSE alert 实时推送。

import (
	"fmt"
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

// Security 研判器。
type Security struct {
	app *App

	mu      sync.Mutex
	scan    map[string]map[int]int64 // 设备 -> 目的端口 -> 首次出现时间
	dedupe  map[string]int64         // 去重键 -> 最近事件时间
	hourly  map[string]*hourAgg
	risk    map[string]float64
	reasons map[string]map[string]*riskReason
	level   string

	wlMu sync.RWMutex
	wl   map[string]bool // 告警白名单：type|target -> true
}

// NewSecurity 创建研判器。
func NewSecurity(a *App) *Security {
	return &Security{
		app:     a,
		scan:    map[string]map[int]int64{},
		dedupe:  map[string]int64{},
		hourly:  map[string]*hourAgg{},
		risk:    map[string]float64{},
		reasons: map[string]map[string]*riskReason{},
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
		if !isPrivateIPStr(d.DstIP) {
			h.UpTotal += d.UpDelta
			h.DownTotal += d.DownDelta
			if dstForeign {
				h.ForeignUp += d.UpDelta
			}
		}
	}
	// 端口扫描：只统计「公网目的」的新连接，排除内网/ZeroTier/VPN 网段与 ZT 控制端口。
	// ZeroTier 是 P2P：设备会同时连接多个 ZT 对等体的不同端口（9993 + 随机端口，目的在内网），
	// 若把内网多端口也算进来会误判为端口扫描，因此这里仅对公网目的计数。
	scanFlow := d.New && !isPrivateIPStr(d.DstIP) && d.DPort != 9993 && d.DPort != 9994
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
				Detail: fmt.Sprintf("60 秒内新连接 %d 个不同公网端口（阈值 %d；已排除内网/ZeroTier/VPN 目的）",
					portCount, threshold),
				DeviceIP:   d.DeviceIP,
				DeviceName: s.deviceName(d.DeviceIP),
				Evidence: map[string]interface{}{
					"ports": portCount, "portList": portList, "windowSec": 60,
					"threshold": threshold, "sample": sample,
					"excluded": "私有/ZeroTier/VPN 目的地址与 9993/9994 控制端口不计入",
				},
			})
		}
	}
	if badPorts[d.DPort] && !isPrivateIPStr(d.DstIP) {
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

// emit 去重后落库并推送。
func (s *Security) emit(ev Event) bool {
	if ev.Evidence == nil {
		ev.Evidence = map[string]interface{}{}
	}
	// 告警白名单：同 type + 同设备/域名/目标 → 不再产生新事件（历史事件保留）
	if s.whitelisted(ev) {
		return false
	}
	key := ev.Type + "|" + ev.DeviceIP
	if ev.DeviceIP == "" {
		key = ev.Type + "|" + ev.Title
	}
	s.mu.Lock()
	if last, ok := s.dedupe[key]; ok && ev.Ts-last < 600 {
		s.mu.Unlock()
		return false
	}
	s.dedupe[key] = ev.Ts
	// 去重表上限
	if len(s.dedupe) > 2000 {
		for k, ts := range s.dedupe {
			if ev.Ts-ts > 600 {
				delete(s.dedupe, k)
			}
		}
	}
	s.mu.Unlock()
	if s.app != nil {
		s.app.emitEvent(ev)
	}
	return true
}

// Analyze 周期性研判（每 5s）：流量异常、DNS 隧道、风险分。
func (s *Security) Analyze(now int64) {
	if s.app == nil {
		return
	}
	enable := true
	if s.app.store != nil {
		enable = s.app.store.Settings().Alert.Enable
	}
	if enable {
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

// updateRisk 依据近 1 小时事件重算设备风险与全局等级。
func (s *Security) updateRisk(now int64) {
	events, _ := s.app.store.Events(500, "", "", "all")
	reasons := map[string]map[string]*riskReason{}
	risk := map[string]float64{}
	cut := now - 3600
	for _, e := range events {
		if e.Ts < cut || e.DeviceIP == "" {
			continue
		}
		var w float64
		switch e.Severity {
		case "critical":
			w = 0.4
		case "warn":
			w = 0.2
		default:
			w = 0.05
		}
		risk[e.DeviceIP] += w
		if reasons[e.DeviceIP] == nil {
			reasons[e.DeviceIP] = map[string]*riskReason{}
		}
		r := reasons[e.DeviceIP][e.Type]
		if r == nil {
			r = &riskReason{Type: e.Type}
			reasons[e.DeviceIP][e.Type] = r
		}
		r.Count++
		if e.Ts > r.LastTs {
			r.LastTs = e.Ts
		}
	}
	maxRisk := 0.0
	hasCritical := false
	for dev, v := range risk {
		if v > 1 {
			v = 1
		}
		risk[dev] = v
		if v > maxRisk {
			maxRisk = v
		}
		if s.app.devs != nil {
			s.app.devs.SetRisk(dev, v)
		}
	}
	for _, e := range events {
		if e.Ts >= cut && e.Severity == "critical" {
			hasCritical = true
			break
		}
	}
	level := "low"
	if maxRisk >= 0.75 || hasCritical {
		level = "high"
	} else if maxRisk >= 0.35 {
		level = "guard"
	}
	s.mu.Lock()
	s.risk = risk
	s.reasons = reasons
	s.level = level
	s.mu.Unlock()
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
		for k, ts := range s.dedupe {
			if now-ts > 600 {
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
	s.dedupe = map[string]int64{}
	s.hourly = map[string]*hourAgg{}
	s.risk = map[string]float64{}
	s.reasons = map[string]map[string]*riskReason{}
	s.level = "low"
}
