package main

// 演示模式（-demo）：不读 /proc、不执行任何真实命令，生成与契约一致的合成数据，
// 用于 Windows 本地联调 / 截图验收。
//
// 合成数据走的是和真机一致的管线：演示流程同样生成 conntrack 条目 → 差分引擎 →
// 聚合 → 设备速率 → SSD/API，因此接口返回结构与真机完全一致。

import (
	"fmt"
	"math"
	"math/rand"
	"strconv"
	"strings"
	"time"
)

// demoDevice 演示设备。
type demoDevice struct {
	IP       string
	MAC      string
	Hostname string
	Online   bool
	Alias    string
	Group    string
}

// demoDomain 演示域名池。
type demoDomain struct {
	Domain string
	IP     string
	Weight int // 流量权重
	Bytes  int64
}

// demoFlow 演示连接（累计字节随时间增长，由差分引擎算出增量）。
type demoFlow struct {
	Device   string
	DstIP    string
	Proto    string
	SPort    int
	DPort    int
	Mark     uint32 // conntrack mark：>0 表示被代理（演示 path=proxy）
	Up       int64
	Down     int64
	UpRate   float64 // bytes/s
	DownRate float64
	Expire   int64
	Domain   string
}

// demoRouteTargets 演示用的 zt/vpn/代理流向目的地址，用于展示 Connection.path。
var demoRouteTargets = []struct {
	IP     string
	Mark   uint32
	Domain string
}{
	{"10.0.2.20", 0, "zt-remote-nas"},   // 经 ZeroTier 的远端网段
	{"10.10.10.20", 0, "zt-remote-svc"}, // 经 ZeroTier
	{"192.168.2.20", 0, "zt-branch"},    // 经 ZeroTier 的远端 LAN
	{"10.8.0.20", 0, "vpn-node"},        // 经 VPN
	{"142.250.72.14", 1, "google.com"},  // 公网 + mark=1 → 代理
}

// Demo 演示数据生成器。
type Demo struct {
	app           *App
	devices       []demoDevice
	domains       []demoDomain
	flows         map[string]*demoFlow
	rng           *rand.Rand
	started       int64
	tickN         int64
	lastNewDevice int64
}

var demoDeviceTable = []demoDevice{
	{"192.168.1.31", "90:f0:52:d5:9a:cb", "MEIZU-Note-16", true, "妈妈的手机", "家人"},
	{"192.168.1.32", "3c:5a:b4:1a:22:01", "iPhone-15-Pro", true, "爸爸的手机", "家人"},
	{"192.168.1.33", "00:9a:cd:11:22:33", "Redmi-Turbo-3", true, "小明的手机", "孩子"},
	{"192.168.1.34", "00:1b:63:12:34:56", "MacBook-Pro", true, "客厅MacBook", "家人"},
	{"192.168.1.35", "00:e0:4c:aa:bb:01", "DESKTOP-7K3M", true, "书房台式机", "办公"},
	{"192.168.1.36", "00:0c:43:01:02:03", "MI-BOX-4", true, "客厅电视盒子", "家人"},
	{"192.168.1.37", "00:0c:43:04:05:06", "MI-TV-65", true, "客厅电视", "家人"},
	{"192.168.1.38", "24:db:ac:00:00:01", "UniFi-AP", true, "客厅AP", "网络"},
	{"192.168.1.39", "b8:27:eb:00:00:02", "raspberrypi", true, "树莓派NAS", "网络"},
	{"192.168.1.40", "00:0c:29:01:02:03", "VM-Ubuntu", true, "开发虚拟机", "办公"},
	{"192.168.1.41", "38:01:46:aa:00:01", "Galaxy-S24", true, "备用手机", "家人"},
	{"192.168.1.42", "00:23:cd:00:00:09", "TP-LINK-Cam", false, "门口摄像头", "家庭安防"},
	{"192.168.1.43", "00:1d:0f:00:00:0a", "kindle", false, "Kindle", "家人"},
	{"192.168.1.44", "18:b4:30:00:00:0b", "Nest-Thermostat", true, "温控器", "智能家居"},
	{"192.168.99.16", "24:db:ac:00:00:10", "ZT-NAS", true, "ZeroTier NAS", "网络"},
	{"192.168.99.94", "24:db:ac:00:00:5e", "ZT-Laptop", true, "ZeroTier 笔记本", "办公"},
}

var demoDomainTable = []demoDomain{
	{"bilibili.com", "112.252.211.104", 30, 0},
	{"douyin.com", "223.109.101.20", 18, 0},
	{"iqiyi.com", "116.132.251.20", 8, 0},
	{"youku.com", "117.135.198.20", 5, 0},
	{"v.qq.com", "183.192.65.20", 8, 0},
	{"steampowered.com", "23.45.64.20", 4, 0},
	{"steamcommunity.com", "23.45.64.21", 2, 0},
	{"weixin.qq.com", "120.241.161.20", 6, 0},
	{"weibo.com", "111.202.60.20", 3, 0},
	{"xiaohongshu.com", "124.71.190.20", 4, 0},
	{"telegram.org", "91.108.56.20", 2, 0},
	{"baidu.com", "110.242.68.20", 5, 0},
	{"taobao.com", "113.96.108.20", 4, 0},
	{"jd.com", "211.144.24.20", 3, 0},
	{"zhihu.com", "115.24.30.20", 2, 0},
	{"meituan.com", "117.184.30.20", 2, 0},
	{"microsoft.com", "13.107.42.20", 3, 0},
	{"apple.com", "17.253.144.20", 2, 0},
	{"google.com", "142.250.72.14", 2, 0},
	{"github.com", "140.82.112.20", 2, 0},
	{"163.com", "59.111.181.20", 2, 0},
	{"gmail.com", "142.250.4.20", 1, 0},
	{"pan.baidu.com", "113.32.10.20", 4, 0},
	{"aliyundrive.com", "47.103.10.20", 3, 0},
	{"qq.com", "112.90.10.20", 3, 0},
	{"douyu.com", "119.97.10.20", 3, 0},
	{"huya.com", "125.88.10.20", 2, 0},
	{"taptap.com", "118.31.10.20", 1, 0},
	{"githubusercontent.com", "185.199.108.20", 1, 0},
	{"pool.minexmr.com", "45.77.10.20", 1, 0},
}

// NewDemo 创建演示生成器。
func NewDemo(a *App) *Demo {
	return &Demo{
		app:     a,
		devices: append([]demoDevice(nil), demoDeviceTable...),
		domains: append([]demoDomain(nil), demoDomainTable...),
		flows:   map[string]*demoFlow{},
		rng:     rand.New(rand.NewSource(20251031)),
		started: nowUnix(),
	}
}

// Init 初始化演示数据：设备、策略、域名统计、历史分钟桶、趋势点、事件。
func (d *Demo) Init() {
	if d.app == nil {
		return
	}
	now := nowUnix()
	d.seedDevicesAndDomains(now)
	d.seedPolicies()

	// 历史分钟桶（8 天）与最近趋势点
	d.app.agg.SetMaxBuckets(12000)
	d.prefillBuckets(now, 8)
	d.prefillTrend(now)

	// 初始事件（让安全页/总览一打开就有内容）
	d.seedEvents(now)
	// 演示封禁记录：让「封禁列表/解封」入口一打开就有数据可操作
	d.app.store.UpdateDeviceMeta("192.168.1.33", func(m *DeviceMeta) {
		m.Blocked = true
		m.BlockedAt = now - 600
	})
	d.app.store.PutDstBlock("45.77.10.20", now-300)
	// 演示告警白名单（前端白名单列表卡片预览）
	d.app.store.PutWhitelist("port_scan", "192.168.1.84", "演示：已知的端口扫描器", now-3600)
}

// demoNetwork 演示设备的所属网络。
func demoNetwork(ip string) string {
	if strings.HasPrefix(ip, "192.168.99.") {
		return "zerotier"
	}
	return "lan"
}

// ensureSeed 开关重新打开后补种演示设备/域名（不重复插入策略与历史）。
func (d *Demo) ensureSeed() {
	if d.app == nil || len(d.app.devs.States()) > 0 {
		return
	}
	now := nowUnix()
	d.seedDevicesAndDomains(now)
	d.seedPolicies()
}

// seedDevicesAndDomains 预置演示设备、别名分组、域名统计与 IP 归因（不触发事件）。
func (d *Demo) seedDevicesAndDomains(now int64) {
	states := make([]*DeviceState, 0, len(d.devices))
	for _, dev := range d.devices {
		last := now
		if !dev.Online {
			last = now - 1800
		}
		states = append(states, &DeviceState{
			IP: dev.IP, MAC: dev.MAC, Hostname: dev.Hostname,
			Vendor: VendorForMAC(dev.MAC), Network: demoNetwork(dev.IP), Online: dev.Online,
			FirstSeen: now - 86400*3, LastSeen: last,
			TotalUp:   int64(d.rng.Intn(50_000_000)),
			TotalDown: int64(d.rng.Intn(2_000_000_000)),
		})
		// 别名/分组写入 store（与真机一致，UI 可编辑）
		d.app.store.UpdateDeviceMeta(dev.IP, func(m *DeviceMeta) {
			m.FirstSeen = now - 86400*3
			if m.Alias == "" {
				m.Alias = dev.Alias
			}
			if m.Group == "" {
				m.Group = dev.Group
			}
		})
	}
	d.app.devs.Seed(states)

	// 域名统计与 IP 归因
	for i := range d.domains {
		dom := &d.domains[i]
		cat, label, _, _ := classifyHost(dom.Domain)
		d.app.dns.SeedIP(dom.IP, dom.Domain)
		d.app.dns.SeedDomain(dom.Domain, cat, label, int64(20+dom.Weight*3), 0, "")
	}
	// zt/vpn/代理流向目的地址的归因（用于连接 URL/域名列展示）
	for _, t := range demoRouteTargets {
		cat, label, _, _ := classifyHost(t.Domain)
		if label == "" {
			label = t.Domain
		}
		d.app.dns.SeedIP(t.IP, t.Domain)
		d.app.dns.SeedDomain(t.Domain, cat, label, 8, 0, "")
	}
}

// seedPolicies 首次运行预置两条演示策略。
func (d *Demo) seedPolicies() {
	if len(d.app.store.Policies()) > 0 {
		return
	}
	d.app.store.UpsertPolicy(Policy{
		Name: "22点后禁止刷短视频", Enabled: true,
		Targets:  Targets{IPs: []string{"192.168.1.31", "192.168.1.33"}},
		Schedule: Schedule{Days: []int{1, 2, 3, 4, 5, 6, 7}, Start: "22:00", End: "23:59"},
		Action:   "block", Categories: []string{"video", "game"},
	})
	d.app.store.UpsertPolicy(Policy{
		Name: "孩子设备限速", Enabled: false,
		Targets:  Targets{IPs: []string{"192.168.1.33"}},
		Schedule: Schedule{Start: "00:00", End: "23:59"},
		Action:   "limit", LimitKbps: LimitKbps{Down: 2000, Up: 500},
	})
}

// prefillBuckets 生成过去 days 天的 1min 桶，供 1h/6h/24h/7d 图表使用。
func (d *Demo) prefillBuckets(now int64, days int) {
	agg := d.app.agg
	curMinute := now / 60 * 60
	start := curMinute - int64(days)*86400
	online := make([]string, 0, len(d.devices))
	for _, dev := range d.devices {
		if dev.Online {
			online = append(online, dev.IP)
		}
	}
	catWeights := map[string]float64{
		"video": 0.42, "game": 0.10, "social": 0.12, "web": 0.16,
		"download": 0.07, "mail": 0.02, "cloud": 0.07, "other": 0.04,
	}
	agg.mu.Lock()
	defer agg.mu.Unlock()
	agg.buckets = agg.buckets[:0]
	for t := start; t < curMinute; t += 60 {
		hour := time.Unix(t, 0).Hour()
		// 白天/晚间流量更高，凌晨低
		dayFactor := 0.25 + 0.75*math.Max(0, math.Sin(float64(hour-6)/24*math.Pi*2))
		if hour >= 19 && hour <= 23 {
			dayFactor = 1.0
		}
		baseDown := 2.2e6 * dayFactor * (0.85 + d.rng.Float64()*0.3) // bytes/s
		baseUp := baseDown * 0.16
		b := newBucket(t)
		b.Down = int64(baseDown * 60)
		b.Up = int64(baseUp * 60)
		for cat, w := range catWeights {
			b.CatDown[cat] = int64(float64(b.Down) * w)
			b.CatUp[cat] = int64(float64(b.Up) * w)
		}
		// 设备分布
		for i, ip := range online {
			w := 1.0 / float64(i+2)
			up := int64(float64(b.Up) * w / 3)
			down := int64(float64(b.Down) * w / 3)
			b.ByDev[ip] = [2]int64{up, down}
		}
		agg.buckets = append(agg.buckets, b)
	}
	if len(agg.buckets) > agg.maxBuckets {
		agg.buckets = agg.buckets[len(agg.buckets)-agg.maxBuckets:]
	}
}

// prefillTrend 预填最近 60 个 2s 趋势点，让首屏曲线立即有形状。
func (d *Demo) prefillTrend(now int64) {
	agg := d.app.agg
	agg.mu.Lock()
	defer agg.mu.Unlock()
	agg.recent = agg.recent[:0]
	for i := 59; i >= 0; i-- {
		t := now - int64(i)*2
		down := int64(1.8e6 * (0.85 + 0.3*math.Sin(float64(t)/37)))
		up := down / 9
		agg.recent = append(agg.recent, TrendPoint{T: t, Up: up, Down: down})
	}
}

// seedEvents 预置几条典型事件。
func (d *Demo) seedEvents(now int64) {
	events := []Event{
		{
			Ts: now - 240, Severity: "warn", Type: "blacklist_domain",
			Title: "命中黑名单域名：pool.minexmr.com", Detail: "设备 192.168.1.40 访问矿池地址（pool.minexmr.com）",
			DeviceIP: "192.168.1.40", DeviceName: "VM-Ubuntu",
			Evidence: map[string]interface{}{"domain": "pool.minexmr.com", "category": "mining"},
		},
		{
			Ts: now - 420, Severity: "warn", Type: "port_scan",
			Title:    "疑似端口扫描：192.168.1.33",
			Detail:   "60 秒内对 28 个不同目的端口发起新连接",
			DeviceIP: "192.168.1.33", DeviceName: "Redmi-Turbo-3",
			Evidence: map[string]interface{}{"ports": 28, "windowSec": 60, "sample": []string{"23", "445", "3389", "1433", "5900"}},
		},
		{
			Ts: now - 900, Severity: "info", Type: "new_device",
			Title: "新设备入网：Nest-Thermostat", Detail: "发现设备 Nest-Thermostat（192.168.1.44）接入局域网",
			DeviceIP: "192.168.1.44", DeviceName: "Nest-Thermostat",
			Evidence: map[string]interface{}{"ip": "192.168.1.44"},
		},
		{
			Ts: now - 1500, Severity: "info", Type: "device_offline",
			Title: "设备离线：TP-LINK-Cam", Detail: "设备 TP-LINK-Cam（192.168.1.42）已离线",
			DeviceIP: "192.168.1.42", DeviceName: "TP-LINK-Cam",
			Evidence: map[string]interface{}{"ip": "192.168.1.42"},
		},
		{
			Ts: now - 1800, Severity: "info", Type: "bad_port",
			Title: "高危端口外联：192.168.1.40", Detail: "设备主动外联 45.77.10.20:445（高危端口）",
			DeviceIP: "192.168.1.40", DeviceName: "VM-Ubuntu",
			Evidence: map[string]interface{}{"port": 445, "dstIp": "45.77.10.20"},
		},
	}
	// 开源威胁情报命中示例（让安全页/告警详情一打开就有 kind/source 依据可看）
	if doms, ips := ThreatLists(); len(doms) > 0 && len(ips) > 0 {
		td := doms[0]
		events = append(events, Event{
			Ts: now - 360, Severity: threatSeverity(td.Kind), Type: "blacklist_domain",
			Title:    "命中高危域名：" + td.Target,
			Detail:   "命中" + threatKindLabel(td.Kind) + "（来源 " + td.Source + "）",
			DeviceIP: "192.168.1.40", DeviceName: "VM-Ubuntu",
			Evidence: map[string]interface{}{"domain": td.Target, "kind": string(td.Kind), "source": td.Source},
		})
		ti := ips[0]
		events = append(events, Event{
			Ts: now - 300, Severity: threatSeverity(ti.Kind), Type: "bad_ip",
			Title:    "连接高危 IP：" + ti.Target,
			Detail:   "命中" + threatKindLabel(ti.Kind) + "：" + ti.Source,
			DeviceIP: "192.168.1.44", DeviceName: "Nest-Thermostat",
			Evidence: map[string]interface{}{"ip": ti.Target, "kind": string(ti.Kind), "source": ti.Source},
		})
	}
	for i := len(events) - 1; i >= 0; i-- {
		d.app.store.AddEvent(events[i])
	}
}

// pickDomain 按权重随机挑一个域名。
func (d *Demo) pickDomain() demoDomain {
	total := 0
	for _, dom := range d.domains {
		total += dom.Weight
	}
	if total <= 0 {
		return d.domains[0]
	}
	r := d.rng.Intn(total)
	for _, dom := range d.domains {
		r -= dom.Weight
		if r < 0 {
			return dom
		}
	}
	return d.domains[0]
}

// onlineDevices 返回在线设备 IP。
func (d *Demo) onlineDevices() []string {
	out := make([]string, 0, len(d.devices))
	for _, dev := range d.devices {
		if dev.Online {
			out = append(out, dev.IP)
		}
	}
	return out
}

// ensureProxyExitFlows 生成"本机/docker0 经代理"的公网流量（只计入 proxy 链路，不显示为设备连接）。
// 对应真机上 passwall/xray 透明代理：入口连接 mark=1、src=172.31.0.1 等非用户设备。
func (d *Demo) ensureProxyExitFlows(now int64) {
	for _, e := range []struct {
		key     string
		dst     string
		domain  string
		downBps float64
	}{
		{"tcp-172.31.0.1-40101-142.250.72.14-443", "142.250.72.14", "google.com", 1_800_000},
		{"tcp-172.31.0.1-40102-23.45.64.20-443", "23.45.64.20", "steampowered.com", 900_000},
	} {
		if f, ok := d.flows[e.key]; ok && now <= f.Expire {
			continue
		}
		d.flows[e.key] = &demoFlow{
			Device: "172.31.0.1", DstIP: e.dst, Proto: "tcp", SPort: 40101, DPort: 443,
			Mark: 1, DownRate: e.downBps, UpRate: e.downBps / 15,
			Expire: now + 180, Domain: e.domain,
		}
	}
}

// Lines 生成当前时刻的合成 conntrack 快照文本（累计值，交给流水线做差分）。
// 直接生成 nf_conntrack 行格式，复用真实解析/差分路径。
func (d *Demo) Lines(now int64, intervalSec int64) string {
	if intervalSec <= 0 {
		intervalSec = 2
	}
	d.ensureProxyExitFlows(now)
	online := d.onlineDevices()
	perDev := map[string]int{}
	for _, f := range d.flows {
		perDev[f.Device]++
	}
	// 补充新连接
	for _, ip := range online {
		n := perDev[ip]
		if n < 1 || d.rng.Float64() < 0.18 {
			dom := d.pickDomain()
			dstIP := dom.IP
			proto := "tcp"
			dport := 443
			var mark uint32
			// 30%（zt 设备 80%）概率生成一条 zt/vpn/代理流向的连接，便于前端展示 path 列
			routeProb := 0.30
			if strings.HasPrefix(ip, "192.168.99.") {
				routeProb = 0.80
			}
			if d.rng.Float64() < routeProb {
				t := demoRouteTargets[d.rng.Intn(len(demoRouteTargets))]
				dstIP, mark, dom.Domain = t.IP, t.Mark, t.Domain
				if strings.HasPrefix(t.IP, "192.168.2.") {
					dport = 445 // 经 zt 访问远端 SMB
				}
			}
			if mark == 0 && d.rng.Float64() < 0.12 {
				proto, dport = "udp", 443
			}
			key := fmt.Sprintf("%s-%s-%d-%s-%d", proto, ip, 30000+d.rng.Intn(20000), dstIP, dport)
			if _, exists := d.flows[key]; !exists {
				downRate := float64(dom.Weight) * 9000 * (0.6 + d.rng.Float64())
				if dom.Domain == "bilibili.com" || dom.Domain == "douyin.com" {
					downRate *= 5
				}
				d.flows[key] = &demoFlow{
					Device: ip, DstIP: dstIP, Proto: proto,
					SPort: 30000 + d.rng.Intn(20000), DPort: dport, Mark: mark,
					DownRate: downRate, UpRate: downRate / 12,
					Expire: now + 30 + int64(d.rng.Intn(120)),
					Domain: dom.Domain,
				}
			}
		}
	}
	// 更新累计值并生成 conntrack 文本
	var b strings.Builder
	for key, f := range d.flows {
		if now > f.Expire {
			delete(d.flows, key)
			continue
		}
		f.Up += int64(f.UpRate * float64(intervalSec))
		f.Down += int64(f.DownRate * float64(intervalSec))
		b.WriteString("ipv4 2 ")
		b.WriteString(f.Proto)
		b.WriteString(" 6 61 ESTABLISHED src=")
		b.WriteString(f.Device)
		b.WriteString(" dst=")
		b.WriteString(f.DstIP)
		b.WriteString(" sport=")
		b.WriteString(strconv.Itoa(f.SPort))
		b.WriteString(" dport=")
		b.WriteString(strconv.Itoa(f.DPort))
		b.WriteString(" packets=1 bytes=")
		b.WriteString(strconv.FormatInt(f.Up, 10))
		b.WriteString(" src=")
		b.WriteString(f.DstIP)
		b.WriteString(" dst=")
		b.WriteString(f.Device)
		b.WriteString(" sport=")
		b.WriteString(strconv.Itoa(f.DPort))
		b.WriteString(" dport=")
		b.WriteString(strconv.Itoa(f.SPort))
		b.WriteString(" packets=1 bytes=")
		b.WriteString(strconv.FormatInt(f.Down, 10))
		b.WriteString(" mark=")
		b.WriteString(strconv.FormatUint(uint64(f.Mark), 10))
		b.WriteString(" use=1\n")
	}
	return b.String()
}

// Tick 每个采集周期调用：生成 DNS 查询/应答、偶尔产生事件。
func (d *Demo) Tick(now int64) {
	d.tickN++
	online := d.onlineDevices()
	if len(online) == 0 {
		return // 设备被清空（例如开关刚重新打开）时避免空切片取随机下标
	}
	// DNS 查询：让 QPS/域名统计有持续数据
	for i := 0; i < 2; i++ {
		ip := online[d.rng.Intn(len(online))]
		dom := d.pickDomain()
		d.app.dns.HandleRecord(dnsRecord{Kind: "query", QType: "A", Name: dom.Domain, SrcIP: ip}, now)
		if d.rng.Float64() < 0.7 {
			d.app.dns.HandleRecord(dnsRecord{Kind: "reply", Name: dom.Domain, IP: dom.IP}, now)
		}
	}
	// 命中黑名单域名（产生 blacklist_domain 事件）
	if d.tickN%25 == 3 {
		ip := online[d.rng.Intn(len(online))]
		d.app.dns.HandleRecord(dnsRecord{Kind: "query", QType: "A", Name: "pool.minexmr.com", SrcIP: ip}, now)
	}
	// 端口扫描事件
	if d.tickN == 6 {
		d.app.sec.OnFlow(FlowDelta{
			DeviceIP: "192.168.1.33", DstIP: "45.77.10.20", DPort: 3389, Proto: "tcp",
			New: true, State: "SYN_SENT",
		}, now, true)
		for _, p := range []int{23, 445, 1433, 5900, 6379, 11211} {
			d.app.sec.OnFlow(FlowDelta{
				DeviceIP: "192.168.1.33", DstIP: "45.77.10.20", DPort: p, Proto: "tcp",
				New: true, State: "SYN_SENT",
			}, now, true)
		}
	}
	// 新设备入网事件（演示）
	if now-d.lastNewDevice > 180 && d.tickN > 20 {
		d.lastNewDevice = now
		d.app.sec.OnNewDevice("192.168.1.45", "iPad-Air", now)
	}
}

// mustIP4 解析 IPv4（demo 内置合法地址，失败返回 0）。
func mustIP4(s string) uint32 {
	v, _ := parseIPv4Str(s)
	return v
}
