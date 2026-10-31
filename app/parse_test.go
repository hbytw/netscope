package main

// 关键纯函数的表格驱动单测：conntrack 解析 / dnsmasq 日志解析 / 差分 / 分类 / 策略时段。

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"
)

func TestParseConntrackLine(t *testing.T) {
	lan := NewConnEngine("192.168.1.0/24")
	cases := []struct {
		name      string
		line      string
		wantOK    bool
		wantProto string
		wantState string
		wantSrc   string
		wantDst   string
		wantOrig  int64
		wantReply int64
		// 方向归一化后的 key（LAN 侧为源）
		wantKey string
	}{
		{
			name:      "正常已建立连接（含双向字节）",
			line:      `ipv4     2 tcp      6 431999 ESTABLISHED src=192.168.1.31 dst=112.252.211.104 sport=11223 dport=17776 packets=10 bytes=520 src=112.252.211.104 dst=192.168.1.31 sport=17776 dport=11223 packets=20 bytes=20480 mark=0 zone=0 use=2`,
			wantOK:    true,
			wantProto: "tcp",
			wantState: "ESTABLISHED",
			wantSrc:   "192.168.1.31",
			wantDst:   "112.252.211.104",
			wantOrig:  520,
			wantReply: 20480,
			wantKey:   "tcp-192.168.1.31-11223-112.252.211.104-17776",
		},
		{
			name:      "UNREPLIED 只有原始方向",
			line:      `ipv4 2 tcp 6 61 SYN_SENT src=192.168.1.106 dst=112.252.211.104 sport=11223 dport=17776 packets=1 bytes=52 [UNREPLIED] src=112.252.211.104 dst=192.168.1.254 sport=17776 dport=11223 packets=0 bytes=0 mark=0 zone=0 use=2`,
			wantOK:    true,
			wantProto: "tcp",
			wantState: "SYN_SENT",
			wantSrc:   "192.168.1.106",
			wantDst:   "112.252.211.104",
			wantOrig:  52,
			wantReply: 0,
		},
		{
			name:      "反向连接（LAN 是回复方向源）",
			line:      `ipv4 2 udp 17 29 src=8.8.8.8 dst=192.168.1.32 sport=53 dport=5353 packets=2 bytes=120 src=192.168.1.32 dst=8.8.8.8 sport=5353 dport=53 packets=1 bytes=30 mark=0 use=1`,
			wantOK:    true,
			wantProto: "udp",
			wantSrc:   "8.8.8.8",
			wantDst:   "192.168.1.32",
			wantOrig:  120,
			wantReply: 30,
			wantKey:   "udp-192.168.1.32-5353-8.8.8.8-53",
		},
		{
			name:   "无关行",
			line:   "garbage line without fields",
			wantOK: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ent, ok := parseConntrackLine([]byte(tc.line))
			if ok != tc.wantOK {
				t.Fatalf("ok=%v want %v", ok, tc.wantOK)
			}
			if !ok {
				return
			}
			if ent.Proto != tc.wantProto || ent.State != tc.wantState {
				t.Errorf("proto=%q state=%q want %q/%q", ent.Proto, ent.State, tc.wantProto, tc.wantState)
			}
			if ip4String(ent.SrcIP) != tc.wantSrc || ip4String(ent.DstIP) != tc.wantDst {
				t.Errorf("src/dst = %s/%s want %s/%s",
					ip4String(ent.SrcIP), ip4String(ent.DstIP), tc.wantSrc, tc.wantDst)
			}
			if ent.OrigBytes != tc.wantOrig || ent.ReplyBytes != tc.wantReply {
				t.Errorf("bytes = %d/%d want %d/%d", ent.OrigBytes, ent.ReplyBytes, tc.wantOrig, tc.wantReply)
			}
			if tc.wantKey != "" {
				key, _, _, _, ok := lan.normalize(ent)
				if !ok {
					t.Fatalf("normalize 失败")
				}
				if got := flowID(key); got != tc.wantKey {
					t.Errorf("key=%q want %q", got, tc.wantKey)
				}
			}
		})
	}
}

func TestParseDNSLine(t *testing.T) {
	cases := []struct {
		name       string
		line       string
		wantOK     bool
		wantKind   string
		wantName   string
		wantIP     string
		wantSrc    string
		wantQType  string
		wantTarget string
	}{
		{
			name:      "查询行",
			line:      `Oct 31 16:25:38 dnsmasq[26278]: query[A] tracker.torrent.eu.org from 192.168.1.106`,
			wantOK:    true,
			wantKind:  "query",
			wantName:  "tracker.torrent.eu.org",
			wantSrc:   "192.168.1.106",
			wantQType: "A",
		},
		{
			name:     "应答行",
			line:     `Oct 31 16:25:38 dnsmasq[26278]: reply tracker.torrent.eu.org is 89.234.156.205`,
			wantOK:   true,
			wantKind: "reply",
			wantName: "tracker.torrent.eu.org",
			wantIP:   "89.234.156.205",
		},
		{
			name:     "缓存应答行（NXDOMAIN 无 IP）",
			line:     `Oct 31 16:25:38 dnsmasq[26278]: cached tracker.parrotlinux.org is NXDOMAIN`,
			wantOK:   true,
			wantKind: "cached",
			wantName: "tracker.parrotlinux.org",
			wantIP:   "",
		},
		{
			name:     "NODATA-IPv6 无 IP",
			line:     `Oct 31 16:25:38 dnsmasq[26278]: reply example.com is NODATA-IPv6`,
			wantOK:   true,
			wantKind: "reply",
			wantName: "example.com",
		},
		{
			name:      "TXT 查询（DNS 隧道检测用）",
			line:      `Oct 31 16:25:38 dnsmasq[26278]: query[TXT] aGVsbG8.dnslog.example.com from 192.168.1.33`,
			wantOK:    true,
			wantKind:  "query",
			wantName:  "aGVsbG8.dnslog.example.com",
			wantSrc:   "192.168.1.33",
			wantQType: "TXT",
		},
		{
			name:      "dnsmasq 2.88 带前缀的 IPv6 查询行（仍计入 QPS，客户端 IPv4 未知）",
			line:      `Oct 31 18:37:28 dnsmasq[9475]: 6727 fd16:93d2:e775:0:1168:4400:756a:986b/21229 query[AAAA] cn.voice.gcloudcs.com from fd16:93d2:e775:0:1168:4400:756a:986b`,
			wantOK:    true,
			wantKind:  "query",
			wantName:  "cn.voice.gcloudcs.com",
			wantSrc:   "",
			wantQType: "AAAA",
		},
		{
			name:      "dnsmasq 2.88 IPv4 客户端查询行",
			line:      `Oct 31 18:37:28 dnsmasq[9475]: 6801 192.168.1.31/5353 query[A] www.bilibili.com from 192.168.1.31`,
			wantOK:    true,
			wantKind:  "query",
			wantName:  "www.bilibili.com",
			wantSrc:   "192.168.1.31",
			wantQType: "A",
		},
		{
			name:     "dnsmasq 2.88 带前缀的应答行",
			line:     `Oct 31 18:37:28 dnsmasq[9475]: 6725 fd16:93d2:e775:0:1168:4400:756a:986b/65169 reply speed.ino.qq.com is 183.194.237.51`,
			wantOK:   true,
			wantKind: "reply",
			wantName: "speed.ino.qq.com",
			wantIP:   "183.194.237.51",
		},
		{
			name:       "dnsmasq 2.88 forwarded 行",
			line:       `Oct 31 18:37:28 dnsmasq[9475]: 6727 fd16:93d2:e775:0:1168:4400:756a:986b/21229 forwarded cn.voice.gcloudcs.com to 127.0.0.1#5333`,
			wantOK:     true,
			wantKind:   "forwarded",
			wantName:   "cn.voice.gcloudcs.com",
			wantTarget: "127.0.0.1#5333",
		},
		{
			name:   "dnsmasq 2.88 ipset 行应跳过",
			line:   `Oct 31 18:37:28 dnsmasq[9475]: 6726 fd16:93d2:e775:0:1168:4400:756a:986b/26008 ipset add passwall_chnroute 183.194.237.51 qq.com`,
			wantOK: false,
		},
		{
			name:       "旧版 forwarded 行",
			line:       `Oct 31 16:25:38 dnsmasq[26278]: forwarded example.com to 127.0.0.1#5333`,
			wantOK:     true,
			wantKind:   "forwarded",
			wantName:   "example.com",
			wantTarget: "127.0.0.1#5333",
		},
		{
			name:   "非 dnsmasq 行",
			line:   `random log line`,
			wantOK: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec, ok := parseDNSLine(tc.line)
			if ok != tc.wantOK {
				t.Fatalf("ok=%v want %v", ok, tc.wantOK)
			}
			if !ok {
				return
			}
			if rec.Kind != tc.wantKind || rec.Name != tc.wantName || rec.IP != tc.wantIP || rec.SrcIP != tc.wantSrc {
				t.Errorf("rec=%+v want kind=%s name=%s ip=%s src=%s",
					rec, tc.wantKind, tc.wantName, tc.wantIP, tc.wantSrc)
			}
			if tc.wantQType != "" && rec.QType != tc.wantQType {
				t.Errorf("qtype=%q want %q", rec.QType, tc.wantQType)
			}
			if tc.wantTarget != "" && rec.Target != tc.wantTarget {
				t.Errorf("target=%q want %q", rec.Target, tc.wantTarget)
			}
		})
	}
}

// TestDNSPrefixQPS dnsmasq 2.88 前缀格式的 query 必须计入 QPS 并建立 ip→domain 反查。
func TestDNSPrefixQPS(t *testing.T) {
	a := newTestApp(t, true)
	now := int64(1700000000)
	for i := 0; i < 5; i++ {
		line := fmt.Sprintf("Oct 31 18:37:28 dnsmasq[9475]: %d 192.168.1.31/5%03d query[A] vid%d.example.com from 192.168.1.31", 6700+i, i, i)
		rec, ok := parseDNSLine(line)
		if !ok || rec.Kind != "query" || rec.SrcIP != "192.168.1.31" {
			t.Fatalf("2.88 query 解析失败: %+v ok=%v", rec, ok)
		}
		a.dns.HandleRecord(rec, now)
	}
	if qps := a.dns.QPS(now); qps <= 0 {
		t.Errorf("QPS 应大于 0，实际 %.2f", qps)
	}
	reply := `Oct 31 18:37:28 dnsmasq[9475]: 6801 192.168.1.31/5353 reply www.bilibili.com is 112.252.211.104`
	rec, ok := parseDNSLine(reply)
	if !ok || rec.IP != "112.252.211.104" {
		t.Fatalf("2.88 reply 解析失败: %+v ok=%v", rec, ok)
	}
	a.dns.HandleRecord(rec, now)
	if domain, _, _, ok := a.dns.Attribute("112.252.211.104", now+10); !ok || domain != "bilibili.com" {
		t.Errorf("带前缀 reply 未建立 ip→domain 反查: %q ok=%v", domain, ok)
	}
}

func TestConnEngineDiff(t *testing.T) {
	eng := NewConnEngine("192.168.1.0/24")
	round1 := `ipv4 2 tcp 6 61 ESTABLISHED src=192.168.1.31 dst=1.2.3.4 sport=1000 dport=443 packets=1 bytes=100 src=1.2.3.4 dst=192.168.1.31 sport=443 dport=1000 packets=1 bytes=900 mark=0 use=1
ipv4 2 tcp 6 61 ESTABLISHED src=192.168.1.32 dst=5.6.7.8 sport=2000 dport=80 packets=1 bytes=50 src=5.6.7.8 dst=192.168.1.32 sport=80 dport=2000 packets=1 bytes=250 mark=0 use=1
ipv4 2 tcp 6 61 ESTABLISHED src=10.0.0.1 dst=9.9.9.9 sport=3000 dport=80 packets=1 bytes=10 src=9.9.9.9 dst=10.0.0.1 sport=80 dport=3000 packets=1 bytes=10 mark=0 use=1`

	// 首轮：baseline，只登记连接，不产生统计增量
	var firstDeltas []FlowDelta
	_, err := eng.Collect(strings.NewReader(round1), 1000, func(d FlowDelta) {
		firstDeltas = append(firstDeltas, d)
	}, func(string) {})
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if len(firstDeltas) != 2 {
		t.Fatalf("首轮应有 2 条 LAN 连接，实际 %d", len(firstDeltas))
	}
	for _, d := range firstDeltas {
		if !d.Baseline {
			t.Errorf("首轮应为 baseline: %+v", d)
		}
	}
	if len(eng.flows) != 2 {
		t.Fatalf("快照应只有 LAN 侧 2 条 flow，实际 %d", len(eng.flows))
	}

	// 第二轮：第一条 flow 字节增长 100/500，新增一条，第二条消失
	round2 := `ipv4 2 tcp 6 61 ESTABLISHED src=192.168.1.31 dst=1.2.3.4 sport=1000 dport=443 packets=2 bytes=200 src=1.2.3.4 dst=192.168.1.31 sport=443 dport=1000 packets=2 bytes=1400 mark=0 use=1
ipv4 2 tcp 6 61 ESTABLISHED src=192.168.1.33 dst=7.7.7.7 sport=4000 dport=53 packets=1 bytes=10 src=7.7.7.7 dst=192.168.1.33 sport=53 dport=4000 packets=1 bytes=20 mark=0 use=1`
	deltas := map[string]FlowDelta{}
	var gone []string
	_, err = eng.Collect(strings.NewReader(round2), 1002, func(d FlowDelta) {
		deltas[d.Key] = d
	}, func(k string) { gone = append(gone, k) })
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	d1, ok := deltas["tcp-192.168.1.31-1000-1.2.3.4-443"]
	if !ok {
		t.Fatalf("缺少第一条 flow 的增量: %v", deltas)
	}
	if d1.UpDelta != 100 || d1.DownDelta != 500 {
		t.Errorf("第一条增量 = %d/%d，期望 100/500", d1.UpDelta, d1.DownDelta)
	}
	if d1.New || d1.Baseline {
		t.Errorf("已有连接不应标记 New/Baseline: %+v", d1)
	}
	d3, ok := deltas["tcp-192.168.1.33-4000-7.7.7.7-53"]
	if !ok {
		t.Fatalf("缺少新 flow 的增量: %v", deltas)
	}
	if !d3.New || d3.UpDelta != 10 || d3.DownDelta != 20 {
		t.Errorf("新 flow 增量 = %+v，期望 New 且 10/20", d3)
	}
	if len(gone) != 1 || gone[0] != "tcp-192.168.1.32-2000-5.6.7.8-80" {
		t.Errorf("消失 flow = %v", gone)
	}
}

func TestClassifyHostAndPort(t *testing.T) {
	cases := []struct {
		host    string
		wantCat string
		wantBlo string
	}{
		{"www.bilibili.com", "video", ""},
		{"game.bilibili.com", "video", ""},
		{"lol.qq.com", "game", ""},
		{"qq.com", "social", ""},
		{"www.baidu.com", "web", ""},
		{"pan.baidu.com", "cloud", ""},
		{"mail.163.com", "mail", ""},
		{"www.163.com", "web", ""},
		{"github.com", "download", ""},
		{"pool.minexmr.com", "other", "mining"},
		{"www.bet365.com", "other", "gambling"},
		{"unknown-domain.example", "other", ""},
	}
	for _, tc := range cases {
		cat, _, _, block := classifyHost(tc.host)
		if cat != tc.wantCat || block != tc.wantBlo {
			t.Errorf("classifyHost(%q) = %s/%s，期望 %s/%s", tc.host, cat, block, tc.wantCat, tc.wantBlo)
		}
	}
	if got := classifyPort("tcp", 443); got != "web" {
		t.Errorf("443 分类 = %s，期望 web", got)
	}
	if got := classifyPort("udp", 53); got != "other" {
		t.Errorf("53 分类 = %s，期望 other", got)
	}
}

func TestParseDHCPAndNeigh(t *testing.T) {
	leases := parseDHCPLeases(strings.NewReader(
		"1761900000 90:f0:52:d5:9a:cb 192.168.1.31 MEIZU-Note-16 01:90:f0:52:d5:9a:cb\n" +
			"1761900000 aa:bb:cc:dd:ee:ff 192.168.1.32 * *\n" +
			"bad line\n"))
	if len(leases) != 2 {
		t.Fatalf("租约解析数量 = %d，期望 2", len(leases))
	}
	if leases[0].MAC != "90:f0:52:d5:9a:cb" || leases[0].Hostname != "MEIZU-Note-16" {
		t.Errorf("租约解析错误: %+v", leases[0])
	}
	if leases[1].Hostname != "" {
		t.Errorf("通配主机名应为空: %+v", leases[1])
	}
	neighs := parseNeigh("192.168.1.31 dev br-lan lladdr 90:f0:52:d5:9a:cb REACHABLE\n" +
		"192.168.1.42 dev br-lan FAILED\n" +
		"fe80::1 dev br-lan lladdr 00:11:22:33:44:55 router\n")
	if len(neighs) != 2 {
		t.Fatalf("邻居解析数量 = %d，期望 2（IPv6 跳过）", len(neighs))
	}
	if neighs[0].MAC != "90:f0:52:d5:9a:cb" || !isNeighOnline(neighs[0].State) {
		t.Errorf("邻居解析错误: %+v", neighs[0])
	}
	if isNeighOnline(neighs[1].State) {
		t.Errorf("FAILED 不应在线: %+v", neighs[1])
	}
}

func TestScheduleActive(t *testing.T) {
	// 2024-11-05 是周二
	tue := time.Date(2024, 11, 5, 23, 30, 0, 0, time.Local)
	p := Schedule{Days: []int{2}, Start: "22:00", End: "23:59"}
	if !scheduleActive(p, tue) {
		t.Errorf("周二 23:30 应命中 22:00-23:59 策略")
	}
	mon := time.Date(2024, 11, 4, 23, 30, 0, 0, time.Local)
	if scheduleActive(p, mon) {
		t.Errorf("周一不应命中 days=[2] 策略")
	}
	// 跨零点：22:00 - 06:00
	cross := Schedule{Start: "22:00", End: "06:00"}
	if !scheduleActive(cross, time.Date(2024, 11, 5, 1, 0, 0, 0, time.Local)) {
		t.Errorf("跨零点策略凌晨 1 点应命中")
	}
	if scheduleActive(cross, time.Date(2024, 11, 5, 12, 0, 0, 0, time.Local)) {
		t.Errorf("跨零点策略中午不应命中")
	}
	// 空时段视为全天
	if !scheduleActive(Schedule{}, tue) {
		t.Errorf("空时段应视为全天生效")
	}
}

func TestAggregateSeries(t *testing.T) {
	buckets := []*Bucket{
		newBucket(0),
		newBucket(60),
		newBucket(120),
	}
	for i, b := range buckets {
		b.Up = int64(100 * (i + 1))
		b.Down = int64(200 * (i + 1))
		b.CatDown["video"] = int64(50 * (i + 1))
	}
	// 30s 桶宽时 3 个原桶保持 3 个点
	series := aggregateSeries(buckets, 60)
	if len(series) != 3 {
		t.Fatalf("series 长度 = %d，期望 3", len(series))
	}
	// 120s 桶宽时前两个原桶合并为 1 个点
	series = aggregateSeries(buckets[:2], 120)
	if len(series) != 1 {
		t.Fatalf("120s 聚合长度 = %d，期望 1", len(series))
	}
	if series[0].ByCat["video"] != 150 {
		t.Errorf("byCat 汇聚 = %d，期望 150", series[0].ByCat["video"])
	}
	if series[0].Up != 300*8/120 {
		t.Errorf("up 速率 = %d，期望 %d", series[0].Up, 300*8/120)
	}
}

func TestParseMemInfoAndNetDev(t *testing.T) {
	total, avail, ok := parseMemInfo("MemTotal:        1888120 kB\nMemFree:          100000 kB\nMemAvailable:     777000 kB\n")
	if !ok || total != 1888120 || avail != 777000 {
		t.Errorf("meminfo 解析 = %d/%d/%v", total, avail, ok)
	}
	rx, tx, ok := parseNetDev("Inter-|   Receive                                                |  Transmit\n" +
		" face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n" +
		"br-lan: 1000 10 0 0 0 0 0 0 2000 20 0 0 0 0 0 0\n" +
		"eth0:   5000 50 0 0 0 0 0 0 6000 60 0 0 0 0 0 0\n")
	if !ok || rx != 1000 || tx != 2000 {
		t.Errorf("netdev 解析 = %d/%d/%v（应优先 br-lan）", rx, tx, ok)
	}
}

// ---------------- 两级开关单测 ----------------

// newTestApp 构造一个不启动任何协程的 App（dry-run，外部命令只记录不执行）。
func newTestApp(t *testing.T, demo bool) *App {
	t.Helper()
	cfg := &Config{
		DataDir: t.TempDir(),
		Demo:    demo,
		DryRun:  true,
		LANCIDR: "192.168.1.0/24",
	}
	a := NewApp(cfg)
	a.webFS = buildWebFS("")
	if err := a.store.Load(); err != nil {
		t.Fatalf("store.Load: %v", err)
	}
	return a
}

// TestDisabledCollectDoesNothing 总开关默认关闭时：采集不读文件、不产生任何数据。
func TestDisabledCollectDoesNothing(t *testing.T) {
	a := newTestApp(t, true)
	// 默认 Settings 全部开关 false
	s := a.store.Settings()
	if s.Enabled || s.Collect || s.DNSTap || s.DeviceControl || s.DomainBlock || s.Schedule || s.Alerts || s.History {
		t.Fatalf("默认开关应全部关闭: %+v", s)
	}
	for i := 0; i < 3; i++ {
		a.collectOnce()
	}
	if states := a.devs.States(); len(states) != 0 {
		t.Errorf("未启用时不应产生设备，实际 %d 台", len(states))
	}
	if buckets := a.agg.BucketsSince(0); len(buckets) != 0 {
		t.Errorf("未启用时不应产生流量桶，实际 %d 个", len(buckets))
	}
	if conns, total := a.agg.ConnList(10, "", ""); total != 0 || len(conns) != 0 {
		t.Errorf("未启用时不应有连接明细，实际 %d", total)
	}
}

// TestCollectOffNoTraffic 总开关开、采集开关关：仍不产生数据。
func TestCollectOffNoTraffic(t *testing.T) {
	a := newTestApp(t, true)
	a.store.UpdateSettings(func(s *Settings) {
		s.Enabled = true
		s.Collect = false
	})
	a.collectOnce()
	if len(a.devs.States()) != 0 {
		t.Errorf("采集关闭时不应产生设备")
	}
	if len(a.agg.BucketsSince(0)) != 0 {
		t.Errorf("采集关闭时不应产生流量桶")
	}
}

// TestCollectOnProducesData 采集开启后演示管线产生数据（复用真实差分路径）。
func TestCollectOnProducesData(t *testing.T) {
	a := newTestApp(t, true)
	a.store.UpdateSettings(func(s *Settings) {
		s.Enabled = true
		s.Collect = true
		s.Alerts = false
		s.History = true
	})
	a.collectOnce() // baseline：登记连接
	a.collectOnce() // 第二轮：产生增量
	_, total := a.agg.ConnList(10, "", "")
	if total == 0 {
		t.Errorf("采集开启后应产生连接明细")
	}
	rates := a.agg.LastRates()
	if rates.UpBps == 0 && rates.DownBps == 0 {
		t.Errorf("采集开启后应产生速率，实际 up=%d down=%d", rates.UpBps, rates.DownBps)
	}
	if len(a.agg.BucketsSince(0)) == 0 {
		t.Errorf("采集开启后应有分钟桶")
	}
}

// TestSwitchDependencies enabled=false 级联关闭全部子开关并撤销规则。
func TestSwitchDependencies(t *testing.T) {
	a := newTestApp(t, false)
	a.store.UpdateSettings(func(s *Settings) {
		s.Enabled = true
		s.Collect = true
		s.DNSTap = true
		s.DeviceControl = true
		s.DomainBlock = true
		s.Schedule = true
		s.Alerts = true
		s.History = true
	})
	off := false
	out, _, revoked, err := a.ApplySwitchPatch(settingsPatch{Enabled: &off})
	if err != nil {
		t.Fatalf("关闭总开关失败: %v", err)
	}
	if out.Enabled || out.Collect || out.DNSTap || out.DeviceControl ||
		out.DomainBlock || out.Schedule || out.Alerts || out.History {
		t.Errorf("enabled=false 应级联关闭全部子开关: %+v", out)
	}
	if len(revoked) == 0 {
		t.Errorf("关闭总开关应返回撤销动作列表")
	}
	if len(a.recordedCommands()) == 0 {
		t.Errorf("关闭总开关应尝试撤销已下发规则（dry-run 下应有命令记录）")
	}
}

// TestDNSTapEnableDryRun dry-run/demo 下开启 dnsTap 必须成功（命令只记录不执行）。
// 关键回归：conf 替换后的 `grep -c` 校验在 dry-run 下拿不到真实输出，不能误判为失败。
func TestDNSTapEnableDryRun(t *testing.T) {
	a := newTestApp(t, false) // cfg.DryRun = true
	a.store.UpdateSettings(func(s *Settings) { s.Enabled = true })
	on := true
	_, applied, _, err := a.ApplySwitchPatch(settingsPatch{DNSTap: &on})
	if err != nil {
		t.Fatalf("dry-run 下开启 dnsTap 不应失败: %v", err)
	}
	cmds := strings.Join(a.recordedCommands(), "\n")
	for _, want := range []string{
		"uci set dhcp.@dnsmasq[0].logqueries='1'",
		"log-facility=/tmp/guanlan/dnsmasq.log",
		"/etc/init.d/dnsmasq stop",
		"/etc/init.d/dnsmasq start",
	} {
		if !strings.Contains(cmds, want) {
			t.Errorf("开启 dnsTap 缺少命令: %s\n实际命令:\n%s", want, cmds)
		}
	}
	if !strings.Contains(strings.Join(applied, "\n"), "dnsmasq 日志旁挂") {
		t.Errorf("applied 应包含 DNS 旁挂启用描述: %v", applied)
	}
	if !a.store.Settings().DNSTap {
		t.Errorf("dnsTap 设置应为开启")
	}
}

// TestDNSTapDisableRevokes 关闭 dnsTap 必须执行 uci delete + stop/start（禁止 reload）。
func TestDNSTapDisableRevokes(t *testing.T) {
	a := newTestApp(t, false)
	a.store.UpdateSettings(func(s *Settings) {
		s.Enabled = true
		s.DNSTap = true
	})
	off := false
	_, applied, revoked, err := a.ApplySwitchPatch(settingsPatch{DNSTap: &off})
	if err != nil {
		t.Fatalf("关闭 dnsTap 失败: %v", err)
	}
	_ = applied
	cmds := strings.Join(a.recordedCommands(), "\n")
	for _, want := range []string{
		"uci delete dhcp.@dnsmasq[0].logqueries",
		"uci commit dhcp",
		"sed -i 's#^[[:space:]]*log-facility[[:space:]]*=.*#log-facility=/dev/null#' /etc/dnsmasq.conf",
		"/etc/init.d/dnsmasq stop",
		"/etc/init.d/dnsmasq start",
	} {
		if !strings.Contains(cmds, want) {
			t.Errorf("撤销 dnsTap 缺少命令: %s\n实际命令:\n%s", want, cmds)
		}
	}
	if strings.Contains(cmds, "uci delete dhcp.@dnsmasq[0].logfacility") {
		t.Errorf("不应再通过 UCI logfacility 撤销（改用 conf 文件还原），实际命令:\n%s", cmds)
	}
	if strings.Contains(cmds, "dnsmasq reload") {
		t.Errorf("禁止使用 dnsmasq reload，实际命令:\n%s", cmds)
	}
	if len(revoked) == 0 {
		t.Errorf("关闭 dnsTap 应返回撤销描述")
	}
	if a.store.Settings().DNSTap {
		t.Errorf("dnsTap 应已关闭")
	}
}

// TestToggleEndpointPatch 便捷开关参数校验。
func TestToggleEndpointPatch(t *testing.T) {
	p, err := togglePatch("enabled", false)
	if err != nil || p.Enabled == nil || *p.Enabled {
		t.Errorf("togglePatch enabled=false 解析错误: %+v %v", p, err)
	}
	if _, err := togglePatch("not_a_switch", true); err == nil {
		t.Errorf("未知开关 key 应报错")
	}
}

// TestTickRemovedDevices 增量帧通过 removed 字段告知消失设备，全量帧不需要。
func TestTickRemovedDevices(t *testing.T) {
	a := newTestApp(t, true)
	a.store.UpdateSettings(func(s *Settings) { s.Enabled = true; s.Collect = true })
	a.devs.Seed([]*DeviceState{{IP: "192.168.1.31", Hostname: "phone", Online: true, LastSeen: nowUnix()}})
	last := map[string]tickDevice{"192.168.1.99": {IP: "192.168.1.99"}}
	f := a.buildTick(nowUnix(), false, last)
	if len(f.Removed) != 1 || f.Removed[0] != "192.168.1.99" {
		t.Errorf("增量帧应带 removed=[192.168.1.99]，实际 %v", f.Removed)
	}
	if _, ok := last["192.168.1.99"]; ok {
		t.Errorf("removed 设备应从 last 快照中删除")
	}
	last2 := map[string]tickDevice{"192.168.1.98": {IP: "192.168.1.98"}}
	f2 := a.buildTick(nowUnix(), true, last2)
	if len(f2.Removed) != 0 {
		t.Errorf("全量帧不应输出 removed，实际 %v", f2.Removed)
	}
}

// TestBlockedDomainsUnion /api/enforce/dns 返回手工封堵 + 策略下发域名的并集。
func TestBlockedDomainsUnion(t *testing.T) {
	a := newTestApp(t, false)
	a.store.SetDomainBlocks([]string{"manual.com", "b.com"})
	a.enf.dnsDomains = map[string]bool{"policy.com": true, "b.com": true}
	got := a.enf.BlockedDomains()
	want := []string{"b.com", "manual.com", "policy.com"}
	if len(got) != len(want) {
		t.Fatalf("BlockedDomains = %v，期望 %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("BlockedDomains = %v，期望 %v", got, want)
			break
		}
	}
}

// ---------------- task-5：内网过滤 / 拓扑 / 封禁保护 ----------------

func TestProtectedIP(t *testing.T) {
	a := newTestApp(t, true) // demo 接口：192.168.1.254 / 192.168.99.1 / 网关 192.168.1.1
	protected := []string{
		"192.168.1.254", "192.168.99.1", "192.168.1.1", // 本机 + 网关
		"127.0.0.1", "169.254.10.20", // 回环 + 链路本地
		"192.168.1.0", "192.168.1.255", "192.168.99.0", "192.168.99.255", // 网络/广播
	}
	for _, ip := range protected {
		if !a.isProtectedIP(ip) {
			t.Errorf("%s 应受保护（禁止封禁）", ip)
		}
	}
	for _, ip := range []string{"192.168.1.31", "192.168.99.94", "8.8.8.8", "112.252.211.104"} {
		if a.isProtectedIP(ip) {
			t.Errorf("%s 不应受保护", ip)
		}
	}
}

func TestBlockProtectionAndList(t *testing.T) {
	a := newTestApp(t, true)
	a.store.UpdateSettings(func(s *Settings) {
		s.Enabled = true
		s.Collect = true
		s.DeviceControl = true
	})
	// P0：本机/网关禁止封禁/限速
	if _, err := a.enf.SetBlocked("192.168.1.254", true); !errors.Is(err, errProtectedIP) {
		t.Errorf("封禁本机应返回 errProtectedIP，实际 %v", err)
	}
	if _, err := a.enf.SetBlocked("192.168.1.1", true); !errors.Is(err, errProtectedIP) {
		t.Errorf("封禁网关应返回 errProtectedIP，实际 %v", err)
	}
	if _, err := a.enf.BlockDst("192.168.1.254"); !errors.Is(err, errProtectedIP) {
		t.Errorf("封禁本机目标 IP 应返回 errProtectedIP，实际 %v", err)
	}
	if _, err := a.enf.SetLimit("192.168.1.254", 1000, 0); !errors.Is(err, errProtectedIP) {
		t.Errorf("限速本机应返回 errProtectedIP，实际 %v", err)
	}
	// 正常设备封禁 + 目标封禁，进入封禁列表
	if _, err := a.enf.SetBlocked("192.168.1.31", true); err != nil {
		t.Fatalf("封禁普通设备失败: %v", err)
	}
	a.store.UpdateDeviceMeta("192.168.1.31", func(m *DeviceMeta) {
		m.Blocked = true
		m.BlockedAt = 1700000000
	})
	if _, err := a.enf.BlockDst("45.77.10.20"); err != nil {
		t.Fatalf("封禁目标 IP 失败: %v", err)
	}
	if _, err := a.enf.SetLimit("192.168.1.32", 2000, 500); err != nil {
		t.Fatalf("限速普通设备失败: %v", err)
	}
	blocks := a.enf.Blocks()
	byType := map[string]BlockEntry{}
	for _, b := range blocks {
		byType[b.Type] = b
	}
	if b, ok := byType["device"]; !ok || b.IP != "192.168.1.31" || b.Reason != "手动断网" || b.At != 1700000000 {
		t.Errorf("device 封禁记录错误: %+v", blocks)
	}
	if b, ok := byType["dst"]; !ok || b.IP != "45.77.10.20" {
		t.Errorf("dst 封禁记录错误: %+v", blocks)
	}
	if b, ok := byType["limit"]; !ok || b.IP != "192.168.1.32" || b.DownKbps != 2000 || b.UpKbps != 500 {
		t.Errorf("limit 记录错误: %+v", blocks)
	}
	// dst 封禁持久化到 store
	if _, ok := a.store.DstBlocks()["45.77.10.20"]; !ok {
		t.Errorf("目标封禁应持久化到 store")
	}
	// 解封
	if _, err := a.enf.SetBlocked("192.168.1.31", false); err != nil {
		t.Errorf("解封设备失败: %v", err)
	}
	if _, err := a.enf.UnblockDst("45.77.10.20"); err != nil {
		t.Errorf("解封目标 IP 失败: %v", err)
	}
	if _, err := a.enf.SetLimit("192.168.1.32", 0, 0); err != nil {
		t.Errorf("取消限速失败: %v", err)
	}
	if len(a.enf.Blocks()) != 0 {
		t.Errorf("全部解封后封禁列表应为空: %+v", a.enf.Blocks())
	}
	if _, ok := a.store.DstBlocks()["45.77.10.20"]; ok {
		t.Errorf("解封后 store 不应保留 dst 记录")
	}
}

func TestParseNeighDevAndIfaceKind(t *testing.T) {
	neighs := parseNeigh("192.168.1.31 dev br-lan lladdr 90:f0:52:d5:9a:cb REACHABLE\n" +
		"192.168.99.94 dev zt6vwy3rne lladdr 24:db:ac:00:00:5e REACHABLE\n" +
		"1.197.2.218 dev docker0 FAILED\n" +
		"192.168.1.42 dev br-lan FAILED\n")
	if len(neighs) != 4 {
		t.Fatalf("邻居解析数量 = %d，期望 4", len(neighs))
	}
	if neighs[0].Dev != "br-lan" || neighs[1].Dev != "zt6vwy3rne" || neighs[2].Dev != "docker0" {
		t.Errorf("dev 字段解析错误: %+v", neighs)
	}
	cases := []struct {
		name     string
		network  string
		internal bool
	}{
		{"br-lan", "lan", true},
		{"zt6vwy3rne", "zerotier", true},
		{"tun0", "vpn", true},
		{"wg0", "vpn", true},
		{"tailscale0", "vpn", true},
		{"ppp0", "vpn", true},
		{"docker0", "docker", false},
		{"eth0", "other", false},
	}
	for _, tc := range cases {
		net, internal := ifaceKind(tc.name)
		if net != tc.network || internal != tc.internal {
			t.Errorf("ifaceKind(%s) = %s/%v，期望 %s/%v", tc.name, net, internal, tc.network, tc.internal)
		}
	}
}

func TestParseIPBrAddrAndRoutes(t *testing.T) {
	ifaces := parseIPBrAddr(
		"lo               UNKNOWN        127.0.0.1/8 ::1/128\n" +
			"br-lan           UP             192.168.1.254/24 fe80::1/64\n" +
			"zt6vwy3rne       UP             192.168.99.1/24 fe80::2/64\n" +
			"docker0          DOWN           172.17.0.1/16\n" +
			"eth0             UP             10.0.0.2/24\n")
	if len(ifaces) != 4 {
		t.Fatalf("接口解析数量 = %d，期望 4（跳过 lo）", len(ifaces))
	}
	byName := map[string]ifaceInfo{}
	for _, f := range ifaces {
		byName[f.Name] = f
	}
	if f := byName["br-lan"]; f.CIDR != "192.168.1.254/24" || f.Network != "lan" || !f.Internal || !f.Up {
		t.Errorf("br-lan 解析错误: %+v", f)
	}
	if f := byName["zt6vwy3rne"]; f.Network != "zerotier" || !f.Internal {
		t.Errorf("zt 解析错误: %+v", f)
	}
	if f := byName["docker0"]; f.Network != "docker" || f.Internal || f.Up {
		t.Errorf("docker0 解析错误: %+v", f)
	}
	routes := []string{
		"default via 192.168.1.1 dev br-lan proto static",
		"192.168.99.0/24 dev zt6vwy3rne proto kernel scope link",
	}
	if dev, ok := parseDefaultRoute(routes); !ok || dev != "br-lan" {
		t.Errorf("默认路由解析错误: %q %v", dev, ok)
	}
	if gw := parseDefaultGateway(routes); gw != "192.168.1.1" {
		t.Errorf("默认网关 = %q，期望 192.168.1.1", gw)
	}
}

func TestParseProxyOutput(t *testing.T) {
	clashSS := "LISTEN 0 4096 127.0.0.1:7890 0.0.0.0:* users:((\"clash\",pid=1234,fd=7))\n"
	if !parseProxyOutput(clashSS) {
		t.Errorf("clash 监听应识别为代理")
	}
	netstat := "tcp 0 0 0.0.0.0:1080 0.0.0.0:* LISTEN 5678/xray\n"
	if !parseProxyOutput(netstat) {
		t.Errorf("1080 监听应识别为代理")
	}
	plain := "tcp 0 0 0.0.0.0:22 0.0.0.0:* LISTEN 1/dropbear\n"
	if parseProxyOutput(plain) {
		t.Errorf("普通 ssh 监听不应识别为代理")
	}
}

func TestReverseLookupFallback(t *testing.T) {
	a := newTestApp(t, true)
	now := int64(1700000000)
	a.dns.HandleRecord(dnsRecord{Kind: "query", QType: "A", Name: "www.bilibili.com", SrcIP: "192.168.1.31"}, now)
	a.dns.HandleRecord(dnsRecord{Kind: "reply", Name: "www.bilibili.com", IP: "112.252.211.104"}, now)
	if _, _, _, ok := a.dns.Attribute("112.252.211.104", now+60); !ok {
		t.Fatalf("短 TTL 内应能归因")
	}
	// 超过 30min 短 TTL，但仍在 6h 长 TTL 内：ReverseLookup 回退应命中
	domain, cat, _, ok := a.dns.ReverseLookup("112.252.211.104", now+31*60)
	if !ok || domain != "bilibili.com" || cat != "video" {
		t.Errorf("长 TTL 回退失败: domain=%q cat=%q ok=%v", domain, cat, ok)
	}
	// 超过 6h：彻底过期
	if _, _, _, ok := a.dns.ReverseLookup("112.252.211.104", now+7*3600); ok {
		t.Errorf("6h 后不应再归因")
	}
}

func TestTopologyDemo(t *testing.T) {
	a := newTestApp(t, true)
	a.store.UpdateSettings(func(s *Settings) {
		s.Enabled = true
		s.Collect = true
	})
	topo := a.buildTopology()
	nodeIDs := map[string]topologyNode{}
	for _, n := range topo.Nodes {
		nodeIDs[n.ID] = n
	}
	for _, want := range []string{"br-lan", "zt6vwy3rne", "internet", "proxy"} {
		if _, ok := nodeIDs[want]; !ok {
			t.Errorf("拓扑缺少节点 %s: %+v", want, topo.Nodes)
		}
	}
	if n := nodeIDs["br-lan"]; n.Type != "lan" || n.CIDR != "192.168.1.0/24" {
		t.Errorf("br-lan 节点错误（cidr 应为网段）: %+v", n)
	}
	if n := nodeIDs["zt6vwy3rne"]; n.Type != "zerotier" || n.CIDR != "192.168.99.0/24" {
		t.Errorf("zt 节点类型/cidr 错误: %+v", n)
	}
	if !nodeIDs["proxy"].Up {
		t.Errorf("demo 代理节点应为 up")
	}
	linkKinds := map[string]bool{}
	for _, l := range topo.Links {
		linkKinds[l.From+"->"+l.To+":"+l.Kind] = true
	}
	for _, want := range []string{"br-lan->internet:direct", "br-lan->proxy:proxy", "br-lan->zt6vwy3rne:zt"} {
		if !linkKinds[want] {
			t.Errorf("拓扑缺少链路 %s，实际 %+v", want, topo.Links)
		}
	}
}

// TestDstBlocksPersistence 封禁记录（设备断网时间 + 目标 IP）重启不丢。
func TestDstBlocksPersistence(t *testing.T) {
	dir := t.TempDir()
	s1 := NewStore(dir)
	if err := s1.Load(); err != nil {
		t.Fatalf("store load: %v", err)
	}
	s1.PutDstBlock("45.77.10.20", 1700000000)
	s1.UpdateDeviceMeta("192.168.1.31", func(m *DeviceMeta) {
		m.Blocked = true
		m.BlockedAt = 1700000001
	})
	if err := s1.Save(); err != nil {
		t.Fatalf("store save: %v", err)
	}
	s2 := NewStore(dir)
	if err := s2.Load(); err != nil {
		t.Fatalf("store reload: %v", err)
	}
	if at := s2.DstBlocks()["45.77.10.20"]; at != 1700000000 {
		t.Errorf("dstBlocks 持久化失败: %v", s2.DstBlocks())
	}
	if m := s2.DeviceMeta("192.168.1.31"); !m.Blocked || m.BlockedAt != 1700000001 {
		t.Errorf("DeviceMeta.BlockedAt 持久化失败: %+v", m)
	}
}

// TestRestoreFiltersProtected 启动恢复时必须拦下历史误封的本机/网关记录并清理。
func TestRestoreFiltersProtected(t *testing.T) {
	a := newTestApp(t, true)
	a.store.UpdateSettings(func(s *Settings) {
		s.Enabled = true
		s.Collect = true
		s.DeviceControl = true
	})
	a.store.UpdateDeviceMeta("192.168.1.254", func(m *DeviceMeta) {
		m.Blocked = true
		m.BlockedAt = 1700000002
	})
	a.store.PutDstBlock("192.168.1.1", 1700000003)
	a.enf.RestoreFromStore()
	if a.enf.IsBlocked("192.168.1.254") {
		t.Errorf("受保护的本机 IP 不应从 store 恢复到断网列表")
	}
	if a.enf.IsDstBlocked("192.168.1.1") {
		t.Errorf("受保护的网关不应恢复到目标封禁列表")
	}
	if m := a.store.DeviceMeta("192.168.1.254"); m.Blocked || m.BlockedAt != 0 {
		t.Errorf("受保护 IP 的历史断网记录应被清理: %+v", m)
	}
	if _, ok := a.store.DstBlocks()["192.168.1.1"]; ok {
		t.Errorf("受保护网关的历史封禁记录应被清理")
	}
}

// ---------------- task-5 追加：多网段设备识别与流向 ----------------

// testMultiNetEngine 构造 LAN + ZeroTier + VPN 多网段引擎。
func testMultiNetEngine() *ConnEngine {
	e := NewConnEngine("192.168.1.0/24")
	device := []ipNet{}
	for _, s := range []struct{ cidr, kind, iface string }{
		{"192.168.1.0/24", "lan", "br-lan"},
		{"192.168.99.0/24", "zerotier", "zt6vwy3rne"},
		{"10.8.0.0/24", "vpn", "tun0"},
	} {
		if n, ok := ipNetFromCIDR(s.cidr, s.kind, s.iface); ok {
			device = append(device, n)
		}
	}
	route := []ipNet{}
	for _, s := range []struct{ cidr, kind, iface string }{
		{"192.168.99.0/24", "zerotier", "zt6vwy3rne"},
		{"10.0.2.0/24", "zerotier", "zt6vwy3rne"},
		{"10.10.10.0/24", "zerotier", "zt6vwy3rne"},
		{"192.168.2.0/24", "zerotier", "zt6vwy3rne"},
		{"10.8.0.0/24", "vpn", "tun0"},
	} {
		if n, ok := ipNetFromCIDR(s.cidr, s.kind, s.iface); ok {
			route = append(route, n)
		}
	}
	e.SetNets(device, route)
	return e
}

// collectSingle 对单行 conntrack 做一次非 baseline 差分，返回 FlowDelta。
func collectSingle(t *testing.T, e *ConnEngine, line string) (FlowDelta, bool) {
	t.Helper()
	e.baseline = false
	var got FlowDelta
	found := false
	_, err := e.Collect(strings.NewReader(line), 1000, func(d FlowDelta) {
		got = d
		found = true
	}, func(string) {})
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	return got, found
}

func TestConnMultiNet(t *testing.T) {
	cases := []struct {
		name      string
		line      string
		wantDev   string
		wantPath  string
		wantIface string
		wantKey   string
	}{
		{
			name:      "ZeroTier 设备 → zt 远端网段",
			line:      `ipv4 2 tcp 6 61 ESTABLISHED src=192.168.99.16 dst=10.0.2.5 sport=5000 dport=445 packets=1 bytes=100 src=10.0.2.5 dst=192.168.99.16 sport=445 dport=5000 packets=1 bytes=900 mark=0 use=1`,
			wantDev:   "192.168.99.16",
			wantPath:  "zerotier",
			wantIface: "zt6vwy3rne",
			wantKey:   "tcp-192.168.99.16-5000-10.0.2.5-445",
		},
		{
			name:      "ZeroTier 远端 LAN 网段",
			line:      `ipv4 2 tcp 6 61 ESTABLISHED src=192.168.99.16 dst=192.168.2.20 sport=5001 dport=445 packets=1 bytes=10 src=192.168.2.20 dst=192.168.99.16 sport=445 dport=5001 packets=1 bytes=90 mark=0 use=1`,
			wantDev:   "192.168.99.16",
			wantPath:  "zerotier",
			wantIface: "zt6vwy3rne",
			wantKey:   "tcp-192.168.99.16-5001-192.168.2.20-445",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d, ok := collectSingle(t, testMultiNetEngine(), tc.line)
			if !ok {
				t.Fatalf("zt 网段连接被丢弃，Path=%q", d.Path)
			}
			if d.DeviceIP != tc.wantDev || d.Path != tc.wantPath || d.Iface != tc.wantIface {
				t.Errorf("delta = dev=%s path=%s iface=%s，期望 %s/%s/%s",
					d.DeviceIP, d.Path, d.Iface, tc.wantDev, tc.wantPath, tc.wantIface)
			}
			if d.Key != tc.wantKey {
				t.Errorf("key = %q，期望 %q", d.Key, tc.wantKey)
			}
		})
	}
}

func TestConnVPNPath(t *testing.T) {
	line := `ipv4 2 tcp 6 61 ESTABLISHED src=192.168.1.31 dst=10.8.0.20 sport=4000 dport=443 packets=1 bytes=20 src=10.8.0.20 dst=192.168.1.31 sport=443 dport=4000 packets=1 bytes=200 mark=0 use=1`
	d, ok := collectSingle(t, testMultiNetEngine(), line)
	if !ok {
		t.Fatalf("VPN 网段连接被丢弃")
	}
	if d.Path != "vpn" || d.Iface != "br-lan" {
		t.Errorf("vpn path = %q iface=%q，期望 vpn/br-lan", d.Path, d.Iface)
	}
}

func TestConnProxyPath(t *testing.T) {
	cases := []struct {
		name     string
		line     string
		wantPath string
	}{
		{
			name:     "conntrack mark>0 走代理",
			line:     `ipv4 2 tcp 6 61 ESTABLISHED src=192.168.1.31 dst=142.250.72.14 sport=4000 dport=443 packets=1 bytes=20 src=142.250.72.14 dst=192.168.1.31 sport=443 dport=4000 packets=1 bytes=200 mark=1 use=1`,
			wantPath: "proxy",
		},
		{
			name:     "代理端口 7890 走代理",
			line:     `ipv4 2 tcp 6 61 ESTABLISHED src=192.168.1.31 dst=8.8.8.8 sport=4001 dport=7890 packets=1 bytes=20 src=8.8.8.8 dst=192.168.1.31 sport=7890 dport=4001 packets=1 bytes=200 mark=0 use=1`,
			wantPath: "proxy",
		},
		{
			name:     "普通公网直连",
			line:     `ipv4 2 tcp 6 61 ESTABLISHED src=192.168.1.31 dst=8.8.8.8 sport=4002 dport=443 packets=1 bytes=20 src=8.8.8.8 dst=192.168.1.31 sport=443 dport=4002 packets=1 bytes=200 mark=0 use=1`,
			wantPath: "direct",
		},
		{
			name:     "内网互访",
			line:     `ipv4 2 tcp 6 61 ESTABLISHED src=192.168.1.31 dst=192.168.1.32 sport=4003 dport=445 packets=1 bytes=20 src=192.168.1.32 dst=192.168.1.31 sport=445 dport=4003 packets=1 bytes=200 mark=0 use=1`,
			wantPath: "lan",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d, ok := collectSingle(t, testMultiNetEngine(), tc.line)
			if !ok {
				t.Fatalf("连接被丢弃: %s", tc.name)
			}
			if d.Path != tc.wantPath {
				t.Errorf("path = %q，期望 %q", d.Path, tc.wantPath)
			}
		})
	}
}

func TestParseConntrackMark(t *testing.T) {
	line := `ipv4 2 tcp 6 61 ESTABLISHED src=192.168.1.31 dst=1.2.3.4 sport=1111 dport=443 packets=1 bytes=10 src=1.2.3.4 dst=192.168.1.31 sport=443 dport=1111 packets=1 bytes=20 mark=2 use=1`
	ent, ok := parseConntrackLine([]byte(line))
	if !ok || ent.Mark != 2 {
		t.Errorf("mark 解析失败: mark=%d ok=%v", ent.Mark, ok)
	}
}

// ---------------- 告警白名单 ----------------

func TestWhitelistSuppress(t *testing.T) {
	a := newTestApp(t, true)
	a.store.ClearEvents()
	now := int64(1700000000)
	// 未加白：事件正常产生
	if ok := a.sec.emit(Event{Type: "port_scan", Severity: "warn", Ts: now, DeviceIP: "192.168.1.84", Title: "疑似端口扫描"}); !ok {
		t.Fatalf("未加白时事件应产生")
	}
	// 加白同 type+device：不再产生
	a.store.PutWhitelist("port_scan", "192.168.1.84", "已知扫描器", now)
	a.sec.RestoreWhitelist()
	if ok := a.sec.emit(Event{Type: "port_scan", Severity: "warn", Ts: now + 1000, DeviceIP: "192.168.1.84", Title: "疑似端口扫描"}); ok {
		t.Errorf("加白后同 type+device 不应再产生事件")
	}
	// 同 type 其它设备仍产生
	if ok := a.sec.emit(Event{Type: "port_scan", Severity: "warn", Ts: now + 2000, DeviceIP: "192.168.1.31", Title: "疑似端口扫描"}); !ok {
		t.Errorf("同 type 其它设备应照常产生事件")
	}
	// 域名类事件：按 evidence.domain 加白
	a.store.PutWhitelist("blacklist_domain", "pornhub.com", "误报", now)
	a.sec.RestoreWhitelist()
	if ok := a.sec.emit(Event{
		Type: "blacklist_domain", Severity: "warn", Ts: now + 3000, DeviceIP: "192.168.1.40",
		Title:    "命中黑名单域名：pornhub.com",
		Evidence: map[string]interface{}{"domain": "pornhub.com"},
	}); ok {
		t.Errorf("加白域名后同域名事件不应产生")
	}
	if ok := a.sec.emit(Event{
		Type: "blacklist_domain", Severity: "warn", Ts: now + 4000, DeviceIP: "192.168.1.40",
		Title:    "命中黑名单域名：xvideos.com",
		Evidence: map[string]interface{}{"domain": "xvideos.com"},
	}); !ok {
		t.Errorf("未加白域名应照常产生事件")
	}
}

func TestWhitelistPersist(t *testing.T) {
	dir := t.TempDir()
	s1 := NewStore(dir)
	if err := s1.Load(); err != nil {
		t.Fatalf("store load: %v", err)
	}
	item := s1.PutWhitelist("port_scan", "192.168.1.84", "已知扫描器", 1700000000)
	if item.ID == "" || item.Type != "port_scan" || item.Target != "192.168.1.84" || item.At != 1700000000 {
		t.Fatalf("白名单项字段错误: %+v", item)
	}
	// 幂等：重复加白返回同一 ID，不新增
	again := s1.PutWhitelist("port_scan", "192.168.1.84", "重复", 1700000001)
	if again.ID != item.ID {
		t.Errorf("重复加白应幂等，ID %q != %q", again.ID, item.ID)
	}
	if len(s1.Whitelist()) != 1 {
		t.Errorf("重复加白不应新增项: %d", len(s1.Whitelist()))
	}
	if err := s1.Save(); err != nil {
		t.Fatalf("store save: %v", err)
	}
	s2 := NewStore(dir)
	if err := s2.Load(); err != nil {
		t.Fatalf("store reload: %v", err)
	}
	list := s2.Whitelist()
	if len(list) != 1 || list[0].ID != item.ID || list[0].Note != "已知扫描器" {
		t.Errorf("白名单持久化失败: %+v", list)
	}
	if !s2.DeleteWhitelist(item.ID) {
		t.Errorf("删除白名单失败")
	}
	if len(s2.Whitelist()) != 0 {
		t.Errorf("删除后应为空")
	}
}

// TestConnProxyNonDevice docker0/本机 mark=1 公网连接：只计入 proxy 链路，不进连接表。
func TestConnProxyNonDevice(t *testing.T) {
	e := testMultiNetEngine()
	line := `ipv4 2 tcp 6 61 ESTABLISHED src=172.31.0.1 dst=8.8.8.8 sport=50000 dport=443 packets=1 bytes=100 src=8.8.8.8 dst=172.31.0.1 sport=443 dport=50000 packets=1 bytes=900 mark=1 use=1`
	d, ok := collectSingle(t, e, line)
	if !ok {
		t.Fatalf("docker0 mark=1 公网连接应被计入 proxy")
	}
	if d.DeviceIP != "" || d.Path != "proxy" {
		t.Errorf("非设备代理流量应 DeviceIP 为空、path=proxy，实际 dev=%q path=%q", d.DeviceIP, d.Path)
	}
	// mark=0 的非设备公网连接（xray 出口）不参与统计，避免虚增 direct
	e2 := testMultiNetEngine()
	line0 := `ipv4 2 tcp 6 61 ESTABLISHED src=172.31.0.1 dst=8.8.8.8 sport=50001 dport=443 packets=1 bytes=10 src=8.8.8.8 dst=172.31.0.1 sport=443 dport=50001 packets=1 bytes=90 mark=0 use=1`
	if _, ok := collectSingle(t, e2, line0); ok {
		t.Errorf("非设备 mark=0 出口连接不应产生链路增量")
	}
}

// TestTopoProxySplitByMark 拓扑 proxy/direct 链路按 path 聚合，节点 rx/tx 与链路一致。
func TestTopoProxySplitByMark(t *testing.T) {
	a := newTestApp(t, true)
	a.store.UpdateSettings(func(s *Settings) {
		s.Enabled = true
		s.Collect = true
	})
	now := nowUnix()
	a.agg.AddPathBytes("proxy", 300000, 900000) // bytes in interval
	a.agg.AddPathBytes("direct", 60000, 120000)
	a.agg.Tick(120, now) // 发布速率：proxy 20Kbps/60Kbps，direct 4Kbps/8Kbps
	topo := a.buildTopology()
	var proxyLink, directLink *topologyLink
	for i := range topo.Links {
		switch topo.Links[i].Kind {
		case "proxy":
			proxyLink = &topo.Links[i]
		case "direct":
			directLink = &topo.Links[i]
		}
	}
	if proxyLink == nil || directLink == nil {
		t.Fatalf("拓扑缺少 direct/proxy 链路: %+v", topo.Links)
	}
	if proxyLink.UpBps <= 0 || proxyLink.DownBps <= 0 {
		t.Errorf("proxy 链路流量应 >0（按 mark 统计），实际 up=%d down=%d", proxyLink.UpBps, proxyLink.DownBps)
	}
	if directLink.UpBps <= 0 || directLink.DownBps <= 0 {
		t.Errorf("direct 链路流量应 >0，实际 up=%d down=%d", directLink.UpBps, directLink.DownBps)
	}
	// proxy 节点 rx/tx 必须与链路一致
	var proxyNode *topologyNode
	for i := range topo.Nodes {
		if topo.Nodes[i].ID == "proxy" {
			proxyNode = &topo.Nodes[i]
		}
	}
	if proxyNode == nil {
		t.Fatalf("拓扑缺少 proxy 节点")
	}
	if proxyNode.RxBps != proxyLink.UpBps || proxyNode.TxBps != proxyLink.DownBps {
		t.Errorf("proxy 节点 rx/tx 应与链路一致: node=%d/%d link=%d/%d",
			proxyNode.RxBps, proxyNode.TxBps, proxyLink.UpBps, proxyLink.DownBps)
	}
}

// ---------------- CDN 域名库 / 设备最近 DNS 归因 ----------------

func TestClassifyCDN(t *testing.T) {
	cases := []struct {
		host string
		cat  string
	}{
		{"douyin-vod.e.cdn.chinamobile.com", "video"},
		{"kunluncan.com", "video"},
		{"lf-sourcecdn-tos.bytegecko.com", "video"},
		{"cdn.aliyuncsslb.com", "video"},
		{"x.bsclink.cn", "video"},
		{"cdn.cdnhwc2.com", "video"},
		{"mi.com", "web"},
		{"icbc.com.cn", "web"},
		{"wps.cn", "web"},
	}
	for _, tc := range cases {
		cat, _, _, _ := classifyHost(tc.host)
		if cat != tc.cat {
			t.Errorf("classifyHost(%s) = %s，期望 %s", tc.host, cat, tc.cat)
		}
	}
	if len(Categories) != 8 {
		t.Errorf("仍必须固定 8 个分类")
	}
}

func TestClassifyPortProxy(t *testing.T) {
	for _, p := range []int{16384, 21180, 51045, 4433} {
		if cat := classifyPort("tcp", p); cat != "web" {
			t.Errorf("classifyPort(%d) = %s，期望 web", p, cat)
		}
	}
}

func TestDevRecentAttribution(t *testing.T) {
	a := newTestApp(t, true)
	now := nowUnix()
	// 设备 192.168.1.106 查询 www.youtube.com（真机走代理时 DNS 日志有此 query）
	a.dns.HandleRecord(dnsRecord{Kind: "query", QType: "A", Name: "www.youtube.com", SrcIP: "192.168.1.106"}, now)
	// 连接 dst 是代理服务器 IP（无法按 IP 归因），path=proxy
	key := "tcp-192.168.1.106-51000-129.225.146.84-443"
	a.onDelta(FlowDelta{
		Key: key, DeviceIP: "192.168.1.106", DstIP: "129.225.146.84", DPort: 443, SPort: 51000,
		Proto: "tcp", Path: "proxy", Iface: "br-lan",
		TotalUp: 1000, TotalDown: 9000, UpDelta: 100, DownDelta: 900,
		Started: now - 5, New: true,
	})
	conn, ok := a.agg.ConnByID(key)
	if !ok {
		t.Fatalf("连接未写入明细")
	}
	if !strings.Contains(conn.Domain, "youtube") {
		t.Errorf("代理连接应回退到设备最近查询域名，实际 domain=%q", conn.Domain)
	}
	if conn.Category != "video" {
		t.Errorf("代理 YouTube 连接分类 = %q，期望 video", conn.Category)
	}
}

// ---------------- 端口扫描误报（ZeroTier 内网多端口）----------------

func scanEvents(t *testing.T, a *App) []Event {
	t.Helper()
	events, _ := a.store.Events(100, "", "port_scan", "all")
	return events
}

func TestScanIgnoresInternalDst(t *testing.T) {
	a := newTestApp(t, true)
	a.store.ClearEvents()
	now := nowUnix()
	dev := "192.168.1.33"
	// 30 个不同端口的 ZeroTier/VPN 内网目的：不应触发端口扫描
	for i := 0; i < 30; i++ {
		a.sec.OnFlow(FlowDelta{DeviceIP: dev, DstIP: "192.168.99.16", DPort: 10000 + i, Proto: "tcp", New: true}, now, false)
	}
	for i := 0; i < 30; i++ {
		a.sec.OnFlow(FlowDelta{DeviceIP: dev, DstIP: "10.0.2.5", DPort: 11000 + i, Proto: "tcp", New: true}, now, false)
	}
	if evs := scanEvents(t, a); len(evs) != 0 {
		t.Fatalf("内网/ZT/VPN 多端口被误判为端口扫描: %+v", evs)
	}
	// 25 个不同公网端口：应触发端口扫描
	for i := 0; i < 25; i++ {
		a.sec.OnFlow(FlowDelta{DeviceIP: dev, DstIP: "8.8.8.8", DPort: 20000 + i, Proto: "tcp", New: true}, now+1, true)
	}
	evs := scanEvents(t, a)
	if len(evs) != 1 {
		t.Fatalf("公网多端口应触发端口扫描，实际 events=%d", len(evs))
	}
	ev := evs[0]
	if ev.Type != "port_scan" || ev.DeviceIP != dev {
		t.Errorf("端口扫描事件字段错误: %+v", ev)
	}
	if pl, ok := ev.Evidence["portList"].([]int); !ok || len(pl) == 0 || len(pl) > 20 {
		t.Errorf("evidence.portList 应为前 20 个端口: %+v", ev.Evidence["portList"])
	}
	if _, ok := ev.Evidence["threshold"]; !ok {
		t.Errorf("evidence 应包含 threshold: %+v", ev.Evidence)
	}
}

func TestScanIgnoresZTPort(t *testing.T) {
	a := newTestApp(t, true)
	now := nowUnix()
	dev := "192.168.1.33"
	for _, port := range []int{9993, 9994} {
		a.sec.OnFlow(FlowDelta{DeviceIP: dev, DstIP: "1.2.3.4", DPort: port, Proto: "udp", New: true}, now, true)
	}
	a.sec.mu.Lock()
	n := len(a.sec.scan[dev])
	a.sec.mu.Unlock()
	if n != 0 {
		t.Errorf("ZT 控制端口 9993/9994 不应计入扫描窗口，实际 %d", n)
	}
}

// ---------------- 开源威胁情报库 ----------------

func TestThreatDomainMatch(t *testing.T) {
	resetThreatLibraryForTest()
	domains, _ := ThreatLists()
	if len(domains) < 5000 {
		t.Fatalf("威胁域名库规模不足（目标 ≥5000）: %d", len(domains))
	}
	rule := domains[0]
	got, ok := ThreatDomainLookup(rule.Target)
	if !ok || got.Kind != rule.Kind || got.Source == "" {
		t.Fatalf("精确域名命中失败: %+v -> %+v ok=%v", rule, got, ok)
	}
	if _, ok := ThreatDomainLookup("sub." + rule.Target); !ok {
		t.Errorf("子域名 sub.%s 应命中威胁库", rule.Target)
	}
	if _, ok := ThreatDomainLookup("www.bilibili.com"); ok {
		t.Errorf("正常域名不应命中威胁库")
	}
	if _, ok := ThreatDomainLookup(""); ok {
		t.Errorf("空域名不应命中")
	}
}

func TestThreatIPMatch(t *testing.T) {
	_, ips := ThreatLists()
	if len(ips) < 100 {
		t.Fatalf("威胁 IP 库规模不足: %d", len(ips))
	}
	var exactTarget, cidrTarget string
	for _, r := range ips {
		if strings.Contains(r.Target, "/") && cidrTarget == "" {
			cidrTarget = r.Target
		} else if !strings.Contains(r.Target, "/") && exactTarget == "" {
			exactTarget = r.Target
		}
	}
	if exactTarget == "" || cidrTarget == "" {
		t.Fatalf("库中应同时有精确 IP 与 CIDR 条目")
	}
	if got, ok := ThreatIPLookup(exactTarget); !ok || got.Source == "" {
		t.Errorf("精确 IP %s 应命中威胁库", exactTarget)
	}
	prefix, err := netip.ParsePrefix(cidrTarget)
	if err != nil {
		t.Fatalf("CIDR 解析失败: %v", err)
	}
	inside := prefix.Masked().Addr().Next()
	if !prefix.Contains(inside) {
		inside = prefix.Masked().Addr()
	}
	if got, ok := ThreatIPLookup(inside.String()); !ok || got.Source == "" {
		t.Errorf("CIDR %s 内地址 %s 应命中", cidrTarget, inside)
	}
	for _, ip := range []string{"192.168.1.31", "10.0.2.5", "127.0.0.1", "169.254.1.1"} {
		if _, ok := ThreatIPLookup(ip); ok {
			t.Errorf("内网地址 %s 不应命中威胁库", ip)
		}
	}
	dCount, iCount := ThreatCounts()
	if dCount < 200 || iCount < 100 {
		t.Errorf("威胁库规模不足: domains=%d ips=%d", dCount, iCount)
	}
}

func TestBadIPEvent(t *testing.T) {
	a := newTestApp(t, true)
	a.store.ClearEvents()
	now := nowUnix()
	_, ips := ThreatLists()
	var exact ThreatRule
	for _, r := range ips {
		if !strings.Contains(r.Target, "/") {
			exact = r
			break
		}
	}
	if exact.Target == "" {
		t.Fatalf("威胁库缺少精确 IP 条目")
	}
	a.sec.OnThreatIP(exact.Target, "192.168.1.44", exact, now)
	events, _ := a.store.Events(10, "", "bad_ip", "all")
	if len(events) != 1 {
		t.Fatalf("应产生 bad_ip 事件，实际 %d", len(events))
	}
	ev := events[0]
	if ev.Evidence["kind"] != string(exact.Kind) || ev.Evidence["source"] != exact.Source {
		t.Errorf("bad_ip 事件应带 kind/source: %+v", ev.Evidence)
	}
	// 白名单按 type+target（evidence.ip）可抑制
	a.store.PutWhitelist("bad_ip", exact.Target, "测试", now)
	a.sec.RestoreWhitelist()
	a.store.ClearEvents()
	a.sec.OnThreatIP(exact.Target, "192.168.1.44", exact, now+1000)
	events, _ = a.store.Events(10, "", "bad_ip", "all")
	if len(events) != 0 {
		t.Errorf("加白后 bad_ip 不应再产生事件，实际 %d", len(events))
	}
}

// ---------------- 威胁情报库更新机制 ----------------

func TestThreatUpdatePersist(t *testing.T) {
	resetThreatLibraryForTest()
	dir := t.TempDir()
	path := threatStorePath(dir)
	dom := ThreatRule{Target: "ioc-persist-test.badzone", Kind: ThreatMalware, Source: "unit-test", Confidence: 90}
	ip := ThreatRule{Target: "203.0.113.77", Kind: ThreatC2, Source: "unit-test", Confidence: 95}
	if err := saveThreatFile(path, []ThreatRule{dom}, []ThreatRule{ip}, 1700000123); err != nil {
		t.Fatalf("saveThreatFile: %v", err)
	}
	if err := LoadThreats(path); err != nil {
		t.Fatalf("LoadThreats: %v", err)
	}
	if got, ok := ThreatDomainLookup(dom.Target); !ok || got.Source != "unit-test" {
		t.Errorf("更新文件中的域名未加载: %+v ok=%v", got, ok)
	}
	if got, ok := ThreatIPLookup(ip.Target); !ok || got.Kind != ThreatC2 {
		t.Errorf("更新文件中的 IP 未加载: %+v ok=%v", got, ok)
	}
	if at, _ := ThreatStatus(); at != 1700000123 {
		t.Errorf("updatedAt = %d，期望 1700000123", at)
	}
	// 损坏 json：回退内置静态库
	if err := os.WriteFile(path, []byte("{bad json"), 0o644); err != nil {
		t.Fatalf("write corrupt: %v", err)
	}
	if err := LoadThreats(path); err == nil {
		t.Errorf("损坏 json 应返回错误")
	}
	if _, ok := ThreatDomainLookup(dom.Target); ok {
		t.Errorf("损坏 json 后应回退内置库（不应保留自定义条目）")
	}
	if d, _ := ThreatCounts(); d < 5000 {
		t.Errorf("回退内置库规模异常: %d", d)
	}
	t.Cleanup(resetThreatLibraryForTest)
}

func TestThreatUpdateMerge(t *testing.T) {
	resetThreatLibraryForTest()
	var doms, ips []ThreatRule
	for i := 0; i < maxThreatDomains+10000; i++ {
		conf := 10
		if i >= maxThreatDomains+9000 {
			conf = 100 // 后加入的高置信度条目应优先保留
		}
		doms = append(doms, ThreatRule{Target: fmt.Sprintf("ioc-%d.badzone", i), Kind: ThreatMalware, Source: "unit-test", Confidence: conf})
	}
	for i := 0; i < maxThreatIPs+5000; i++ {
		conf := 20
		if i >= maxThreatIPs+4000 {
			conf = 100
		}
		ips = append(ips, ThreatRule{
			Target: fmt.Sprintf("9.%d.%d.%d", (i/65025)%255, (i/255)%255, i%255),
			Kind:   ThreatBotnet, Source: "unit-test", Confidence: conf,
		})
	}
	// 重复条目应去重
	doms = append(doms, doms[0])
	ips = append(ips, ips[0])
	gotD, gotI := mergeThreatRules(doms, ips)
	if len(gotD) > maxThreatDomains || len(gotI) > maxThreatIPs {
		t.Errorf("超过上限: domains=%d ips=%d", len(gotD), len(gotI))
	}
	if len(gotD) != maxThreatDomains {
		t.Errorf("域名应被截断到 %d，实际 %d", maxThreatDomains, len(gotD))
	}
	if len(gotI) != maxThreatIPs {
		t.Errorf("IP 应被截断到 %d，实际 %d", maxThreatIPs, len(gotI))
	}
	seen := map[string]int{}
	for _, r := range gotD {
		seen[r.Target]++
	}
	for k, n := range seen {
		if n > 1 {
			t.Errorf("域名去重失败: %s 出现 %d 次", k, n)
		}
	}
	// 内置博彩域名始终保留
	if _, ok := ThreatDomainLookup("bet365.com"); !ok {
		t.Errorf("内置博彩域名应在合并后保留")
	}
	// 高置信度条目保留（检查合并结果本身）
	wantHigh := fmt.Sprintf("ioc-%d.badzone", maxThreatDomains+9500)
	foundHigh := false
	for _, r := range gotD {
		if r.Target == wantHigh {
			foundHigh = true
			break
		}
	}
	if !foundHigh {
		t.Errorf("高置信度条目 %s 应优先保留", wantHigh)
	}
}

func TestThreatUpdateFailSafe(t *testing.T) {
	resetThreatLibraryForTest()
	dir := t.TempDir()
	path := threatStorePath(dir)
	base := ThreatRule{Target: "ioc-keep-old.badzone", Kind: ThreatMalware, Source: "unit-test", Confidence: 90}
	if err := saveThreatFile(path, []ThreatRule{base}, nil, 1700000200); err != nil {
		t.Fatalf("save: %v", err)
	}
	if err := LoadThreats(path); err != nil {
		t.Fatalf("LoadThreats: %v", err)
	}
	beforeD, beforeI := ThreatCounts()
	beforeAt, _ := ThreatStatus()
	failFetch := func(threatSource, string) ([]byte, error) {
		return nil, errors.New("network down")
	}
	res := updateThreatsWithFetcher(dir, false, failFetch)
	if res.Ok {
		t.Errorf("全部源失败时应返回 ok=false")
	}
	if len(res.Errors) == 0 {
		t.Errorf("应记录拉取错误")
	}
	afterD, afterI := ThreatCounts()
	if beforeD != afterD || beforeI != afterI {
		t.Errorf("全部源失败应保留旧库: before %d/%d after %d/%d", beforeD, beforeI, afterD, afterI)
	}
	if at, _ := ThreatStatus(); at != beforeAt {
		t.Errorf("更新时间不应变化")
	}
	if _, ok := ThreatDomainLookup(base.Target); !ok {
		t.Errorf("旧库条目应保留")
	}
	t.Cleanup(resetThreatLibraryForTest)
}

func TestThreatUpdateIncremental(t *testing.T) {
	resetThreatLibraryForTest()
	dir := t.TempDir()
	path := threatStorePath(dir)
	old := ThreatRule{Target: "ioc-old.badzone", Kind: ThreatMalware, Source: "unit-test", Confidence: 80}
	if err := saveThreatFile(path, []ThreatRule{old}, nil, 1700000300); err != nil {
		t.Fatalf("save: %v", err)
	}
	if err := LoadThreats(path); err != nil {
		t.Fatalf("LoadThreats: %v", err)
	}
	fetch := func(src threatSource, _ string) ([]byte, error) {
		if src.name == "Abuse.ch URLhaus" {
			return []byte("ioc-new.badzone\n"), nil
		}
		return nil, errors.New("skip")
	}
	res := updateThreatsWithFetcher(dir, false, fetch)
	if !res.Ok {
		t.Fatalf("增量更新应成功: %+v", res)
	}
	if _, ok := ThreatDomainLookup(old.Target); !ok {
		t.Errorf("增量合并应保留旧条目")
	}
	if _, ok := ThreatDomainLookup("ioc-new.badzone"); !ok {
		t.Errorf("增量合并应加入新条目")
	}
	t.Cleanup(resetThreatLibraryForTest)
}

func TestThreatParseSources(t *testing.T) {
	// URLhaus
	rules, err := parseURLhausFeed(threatSource{}, []byte("! comment\n1.2.3.4\nevil-urlhaus.badzone\n# x\n"))
	if err != nil || len(rules) != 2 {
		t.Fatalf("URLhaus 解析: %v %d", err, len(rules))
	}
	// ThreatFox JSON
	tf := `{"query_status":"ok","data":[
		{"ioc":"evil-tf.badzone","ioc_type":"domain","threat_type":"botnet_cc","malware":"win.emotet","confidence_level":75},
		{"ioc":"203.0.113.9:443","ioc_type":"ip:port","threat_type":"botnet_cc","malware":"win.qakbot","confidence_level":90}]}`
	rules, err = parseThreatFoxJSON(threatSource{conf: 50}, []byte(tf))
	if err != nil || len(rules) != 2 {
		t.Fatalf("ThreatFox 解析: %v %d", err, len(rules))
	}
	for _, r := range rules {
		if r.Kind != ThreatC2 || r.Confidence < 75 || r.Source == "" {
			t.Errorf("ThreatFox 规则字段错误: %+v", r)
		}
	}
	// Spamhaus
	rules, err = parseSpamhausDROP(threatSource{}, []byte("; c\n1.10.16.0/20 ; SBL1\n"))
	if err != nil || len(rules) != 1 || rules[0].Target != "1.10.16.0/20" || rules[0].Kind != ThreatBotnet {
		t.Fatalf("Spamhaus 解析: %v %+v", err, rules)
	}
}

func TestThreatUpdateIntervalConfig(t *testing.T) {
	a := newTestApp(t, true)
	if d := a.threatUpdateHours(); d != 6*time.Hour {
		t.Errorf("默认更新间隔 = %v，期望 6h", d)
	}
	a.store.UpdateSettings(func(s *Settings) { s.Alert.ThreatUpdateHours = 12 })
	if d := a.threatUpdateHours(); d != 12*time.Hour {
		t.Errorf("配置更新间隔 = %v，期望 12h", d)
	}
	a.store.UpdateSettings(func(s *Settings) { s.Alert.ThreatUpdateHours = 0 })
	if d := a.threatUpdateHours(); d != 6*time.Hour {
		t.Errorf("非法间隔应回退 6h，实际 %v", d)
	}
}

func TestThreatSearch(t *testing.T) {
	resetThreatLibraryForTest()
	// 域名子串命中（内置矿池域名）
	doms, ips, md, mi, totalD, totalI := ThreatSearch("minexmr", 500)
	if md < 1 || len(doms) == 0 {
		t.Errorf("minexmr 应命中威胁库: md=%d doms=%d", md, len(doms))
	}
	foundMining := false
	for _, r := range doms {
		if r.Target == "pool.minexmr.com" && r.Kind == ThreatMining {
			foundMining = true
		}
	}
	if !foundMining {
		t.Errorf("应命中 pool.minexmr.com（mining）: %+v", doms)
	}
	if mi != 0 || len(ips) != 0 {
		t.Errorf("域名查询不应返回 IP 命中")
	}
	if totalD < 5000 || totalI < 3000 {
		t.Errorf("库总数异常: %d/%d", totalD, totalI)
	}
	// IP 精确命中
	_, allIPs := ThreatLists()
	var exact, cidr string
	for _, r := range allIPs {
		if strings.Contains(r.Target, "/") && cidr == "" {
			cidr = r.Target
		} else if !strings.Contains(r.Target, "/") && exact == "" {
			exact = r.Target
		}
	}
	_, ips, _, mi, _, _ = ThreatSearch(exact, 500)
	if mi < 1 || len(ips) == 0 {
		t.Errorf("IP 精确查询应命中 %s: mi=%d", exact, mi)
	}
	// CIDR 包含（取网段内地址）
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		t.Fatalf("CIDR 解析失败: %v", err)
	}
	inside := prefix.Masked().Addr().Next()
	if !prefix.Contains(inside) {
		inside = prefix.Masked().Addr()
	}
	_, ips, _, mi, _, _ = ThreatSearch(inside.String(), 500)
	if mi < 1 || len(ips) == 0 {
		t.Errorf("CIDR %s 内地址 %s 应命中: mi=%d", cidr, inside, mi)
	}
	// 无命中
	doms, ips, md, mi, _, _ = ThreatSearch("definitely-not-in-library-xyz-12345", 500)
	if md != 0 || mi != 0 || len(doms) != 0 || len(ips) != 0 {
		t.Errorf("无命中应返回空: md=%d mi=%d doms=%d ips=%d", md, mi, len(doms), len(ips))
	}
	// q 为空：返回全 0（API 层走分页分支）
	if d, i, md, mi, td, ti := ThreatSearch("  ", 500); md != 0 || mi != 0 || d != nil || i != nil || td != 0 || ti != 0 {
		t.Errorf("空查询应返回零值: %d/%d/%d/%d/%d/%d", len(d), len(i), md, mi, td, ti)
	}
}

func TestTopDomainsDevList(t *testing.T) {
	a := newTestApp(t, true)
	now := nowUnix()
	domain := "video.test-domain.example"
	a.dns.HandleRecord(dnsRecord{Kind: "query", QType: "A", Name: domain, SrcIP: "192.168.1.31"}, now)
	a.dns.HandleRecord(dnsRecord{Kind: "reply", Name: domain, IP: "1.2.3.4"}, now)
	a.dns.AddBytes(domain, 100, 900, "192.168.1.31", now)
	a.dns.AddBytes(domain, 5000, 5000, "192.168.1.32", now+1)
	a.dns.AddBytes(domain, 10, 10, "192.168.1.31", now+2)

	list := a.dns.TopDomains(now-3600, 100)
	var got *DomainAgg
	for i := range list {
		if list[i].Domain == domain {
			got = &list[i]
			break
		}
	}
	if got == nil {
		t.Fatalf("未找到域名统计: %+v", list)
	}
	if got.Devices != 2 || len(got.DevList) != 2 {
		t.Fatalf("设备数量错误: devices=%d devList=%+v", got.Devices, got.DevList)
	}
	// 按 bytes 降序：192.168.1.32 (10000) 在 192.168.1.31 (1020) 前
	if got.DevList[0].IP != "192.168.1.32" || got.DevList[1].IP != "192.168.1.31" {
		t.Errorf("DevList 应按 bytes 降序: %+v", got.DevList)
	}
	if got.DevList[0].Bytes != 10000 {
		t.Errorf("设备字节数错误: %+v", got.DevList[0])
	}
	// 单设备域名
	single := "single.test-domain.example"
	a.dns.HandleRecord(dnsRecord{Kind: "query", QType: "A", Name: single, SrcIP: "192.168.1.33"}, now)
	a.dns.HandleRecord(dnsRecord{Kind: "reply", Name: single, IP: "5.6.7.8"}, now)
	a.dns.AddBytes(single, 50, 50, "192.168.1.33", now)
	list = a.dns.TopDomains(now-3600, 100)
	for i := range list {
		if list[i].Domain == single {
			if list[i].Devices != 1 || len(list[i].DevList) != 1 || list[i].DevList[0].IP != "192.168.1.33" {
				t.Errorf("单设备 DevList 错误: %+v", list[i])
			}
		}
	}
}

func TestVendorAndCategoryMeta(t *testing.T) {
	if v := VendorForMAC("90:F0:52:D5:9A:CB"); v != "魅族" {
		t.Errorf("OUI 厂商 = %q，期望 魅族", v)
	}
	if len(Categories) != 8 {
		t.Fatalf("分类数量 = %d，期望固定 8 项", len(Categories))
	}
	want := map[string]string{
		"video": "#22d3ee", "game": "#a78bfa", "social": "#f472b6", "web": "#38bdf8",
		"download": "#fbbf24", "mail": "#34d399", "cloud": "#2dd4bf", "other": "#94a3b8",
	}
	for _, c := range Categories {
		if want[c.Key] != c.Color {
			t.Errorf("分类 %s 色值 = %s，期望 %s", c.Key, c.Color, want[c.Key])
		}
	}
}
