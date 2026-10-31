package main

// DNS 行为采集（上网行为维度的唯一来源）与域名归因。
//
// 数据源：dnsmasq 查询日志 /tmp/guanlan/dnsmasq.log（tmpfs，重启失效）。
// 启用方式（实测该固件的正规途径，已由 lead 验证）：
//   uci set dhcp.@dnsmasq[0].logqueries='1'
//   uci set dhcp.@dnsmasq[0].logfacility='/tmp/guanlan/dnsmasq.log'
//   uci commit dhcp
//   /etc/init.d/dnsmasq stop → sleep 1 → start → 健康检查
// 禁用：uci delete 两项 + commit + 同样 stop/start。
// 禁止使用 /etc/init.d/dnsmasq reload（该固件有 bug：停得掉起不来）。
//
// 内存约束：
//   - ip→domain 反查表：TTL 30 分钟，容量上限 20000，按最近使用 LRU 淘汰；
//   - domain→ips 表：启动/日志中观测到的解析结果，TTL，容量上限 5000；
//   - 域名统计：容量上限 5000，超过时淘汰最久未活跃的 10%，并周期性清理 6h 前数据；
//   - TXT 隧道嫌疑统计：容量上限 2000。
//
// 域名封堵不走 dnsmasq，而是由 enforce.go 解析成 IP 写入 ipset（见 IPsForDomain）。

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	dnsLogPath     = "/tmp/guanlan/dnsmasq.log"
	dnsLogDir      = "/tmp/guanlan"
	dnsLogMaxBytes = 32 * 1024 * 1024
	ipMapTTL       = int64(30 * 60)     // ip→domain 反查 TTL
	longIPTTL      = int64(6 * 60 * 60) // 长 TTL 反查索引（连接域名回退用）
	domainStatTTL  = int64(6 * 60 * 60)
	ipMapCap       = 20000
	domainIPCap    = 5000
	domainStatCap  = 5000
	txtTrackCap    = 2000
	devRecentTTL   = int64(10 * 60) // 设备最近查询域名的回退有效期（10min）
	devRecentCap   = 512            // 设备数量上限（超出按最旧淘汰）

	// dnsmasq 主配置。该固件在 /etc/dnsmasq.conf 硬编码 log-facility=/dev/null，
	// 与 UCI dhcp.@dnsmasq[0].logfacility 生成的第二个 log-facility 重复，
	// 导致 dnsmasq 报 "illegal repeated keyword" 启动失败。
	// 因此本项目不改 UCI logfacility，而是精确替换 /etc/dnsmasq.conf 的
	// log-facility 行（备份原值到 /tmp/guanlan/logfacility.orig），关闭时还原。
	dnsmasqConfPath = "/etc/dnsmasq.conf"
	dnsConfBackup   = dnsLogDir + "/logfacility.orig"
)

// dnsRecord 一条 DNS 日志记录。
type dnsRecord struct {
	Kind   string // query / reply / cached / forwarded
	QType  string // A / AAAA / TXT / type=65 ...
	Name   string // 域名
	IP     string // reply/cached 的地址（NXDOMAIN 等为空）
	SrcIP  string // 客户端 IPv4（query 的 from；IPv6 会回退到前缀里的 IPv4）
	Target string // forwarded 的目标（如 127.0.0.1#5333）
}

// parseDNSLine 解析 dnsmasq 日志行（纯函数，可单测）。
//
// 兼容两种实测格式：
//
// 旧版（无前缀）：
//
//	Oct 31 16:25:38 dnsmasq[26278]: query[A] tracker.torrent.eu.org from 192.168.1.106
//	Oct 31 16:25:38 dnsmasq[26278]: reply tracker.torrent.eu.org is 89.234.156.205
//
// dnsmasq 2.88（行首带 "<id> <srcaddr>/<srcport> " 前缀）：
//
//	Oct 31 18:37:28 dnsmasq[9475]: 6727 fd16:.../21229 query[AAAA] cn.voice.gcloudcs.com from fd16:...
//	Oct 31 18:37:28 dnsmasq[9475]: 6725 fd16:.../65169 reply speed.ino.qq.com is NODATA-IPv6
//	Oct 31 18:37:28 dnsmasq[9475]: 6727 fd16:.../21229 forwarded cn.voice.gcloudcs.com to 127.0.0.1#5333
//	Oct 31 18:37:28 dnsmasq[9475]: 6726 fd16:.../26008 ipset add passwall_chnroute 183.194.237.51 qq.com
//
// 注意：2.88 的 query 行 from 可能是 IPv6（服务器源地址），此时客户端 IPv4 无法归因，
// 但仍算一次 DNS 查询（QPS 计数）；reply/cached/forwarded 用前缀里的地址兜底。
func parseDNSLine(line string) (dnsRecord, bool) {
	var r dnsRecord
	idx := strings.Index(line, "]:")
	if idx < 0 {
		return r, false
	}
	rest := strings.TrimSpace(line[idx+2:])
	if rest == "" {
		return r, false
	}
	// 2.88 前缀：<id> <srcaddr>/<srcport> <action> ...
	prefixSrc := ""
	if body, src, ok := stripDNSLogPrefix(rest); ok {
		rest = body
		prefixSrc = src
	}
	if strings.HasPrefix(rest, "query[") {
		end := strings.IndexByte(rest, ']')
		if end < 0 {
			return r, false
		}
		r.Kind = "query"
		r.QType = strings.TrimSpace(rest[len("query["):end])
		body := strings.TrimSpace(rest[end+1:])
		p := strings.LastIndex(body, " from ")
		if p <= 0 {
			return r, false
		}
		r.Name = strings.TrimSpace(body[:p])
		from := strings.TrimSpace(body[p+len(" from "):])
		if r.Name == "" {
			return r, false
		}
		// 客户端 IPv4 优先取 query 行 from；IPv6 时用前缀地址兜底（仍无 IPv4 则留空，仅计 QPS）
		if ip := firstIPv4Addr(from); ip != "" {
			r.SrcIP = ip
		} else if ip := firstIPv4Addr(prefixSrc); ip != "" {
			r.SrcIP = ip
		}
		return r, true
	}
	if strings.HasPrefix(rest, "reply ") || strings.HasPrefix(rest, "cached ") {
		if strings.HasPrefix(rest, "cached ") {
			r.Kind = "cached"
			rest = strings.TrimSpace(rest[len("cached "):])
		} else {
			r.Kind = "reply"
			rest = strings.TrimSpace(rest[len("reply "):])
		}
		r.SrcIP = firstIPv4Addr(prefixSrc)
		p := strings.LastIndex(rest, " is ")
		if p <= 0 {
			return r, false
		}
		r.Name = strings.TrimSpace(rest[:p])
		val := strings.TrimSpace(rest[p+len(" is "):])
		if r.Name == "" {
			return r, false
		}
		// 去掉可能的 "(ttl)" 等后缀
		if sp := strings.IndexByte(val, ' '); sp > 0 {
			val = val[:sp]
		}
		if ip := net.ParseIP(val); ip != nil && ip.To4() != nil {
			r.IP = ip.String()
		}
		// NXDOMAIN / NODATA-IPv6 / CNAME 等没有可用 IP，返回 true 由上层忽略
		return r, true
	}
	// 2.88：forwarded <name> to <target>（代理/上游线索，不计数 QPS）
	if strings.HasPrefix(rest, "forwarded ") {
		body := strings.TrimSpace(rest[len("forwarded "):])
		p := strings.LastIndex(body, " to ")
		if p <= 0 {
			return r, false
		}
		r.Kind = "forwarded"
		r.Name = strings.TrimSpace(body[:p])
		r.Target = strings.TrimSpace(body[p+len(" to "):])
		r.SrcIP = firstIPv4Addr(prefixSrc)
		return r, r.Name != ""
	}
	// ipset/config/DHCP 等其它 action 忽略
	return r, false
}

// stripDNSLogPrefix 剥离 dnsmasq 2.88 的 "<id> <srcaddr>/<srcport> " 前缀。
func stripDNSLogPrefix(rest string) (body, src string, ok bool) {
	sp1 := strings.IndexByte(rest, ' ')
	if sp1 <= 0 || !allDigits(rest[:sp1]) {
		return rest, "", false
	}
	tail := strings.TrimSpace(rest[sp1+1:])
	sp2 := strings.IndexByte(tail, ' ')
	if sp2 <= 0 {
		return rest, "", false
	}
	tok := tail[:sp2]
	slash := strings.IndexByte(tok, '/')
	if slash <= 0 || slash == len(tok)-1 {
		return rest, "", false
	}
	addr := tok[:slash]
	if net.ParseIP(addr) == nil || !allDigits(tok[slash+1:]) {
		return rest, "", false
	}
	return strings.TrimSpace(tail[sp2+1:]), addr, true
}

// firstIPv4Addr 从字符串中取 IPv4 地址（IPv6 返回空）。
func firstIPv4Addr(s string) string {
	ip := net.ParseIP(strings.TrimSpace(s))
	if ip == nil || ip.To4() == nil {
		return ""
	}
	return ip.To4().String()
}

// allDigits 判断字符串全为数字。
func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// DomainDev 设备维度的域名统计。
type DomainDev struct {
	Hits     int64
	Bytes    int64
	LastSeen int64
}

// DomainStat 域名统计。
type DomainStat struct {
	Domain    string
	Category  string
	Label     string
	BlockKind string
	Hits      int64
	BytesUp   int64
	BytesDown int64
	FirstSeen int64
	LastSeen  int64
	Devices   map[string]*DomainDev
}

// Bytes 总字节。
func (d *DomainStat) Bytes() int64 { return d.BytesUp + d.BytesDown }

// DomainDevAgg 域名访问设备明细（最近访问该域名的设备，供流量页"源主机"列）。
type DomainDevAgg struct {
	IP       string
	Hits     int64
	Bytes    int64
	LastSeen int64
}

// DomainAgg 对外聚合结果（API 序列化在 api.go）。
type DomainAgg struct {
	Domain   string
	Category string
	Label    string
	Hits     int64
	Bytes    int64
	Devices  int
	LastSeen int64
	DevList  []DomainDevAgg // 按 Bytes 降序的设备明细（最多 20 条）
}

type ipEntry struct {
	domain  string
	expires int64
	last    int64
}

type domIPEntry struct {
	ips     []uint32
	expires int64
	last    int64
}

type txtTrack struct {
	times []int64
	// lens 与 times 一一对应的子域标签长度：均值只在窗口内求和，
	// 避免「累计全部历史」导致 avg 单调虚高、持续误报。
	lens  []int64
	last  int64
	srcIP string
}

// TXTSuspect TXT 隧道嫌疑。
type TXTSuspect struct {
	Domain   string
	Count    int
	AvgLabel float64
	SrcIP    string
}

// devRecentEntry 设备最近一次 DNS 查询（代理连接无法按目的 IP 归因时的设备级回退）。
type devRecentEntry struct {
	domain string
	cat    string
	label  string
	at     int64
}

// DNSResolver 域名归因与统计（并发安全）。
type DNSResolver struct {
	mu        sync.RWMutex
	app       *App
	ipMap     map[uint32]*ipEntry
	ipLong    map[uint32]*ipEntry // 长 TTL 反查索引（6h），供 dnsTap 关闭/过期后的域名回退
	domIPs    map[string]*domIPEntry
	stats     map[string]*DomainStat
	txt       map[string]*txtTrack
	devRecent map[string]*devRecentEntry // 设备 IP -> 最近查询域名
	qTimes    []int64
	lastTrim  int64
	// flowCtx 采集侧发布的当前流向上下文（emit 期间有效）：
	// 用于把设备级 DNS 回退限制在「走代理、目的为代理服务器」的连接上。
	flowCtx FlowContext
}

// NewDNSResolver 创建解析器。
func NewDNSResolver(a *App) *DNSResolver {
	d := &DNSResolver{
		app:       a,
		ipMap:     map[uint32]*ipEntry{},
		ipLong:    map[uint32]*ipEntry{},
		domIPs:    map[string]*domIPEntry{},
		stats:     map[string]*DomainStat{},
		txt:       map[string]*txtTrack{},
		devRecent: map[string]*devRecentEntry{},
	}
	// 订阅采集侧的流向上下文（emit 前后各一次，空上下文表示当前无 flow）
	if a != nil && a.ct != nil {
		a.ct.SetFlowHook(d.onFlowContext)
	}
	return d
}

// HandleRecord 处理一条 DNS 日志记录。
func (d *DNSResolver) HandleRecord(rec dnsRecord, now int64) {
	switch rec.Kind {
	case "query":
		d.handleQuery(rec, now)
	case "reply", "cached":
		if rec.IP != "" {
			d.handleAnswer(rec, now)
		}
	}
}

func (d *DNSResolver) handleQuery(rec dnsRecord, now int64) {
	domain, cat, label, blockKind := displayDomain(rec.Name)
	if domain == "" {
		return
	}
	d.mu.Lock()
	st := d.statLocked(domain, cat, label, blockKind, now)
	if st != nil {
		st.Hits++
		st.LastSeen = now
		if rec.SrcIP != "" {
			dev := st.Devices[rec.SrcIP]
			if dev == nil {
				if len(st.Devices) < 256 { // 单域名设备维度上限，防异常撑爆
					dev = &DomainDev{}
					st.Devices[rec.SrcIP] = dev
				}
			}
			if dev != nil {
				dev.Hits++
				dev.LastSeen = now
			}
		}
	}
	// 外部 QPS 统计
	d.qTimes = append(d.qTimes, now)
	if len(d.qTimes) > 600 {
		d.qTimes = d.qTimes[len(d.qTimes)-600:]
	}
	// 记录设备最近查询域名：走代理的连接（dst=代理服务器 IP，无法按 IP 归因）回退用
	if rec.SrcIP != "" {
		if len(d.devRecent) >= devRecentCap {
			if _, exists := d.devRecent[rec.SrcIP]; !exists {
				var oldestIP string
				var oldestAt int64
				for ip, e := range d.devRecent {
					if oldestIP == "" || e.at < oldestAt {
						oldestIP, oldestAt = ip, e.at
					}
				}
				delete(d.devRecent, oldestIP)
			}
		}
		d.devRecent[rec.SrcIP] = &devRecentEntry{domain: domain, cat: cat, label: label, at: now}
	}
	// TXT 隧道嫌疑统计
	if isTXTQType(rec.QType) {
		base := baseDomain(rec.Name)
		tr := d.txt[base]
		if tr == nil {
			if len(d.txt) >= txtTrackCap {
				d.evictTxtLocked()
			}
			tr = &txtTrack{}
			d.txt[base] = tr
		}
		tr.times = append(tr.times, now)
		tr.lens = append(tr.lens, int64(avgLabelLen(rec.Name)))
		if len(tr.times) > 200 {
			tr.times = tr.times[len(tr.times)-200:]
			tr.lens = tr.lens[len(tr.lens)-200:]
		}
		tr.last = now
		if rec.SrcIP != "" {
			tr.srcIP = rec.SrcIP // 来源设备每次 TXT 查询都更新
		}
	}
	d.mu.Unlock()
	// 黑名单命中交给研判层（在锁外调用，避免与研判层的锁顺序形成环）
	if d.app != nil && d.app.sec != nil {
		if blockKind != "" {
			d.app.sec.OnBlacklistDomain(domain, rec.SrcIP, blockKind, now)
		}
		// 开源威胁情报库：恶意域名（C2/钓鱼/矿池/恶意软件）
		if tr, ok := ThreatDomainLookup(domain); ok {
			d.app.sec.OnThreatDomain(domain, rec.SrcIP, tr, now)
		}
	}
}

func (d *DNSResolver) handleAnswer(rec dnsRecord, now int64) {
	domain, cat, label, blockKind := displayDomain(rec.Name)
	if domain == "" {
		return
	}
	addr, err := netipParse4(rec.IP)
	if err != nil {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	st := d.statLocked(domain, cat, label, blockKind, now)
	if st != nil {
		// reply 也算一次访问时间但不计入 hits（hits 只统计查询次数）
		if now > st.LastSeen {
			st.LastSeen = now
		}
	}
	d.ipMap[addr] = &ipEntry{domain: domain, expires: now + ipMapTTL, last: now}
	if len(d.ipMap) > ipMapCap {
		d.evictIPMapLocked(now)
	}
	// 长 TTL 反查索引（6h）：dnsTap 关闭/短 TTL 过期后仍可把连接目的 IP 归因到域名
	d.ipLong[addr] = &ipEntry{domain: domain, expires: now + longIPTTL, last: now}
	if len(d.ipLong) > ipMapCap {
		d.evictIPLongLocked()
	}
	ent := d.domIPs[domain]
	if ent == nil {
		if len(d.domIPs) >= domainIPCap {
			d.evictDomIPsLocked(now)
		}
		ent = &domIPEntry{}
		d.domIPs[domain] = ent
	}
	ent.last = now
	ent.expires = now + ipMapTTL
	if len(ent.ips) < 16 {
		exists := false
		for _, ip := range ent.ips {
			if ip == addr {
				exists = true
				break
			}
		}
		if !exists {
			ent.ips = append(ent.ips, addr)
		}
	}
}

// statLocked 获取/创建域名统计（调用方持有写锁）。
func (d *DNSResolver) statLocked(domain, cat, label, blockKind string, now int64) *DomainStat {
	st := d.stats[domain]
	if st == nil {
		if len(d.stats) >= domainStatCap {
			d.evictStatsLocked()
		}
		st = &DomainStat{
			Domain: domain, Category: cat, Label: label, BlockKind: blockKind,
			FirstSeen: now, Devices: map[string]*DomainDev{},
		}
		d.stats[domain] = st
	}
	return st
}

// Attribute 把目的 IP 归因到域名/分类。
func (d *DNSResolver) Attribute(ip string, now int64) (domain, cat, label string, ok bool) {
	addr, err := netipParse4(ip)
	if err != nil {
		return "", "", "", false
	}
	d.mu.RLock()
	ent := d.ipMap[addr]
	if ent == nil || ent.expires < now {
		d.mu.RUnlock()
		return "", "", "", false
	}
	domain = ent.domain
	d.mu.RUnlock()
	d.mu.RLock()
	st := d.stats[domain]
	if st != nil {
		cat, label = st.Category, st.Label
	}
	d.mu.RUnlock()
	if cat == "" {
		cat = "other"
	}
	if label == "" {
		label = domain
	}
	return domain, cat, label, true
}

// ReverseLookup 连接域名回退：短 TTL 未命中时查 6h 长 TTL 反查索引。
// 用于 dnsTap 关闭/日志断档后，仍尽量给 Connection.Domain 一个可读域名。
func (d *DNSResolver) ReverseLookup(ip string, now int64) (domain, cat, label string, ok bool) {
	addr, err := netipParse4(ip)
	if err != nil {
		return "", "", "", false
	}
	d.mu.RLock()
	ent := d.ipMap[addr]
	if ent == nil || ent.expires < now {
		ent = d.ipLong[addr]
	}
	if ent == nil || ent.expires < now {
		d.mu.RUnlock()
		return "", "", "", false
	}
	domain = ent.domain
	st := d.stats[domain]
	if st != nil {
		cat, label = st.Category, st.Label
	}
	d.mu.RUnlock()
	if domain == "" {
		return "", "", "", false
	}
	if cat == "" {
		cat = classifyPort("tcp", 443)
	}
	if label == "" {
		label = domain
	}
	return domain, cat, label, true
}

// RecentForDevice 设备最近一次 DNS 查询（代理连接按目的 IP 无法归因时的设备级回退）。
//
// 限制（避免把无法按 IP 归因的裸 IP/DoH 流量乱挂到设备最后一次查询上）：
//   - 仅返回 TTL（10min）内的记录，避免长时间误归因；
//   - 分类一致性：记住的分类为空/other 时不覆盖端口启发式分类；
//   - 流向限制：采集侧提供了连接上下文（FlowContext）时，只对走代理的连接生效——
//     代理连接的目的地是代理服务器/隧道，本就无法按目的 IP 归因，只能回退到设备最近查询；
//     直连/内网连接不适用（那会把裸 IP 流量误归到上一次查询的域名）。
func (d *DNSResolver) RecentForDevice(ip string, now int64) (domain, cat, label string, ok bool) {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return "", "", "", false
	}
	d.mu.RLock()
	ent := d.devRecent[ip]
	ctx := d.flowCtx
	d.mu.RUnlock()
	if ent == nil {
		return "", "", "", false
	}
	if now-ent.at > devRecentTTL {
		return "", "", "", false
	}
	// 复制到局部变量后再返回：不在读锁外写共享条目（避免数据竞争）
	domain, cat, label = ent.domain, ent.cat, ent.label
	if domain == "" {
		return "", "", "", false
	}
	if cat == "" {
		cat = "other"
	}
	if label == "" {
		label = domain
	}
	// 分类一致性：记住的分类没有信息量时交给端口启发式分类
	if cat == "other" {
		return "", "", "", false
	}
	// 流向限制：有连接上下文时只对代理连接生效
	if ctx.DeviceIP != "" {
		if ctx.DeviceIP != ip || ctx.Path != "proxy" {
			return "", "", "", false
		}
	}
	return domain, cat, label, true
}

// onFlowContext 接收采集侧发布的流向上下文（emit 期间有效）。
func (d *DNSResolver) onFlowContext(ctx FlowContext) {
	d.mu.Lock()
	d.flowCtx = ctx
	d.mu.Unlock()
}

// evictIPLongLocked 长 TTL 反查索引超限时按最近使用淘汰 10%。
func (d *DNSResolver) evictIPLongLocked() {
	list := make([]struct {
		ip   uint32
		last int64
	}, 0, len(d.ipLong))
	for ip, ent := range d.ipLong {
		list = append(list, struct {
			ip   uint32
			last int64
		}{ip, ent.last})
	}
	sort.Slice(list, func(i, j int) bool { return list[i].last < list[j].last })
	n := len(list) / 10
	if n < 1 {
		n = 1
	}
	for i := 0; i < n && i < len(list); i++ {
		delete(d.ipLong, list[i].ip)
	}
}

// AddBytes 累计域名流量与设备维度字节。
func (d *DNSResolver) AddBytes(domain string, up, down int64, devIP string, now int64) {
	if domain == "" || (up == 0 && down == 0) {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	st := d.stats[domain]
	if st == nil || devIP == "" {
		return
	}
	st.BytesUp += up
	st.BytesDown += down
	if now > st.LastSeen {
		st.LastSeen = now
	}
	dev := st.Devices[devIP]
	if dev == nil {
		// 首次由流量归因发现访问：至少记 1 次访问
		dev = &DomainDev{Hits: 1}
		st.Devices[devIP] = dev
	}
	dev.Bytes += up + down
	dev.LastSeen = now
}

// QPS 最近 10 秒的 DNS 查询速率（取整）。
func (d *DNSResolver) QPS(now int64) float64 {
	d.mu.RLock()
	defer d.mu.RUnlock()
	cut := now - 10
	n := 0
	for i := len(d.qTimes) - 1; i >= 0; i-- {
		if d.qTimes[i] < cut {
			break
		}
		n++
	}
	return float64(n) / 10.0
}

// TopDomains 指定时间之后活跃的域名，按字节降序。
func (d *DNSResolver) TopDomains(since int64, limit int) []DomainAgg {
	d.mu.RLock()
	defer d.mu.RUnlock()
	out := make([]DomainAgg, 0, 64)
	for _, st := range d.stats {
		if st.LastSeen < since {
			continue
		}
		devList := make([]DomainDevAgg, 0, len(st.Devices))
		for ip, dev := range st.Devices {
			devList = append(devList, DomainDevAgg{IP: ip, Hits: dev.Hits, Bytes: dev.Bytes, LastSeen: dev.LastSeen})
		}
		sort.Slice(devList, func(i, j int) bool {
			if devList[i].Bytes != devList[j].Bytes {
				return devList[i].Bytes > devList[j].Bytes
			}
			return devList[i].LastSeen > devList[j].LastSeen
		})
		if len(devList) > 20 {
			devList = devList[:20]
		}
		out = append(out, DomainAgg{
			Domain: st.Domain, Category: st.Category, Label: st.Label,
			Hits: st.Hits, Bytes: st.Bytes(), Devices: len(st.Devices), LastSeen: st.LastSeen,
			DevList: devList,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Bytes > out[j].Bytes })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

// DeviceTopDomains 某设备访问量最大的域名。
func (d *DNSResolver) DeviceTopDomains(devIP string, since int64, limit int) []DomainAgg {
	d.mu.RLock()
	defer d.mu.RUnlock()
	out := make([]DomainAgg, 0, 32)
	for _, st := range d.stats {
		dev := st.Devices[devIP]
		if dev == nil || dev.LastSeen < since {
			continue
		}
		out = append(out, DomainAgg{
			Domain: st.Domain, Category: st.Category, Label: st.Label,
			Hits: dev.Hits, Bytes: dev.Bytes, Devices: 1, LastSeen: dev.LastSeen,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Bytes > out[j].Bytes })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

// DomainHits 域名累计命中次数（overview topDomains 用）。
func (d *DNSResolver) DomainHits(domain string) (hits int64, label, cat string, ok bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	st := d.stats[domain]
	if st == nil {
		return 0, "", "", false
	}
	return st.Hits, st.Label, st.Category, true
}

// SuspectTXT 返回正在发生的 TXT 隧道嫌疑（60s 窗口内查询 >20 次或标签平均长度 >40）。
func (d *DNSResolver) SuspectTXT(now int64) []TXTSuspect {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.txt) == 0 {
		return nil
	}
	var out []TXTSuspect
	for base, tr := range d.txt {
		// 缩窗（times 与 lens 同步裁剪，均值只统计窗口内样本）
		cut := now - 60
		idx := 0
		for idx < len(tr.times) && tr.times[idx] < cut {
			idx++
		}
		if idx > 0 {
			tr.times = append([]int64(nil), tr.times[idx:]...)
			tr.lens = append([]int64(nil), tr.lens[idx:]...)
		}
		if len(tr.times) == 0 {
			if tr.last < now-300 {
				delete(d.txt, base)
			}
			continue
		}
		cnt := len(tr.times)
		var sum int64
		for i, l := range tr.lens {
			if i >= cnt {
				break
			}
			sum += l
		}
		avg := float64(sum) / float64(maxInt(cnt, 1))
		if cnt > 20 || avg > 40 {
			out = append(out, TXTSuspect{Domain: base, Count: cnt, AvgLabel: avg, SrcIP: tr.srcIP})
		}
	}
	return out
}

// IPsForDomain 返回该域名已观测到且未过期的 IP（封堵用）。
func (d *DNSResolver) IPsForDomain(domain string, now int64) []string {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return nil
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	ent := d.domIPs[domain]
	if ent == nil || ent.expires < now {
		return nil
	}
	out := make([]string, 0, len(ent.ips))
	for _, ip := range ent.ips {
		out = append(out, ip4String(ip))
	}
	return out
}

// Cleanup 周期性清理过期数据，控制内存。
func (d *DNSResolver) Cleanup(now int64) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if now-d.lastTrim < 60 {
		return
	}
	d.lastTrim = now

	for ip, ent := range d.ipMap {
		if ent.expires < now {
			delete(d.ipMap, ip)
		}
	}
	for ip, ent := range d.ipLong {
		if ent.expires < now {
			delete(d.ipLong, ip)
		}
	}
	for ip, ent := range d.devRecent {
		if now-ent.at > devRecentTTL {
			delete(d.devRecent, ip)
		}
	}
	for dom, ent := range d.domIPs {
		if ent.expires < now {
			delete(d.domIPs, dom)
		}
	}
	for dom, st := range d.stats {
		if now-st.LastSeen > domainStatTTL {
			delete(d.stats, dom)
		}
	}
	for base, tr := range d.txt {
		if now-tr.last > 300 {
			delete(d.txt, base)
		}
	}
	if len(d.ipMap) > ipMapCap {
		d.evictIPMapLocked(now)
	}
	if len(d.stats) > domainStatCap {
		d.evictStatsLocked()
	}
}

func (d *DNSResolver) evictIPMapLocked(now int64) {
	list := make([]struct {
		ip   uint32
		last int64
	}, 0, len(d.ipMap))
	for ip, ent := range d.ipMap {
		list = append(list, struct {
			ip   uint32
			last int64
		}{ip, ent.last})
	}
	sort.Slice(list, func(i, j int) bool { return list[i].last < list[j].last })
	n := len(list) / 10
	if n < 1 {
		n = 1
	}
	for i := 0; i < n && i < len(list); i++ {
		delete(d.ipMap, list[i].ip)
	}
}

func (d *DNSResolver) evictDomIPsLocked(now int64) {
	list := make([]struct {
		dom  string
		last int64
	}, 0, len(d.domIPs))
	for dom, ent := range d.domIPs {
		list = append(list, struct {
			dom  string
			last int64
		}{dom, ent.last})
	}
	sort.Slice(list, func(i, j int) bool { return list[i].last < list[j].last })
	n := len(list) / 10
	if n < 1 {
		n = 1
	}
	for i := 0; i < n && i < len(list); i++ {
		delete(d.domIPs, list[i].dom)
	}
}

func (d *DNSResolver) evictStatsLocked() {
	list := make([]struct {
		dom  string
		last int64
	}, 0, len(d.stats))
	for dom, st := range d.stats {
		list = append(list, struct {
			dom  string
			last int64
		}{dom, st.LastSeen})
	}
	sort.Slice(list, func(i, j int) bool { return list[i].last < list[j].last })
	n := len(list) / 10
	if n < 1 {
		n = 1
	}
	for i := 0; i < n && i < len(list); i++ {
		delete(d.stats, list[i].dom)
	}
}

func (d *DNSResolver) evictTxtLocked() {
	for k := range d.txt {
		delete(d.txt, k)
		if len(d.txt) < txtTrackCap/2 {
			break
		}
	}
}

// SeedDomain 演示模式：预置域名统计。
func (d *DNSResolver) SeedDomain(domain, cat, label string, hits, bytes int64, devIP string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	now := nowUnix()
	st := &DomainStat{
		Domain: domain, Category: cat, Label: label,
		Hits: hits, BytesDown: bytes, FirstSeen: now - 3600, LastSeen: now,
		Devices: map[string]*DomainDev{},
	}
	if devIP != "" {
		st.Devices[devIP] = &DomainDev{Hits: hits / 10, Bytes: bytes / 4, LastSeen: now}
	}
	d.stats[domain] = st
}

// SeedIP 演示模式：预置 ip→domain 归因。
func (d *DNSResolver) SeedIP(ip, domain string) {
	addr, err := netipParse4(ip)
	if err != nil {
		return
	}
	d.mu.Lock()
	d.ipMap[addr] = &ipEntry{domain: domain, expires: nowUnix() + ipMapTTL, last: nowUnix()}
	d.mu.Unlock()
}

// displayDomain 归一化域名：命中规则时聚合到规则域名，否则去掉 www.。
func displayDomain(host string) (domain, cat, label, blockKind string) {
	host = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(host, ".")))
	if host == "" {
		return "", "", "", ""
	}
	cat, label, rule, kind := classifyHost(host)
	if rule == "" {
		rule = host
	}
	return rule, cat, label, kind
}

// baseDomain 取域名的后两级（用于 TXT 隧道按主域聚合）。
func baseDomain(host string) string {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	parts := strings.Split(host, ".")
	if len(parts) <= 2 {
		return host
	}
	return strings.Join(parts[len(parts)-2:], ".")
}

// avgLabelLen 子域标签平均长度（去掉主域后）。
func avgLabelLen(host string) int {
	host = strings.TrimSuffix(strings.TrimSpace(host), ".")
	parts := strings.Split(host, ".")
	if len(parts) <= 2 {
		return 0
	}
	sub := parts[:len(parts)-2]
	total := 0
	for _, s := range sub {
		total += len(s)
	}
	return total / len(sub)
}

func isTXTQType(t string) bool {
	t = strings.ToLower(strings.TrimSpace(t))
	return t == "txt" || t == "type=16" || strings.Contains(t, "16")
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func netipParse4(s string) (uint32, error) {
	ip := net.ParseIP(strings.TrimSpace(s))
	if ip == nil {
		return 0, fmt.Errorf("invalid ip")
	}
	v4 := ip.To4()
	if v4 == nil {
		return 0, fmt.Errorf("not ipv4")
	}
	return ip4ToUint32([4]byte{v4[0], v4[1], v4[2], v4[3]}), nil
}

// ---------------- DNS 日志 tail（按偏移量续读） ----------------

// runDNSTailer 后台线程：按偏移量续读 dnsmasq 日志；文件不存在时每 2s 重试。
func (a *App) runDNSTailer() {
	var offset int64
	missingLogged := false
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-a.stop:
			return
		case <-ticker.C:
			// 总开关/采集开关/DNS 旁挂开关任意关闭：不读日志文件
			if !a.dataActive() || !a.settings().DNSTap {
				continue
			}
			fi, err := os.Stat(dnsLogPath)
			if err != nil {
				if !missingLogged {
					logf("DNS 旁挂日志不存在（%s），等待 dnsmasq 写入或启用旁挂", dnsLogPath)
					missingLogged = true
				}
				offset = 0
				continue
			}
			missingLogged = false
			if fi.Size() < offset {
				offset = 0 // 文件被截断/重建
			}
			if fi.Size() > dnsLogMaxBytes {
				a.rotateDNSLog()
				offset = 0
				continue
			}
			if fi.Size() == offset {
				continue
			}
			n, err := a.readDNSLogFrom(offset)
			if err != nil {
				logf("读取 DNS 日志失败: %v", err)
				continue
			}
			offset += n
		}
	}
}

// readDNSLogFrom 从 offset 读取新日志行，返回消费的字节数。
func (a *App) readDNSLogFrom(offset int64) (int64, error) {
	f, err := os.Open(dnsLogPath)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	if _, err := f.Seek(offset, 0); err != nil {
		return 0, err
	}
	now := nowUnix()
	var consumed int64
	reader := bufio.NewReaderSize(f, 64*1024)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			// 末行不完整（还没等到换行）：不计入 consumed，也不解析，
			// 等下一轮补齐换行后再读，避免该条 DNS 记录被永久跳过。
			break
		}
		consumed += int64(len(line))
		trimmed := strings.TrimRight(line, "\r\n")
		if rec, ok := parseDNSLine(trimmed); ok {
			a.dns.HandleRecord(rec, now)
		}
	}
	return consumed, nil
}

// rotateDNSLog 超过 32MB 时轮转（mv + kill -HUP dnsmasq，dnsmasq 会重新打开日志）。
func (a *App) rotateDNSLog() {
	logf("DNS 日志超过 32MB，执行轮转")
	a.shellQuiet("mv -f " + dnsLogPath + " " + dnsLogPath + ".old")
	a.shellQuiet("kill -HUP $(pidof dnsmasq) 2>/dev/null")
}

// ---------------- DNS 旁挂开关（UCI logqueries + conf 文件 log-facility + 健康检查 + 回滚） ----------------

// dnsConfLogFacility 读取 /etc/dnsmasq.conf 的 log-facility 值（只读）。
// 返回（值, 是否存在）。存在指该行匹配 "log-facility=<值>"。
func (a *App) dnsConfLogFacility() (string, bool) {
	out, err := a.shellQuietOutput("grep -m1 -n '^[[:space:]]*log-facility[[:space:]]*=' " + dnsmasqConfPath + " 2>/dev/null")
	if err != nil || strings.TrimSpace(out) == "" {
		return "", false
	}
	// 形如 "38:log-facility=/dev/null" 或 "38:log-facility = /dev/null"
	line := strings.TrimSpace(out)
	if i := strings.Index(line, ":"); i >= 0 {
		line = line[i+1:]
	}
	line = strings.TrimSpace(line)
	line = strings.TrimSpace(strings.TrimPrefix(line, "log-facility"))
	line = strings.TrimSpace(strings.TrimLeft(line, "="))
	return strings.TrimSpace(line), true
}

// dnsConfSetLogFacility 把 /etc/dnsmasq.conf 的 log-facility 行替换为 newVal。
// 若该行存在则 sed 替换；不存在则追加一行（通常不会走到，conf 恒有该行）。
// 首次替换前把原值备份到 dnsConfBackup（供关闭时还原）。
func (a *App) dnsConfSetLogFacility(newVal string) error {
	// 备份原值（仅首次；备份文件存在且非空即视为已备份 —— 备份内容为纯值）
	if _, err := a.shellQuietOutput("test -s " + dnsConfBackup + " 2>/dev/null"); err != nil {
		cur, ok := a.dnsConfLogFacility()
		if ok && cur != newVal {
			a.shellQuiet("printf '%s\\n' '" + cur + "' > " + dnsConfBackup)
		}
	}
	// 替换 log-facility=<任意> 为 log-facility=<newVal>（容忍行首/等号周围空白；# 作分隔避免路径斜杠问题）
	if _, err := a.shell("sed -i 's#^[[:space:]]*log-facility[[:space:]]*=.*#log-facility=" + newVal + "#' " + dnsmasqConfPath); err != nil {
		return fmt.Errorf("修改 %s 的 log-facility 失败: %w", dnsmasqConfPath, err)
	}
	// 若原来没有该行（异常情况），追加
	a.shellQuiet("grep -q '^[[:space:]]*log-facility[[:space:]]*=' " + dnsmasqConfPath + " || echo 'log-facility=" + newVal + "' >> " + dnsmasqConfPath)
	// 校验替换后 log-facility 恰好 1 行（>1 说明仍有重复源，回滚前报错）。
	// demo / dry-run 下命令不真正执行、拿不到文件内容，跳过该校验（避免误判为失败）。
	if !a.cfg.Demo && !a.cfg.DryRun {
		if n, err := a.shellQuietOutput("grep -c '^[[:space:]]*log-facility[[:space:]]*=' " + dnsmasqConfPath + " 2>/dev/null"); err == nil {
			if strings.TrimSpace(n) != "1" {
				return fmt.Errorf("设置 %s 后 log-facility 出现 %s 行（应为 1），可能仍有重复源", dnsmasqConfPath, strings.TrimSpace(n))
			}
		}
	}
	return nil
}

// dnsConfRestoreLogFacility 还原 log-facility 为备份值（无备份则 /dev/null），并清掉备份文件。
// 返回 error 以便调用方在关闭开关时能感知还原失败（避免"已关闭但仍写日志"的静默漂移）。
func (a *App) dnsConfRestoreLogFacility() error {
	orig := "/dev/null"
	if out, err := a.shellQuietOutput("cat " + dnsConfBackup + " 2>/dev/null"); err == nil {
		if v := strings.TrimSpace(out); v != "" {
			orig = v
		}
	}
	if _, err := a.shell("sed -i 's#^[[:space:]]*log-facility[[:space:]]*=.*#log-facility=" + orig + "#' " + dnsmasqConfPath); err != nil {
		return fmt.Errorf("还原 %s 的 log-facility 失败: %w", dnsmasqConfPath, err)
	}
	a.shellQuiet("grep -q '^[[:space:]]*log-facility[[:space:]]*=' " + dnsmasqConfPath + " || echo 'log-facility=" + orig + "' >> " + dnsmasqConfPath)
	a.shellQuiet("rm -f " + dnsConfBackup)
	return nil
}

// DNSTapEnabled 判断 DNS 旁挂是否已启用（只读）。
// 判据：/etc/dnsmasq.conf 的 log-facility 指向 dnsLogPath，且 UCI logqueries=1。
func (a *App) DNSTapEnabled() bool {
	if a.cfg.Demo || a.cfg.DryRun {
		return a.store.Settings().DNSTap
	}
	val, ok := a.dnsConfLogFacility()
	if !ok || val != dnsLogPath {
		return false
	}
	out, _ := a.shellQuietOutput("uci get dhcp.@dnsmasq[0].logqueries 2>/dev/null")
	return strings.TrimSpace(out) == "1"
}

// ApplyDNSTap 启用/关闭 DNS 旁挂。失败自动还原并返回中文错误。
// 注意：该操作会 stop/start dnsmasq（DNS 有 1~2 秒空窗），仅在用户明确操作时调用。
// demo / dry-run 下所有命令只记录不执行（App.shell 统一短路）。
//
// 实现（规避 flippy 固件 log-facility 重复关键字）：
//   - UCI 只写 logqueries=1（不写 logfacility，避免与 conf 文件冲突）；
//   - log-facility 通过精确修改 /etc/dnsmasq.conf 指向 dnsLogPath（备份原值）；
//   - 关闭时还原 conf 的 log-facility 并删除 UCI logqueries。
func (a *App) ApplyDNSTap(enabled bool) error {
	a.dnsTapMu.Lock()
	defer a.dnsTapMu.Unlock()

	if !a.cfg.Demo && !a.cfg.DryRun {
		if err := os.MkdirAll(dnsLogDir, 0o755); err != nil {
			return fmt.Errorf("创建 DNS 日志目录失败: %w", err)
		}
	}
	if enabled {
		a.shellQuiet("uci set dhcp.@dnsmasq[0].logqueries='1'")
		if err := a.dnsConfSetLogFacility(dnsLogPath); err != nil {
			a.shellQuiet("uci delete dhcp.@dnsmasq[0].logqueries")
			a.shellQuiet("uci commit dhcp")
			// conf 可能已被部分修改（例如重复行校验失败发生在 sed 之后），一并还原
			if rerr := a.dnsConfRestoreLogFacility(); rerr != nil {
				logf("回滚时还原 log-facility 也失败: %v", rerr)
			}
			return fmt.Errorf("设置 DNS 日志去向失败，已回滚: %w", err)
		}
		if _, err := a.shell("uci commit dhcp"); err != nil {
			a.shellQuiet("uci delete dhcp.@dnsmasq[0].logqueries")
			_ = a.dnsConfRestoreLogFacility()
			return fmt.Errorf("提交 UCI 配置失败，已回滚: %w", err)
		}
		if err := a.restartDNSMasq(); err != nil {
			// 回滚：删 UCI logqueries + 还原 conf log-facility + 重启
			logf("DNS 旁挂启用失败，开始回滚: %v", err)
			a.shellQuiet("uci delete dhcp.@dnsmasq[0].logqueries")
			a.shellQuiet("uci commit dhcp")
			if rerr := a.dnsConfRestoreLogFacility(); rerr != nil {
				logf("回滚时还原 log-facility 也失败: %v", rerr)
			}
			a.restartDNSMasq()
			return fmt.Errorf("启用 DNS 旁挂失败，已回滚: %v", err)
		}
		logf("DNS 旁挂已启用：%s", dnsLogPath)
		return nil
	}

	a.shellQuiet("uci delete dhcp.@dnsmasq[0].logqueries")
	if _, err := a.shell("uci commit dhcp"); err != nil {
		return fmt.Errorf("提交 UCI 配置失败: %w", err)
	}
	if err := a.dnsConfRestoreLogFacility(); err != nil {
		// 还原失败：尝试反做（重设旁挂）并返回错误，避免"已关闭但仍写日志"漂移
		logf("DNS 旁挂关闭时还原 log-facility 失败，尝试反做: %v", err)
		a.shellQuiet("uci set dhcp.@dnsmasq[0].logqueries='1'")
		a.shellQuiet("uci commit dhcp")
		_ = a.dnsConfSetLogFacility(dnsLogPath)
		a.restartDNSMasq()
		return fmt.Errorf("关闭 DNS 旁挂失败（还原 log-facility 失败，已反做）: %w", err)
	}
	if err := a.restartDNSMasq(); err != nil {
		logf("DNS 旁挂关闭失败，开始回滚: %v", err)
		a.shellQuiet("uci set dhcp.@dnsmasq[0].logqueries='1'")
		a.shellQuiet("uci commit dhcp")
		_ = a.dnsConfSetLogFacility(dnsLogPath)
		a.restartDNSMasq()
		return fmt.Errorf("关闭 DNS 旁挂失败，已回滚: %v", err)
	}
	logf("DNS 旁挂已关闭")
	return nil
}

// restartDNSMasq stop → sleep 1 → start → 健康检查；禁止使用 reload。
func (a *App) restartDNSMasq() error {
	logf("重启 dnsmasq（stop + start，禁止 reload）")
	if _, err := a.shell("/etc/init.d/dnsmasq stop"); err != nil {
		return fmt.Errorf("停止 dnsmasq 失败: %w", err)
	}
	time.Sleep(1 * time.Second)
	if _, err := a.shell("/etc/init.d/dnsmasq start"); err != nil {
		return fmt.Errorf("启动 dnsmasq 失败: %w", err)
	}
	for i := 0; i < 16; i++ {
		time.Sleep(500 * time.Millisecond)
		if a.dnsHealthy() {
			return nil
		}
	}
	return fmt.Errorf("dnsmasq 启动后 DNS 健康检查未通过")
}

// dnsHealthy 健康检查：优先 nslookup，失败再直接向 127.0.0.1:53 发 UDP 查询。
func (a *App) dnsHealthy() bool {
	if a.cfg.Demo || a.cfg.DryRun {
		return true
	}
	if _, err := a.shell("nslookup www.baidu.com 127.0.0.1 >/dev/null 2>&1"); err == nil {
		return true
	}
	return dnsProbe("127.0.0.1:53")
}

// dnsProbe 发送一条最小 DNS A 查询，收到任意响应即认为 DNS 服务存活。
func dnsProbe(addr string) bool {
	host := "www.baidu.com"
	pkt := make([]byte, 12, 12+len(host)+6)
	id := uint16(rand.Intn(65535))
	binary.BigEndian.PutUint16(pkt[0:], id)
	pkt[2] = 0x01 // RD
	pkt[5] = 0x01 // QDCOUNT
	for _, part := range strings.Split(host, ".") {
		pkt = append(pkt, byte(len(part)))
		pkt = append(pkt, part...)
	}
	pkt = append(pkt, 0, 0, 1, 0, 1) // QTYPE=A, QCLASS=IN
	conn, err := net.DialTimeout("udp", addr, 1500*time.Millisecond)
	if err != nil {
		return false
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write(pkt); err != nil {
		return false
	}
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil || n < 12 {
		return false
	}
	return binary.BigEndian.Uint16(buf[0:]) == id
}

// ResolveDomain 解析域名（先查日志观测缓存，再用本地 127.0.0.1:53 解析）。
// 用于域名封堵写 ipset；解析失败返回空列表，由调用方安排重试。
func (a *App) ResolveDomain(domain string) []string {
	now := nowUnix()
	if ips := a.dns.IPsForDomain(domain, now); len(ips) > 0 {
		return ips
	}
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" || strings.ContainsAny(domain, " *?/") {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	ips, err := localLookup(ctx, domain)
	if err != nil {
		return nil
	}
	return ips
}

// localLookup 用本地 dnsmasq（127.0.0.1:53）解析。
func localLookup(ctx context.Context, domain string) ([]string, error) {
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 3 * time.Second}
			return d.DialContext(ctx, "udp", "127.0.0.1:53")
		},
	}
	addrs, err := r.LookupHost(ctx, domain)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(addrs))
	for _, s := range addrs {
		if ip := net.ParseIP(s); ip != nil && ip.To4() != nil {
			out = append(out, ip.String())
		}
	}
	return out, nil
}

// Clear 清空域名归因与统计（关闭采集开关时调用）。
func (d *DNSResolver) Clear() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.ipMap = map[uint32]*ipEntry{}
	d.ipLong = map[uint32]*ipEntry{}
	d.domIPs = map[string]*domIPEntry{}
	d.stats = map[string]*DomainStat{}
	d.txt = map[string]*txtTrack{}
	d.devRecent = map[string]*devRecentEntry{}
	d.qTimes = nil
	d.lastTrim = 0
}

// strconvInt 小工具（避免引入额外依赖）。
func strconvInt(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}
