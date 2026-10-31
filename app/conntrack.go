package main

// conntrack 采集：流式解析 + 字节差分。
//
// 内存与性能约束（路由器 conntrack 可达 8.5 万条）：
//   - 用 bufio.Scanner 逐行扫描 /proc/net/nf_conntrack，绝不整文件 ReadFile；
//   - 解析在栈上完成，IP 用 uint32 表示（无字符串分配），仅 LAN 侧条目构建 flow key；
//   - 差分快照只保留 LAN 侧 flow：map[flowKey]flowSnap，上限 maxFlows（默认 20000），
//     超限时按最早开始时间淘汰；
//   - 每轮只把「有增量」或「新出现」的 flow 通过回调交给聚合层，中间态立即丢弃；
//   - 条目消失时回调 emitGone，由聚合层删除连接明细（最后一小段字节可接受地丢失）。

import (
	"bufio"
	"bytes"
	"io"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

// conntrackPath 采集文件（变量形式便于测试/demo 替换）。
var conntrackPath = "/proc/net/nf_conntrack"

// ctEntry 一行 conntrack 条目（仅解析需要的字段）。
type ctEntry struct {
	Proto      string
	State      string
	V4         bool
	SrcIP      uint32
	DstIP      uint32
	SPort      int
	DPort      int
	Mark       uint32 // conntrack mark（passwall 等代理常用 0x1/0x2 标记被代理连接）
	OrigBytes  int64
	ReplyBytes int64
}

// flowKey 规范化 flow 键：LAN 源 -> 目的。
type flowKey struct {
	Proto uint8
	Dev   uint32
	SPort uint16
	Dst   uint32
	DPort uint16
}

// flowSnap 差分快照（紧凑结构，20000 条约 1.5MB）。
type flowSnap struct {
	Up      uint64
	Down    uint64
	Started int64
	Gen     uint32
}

// FlowDelta 一次采样得到的增量。
type FlowDelta struct {
	Key       string
	DeviceIP  string
	DstIP     string
	SPort     int
	DPort     int
	Proto     string
	State     string
	Path      string // 流向：direct / proxy / zerotier / vpn / lan
	Iface     string // 设备侧接口名（br-lan / zt6vwy3rne / tun0 ...）
	UpDelta   int64
	DownDelta int64
	TotalUp   int64
	TotalDown int64
	Started   int64
	New       bool
	Baseline  bool // 启动首个采样轮：只登记连接，不参与统计/研判
}

// ipNet 一个网段及其类型/接口（用于多网段设备识别与流向判断）。
type ipNet struct {
	net   uint32
	mask  uint32
	kind  string // lan / zerotier / vpn
	iface string // 接口名（可空）
}

// ConnEngine conntrack 差分引擎（单 goroutine 使用，无需锁）。
type ConnEngine struct {
	deviceNets []ipNet // 设备网段（br-lan + zt/vpn 本地接口）
	routeNets  []ipNet // 路由目标网段（经 zt/vpn 可达的远端网段）
	maxFlows   int
	flows      map[flowKey]*flowSnap
	gen        uint32
	baseline   bool
}

// NewConnEngine 按 LAN 网段创建引擎；extra 为额外设备网段（默认按 lan 处理）。
// 运行期由 App.syncConnNets() 用拓扑采集结果覆盖为多网段（zt/vpn）。
func NewConnEngine(lanCIDR string, extra ...string) *ConnEngine {
	e := &ConnEngine{maxFlows: 20000, flows: map[flowKey]*flowSnap{}, baseline: true}
	for _, cidr := range append([]string{lanCIDR}, extra...) {
		if n, ok := ipNetFromCIDR(cidr, "lan", ""); ok {
			e.deviceNets = append(e.deviceNets, n)
		}
	}
	return e
}

// SetNets 更新设备网段与路由目标网段（运行期动态，来自 ip -br addr / ip route）。
func (e *ConnEngine) SetNets(device, route []ipNet) {
	e.deviceNets = append([]ipNet(nil), device...)
	e.routeNets = append([]ipNet(nil), route...)
}

// Reset 清空差分状态（例如设置里改了 LAN 网段）。
func (e *ConnEngine) Reset() {
	e.flows = map[flowKey]*flowSnap{}
	e.baseline = false
}

// ipNetFromCIDR 解析 CIDR 为 ipNet。
func ipNetFromCIDR(cidr, kind, iface string) (ipNet, bool) {
	prefix, err := netip.ParsePrefix(strings.TrimSpace(cidr))
	if err != nil || !prefix.Addr().Is4() {
		return ipNet{}, false
	}
	addr := prefix.Addr().As4()
	bits := prefix.Bits()
	if bits < 0 || bits > 32 {
		return ipNet{}, false
	}
	mask := ^uint32(0)
	if bits < 32 {
		mask = ^uint32(0) << (32 - bits)
	}
	return ipNet{net: ip4ToUint32(addr) & mask, mask: mask, kind: kind, iface: iface}, true
}

// matchDevice 判断 IP 是否属于任一设备网段，返回命中的网段。
func (e *ConnEngine) matchDevice(ip uint32) (ipNet, bool) {
	for _, n := range e.deviceNets {
		if ip&n.mask == n.net {
			return n, true
		}
	}
	return ipNet{}, false
}

// matchRoute 判断目的 IP 是否命中路由目标网段，返回命中的网段。
func (e *ConnEngine) matchRoute(ip uint32) (ipNet, bool) {
	for _, n := range e.routeNets {
		if ip&n.mask == n.net {
			return n, true
		}
	}
	return ipNet{}, false
}

// proxyPortSet 常见代理端口（目的端口命中即认为走代理）。
var proxyPortSet = map[int]bool{
	7890: true, 7891: true, 7892: true, 1080: true, 1081: true,
	8888: true, 8889: true, 9090: true, 10808: true, 10809: true, 10810: true,
}

// pathFor 判断一条连接的网络流向。
//   - dst 命中 zt 路由/接口网段 → zerotier；命中 vpn → vpn；
//   - dst 属于任一设备网段（内网互访）→ lan；
//   - dst 是公网且 conntrack mark>0（passwall/xray TPROXY 等代理标记）或目的端口是代理端口 → proxy；
//   - dst 是私网但非设备网段（docker0 等）→ lan；
//   - 其余公网 → direct。
func (e *ConnEngine) pathFor(dstIP uint32, dport int, mark uint32) string {
	if n, ok := e.matchRoute(dstIP); ok {
		if n.kind == "zerotier" || n.kind == "vpn" {
			return n.kind
		}
	}
	if _, ok := e.matchDevice(dstIP); ok {
		return "lan"
	}
	dst := ip4String(dstIP)
	if isPrivateIPStr(dst) {
		return "lan"
	}
	if mark > 0 || proxyPortSet[dport] {
		return "proxy"
	}
	return "direct"
}

// CollectFile 读取并处理 conntrack 文件。返回解析到的条目总数。
func (e *ConnEngine) CollectFile(path string, now int64, emit func(FlowDelta), gone func(string)) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	return e.Collect(f, now, emit, gone)
}

// Collect 流式处理 conntrack 内容。
func (e *ConnEngine) Collect(r io.Reader, now int64, emit func(FlowDelta), gone func(string)) (int, error) {
	e.gen++
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	total := 0
	for sc.Scan() {
		ent, ok := parseConntrackLine(sc.Bytes())
		if !ok {
			continue
		}
		total++
		if !ent.V4 {
			continue
		}
		key, up, down, meta, ok := e.normalize(ent)
		if !ok {
			continue
		}
		snap, exists := e.flows[key]
		if !exists {
			snap = &flowSnap{Started: now}
			e.flows[key] = snap
			delta := e.makeDelta(key, ent, meta, up, down, snap.Started, true)
			if e.baseline {
				delta.Baseline = true
			}
			emit(delta)
		} else {
			var du, dd int64
			if uint64(up) > snap.Up {
				du = int64(uint64(up) - snap.Up)
			}
			if uint64(down) > snap.Down {
				dd = int64(uint64(down) - snap.Down)
			}
			if du > 0 || dd > 0 {
				delta := e.makeDelta(key, ent, meta, up, down, snap.Started, false)
				delta.UpDelta = du
				delta.DownDelta = dd
				emit(delta)
			}
		}
		snap.Up = uint64(up)
		snap.Down = uint64(down)
		snap.Gen = e.gen
	}
	if err := sc.Err(); err != nil {
		return total, err
	}

	// 清理本轮未出现的 flow
	for k, snap := range e.flows {
		if snap.Gen != e.gen {
			if gone != nil {
				gone(flowID(k))
			}
			delete(e.flows, k)
		}
	}
	e.evict()
	e.baseline = false
	return total, nil
}

// flowMeta 设备/流向元信息（随 FlowDelta 下发）。
type flowMeta struct {
	path   string
	iface  string
	device bool // 是否设备侧连接（false = 本机/docker0 等非用户设备流量，只计入链路不展示连接）
}

// normalize 判断方向并生成规范化 key，同时返回设备方向的上/下行累计字节与流向元信息。
func (e *ConnEngine) normalize(ent ctEntry) (flowKey, int64, int64, flowMeta, bool) {
	k := flowKey{Proto: protoCode(ent.Proto)}
	if n, ok := e.matchDevice(ent.SrcIP); ok {
		k.Dev = ent.SrcIP
		k.SPort = uint16(ent.SPort)
		k.Dst = ent.DstIP
		k.DPort = uint16(ent.DPort)
		meta := flowMeta{
			path:   e.pathFor(ent.DstIP, ent.DPort, ent.Mark),
			iface:  n.iface,
			device: true,
		}
		if meta.iface == "" {
			meta.iface = "br-lan"
		}
		return k, ent.OrigBytes, ent.ReplyBytes, meta, true
	}
	if n, ok := e.matchDevice(ent.DstIP); ok {
		// 反向：设备是回复方向的源（例如 WAN 主动连入），交换方向
		k.Dev = ent.DstIP
		k.SPort = uint16(ent.DPort)
		k.Dst = ent.SrcIP
		k.DPort = uint16(ent.SPort)
		meta := flowMeta{
			path:   e.pathFor(ent.SrcIP, ent.SPort, ent.Mark),
			iface:  n.iface,
			device: true,
		}
		if meta.iface == "" {
			meta.iface = "br-lan"
		}
		return k, ent.ReplyBytes, ent.OrigBytes, meta, true
	}
	// 非用户设备来源（本机 / docker0 等）：mark>0 且目的为公网 → 计入 proxy 链路流量，
	// 但 DeviceIP 留空，连接表/设备统计不展示这些行（避免 docker0 混进设备列表）。
	if ent.Mark > 0 && !isPrivateIPStr(ip4String(ent.DstIP)) {
		k.Dev = ent.SrcIP
		k.SPort = uint16(ent.SPort)
		k.Dst = ent.DstIP
		k.DPort = uint16(ent.DPort)
		return k, ent.OrigBytes, ent.ReplyBytes, flowMeta{path: "proxy", device: false}, true
	}
	return k, 0, 0, flowMeta{}, false
}

func (e *ConnEngine) makeDelta(k flowKey, ent ctEntry, meta flowMeta, up, down int64, started int64, isNew bool) FlowDelta {
	devIP := ip4String(k.Dev)
	if !meta.device {
		devIP = "" // 非设备流量（docker0/本机代理）只计入链路，不进连接表/设备统计
	}
	d := FlowDelta{
		Key:       flowID(k),
		DeviceIP:  devIP,
		DstIP:     ip4String(k.Dst),
		SPort:     int(k.SPort),
		DPort:     int(k.DPort),
		Proto:     protoName(k.Proto),
		State:     ent.State,
		Path:      meta.path,
		Iface:     meta.iface,
		TotalUp:   up,
		TotalDown: down,
		Started:   started,
		New:       isNew,
	}
	if e.baseline {
		return d
	}
	// 新 flow 的累计值即本区间增量（该 flow 在两次采样之间建立）
	if isNew {
		d.UpDelta = up
		d.DownDelta = down
	}
	return d
}

// evict 控制快照容量，超限时淘汰最早开始的 flow。
func (e *ConnEngine) evict() {
	if len(e.flows) <= e.maxFlows {
		return
	}
	type pair struct {
		k flowKey
		t int64
	}
	list := make([]pair, 0, len(e.flows)-e.maxFlows+1)
	for k, s := range e.flows {
		list = append(list, pair{k, s.Started})
	}
	// 简单选择：按开始时间排序后删除最旧的 10%
	for i := 0; i < len(list); i++ {
		for j := i + 1; j < len(list); j++ {
			if list[j].t < list[i].t {
				list[i], list[j] = list[j], list[i]
			}
		}
		if i > 1024 {
			break // 避免极端情况下 O(n^2)
		}
	}
	need := len(e.flows) - e.maxFlows + 1
	n := len(list) / 10
	if n < need {
		n = need
	}
	if n > len(list) {
		n = len(list)
	}
	for i := 0; i < n; i++ {
		delete(e.flows, list[i].k)
	}
}

// protoCode 协议名 -> 单字节编码。
func protoCode(proto string) uint8 {
	switch proto {
	case "tcp":
		return 6
	case "udp":
		return 17
	case "icmp":
		return 1
	case "icmpv6":
		return 58
	case "sctp":
		return 132
	}
	return 0
}

func protoName(code uint8) string {
	switch code {
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 1:
		return "icmp"
	case 58:
		return "icmpv6"
	case 132:
		return "sctp"
	}
	return "other"
}

// flowID 生成连接 ID：proto-devip-sport-dstip-dport（api.md §4 示例格式）。
func flowID(k flowKey) string {
	var b [22]byte
	buf := b[:0]
	buf = append(buf, protoName(k.Proto)...)
	buf = append(buf, '-')
	buf = appendIP4(buf, k.Dev)
	buf = append(buf, '-')
	buf = strconv.AppendUint(buf, uint64(k.SPort), 10)
	buf = append(buf, '-')
	buf = appendIP4(buf, k.Dst)
	buf = append(buf, '-')
	buf = strconv.AppendUint(buf, uint64(k.DPort), 10)
	return string(buf)
}

// ---------------- 纯解析函数（可单测） ----------------

// parseConntrackLine 解析 nf_conntrack 一行。
// 示例：
//
//	ipv4 2 tcp 6 61 SYN_SENT src=192.168.1.106 dst=112.252.211.104 sport=11223 dport=17776
//	packets=1 bytes=52 [UNREPLIED] src=112.252.211.104 dst=192.168.1.254 sport=17776 dport=11223
//	packets=0 bytes=0 mark=0 zone=0 use=2
//
// 解析失败返回 false（不认识的协议行直接跳过）。
func parseConntrackLine(line []byte) (ctEntry, bool) {
	var e ctEntry
	var (
		origSrc, origDst   uint32
		origSP, origDP     int
		replySrc, replyDst uint32
		origBytes          int64
		replyBytes         int64
		sec                = -1
		curSrc, curDst     uint32
		curSP, curDP       int
		curBytes           int64
		haveSrc            bool
	)
	flush := func() {
		if sec == 0 {
			origSrc, origDst, origSP, origDP, origBytes = curSrc, curDst, curSP, curDP, curBytes
		} else if sec == 1 {
			replySrc, replyDst, replyBytes = curSrc, curDst, curBytes
		}
	}
	resetSection := func(s int) {
		sec = s
		curSrc, curDst, curSP, curDP, curBytes = 0, 0, 0, 0, 0
		haveSrc = false
	}

	idx := 0
	i := 0
	for i < len(line) {
		// 跳过空格
		for i < len(line) && line[i] == ' ' {
			i++
		}
		if i >= len(line) {
			break
		}
		start := i
		for i < len(line) && line[i] != ' ' {
			i++
		}
		tok := line[start:i]
		if len(tok) == 0 {
			continue
		}
		if idx < 3 {
			if idx == 2 {
				e.Proto = string(tok)
			}
			idx++
			continue
		}
		idx++
		eq := bytes.IndexByte(tok, '=')
		if eq < 0 {
			// 状态字段（ESTABLISHED / SYN_SENT ...），忽略纯数字（协议号/超时）和 [UNREPLIED] 标记
			if e.State == "" && !isNumericTok(tok) && tok[0] != '[' {
				e.State = string(tok)
			}
			continue
		}
		key := tok[:eq]
		val := tok[eq+1:]
		switch string(key) {
		case "src":
			if haveSrc {
				// 第二个 src 表示 reply 段开始
				if sec < 0 {
					sec = 0
				}
				flush()
				resetSection(1)
			} else if sec < 0 {
				sec = 0
			}
			if ip, ok := parseIPv4(val); ok {
				curSrc = ip
				haveSrc = true
			}
		case "dst":
			if ip, ok := parseIPv4(val); ok {
				curDst = ip
			}
		case "sport":
			curSP = atoiSafe(val)
		case "dport":
			curDP = atoiSafe(val)
		case "bytes":
			curBytes = atoi64Safe(val)
		case "mark":
			// passwall 等代理会用 conntrack mark 标记被代理连接（如 0x1/0x2）
			e.Mark = uint32(atoi64Safe(val))
		}
	}
	flush()

	if e.Proto == "" || origSrc == 0 || origDst == 0 {
		return e, false
	}
	e.V4 = true
	e.SrcIP = origSrc
	e.DstIP = origDst
	e.SPort = origSP
	e.DPort = origDP
	e.OrigBytes = origBytes
	if replySrc != 0 && replyDst != 0 {
		e.ReplyBytes = replyBytes
	}
	return e, true
}

// parseIPv4 手工解析点分十进制 IPv4（避免字符串分配）。
func parseIPv4(b []byte) (uint32, bool) {
	var ip uint32
	part := 0
	val := 0
	digits := 0
	for _, c := range b {
		switch {
		case c >= '0' && c <= '9':
			val = val*10 + int(c-'0')
			digits++
			if val > 255 {
				return 0, false
			}
		case c == '.':
			if digits == 0 || part >= 3 {
				return 0, false
			}
			ip = ip<<8 | uint32(val)
			part++
			val, digits = 0, 0
		default:
			return 0, false
		}
	}
	if part != 3 || digits == 0 {
		return 0, false
	}
	ip = ip<<8 | uint32(val)
	return ip, true
}

func appendIP4(dst []byte, ip uint32) []byte {
	dst = strconv.AppendUint(dst, uint64(ip>>24), 10)
	dst = append(dst, '.')
	dst = strconv.AppendUint(dst, uint64((ip>>16)&0xff), 10)
	dst = append(dst, '.')
	dst = strconv.AppendUint(dst, uint64((ip>>8)&0xff), 10)
	dst = append(dst, '.')
	dst = strconv.AppendUint(dst, uint64(ip&0xff), 10)
	return dst
}

func ip4String(ip uint32) string {
	var b [15]byte
	return string(appendIP4(b[:0], ip))
}

func ip4ToUint32(a [4]byte) uint32 {
	return uint32(a[0])<<24 | uint32(a[1])<<16 | uint32(a[2])<<8 | uint32(a[3])
}

// isNumericTok 判断 token 是否全为数字（用于跳过 conntrack 的协议号/超时字段）。
func isNumericTok(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	for _, c := range b {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func atoiSafe(b []byte) int {
	n, _ := atoiOK(b)
	return n
}

// atoiOK 解析纯数字 token，返回是否合法。
func atoiOK(b []byte) (int, bool) {
	if len(b) == 0 {
		return 0, false
	}
	n := 0
	for _, c := range b {
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + int(c-'0')
		if n > 1<<30 {
			return 0, false
		}
	}
	return n, true
}

func atoi64Safe(b []byte) int64 {
	n, _ := atoi64OK(b)
	return n
}

// atoi64OK 解析纯数字 token 为 int64。
func atoi64OK(b []byte) (int64, bool) {
	if len(b) == 0 {
		return 0, false
	}
	var n int64
	for _, c := range b {
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + int64(c-'0')
		if n > 1<<50 {
			return 0, false
		}
	}
	return n, true
}

// ---------------- IP 辅助判断 ----------------

// isPrivateIPStr 判断是否内网地址（RFC1918 / CGNAT / 回环 / 链路本地）。
func isPrivateIPStr(s string) bool {
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return false
	}
	return addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast()
}

// isForeignIP 判断目的地是否"境外"。无 GeoIP 库时用常见中国 ISP/云厂商前缀做启发式，
// 结果只用于 traffic_anomaly 研判与设备详情展示，不参与任何管控。
func isForeignIP(s string) bool {
	addr, err := netip.ParseAddr(s)
	if err != nil || !addr.Is4() {
		return false
	}
	if addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() {
		return false
	}
	ip := ip4ToUint32(addr.As4())
	for _, p := range cnPrefixes {
		if ip&p.mask == p.net {
			return false
		}
	}
	return true
}

type cnPrefix struct {
	net  uint32
	mask uint32
}

func mk32(a, b, c, d uint32) uint32 { return a<<24 | b<<16 | c<<8 | d }

func cidr8(a uint32) cnPrefix { return cnPrefix{net: a << 24, mask: 0xff000000} }
func cidr12(a, b uint32) cnPrefix {
	return cnPrefix{net: a<<24 | b<<20, mask: 0xfff00000}
}
func cidr16(a, b uint32) cnPrefix {
	return cnPrefix{net: a<<24 | b<<16, mask: 0xffff0000}
}

// cnPrefixes 中国常见公网前缀（启发式，覆盖主要 ISP/云/CDN）。
var cnPrefixes = []cnPrefix{
	cidr8(1), cidr8(14), cidr8(27), cidr8(36), cidr8(39), cidr8(42), cidr8(43),
	cidr8(49), cidr8(58), cidr8(59), cidr8(60), cidr8(61), cidr8(101), cidr8(106),
	cidr8(110), cidr8(111), cidr8(112), cidr8(113), cidr8(114), cidr8(115), cidr8(116),
	cidr8(117), cidr8(118), cidr8(119), cidr8(120), cidr8(121), cidr8(122), cidr8(123),
	cidr8(124), cidr8(125), cidr8(175), cidr8(180), cidr8(182), cidr8(183), cidr8(203),
	cidr8(210), cidr8(211), cidr8(218), cidr8(219), cidr8(220), cidr8(221), cidr8(222),
	cidr8(223), cidr12(100, 64), cidr12(100, 96), cidr16(202, 96), cidr16(202, 97),
	cidr16(202, 99), cidr16(202, 100), cidr16(202, 101), cidr16(202, 102),
	cidr16(202, 103), cidr16(202, 104), cidr16(202, 105), cidr16(202, 106),
	cidr16(202, 107), cidr16(202, 108), cidr16(202, 109), cidr16(202, 110),
	cidr16(202, 111), cidr16(202, 112), cidr16(202, 113), cidr16(202, 114),
	cidr16(202, 115), cidr16(202, 116), cidr16(202, 117), cidr16(202, 118),
	cidr16(202, 119), cidr16(202, 120), cidr16(202, 121), cidr16(202, 122),
	cidr16(202, 123), cidr16(202, 124), cidr16(202, 125),
	cidr16(114, 114), cidr16(223, 5), cidr16(223, 6), cidr16(119, 29),
	cidr16(119, 75), cidr16(8, 210), cidr16(8, 209),
}

// ---------------- 演示/测试辅助 ----------------

// ctEntryFrom4 构造 IPv4 条目（demo 生成合成流量时复用同一差分路径）。
func ctEntryFrom4(proto, state, src, dst string, sport, dport int, up, down int64) (ctEntry, bool) {
	s, err1 := netip.ParseAddr(src)
	d, err2 := netip.ParseAddr(dst)
	if err1 != nil || err2 != nil || !s.Is4() || !d.Is4() {
		return ctEntry{}, false
	}
	return ctEntry{
		Proto: proto, State: state, V4: true,
		SrcIP: ip4ToUint32(s.As4()), DstIP: ip4ToUint32(d.As4()),
		SPort: sport, DPort: dport,
		OrigBytes: up, ReplyBytes: down,
	}, true
}
