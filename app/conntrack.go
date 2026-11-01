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
//
// 差分口径（重要，勿随意改动）：
//   - 单流增量不设固定上限：只要累计值没有倒退，就按差值计入（高速单流不能被永久漏计）；
//   - 累计值倒退（up < snap.Up 或 down < snap.Down）说明该 key 对应的流被重建
//     （端口复用 / tuple 形态切换），新旧累计值不可比，此时只更新快照、不计入增量；
//   - 新 key 首见：累计字节很小 → 累计值即本区间增量；累计字节很大 → 不推进该流的
//     快照基线，下一轮把累计值一次性计入（避免首见窗口的字节永久丢失）；
//   - baseline 轮（启动/Reset 后的第一轮）只登记快照，不计入任何统计（避免幻影流量）。

import (
	"bufio"
	"bytes"
	"io"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
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
	// Dir 方向标记：0 = 设备在 orig 侧，1 = 设备在 reply 侧。
	// conntrack 表中同一条流会占两行（原方向一行、反向一行），若不区分方向，
	// 两行会落到同一个 key，orig/reply 的累计值互相覆盖，差分时产生大量虚假增量。
	Dir uint8
}

// flowSnap 差分快照（紧凑结构，20000 条约 1.5MB）。
type flowSnap struct {
	Up       uint64
	Down     uint64
	Started  int64
	Gen      uint32
	LastSeen int64 // 最后一次在 conntrack 表中出现的时间（用于老化淘汰）
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

// ConnEngine conntrack 差分引擎。
// 常规路径由采集协程单 goroutine 驱动；Reset 由 HTTP 协程调用，
// 因此 flows/retired/baseline/gen 由 mu 串行化。
type ConnEngine struct {
	// nets 网段与本机 IP 快照（整体原子替换）。
	// 设备刷新协程写、采集协程读，用 atomic.Value 避免「新指针 + 旧长度」的中间态。
	nets     atomic.Value // netsSnapshot
	maxFlows int
	flows    map[flowKey]*flowSnap
	// retired 被淘汰/老化流的最后累计值（幻影流量防护）：
	// 一条流的快照因容量/老化被移除后，若它在 conntrack 表里重现，
	// 没有墓碑就会被当成「从未见过的大额新流」，其全生命周期累计字节
	//（可达数百 MB）被一次性计入 2 秒增量。墓碑保留基线后可正确差分。
	retired    map[flowKey]flowSnap
	maxRetired int
	gen        uint32
	baseline   bool
	mu         sync.Mutex // 串行化 Reset 与 Collect 对 flows/retired/baseline 的访问
	flowMu     sync.Mutex // 保护 flowHook
	flowHook   func(FlowContext)
}

// netsSnapshot 设备网段 / 路由网段 / 本机 IP 的不可变快照。
type netsSnapshot struct {
	device []ipNet
	route  []ipNet
	self   map[uint32]bool
}

// FlowContext 一条连接的流向上下文（emit 前后发布，供其它模块判断是否走代理）。
type FlowContext struct {
	DeviceIP string
	DstIP    string
	SPort    int
	DPort    int
	Proto    string
	Path     string // direct / proxy / zerotier / vpn / lan
}

// smallFlowBytes 新 key 的「累计字节」低于该阈值才视为本区间新建的流并计入增量。
// 超过阈值的绝大多数是首见之前就存在的旧流（conntrack 表 churn / 端口复用 / tuple 形态切换），
// 直接把它们的累计值当增量会成百上千倍高估流量（实测放大 1000 倍以上）。
// 阈值取 16KB：既能保留真正的新建小流，又最大限度避免旧流重现被重复计入。
// 注意：超过阈值时并不是丢弃，而是「不推进快照基线」——下一轮把累计值一次性计入。
const smallFlowBytes = 16 * 1024

// NewConnEngine 按 LAN 网段创建引擎；extra 为额外设备网段（默认按 lan 处理）。
// 运行期由 App.syncConnNets() 用拓扑采集结果覆盖为多网段（zt/vpn）。
func NewConnEngine(lanCIDR string, extra ...string) *ConnEngine {
	e := &ConnEngine{
		maxFlows: 20000, flows: map[flowKey]*flowSnap{},
		retired: map[flowKey]flowSnap{}, maxRetired: 30000, baseline: true,
	}
	var device []ipNet
	for _, cidr := range append([]string{lanCIDR}, extra...) {
		if n, ok := ipNetFromCIDR(cidr, "lan", ""); ok {
			device = append(device, n)
		}
	}
	e.setNets(device, nil)
	return e
}

// SetSelfIPs 设置本机各接口的 IPv4（路由器自身）。
// 本机出站连接（如 xray 透明代理的出口）不计入任何设备，只计入链路流向。
func (e *ConnEngine) SetSelfIPs(ips []uint32) {
	m := make(map[uint32]bool, len(ips))
	for _, ip := range ips {
		m[ip] = true
	}
	snap := e.netsSnapshot()
	snap.self = m
	e.nets.Store(snap)
}

// SetNets 更新设备网段与路由目标网段（运行期动态，来自 ip -br addr / ip route）。
// 整体原子替换：采集协程要么看到旧快照、要么看到新快照，不会读到中间态。
func (e *ConnEngine) SetNets(device, route []ipNet) {
	e.setNets(device, route)
}

// setNets 原子替换设备/路由网段（保留本机 IP 集合）。
func (e *ConnEngine) setNets(device, route []ipNet) {
	snap := e.netsSnapshot()
	snap.device = append([]ipNet(nil), device...)
	snap.route = append([]ipNet(nil), route...)
	e.nets.Store(snap)
}

// netsSnapshot 取当前网段快照（未初始化时返回空快照）。
func (e *ConnEngine) netsSnapshot() netsSnapshot {
	if v := e.nets.Load(); v != nil {
		return v.(netsSnapshot)
	}
	return netsSnapshot{self: map[uint32]bool{}}
}

// SetFlowHook 设置流向上下文回调：emit 前发布当前 flow、emit 后发布空上下文。
func (e *ConnEngine) SetFlowHook(fn func(FlowContext)) {
	e.flowMu.Lock()
	e.flowHook = fn
	e.flowMu.Unlock()
}

// publishFlow 发布流向上下文（无回调时直接返回）。
func (e *ConnEngine) publishFlow(ctx FlowContext) {
	e.flowMu.Lock()
	fn := e.flowHook
	e.flowMu.Unlock()
	if fn != nil {
		fn(ctx)
	}
}

// Reset 清空差分状态（例如设置里改了 LAN 网段）。
// baseline 置 true：下一轮只登记存量连接、不计入统计，
// 否则关闭再开启采集后第一轮会把存量连接的累计字节当成新流量（幻影流量）。
// Reset 由 HTTP 协程调用，与采集协程并发，必须与 Collect 串行化。
func (e *ConnEngine) Reset() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.flows = map[flowKey]*flowSnap{}
	e.retired = map[flowKey]flowSnap{}
	e.baseline = true
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
	snap := e.netsSnapshot()
	for _, n := range snap.device {
		if ip&n.mask == n.net {
			return n, true
		}
	}
	return ipNet{}, false
}

// matchRoute 判断目的 IP 是否命中路由目标网段，返回命中的网段。
func (e *ConnEngine) matchRoute(ip uint32) (ipNet, bool) {
	snap := e.netsSnapshot()
	for _, n := range snap.route {
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
// 与 Reset（HTTP 协程）串行化：全程持 mu，避免并发改 flows/retired/baseline。
func (e *ConnEngine) Collect(r io.Reader, now int64, emit func(FlowDelta), gone func(string)) (int, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
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
		// 累计字节（负值按 0 处理，避免异常值被当成巨量增量）
		var upv, downv uint64
		if up > 0 {
			upv = uint64(up)
		}
		if down > 0 {
			downv = uint64(down)
		}
		snap, exists := e.flows[key]
		if !exists {
			// 墓碑命中：该流曾因容量/老化被移出跟踪，但保留了最后累计基线。
			// 若直接按「新 key」处理，大额流会被当成从未见过的新流，
			// 下一轮把全生命周期累计字节（可达数百 MB）一次性计入 2 秒增量，
			// 在流量曲线上形成几十 Gbps 的幻影尖峰并永久落盘。
			if tomb, ok := e.retired[key]; ok {
				if upv >= tomb.Up && downv >= tomb.Down {
					du := int64(upv - tomb.Up)
					dd := int64(downv - tomb.Down)
					snap = &flowSnap{Started: tomb.Started, Up: upv, Down: downv, LastSeen: now, Gen: e.gen}
					e.flows[key] = snap
					delete(e.retired, key)
					if !e.baseline && (du > 0 || dd > 0) {
						delta := e.makeDelta(key, ent, meta, up, down, snap.Started, false)
						delta.UpDelta = du
						delta.DownDelta = dd
						e.emitFlow(emit, delta)
					}
					continue
				}
				// 累计值倒退：计数器已重置（同 5 元组的新连接），按新流处理
				delete(e.retired, key)
			}
			// 新 key 首见：
			//   - baseline 轮（启动/Reset 后第一轮）：只登记快照，不计入统计；
			//   - 累计字节很小：确属本区间内新建的流，累计值即增量；
			//   - 累计字节很大：多半是「首见之前就存在」的旧流（conntrack 表 churn /
			//     端口复用 / tuple 形态切换），此时不推进该流的快照基线，
			//     下一轮把累计值一次性计入，避免首见窗口的字节被永久丢弃。
			snap = &flowSnap{Started: now, LastSeen: now}
			e.flows[key] = snap
			switch {
			case e.baseline:
				snap.Up, snap.Down = upv, downv
				if upv+downv <= smallFlowBytes {
					delta := e.makeDelta(key, ent, meta, up, down, snap.Started, true)
					delta.Baseline = true
					e.emitFlow(emit, delta)
				}
			case upv+downv <= smallFlowBytes:
				snap.Up, snap.Down = upv, downv
				delta := e.makeDelta(key, ent, meta, up, down, snap.Started, true)
				e.emitFlow(emit, delta)
			default:
				// 大额新流：保持快照基线为 0，下一轮把累计值一次性计入
			}
			snap.Gen = e.gen
			snap.LastSeen = now
			continue
		}
		// 已有 key：按累计值差分。
		// 累计值倒退说明该 key 对应的流被重建（端口复用 / tuple 形态切换），
		// 新旧累计值不可比：只更新快照、不计入增量，否则会成倍虚高。
		if upv < snap.Up || downv < snap.Down {
			snap.Up, snap.Down = upv, downv
			snap.Gen = e.gen
			snap.LastSeen = now
			continue
		}
		du := int64(upv - snap.Up)
		dd := int64(downv - snap.Down)
		snap.Up, snap.Down = upv, downv
		snap.Gen = e.gen
		snap.LastSeen = now
		// 增量不设固定上限：只要累计值递增就计入（高速单流不能被永久漏计）。
		if du > 0 || dd > 0 {
			delta := e.makeDelta(key, ent, meta, up, down, snap.Started, false)
			delta.UpDelta = du
			delta.DownDelta = dd
			e.emitFlow(emit, delta)
		}
	}
	if err := sc.Err(); err != nil {
		return total, err
	}

	// 清理本轮未出现的 flow
	// 注意：保留快照（不删除），以记住该 key 的累计字节。
	// 否则流消失后重现会被当作新流，把累计值当增量重复计入（会造成数量级放大）。
	// 快照由 evict() 按 LastSeen 老化淘汰。
	for k, snap := range e.flows {
		if snap.Gen != e.gen {
			if gone != nil {
				gone(flowID(k))
			}
		}
	}
	e.evict(now)
	e.baseline = false
	return total, nil
}

// flowMeta 设备/流向元信息（随 FlowDelta 下发）。
type flowMeta struct {
	path   string
	iface  string
	device bool // 是否设备侧连接（false = 本机/docker0 等非用户设备流量，只计入链路不展示连接）
}

// emitFlow 发布流向上下文后回调（emit 期间上下文有效，emit 后清除，避免陈旧上下文被误用）。
func (e *ConnEngine) emitFlow(emit func(FlowDelta), d FlowDelta) {
	e.publishFlow(FlowContext{
		DeviceIP: d.DeviceIP,
		DstIP:    d.DstIP,
		SPort:    d.SPort,
		DPort:    d.DPort,
		Proto:    d.Proto,
		Path:     d.Path,
	})
	emit(d)
	e.publishFlow(FlowContext{})
}

// tproxySport TPROXY 劫持使用的源端口特征。
// passwall/xray 的透明代理会把「设备 → 真实目标」改写成 dst=路由器IP:16384，
// 据此可把代理流量准确归到对应设备与 proxy 链路（否则代理流量会丢失或被记成直连）。
const tproxySport = 16384

// normalize 判断方向并生成规范化 key，同时返回设备方向的上/下行累计字节与流向元信息。
func (e *ConnEngine) normalize(ent ctEntry) (flowKey, int64, int64, flowMeta, bool) {
	k := flowKey{Proto: protoCode(ent.Proto)}
	// 本机出站连接（如 xray 透明代理的出口）：只计入链路流向，不归到任何设备，
	// 否则代理出口的全部流量会记在路由器自己名下（Top 设备里出现路由器自身）。
	// 流向复用统一的 pathFor()（含 zt/vpn/lan 判定），避免代理出口流量被记成 direct
	// 而与设备侧的 proxy 链路重复计算。
	if e.netsSnapshot().self[ent.SrcIP] {
		k.Dev = ent.SrcIP
		k.SPort = uint16(ent.SPort)
		k.Dst = ent.DstIP
		k.DPort = uint16(ent.DPort)
		k.Dir = 0
		path := e.pathFor(ent.DstIP, ent.DPort, ent.Mark)
		return k, ent.OrigBytes, ent.ReplyBytes, flowMeta{path: path, device: false}, true
	}
	// 目的地址是本机（dst=路由器）：
	//  · TPROXY 劫持记录（sport=16384）：设备 → 真实目标 被内核改写成 dst=本机IP:16384，
	//    这是**设备流量**（经代理），必须计入设备与 proxy 链路，否则代理流量全部丢失；
	//  · 其它指向本机的连接（访问路由器自身 Web/SSH/DNS 服务）：不是用户设备流量，
	//    只计入链路流向，避免这些字节记到路由器自己名下（Top 设备里出现路由器自身）。
	if e.netsSnapshot().self[ent.DstIP] {
		if ent.SPort == tproxySport {
			// TPROXY 劫持：按设备流量处理，流向固定为 proxy
			k.Dev = ent.SrcIP
			k.SPort = uint16(ent.SPort)
			k.Dst = ent.DstIP
			k.DPort = uint16(ent.DPort)
			k.Dir = 0
			return k, ent.OrigBytes, ent.ReplyBytes, flowMeta{path: "proxy", device: true}, true
		}
		k.Dev = ent.DstIP
		k.SPort = uint16(ent.DPort)
		k.Dst = ent.SrcIP
		k.DPort = uint16(ent.SPort)
		k.Dir = 1
		path := e.pathFor(ent.SrcIP, ent.SPort, ent.Mark)
		return k, ent.ReplyBytes, ent.OrigBytes, flowMeta{path: path, device: false}, true
	}
	if n, ok := e.matchDevice(ent.SrcIP); ok {
		k.Dev = ent.SrcIP
		k.SPort = uint16(ent.SPort)
		k.Dst = ent.DstIP
		k.DPort = uint16(ent.DPort)
		k.Dir = 0
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
		k.Dir = 1
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
		k.Dir = 0
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
// 淘汰/老化的快照不直接丢弃，而是转入墓碑（retired）保留最后累计基线：
// 否则该 key 在 conntrack 表重现时会被当成「从未见过的大额新流」，
// 其全生命周期字节被一次性计入增量（实测可形成数十 Gbps 幻影尖峰并落盘污染历史）。
func (e *ConnEngine) evict(now int64) {
	// 老化：超过 10 分钟未在 conntrack 表中出现的快照转墓碑
	const staleSec = 10 * 60
	for k, s := range e.flows {
		if now-s.LastSeen > staleSec {
			e.retire(k, s)
		}
	}
	if len(e.flows) <= e.maxFlows {
		e.trimRetired(now)
		return
	}
	type pair struct {
		k flowKey
		t int64
	}
	list := make([]pair, 0, len(e.flows))
	for k, s := range e.flows {
		list = append(list, pair{k, s.LastSeen})
	}
	// 按「最久未见」排序，淘汰最旧的一批
	sort.Slice(list, func(i, j int) bool { return list[i].t < list[j].t })
	need := len(e.flows) - e.maxFlows + 1
	n := len(list) / 10
	if n < need {
		n = need
	}
	if n > len(list) {
		n = len(list)
	}
	for i := 0; i < n; i++ {
		k := list[i].k
		e.retire(k, e.flows[k])
	}
	e.trimRetired(now)
}

// retire 把一条流快照移入墓碑（保留最后累计基线）。
func (e *ConnEngine) retire(k flowKey, s *flowSnap) {
	if s == nil {
		delete(e.flows, k)
		return
	}
	if e.retired == nil {
		e.retired = map[flowKey]flowSnap{}
	}
	e.retired[k] = *s
	delete(e.flows, k)
}

// trimRetired 控制墓碑规模：超过上限按最久未见淘汰，并清理 1 小时前的墓碑。
// 墓碑只保留累计值（约 40 字节/条），上限 3 万条约 1.2MB。
func (e *ConnEngine) trimRetired(now int64) {
	if len(e.retired) == 0 {
		return
	}
	const tombStale = int64(60 * 60) // 1 小时前的墓碑失去参考价值
	for k, s := range e.retired {
		if now-s.LastSeen > tombStale {
			delete(e.retired, k)
		}
	}
	if e.maxRetired <= 0 {
		e.maxRetired = 30000
	}
	if len(e.retired) <= e.maxRetired {
		return
	}
	type pair struct {
		k flowKey
		t int64
	}
	list := make([]pair, 0, len(e.retired))
	for k, s := range e.retired {
		list = append(list, pair{k, s.LastSeen})
	}
	sort.Slice(list, func(i, j int) bool { return list[i].t < list[j].t })
	drop := len(e.retired) - e.maxRetired
	for i := 0; i < drop && i < len(list); i++ {
		delete(e.retired, list[i].k)
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

// flowID 生成连接 ID：proto-devip-sport-dstip-dport（api.md §4 示例格式，5 段）。
// 方向位 Dir 只用于内部差分 key（区分设备侧/远端侧同行五元组），
// 不进入对外 ID —— 否则破坏契约，并让 api.go 的「按 ID 回退封禁目标」解析错位。
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
