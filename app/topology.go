package main

// 网络接口/拓扑采集与 /api/topology 数据构建。
//
// 真机采集：
//   - `ip -br addr show`：接口名/状态/IPv4 CIDR（标记 lan/zerotier/vpn/docker）；
//   - `ip route show`：默认网关（internet 是否 up）、经虚拟接口的远端网段；
//   - `ip neigh show`：设备刷新时按接口过滤（见 devices.go）；
//   - 代理探测：`ss -lntp` / `netstat -lntp` 的监听端口与进程名（clash/mihomo/v2ray/xray/sing-box 等）。
// 流量拆分：Agg 的 DstBps（目的 IP 速率）按虚拟接口 CIDR 归入 zt/vpn 链路，其余归 direct/proxy。
//
// 所有采集命令结果做 10s 级缓存，避免每次 API 请求都 fork 命令。

import (
	"fmt"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
)

const (
	ifaceCacheSec = 10
	topoCacheSec  = 5
	proxyCacheSec = 15
)

// ifaceInfo 接口信息。
type ifaceInfo struct {
	Name     string
	Network  string // lan / zerotier / vpn / docker / other / loopback
	CIDR     string // 首个 IPv4 CIDR（如 192.168.1.0/24 的接口地址 192.168.1.254/24）
	Addr     string // IPv4 地址
	Up       bool
	Internal bool
}

// topologyNode 拓扑节点（契约字段）。
type topologyNode struct {
	ID    string `json:"id"`
	Type  string `json:"type"`
	Name  string `json:"name"`
	CIDR  string `json:"cidr"`
	Up    bool   `json:"up"`
	RxBps int64  `json:"rxBps"`
	TxBps int64  `json:"txBps"`
}

// topologyLink 拓扑链路（契约字段）。
type topologyLink struct {
	From    string `json:"from"`
	To      string `json:"to"`
	Kind    string `json:"kind"` // direct / proxy / zt / vpn / docker
	UpBps   int64  `json:"upBps"`
	DownBps int64  `json:"downBps"`
}

// topologyResp GET /api/topology 响应。
type topologyResp struct {
	Nodes []topologyNode `json:"nodes"`
	Links []topologyLink `json:"links"`
}

// ---------------- 接口类型判定 ----------------

// ifaceKind 根据接口名判断网络类型与是否内网接口。
func ifaceKind(name string) (network string, internal bool) {
	n := strings.ToLower(strings.TrimSpace(name))
	if i := strings.IndexByte(n, '@'); i > 0 {
		n = n[:i]
	}
	switch {
	case n == "lo":
		return "loopback", false
	case n == "br-lan" || strings.HasPrefix(n, "br-lan."):
		return "lan", true
	case strings.HasPrefix(n, "zt"):
		return "zerotier", true
	case strings.HasPrefix(n, "tun"), strings.HasPrefix(n, "wg"), n == "tailscale0", strings.HasPrefix(n, "ppp"):
		return "vpn", true
	case n == "docker0" || strings.HasPrefix(n, "docker") || strings.HasPrefix(n, "br-"):
		return "docker", false
	case n == "eth0" || n == "wan" || strings.HasPrefix(n, "eth"):
		return "other", false
	}
	return "other", false
}

// ---------------- 采集（带缓存） ----------------

// interfaces 返回本机接口（10s 缓存）。
func (a *App) interfaces() []ifaceInfo {
	now := nowUnix()
	a.ifMu.Lock()
	defer a.ifMu.Unlock()
	if len(a.ifaces) > 0 && now-a.ifAt < ifaceCacheSec {
		return a.ifaces
	}
	var list []ifaceInfo
	if a.cfg.Demo {
		list = demoInterfaces()
	} else {
		out, _ := a.shellQuietOutput("ip -br addr show 2>/dev/null")
		list = parseIPBrAddr(out)
	}
	if len(list) == 0 {
		// 采集失败时至少保留 LAN 节点（保证拓扑可用）
		cidr := a.cfg.LANCIDR
		list = []ifaceInfo{{Name: "br-lan", Network: "lan", CIDR: cidr, Addr: cidr, Up: true, Internal: true}}
	}
	a.ifaces = list
	a.ifAt = now
	return list
}

// parseIPBrAddr 解析 `ip -br addr show` 输出。
// 行格式：br-lan  UP  192.168.1.254/24 fe80::xxxx/64
func parseIPBrAddr(out string) []ifaceInfo {
	var list []ifaceInfo
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		name := fields[0]
		if i := strings.IndexByte(name, '@'); i > 0 {
			name = name[:i]
		}
		network, internal := ifaceKind(name)
		if network == "loopback" {
			continue
		}
		f := ifaceInfo{Name: name, Network: network, Internal: internal}
		state := strings.ToUpper(fields[1])
		f.Up = state == "UP" || state == "UNKNOWN"
		for _, tok := range fields[2:] {
			if strings.Contains(tok, ":") || !strings.Contains(tok, "/") {
				continue // IPv6 / 非 CIDR
			}
			ip, _, ok := parseCIDRAddr(tok)
			if !ok {
				continue
			}
			f.CIDR = tok
			f.Addr = ip
			break
		}
		list = append(list, f)
	}
	return list
}

// parseCIDRAddr 解析 "192.168.1.254/24" 为地址与掩码位数。
func parseCIDRAddr(s string) (string, int, bool) {
	parts := strings.SplitN(s, "/", 2)
	if len(parts) != 2 {
		return "", 0, false
	}
	addr, err := netip.ParseAddr(parts[0])
	if err != nil || !addr.Is4() {
		return "", 0, false
	}
	bits, err := strconv.Atoi(parts[1])
	if err != nil || bits < 0 || bits > 32 {
		return "", 0, false
	}
	return addr.String(), bits, true
}

// maskedCIDR 把接口地址/前缀转成网段（网络地址/前缀）。
// 例：192.168.1.254/24 → 192.168.1.0/24；契约里 nodes[].cidr 是网段语义，不是接口地址。
func maskedCIDR(cidr string) string {
	p, err := netip.ParsePrefix(strings.TrimSpace(cidr))
	if err != nil {
		return cidr
	}
	return p.Masked().String()
}

// networkForIP 判断 IP 所属网络（lan/zerotier/vpn/docker/other）及是否内网。
func (a *App) networkForIP(ip string) (network string, internal bool) {
	addr, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil || !addr.Is4() {
		return "other", false
	}
	for _, f := range a.interfaces() {
		if f.CIDR == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(f.CIDR)
		if err != nil || !prefix.Addr().Is4() {
			continue
		}
		if prefix.Contains(addr) {
			return f.Network, f.Internal
		}
	}
	// 接口信息缺失时退化为私网判定
	if isPrivateIPStr(ip) {
		return "lan", true
	}
	return "other", false
}

// routeLines 返回路由表（10s 缓存，拓扑构建时使用）。
func (a *App) routeLines() []string {
	if a.cfg.Demo {
		return []string{
			"default via 192.168.1.1 dev br-lan proto static",
			"192.168.1.0/24 dev br-lan proto kernel scope link src 192.168.1.254",
			"192.168.99.0/24 dev zt6vwy3rne proto kernel scope link src 192.168.99.1",
			// ZeroTier 远端路由网段（设备在 LAN/ZT，目的在这些网段 → path=zerotier）
			"10.0.2.0/24 dev zt6vwy3rne scope link",
			"10.10.10.0/24 dev zt6vwy3rne scope link",
			"10.11.0.0/24 dev zt6vwy3rne scope link",
			"10.12.0.0/24 dev zt6vwy3rne scope link",
			"192.168.2.0/24 dev zt6vwy3rne scope link",
			"192.168.3.0/24 dev zt6vwy3rne scope link",
			"192.168.8.0/24 dev zt6vwy3rne scope link",
			"192.168.88.0/24 dev zt6vwy3rne scope link",
			// VPN 网段（tun0，演示为 down 但仍保留路由用于展示 path=vpn）
			"10.8.0.0/24 dev tun0 scope link",
		}
	}
	out, _ := a.shellQuietOutput("ip route show 2>/dev/null")
	if strings.TrimSpace(out) == "" {
		return nil
	}
	return strings.Split(strings.TrimSpace(out), "\n")
}

// parseDefaultRoute 解析默认路由（返回出口接口）。
func parseDefaultRoute(lines []string) (dev string, ok bool) {
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 3 || fields[0] != "default" {
			continue
		}
		for i := 0; i < len(fields)-1; i++ {
			if fields[i] == "dev" {
				return fields[i+1], true
			}
		}
	}
	return "", false
}

// wanIface 返回真正的 WAN（外网）接口名；本机没有 WAN 口时返回空串。
//
// 判定：默认路由的出口接口，且不是内网桥（br-lan*）/ZeroTier/隧道接口。
// 旁路由场景下默认路由常在 br-lan（真正的出口是上一级主路由），
// 此时本机并没有 WAN 口：互联网节点计数置 0 并在名称上标注，
// 避免把 br-lan 的总计数（各链路之和）当成互联网流量而重复计算。
func wanIface(ifaces []ifaceInfo, routes []string) string {
	dev, ok := parseDefaultRoute(routes)
	if !ok || dev == "" {
		return ""
	}
	for _, f := range ifaces {
		if f.Name != dev {
			continue
		}
		switch f.Network {
		case "lan", "zerotier":
			return "" // 内网桥 / ZeroTier 出口不是 WAN
		case "vpn":
			if strings.HasPrefix(strings.ToLower(f.Name), "ppp") {
				return f.Name // PPPoE 拨号口是真实 WAN
			}
			return "" // 隧道出口（tun/wg）不是 WAN
		}
		return f.Name
	}
	return ""
}

// detectProxy 探测本机是否有常见代理在监听（15s 缓存）。
func (a *App) detectProxy() bool {
	now := nowUnix()
	a.proxyMu.Lock()
	defer a.proxyMu.Unlock()
	if now-a.proxyAt < proxyCacheSec && a.proxyAt > 0 {
		return a.proxyUp
	}
	up := false
	if a.cfg.Demo {
		up = true
	} else {
		out, _ := a.shellQuietOutput("ss -lntp 2>/dev/null")
		if strings.TrimSpace(out) == "" {
			out, _ = a.shellQuietOutput("netstat -lntp 2>/dev/null")
		}
		up = parseProxyOutput(out)
	}
	a.proxyUp = up
	a.proxyAt = now
	return up
}

// proxyNames 常见代理进程名/关键字。
var proxyNames = []string{"clash", "mihomo", "v2ray", "xray", "sing-box", "singbox", "trojan", "ss-local", "shadowsocks", "hysteria", "naive", "tuic"}

// proxyPorts 常见代理监听端口。
var proxyPorts = []string{":7890", ":7891", ":7892", ":1080", ":1081", ":8888", ":8889", ":9090", ":10808", ":10809", ":10810"}

// parseProxyOutput 解析 ss/netstat 监听列表，判断是否有代理。
func parseProxyOutput(out string) bool {
	lower := strings.ToLower(out)
	for _, name := range proxyNames {
		if strings.Contains(lower, name) {
			return true
		}
	}
	for _, line := range strings.Split(lower, "\n") {
		for _, port := range proxyPorts {
			if strings.Contains(line, port) {
				return true
			}
		}
	}
	return false
}

// ---------------- 拓扑构建 ----------------

// buildTopology 构建拓扑（5s 缓存）。
func (a *App) buildTopology() topologyResp {
	now := nowUnix()
	a.topoMu.Lock()
	defer a.topoMu.Unlock()
	if now-a.topoAt < topoCacheSec && a.topoAt > 0 {
		return a.topo
	}
	ifaces := a.interfaces()
	routes := a.routeLines()
	proxyUp := a.detectProxy()
	rates := a.agg.LastRates()

	// 接口默认路由出口（internet 是否 up）
	_, hasDefault := parseDefaultRoute(routes)

	// 网卡累计计数器 -> 速率（用于节点 rx/tx）
	counters := readIfaceCounters()
	rxRate, txRate := map[string]int64{}, map[string]int64{}
	if a.topoRAt > 0 && now > a.topoRAt {
		elapsed := now - a.topoRAt
		for name, c := range counters {
			if prev, ok := a.topoRx[name]; ok && c[0] >= prev {
				rxRate[name] = (c[0] - prev) * 8 / elapsed
			}
			if prev, ok := a.topoTx[name]; ok && c[1] >= prev {
				txRate[name] = (c[1] - prev) * 8 / elapsed
			}
		}
	}
	a.topoRx, a.topoTx, a.topoRAt = make(map[string]int64, len(counters)), make(map[string]int64, len(counters)), now
	for name, c := range counters {
		a.topoRx[name], a.topoTx[name] = c[0], c[1]
	}

	nodes := make([]topologyNode, 0, len(ifaces)+3)
	links := make([]topologyLink, 0, len(ifaces)+2)

	lanID := ""
	virtual := make([]ifaceInfo, 0, len(ifaces))
	for _, f := range ifaces {
		switch f.Network {
		case "lan", "zerotier", "vpn", "docker":
		default:
			continue
		}
		// 虚拟接口仅 up 时上拓扑；LAN/Docker 常显
		if !f.Up && (f.Network == "zerotier" || f.Network == "vpn") {
			continue
		}
		if !f.Up && f.Network == "docker" {
			continue
		}
		display := f.Name
		switch f.Network {
		case "lan":
			display = "内网 LAN"
			if lanID == "" {
				lanID = f.Name
			}
		case "zerotier":
			display = "ZeroTier"
			virtual = append(virtual, f)
		case "vpn":
			display = "VPN"
			virtual = append(virtual, f)
		case "docker":
			display = "Docker"
		}
		nodes = append(nodes, topologyNode{
			ID: f.Name, Type: f.Network, Name: display, CIDR: maskedCIDR(f.CIDR),
			Up: f.Up, RxBps: rxRate[f.Name], TxBps: txRate[f.Name],
		})
	}
	if lanID == "" {
		lanID = "br-lan"
		nodes = append(nodes, topologyNode{ID: lanID, Type: "lan", Name: "内网 LAN", CIDR: a.cfg.LANCIDR, Up: true})
	}

	// 互联网节点：使用真正的 WAN 接口计数。
	// 旁路由场景（默认路由在 br-lan）本机没有 WAN 口：计数置 0 并在名称上标注，
	// 不再拿 br-lan 的总计数（各链路之和）当互联网流量，避免与 direct/proxy/zt/vpn 链路重复计算。
	// LAN 内部互访（path=lan）不属于互联网流量，已从总量中扣除：
	// 它只体现在 LAN 节点（br-lan 接口计数）上。
	wanDev := wanIface(ifaces, routes)
	internetRx, internetTx := int64(0), int64(0)
	internetName := "互联网"
	if wanDev != "" {
		internetRx, internetTx = rxRate[wanDev], txRate[wanDev]
	} else {
		internetName = "互联网（无 WAN）"
	}
	nodes = append(nodes, topologyNode{
		ID: "internet", Type: "internet", Name: internetName,
		Up: hasDefault, RxBps: internetRx, TxBps: internetTx,
	})
	// 代理节点（未探测到也返回，up=false 便于前端展示"未启用"状态）
	nodes = append(nodes, topologyNode{ID: "proxy", Type: "proxy", Name: "代理", Up: proxyUp})

	// 链路流量按连接 path 聚合（conntrack mark 拆分），不再把全部公网流量一刀切给 proxy：
	//   - proxy = mark>0 / 代理端口连接的实时速率（含 docker0/本机代理流量）；
	//   - direct = 设备非代理公网连接的实时速率；
	//   - zerotier/vpn = 各自流向的实时速率（无连接时用接口计数器兜底）。
	pathRate := func(path string) [2]int64 {
		if rates.PathBps != nil {
			if v, ok := rates.PathBps[path]; ok {
				return v
			}
		}
		return [2]int64{}
	}
	directRate := pathRate("direct")
	proxyRate := pathRate("proxy")
	ztRate := pathRate("zerotier")
	vpnRate := pathRate("vpn")

	virtualRates := map[string][2]int64{}
	for _, f := range virtual {
		r := ztRate
		if f.Network == "vpn" {
			r = vpnRate
		}
		// 兜底：path 无流量时用接口 rx/tx 计数器（rx=下行，tx=上行）
		if r[0] == 0 && r[1] == 0 && (rxRate[f.Name] > 0 || txRate[f.Name] > 0) {
			r = [2]int64{txRate[f.Name], rxRate[f.Name]}
		}
		virtualRates[f.Name] = r
	}

	// 链路：LAN -> internet(direct) / proxy / 各虚拟网络
	// 注：LAN 内部互访（path=lan）没有对外链路，已从互联网总量中扣除，
	// 它只体现在 LAN 节点（br-lan 接口计数）上。
	directLink := topologyLink{
		From: lanID, To: "internet", Kind: "direct",
		UpBps: directRate[0], DownBps: directRate[1],
	}
	proxyLink := topologyLink{
		From: lanID, To: "proxy", Kind: "proxy",
		UpBps: proxyRate[0], DownBps: proxyRate[1],
	}
	links = append(links, directLink, proxyLink)
	sort.Slice(virtual, func(i, j int) bool { return virtual[i].Name < virtual[j].Name })
	for _, f := range virtual {
		v := virtualRates[f.Name]
		kind := "zt"
		if f.Network == "vpn" {
			kind = "vpn"
		}
		links = append(links, topologyLink{From: lanID, To: f.Name, Kind: kind, UpBps: v[0], DownBps: v[1]})
	}
	// 节点 rx/tx 与链路保持一致（proxy/zt/vpn 节点展示链路实时流量，不再出现链路有值而节点为 0）
	for i := range nodes {
		switch nodes[i].ID {
		case "proxy":
			nodes[i].RxBps, nodes[i].TxBps = proxyLink.UpBps, proxyLink.DownBps
			// 透明代理（passwall/xray TPROXY）可能没有 7890 等监听端口导致探测不到，
			// 但只要有 mark 代理流量就认为代理在用，避免前端把节点显示为未启用。
			if proxyLink.UpBps > 0 || proxyLink.DownBps > 0 {
				nodes[i].Up = true
			}
		default:
			if v, ok := virtualRates[nodes[i].ID]; ok {
				nodes[i].RxBps, nodes[i].TxBps = v[0], v[1]
			}
		}
	}

	a.topo = topologyResp{Nodes: nodes, Links: links}
	a.topoAt = now
	return a.topo
}

// readIfaceCounters 读取 /proc/net/dev，返回接口累计 rx/tx 字节。
func readIfaceCounters() map[string][2]int64 {
	out := map[string][2]int64{}
	b, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return out
	}
	for _, line := range strings.Split(string(b), "\n") {
		colon := strings.IndexByte(line, ':')
		if colon < 0 {
			continue
		}
		name := strings.TrimSpace(line[:colon])
		fields := strings.Fields(line[colon+1:])
		if len(fields) < 9 {
			continue
		}
		rx, err1 := parseInt64(fields[0])
		tx, err2 := parseInt64(fields[8])
		if err1 != nil || err2 != nil {
			continue
		}
		out[name] = [2]int64{rx, tx}
	}
	return out
}

// syncConnNets 用拓扑采集结果更新 ConnEngine 的多网段识别：
//   - deviceNets：LAN + zt/vpn 本地接口网段（用于判断设备归属）；
//   - routeNets：zt/vpn 本地接口网段 + 经 zt/vpn 接口可达的远端路由网段（用于流向判断）。
//
// 由启动、设备刷新（10s）与开启采集时调用；关闭采集/总开关时不执行任何命令。
func (a *App) syncConnNets() {
	if a.ct == nil {
		return
	}
	if !a.cfg.Demo && !a.dataActive() {
		return
	}
	ifaces := a.interfaces()
	var device, route []ipNet
	for _, f := range ifaces {
		if f.CIDR == "" || !f.Internal {
			continue
		}
		switch f.Network {
		case "lan", "zerotier", "vpn":
		default:
			continue
		}
		if n, ok := ipNetFromCIDR(f.CIDR, f.Network, f.Name); ok {
			device = append(device, n)
		}
	}
	if len(device) == 0 {
		if n, ok := ipNetFromCIDR(a.cfg.LANCIDR, "lan", "br-lan"); ok {
			device = append(device, n)
		}
	}
	// 虚拟接口自身网段
	for _, f := range ifaces {
		if f.Network != "zerotier" && f.Network != "vpn" {
			continue
		}
		if n, ok := ipNetFromCIDR(f.CIDR, f.Network, f.Name); ok {
			route = append(route, n)
		}
	}
	// 经 zt/vpn 接口的远端路由网段（如 zt 的 10.0.2.0/24、10.10.10.0/24）
	for _, line := range a.routeLines() {
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
		kind, internal := ifaceKind(dev)
		if !internal || (kind != "zerotier" && kind != "vpn") {
			continue
		}
		if n, ok := ipNetFromCIDR(cidr, kind, dev); ok {
			route = append(route, n)
		}
	}
	a.ct.SetNets(dedupeIPNets(device), dedupeIPNets(route))
}

// dedupeIPNets 去重（net+mask+kind+iface）。
func dedupeIPNets(in []ipNet) []ipNet {
	seen := map[ipNet]bool{}
	out := make([]ipNet, 0, len(in))
	for _, n := range in {
		if seen[n] {
			continue
		}
		seen[n] = true
		out = append(out, n)
	}
	return out
}

// demoInterfaces 演示模式接口列表。
func demoInterfaces() []ifaceInfo {
	return []ifaceInfo{
		{Name: "br-lan", Network: "lan", CIDR: "192.168.1.254/24", Addr: "192.168.1.254", Up: true, Internal: true},
		{Name: "zt6vwy3rne", Network: "zerotier", CIDR: "192.168.99.1/24", Addr: "192.168.99.1", Up: true, Internal: true},
		{Name: "eth0", Network: "other", CIDR: "10.0.0.2/24", Addr: "10.0.0.2", Up: true, Internal: false},
		{Name: "docker0", Network: "docker", CIDR: "172.17.0.1/16", Addr: "172.17.0.1", Up: false, Internal: false},
		{Name: "tun0", Network: "vpn", CIDR: "10.8.0.1/24", Addr: "10.8.0.1", Up: false, Internal: true},
	}
}

// ---------------- 本机/网关保护 ----------------

// parseAllIPv4Addrs 解析本机接口上的全部 IPv4 地址（ip -br addr 的每个 token）。
func parseAllIPv4Addrs(out string) []string {
	var list []string
	seen := map[string]bool{}
	for _, line := range strings.Split(out, "\n") {
		for _, tok := range strings.Fields(line) {
			if !strings.Contains(tok, "/") || strings.Contains(tok, ":") {
				continue
			}
			ip, _, ok := parseCIDRAddr(tok)
			if !ok || seen[ip] {
				continue
			}
			seen[ip] = true
			list = append(list, ip)
		}
	}
	return list
}

// parseDefaultGateway 解析默认路由的 via 网关地址。
func parseDefaultGateway(lines []string) string {
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 3 || fields[0] != "default" {
			continue
		}
		for i := 0; i < len(fields)-1; i++ {
			if fields[i] == "via" {
				if _, ok := parseIPv4Str(fields[i+1]); ok {
					return fields[i+1]
				}
			}
		}
	}
	return ""
}

// protectedSet 本机/网关/关键内网地址集合（10s 缓存）。
// 目的：用户误点"封禁目标 IP/断网"时不允许把路由器自身或上游网关封掉，避免自断网络。
func (a *App) protectedSet() map[string]bool {
	now := nowUnix()
	a.protMu.Lock()
	defer a.protMu.Unlock()
	if a.protIPs != nil && now-a.protAt < ifaceCacheSec {
		return a.protIPs
	}
	set := map[string]bool{}
	add := func(ip string) {
		if _, ok := parseIPv4Str(ip); ok {
			set[ip] = true
		}
	}
	// 回环 / 链路本地（整段保护，由 isProtectedIP 用 netip 判断）
	add("127.0.0.1")
	// 本机所有接口地址
	if a.cfg.Demo {
		for _, f := range demoInterfaces() {
			add(f.Addr)
		}
		add("192.168.1.254")
		add("192.168.99.1")
	} else {
		out, _ := a.shellQuietOutput("ip -br addr show 2>/dev/null")
		for _, ip := range parseAllIPv4Addrs(out) {
			add(ip)
		}
		// 接口采集失败时至少保护 LAN 接口地址
		if len(set) <= 1 {
			if f := a.interfaces(); len(f) > 0 {
				for _, ifc := range f {
					if ifc.Addr != "" {
						add(ifc.Addr)
					}
				}
			}
		}
	}
	// 上游网关
	add(parseDefaultGateway(a.routeLines()))
	// 内网接口的网络地址 / 广播地址（如 192.168.1.0 / 192.168.1.255）
	for _, f := range a.interfaces() {
		if f.CIDR == "" || !f.Internal {
			continue
		}
		if prefix, err := netip.ParsePrefix(f.CIDR); err == nil && prefix.Addr().Is4() {
			addr := prefix.Addr().As4()
			netIP := ip4ToUint32(addr)
			mask := uint32(0xffffffff)
			if bits := prefix.Bits(); bits < 32 {
				mask = ^uint32(0) << (32 - bits)
			}
			netIP &= mask
			broadcast := netIP | ^mask
			add(ip4String(netIP))
			add(ip4String(broadcast))
		}
	}
	a.protIPs = set
	a.protAt = now
	return set
}

// isProtectedIP 判断 IP 是否受保护（禁止封禁/限速）：本机、网关、回环、链路本地、内网网络/广播地址。
// 非法 IP 一律视为受保护（拒绝）。
func (a *App) isProtectedIP(ip string) bool {
	addr, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil || !addr.Is4() {
		return true
	}
	if addr.IsLoopback() || addr.IsLinkLocalUnicast() {
		return true
	}
	return a.protectedSet()[addr.String()]
}

// interfaceCIDR 返回接口 CIDR（调试/测试用）。
func (a *App) interfaceCIDR(name string) string {
	for _, f := range a.interfaces() {
		if f.Name == name {
			return f.CIDR
		}
	}
	return ""
}

// topoSummary 简短描述（日志用）。
func topoSummary(t topologyResp) string {
	return fmt.Sprintf("nodes=%d links=%d", len(t.Nodes), len(t.Links))
}
