package main

// 设备发现与管理。
//
// 三源合并：/tmp/dhcp.leases（租约）+ `ip neigh`（ARP/邻居表）+ conntrack 源 IP。
// 其中 `ip neigh show` 走共享缓存（见 topology.go 的 neighEntries，10s 级）：
// 设备刷新每 10s 一次，同一缓存窗口内不会重复 fork 外部命令。
// 在线判定：最近 5 分钟内有邻居记录或流量。
// 事件：new_device / device_online / device_offline 交给研判层（去重后落库并推 SSE）。
// 状态结构以小对象为主，设备数量级通常 < 100，内存可忽略。

import (
	"bufio"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
)

const dhcpLeasePath = "/tmp/dhcp.leases"

// 在线判定窗口（秒）
const onlineWindowSec = 300

// 设备保留时长（秒）：超过这个时间没有任何活动（租约/邻居/流量）就淘汰。
//
// 为什么必须淘汰：设备表原先对「内网设备」无条件保留，只把状态置为离线，
// 于是任何曾经出现过的设备都会永久留在列表里。结果是设备数越跑越多
// （实机反馈 28 台，但 DHCP 租约只有 8 条），用户看到的数字完全不可信。
// 24 小时足够覆盖「手机晚上关机、第二天再连」这类正常场景，
// 又不会让设备表无限膨胀。
const deviceRetainSec = 24 * 3600

// DeviceState 设备运行时状态（内存态）。
type DeviceState struct {
	IP          string
	MAC         string
	Hostname    string
	Vendor      string
	Network     string // 所属网络：lan / zerotier / vpn / docker / other
	Online      bool
	FirstSeen   int64
	LastSeen    int64
	UpBps       int64
	DownBps     int64
	TotalUp     int64
	TotalDown   int64
	TopCat      string
	TopDomain   string
	Risk        float64
	Trend       []TrendPoint
	Connections int
}

// dhcpLease dnsmasq 租约。
type dhcpLease struct {
	Expiry   int64
	MAC      string
	IP       string
	Hostname string
}

// neighEntry ip neigh 条目。
type neighEntry struct {
	IP    string
	MAC   string
	Dev   string // 所在接口（br-lan / zt* / docker0 ...）
	State string
}

// DeviceMgr 设备管理器（并发安全）。
type DeviceMgr struct {
	app *App

	mu      sync.Mutex
	devices map[string]*DeviceState
	known   map[string]bool // 已经触发过 new_device 的设备
}

// NewDeviceMgr 创建设备管理器。
func NewDeviceMgr(a *App) *DeviceMgr {
	return &DeviceMgr{app: a, devices: map[string]*DeviceState{}, known: map[string]bool{}}
}

// ensureLocked 取设备状态，不存在则创建（created 表示是否为首次创建）。
func (m *DeviceMgr) ensureLocked(ip string, now int64) (*DeviceState, bool) {
	if st, ok := m.devices[ip]; ok {
		return st, false
	}
	first := int64(0)
	if m.app != nil && m.app.store != nil {
		first = m.app.store.DeviceMeta(ip).FirstSeen
	}
	if first == 0 {
		first = now
	}
	st := &DeviceState{IP: ip, FirstSeen: first, LastSeen: now}
	if m.app != nil {
		st.Network, _ = m.app.networkForIP(ip)
	}
	if st.Network == "" {
		st.Network = "other"
	}
	// 非内网地址（vpn/未知私网段等）不建设备：流量侧发现的对端不混入设备列表。
	// 返回 (nil, false) 表示「该 IP 不是设备」，调用方需判空跳过。
	if !isInternalNetwork(st.Network) {
		return nil, false
	}
	m.devices[ip] = st
	return st, true
}

// NoteTraffic 记录设备流量（conntrack 回调）。
func (m *DeviceMgr) NoteTraffic(ip string, up, down, now int64) {
	if ip == "" {
		return
	}
	m.mu.Lock()
	st, created := m.ensureLocked(ip, now)
	if st == nil {
		m.mu.Unlock()
		return // 非内网地址：不建设备、不产生事件
	}
	st.TotalUp += up
	st.TotalDown += down
	if up > 0 || down > 0 {
		st.LastSeen = now
	}
	// 首次见到流量的设备：置 known 并触发 new_device。
	// 否则租约/邻居合并时该设备已存在（created=false），新设备事件会永久丢失，
	// 且该设备后续的上下线事件也会因 known=false 被整体跳过。
	fresh := created && !m.known[ip]
	name := ""
	if fresh {
		m.known[ip] = true
		name = m.displayNameLocked(st)
	}
	m.mu.Unlock()
	if fresh && m.app != nil && m.app.sec != nil {
		m.app.sec.OnNewDevice(ip, name, now)
	}
}

// scaleFactor 当前校准系数（conntrack 归因速率 → 物理真实速率的比例）。
// 与分类/KPI 速率同源，保证同一份响应里各口径一致。
func (m *DeviceMgr) scaleFactor() float64 {
	if m.app == nil || m.app.agg == nil {
		return 1
	}
	sc := m.app.agg.Scale()
	if sc <= 0 {
		return 1
	}
	return sc
}

// ApplyRates 应用一个采样周期的设备速率、分类/域名偏好、趋势点。
// r 为 conntrack 原始速率快照；对外展示的设备速率统一乘校准系数，
// 与分类速率、KPI 保持同一口径（否则同一响应里会相差 10~1000 倍）。
func (m *DeviceMgr) ApplyRates(r IntervalRates, now int64) {
	sc := m.scaleFactor() // 先取系数再取设备锁，避免嵌套加锁
	m.mu.Lock()
	defer m.mu.Unlock()
	for ip, pair := range r.DevBps {
		st, _ := m.ensureLocked(ip, now)
		if st == nil {
			continue // 非内网地址：不建设备
		}
		st.UpBps = int64(float64(pair[0]) * sc)
		st.DownBps = int64(float64(pair[1]) * sc)
		if st.UpBps > 0 || st.DownBps > 0 {
			st.LastSeen = now
			st.Trend = append(st.Trend, TrendPoint{T: now, Up: st.UpBps, Down: st.DownBps})
			if len(st.Trend) > 120 {
				st.Trend = st.Trend[len(st.Trend)-120:]
			}
		}
		// 当前最活跃分类
		if cats := r.DevCatBps[ip]; len(cats) > 0 {
			best, bestV := st.TopCat, int64(-1)
			for c, v := range cats {
				total := v[0] + v[1]
				if total > bestV {
					best, bestV = c, total
				}
			}
			if bestV > 0 {
				st.TopCat = best
			}
		}
		// 当前最活跃域名
		if doms := r.DevDomainBps[ip]; len(doms) > 0 {
			best, bestV := st.TopDomain, int64(-1)
			for d, v := range doms {
				total := v[0] + v[1]
				if total > bestV {
					best, bestV = d, total
				}
			}
			if bestV > 0 {
				st.TopDomain = best
			}
		}
	}
	// 清空没有流量的设备速率，避免数值挂住
	for ip, st := range m.devices {
		if _, ok := r.DevBps[ip]; !ok {
			st.UpBps, st.DownBps = 0, 0
		}
	}
}

// SetRisk 更新设备风险分。
func (m *DeviceMgr) SetRisk(ip string, risk float64) {
	if ip == "" {
		return
	}
	m.mu.Lock()
	if st, ok := m.devices[ip]; ok {
		st.Risk = risk
	}
	m.mu.Unlock()
}

// State 返回设备状态拷贝。
func (m *DeviceMgr) State(ip string) (DeviceState, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	st, ok := m.devices[ip]
	if !ok {
		return DeviceState{}, false
	}
	return *st, true
}

// States 返回全部设备状态拷贝（按 IP 数值排序）。
func (m *DeviceMgr) States() []DeviceState {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]DeviceState, 0, len(m.devices))
	for _, st := range m.devices {
		out = append(out, *st)
	}
	sort.Slice(out, func(i, j int) bool { return ipLess(out[i].IP, out[j].IP) })
	return out
}

// AllIPs 返回全部设备 IP。
func (m *DeviceMgr) AllIPs() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, 0, len(m.devices))
	for ip := range m.devices {
		out = append(out, ip)
	}
	sort.Slice(out, func(i, j int) bool { return ipLess(out[i], out[j]) })
	return out
}

// Refresh 每 10s 合并租约与邻居表，更新在线状态并触发事件。
//
// 只保留内网设备（用户真机反馈的修复）：
//   - DHCP 租约 IP 必留（LAN 真实客户端）；
//   - 邻居表只取内网接口（br-lan / zt* / tun* / wg* / tailscale0 / ppp*）上的私网地址；
//   - 排除 docker0 等非内网接口、公网 IP、FAILED/INCOMPLETE 邻居（除非有租约）；
//   - 已存在但不再匹配的内网设备保留为离线（保留历史），非内网设备直接移除。
func (m *DeviceMgr) Refresh(now int64) {
	if m.app == nil || m.app.cfg.Demo {
		return
	}
	leases := readDHCPSLeases(dhcpLeasePath)
	// 邻居表走共享缓存（topology.go neighEntries，10s）：
	// 设备刷新本身每 10s 一次，同一窗口内不会重复 fork `ip neigh show`。
	neighs := m.app.neighEntries()

	ifaces := m.app.interfaces()
	ifaceNet := make(map[string]string, len(ifaces))
	ifaceInternal := make(map[string]bool, len(ifaces))
	for _, f := range ifaces {
		ifaceNet[f.Name] = f.Network
		ifaceInternal[f.Name] = f.Internal
	}

	// 1) 计算本轮接受的设备集合 ip -> network
	accepted := make(map[string]string, len(leases)+len(neighs))
	for _, l := range leases {
		if l.IP == "" {
			continue
		}
		// 本地 DHCP 租约 = 内网（口径：本地 DHCP 分配的地址才算内网）
		accepted[l.IP] = "lan"
	}
	var acceptedNeigh []neighEntry
	// 上游网关（主路由）不是「设备」：它出现在 br-lan 邻居表里只是因为要转发外网流量。
	// 把它统计进设备数会让用户困惑（家里 8 台设备却显示 9 台，多出来的就是路由器自己）。
	// 只从邻居侧排除；DHCP 租约侧不受影响（网关不会是 DHCP 客户端）。
	gateway := ""
	if m.app != nil {
		gateway = parseDefaultGateway(m.app.routeLines())
	}
	for _, n := range neighs {
		if n.IP == "" {
			continue
		}
		if gateway != "" && n.IP == gateway {
			continue // 上游网关不是终端设备
		}
		if _, ok := accepted[n.IP]; ok {
			continue // 已有租约，后续仅补 MAC
		}
		if !ifaceInternal[n.Dev] {
			continue // docker0 / eth0 等非内网接口上的邻居不纳入
		}
		net, internal := m.app.networkForIP(n.IP)
		if !internal {
			continue // 排除公网 IP（如 zt 路由下一跳）
		}
		if !isNeighOnline(n.State) {
			continue // FAILED / INCOMPLETE 不建新设备
		}
		if k := ifaceNet[n.Dev]; k != "" && k != "other" {
			net = k
		}
		if net != "lan" && net != "zerotier" {
			continue // 其他网络（vpn/tailscale 等）不算设备
		}
		accepted[n.IP] = net
		acceptedNeigh = append(acceptedNeigh, n)
	}

	type pendingEvent struct {
		kind string
		ip   string
		name string
	}
	var events []pendingEvent

	m.mu.Lock()
	// 2) 租约合并
	for _, l := range leases {
		if l.IP == "" {
			continue
		}
		st, _ := m.ensureLocked(l.IP, now)
		if st == nil {
			continue // 理论不可达（租约恒为 lan），防御性判空
		}
		if net, ok := accepted[l.IP]; ok {
			st.Network = net
		}
		if st.MAC == "" && l.MAC != "" {
			st.MAC = l.MAC
			st.Vendor = VendorForMAC(l.MAC)
		}
		if st.Hostname == "" && l.Hostname != "" {
			st.Hostname = l.Hostname
		}
		// 按「是否已知」判断：设备可能先被流量（NoteTraffic）发现，
		// 此时 created=false，若仍按 created 判断，新设备事件会永久丢失。
		if !m.known[l.IP] {
			m.known[l.IP] = true
			events = append(events, pendingEvent{"new_device", l.IP, m.displayNameLocked(st)})
			m.recordFirstSeen(l.IP, now)
		}
	}
	// 3) 内网邻居合并
	for _, n := range acceptedNeigh {
		st, _ := m.ensureLocked(n.IP, now)
		if st == nil {
			continue // 理论不可达（accepted 已过滤），防御性判空
		}
		if net, ok := accepted[n.IP]; ok {
			st.Network = net
		}
		if st.MAC == "" && n.MAC != "" {
			st.MAC = n.MAC
			st.Vendor = VendorForMAC(n.MAC)
		}
		if isNeighOnline(n.State) {
			st.LastSeen = now
			if !st.Online {
				st.Online = true
			}
		}
		if !m.known[n.IP] {
			m.known[n.IP] = true
			events = append(events, pendingEvent{"new_device", n.IP, m.displayNameLocked(st)})
			m.recordFirstSeen(n.IP, now)
		}
	}
	// 4) 清除误加入的非内网设备（公网/docker 邻居等）；内网设备保留离线供历史查看，
	//    但超过保留期就淘汰 —— 否则设备表只增不减，设备数越跑越多。
	for ip, st := range m.devices {
		if _, ok := accepted[ip]; ok {
			continue
		}
		if !isInternalNetwork(st.Network) {
			delete(m.devices, ip)
			delete(m.known, ip)
			continue
		}
		if now-st.LastSeen > deviceRetainSec {
			delete(m.devices, ip)
			delete(m.known, ip)
		}
	}
	// 5) 在线状态迁移
	for ip, st := range m.devices {
		online := now-st.LastSeen <= onlineWindowSec
		if online == st.Online {
			continue
		}
		st.Online = online
		if !m.known[ip] {
			continue
		}
		if online {
			events = append(events, pendingEvent{"device_online", ip, m.displayNameLocked(st)})
		} else {
			events = append(events, pendingEvent{"device_offline", ip, m.displayNameLocked(st)})
		}
	}
	m.mu.Unlock()

	// 在锁外触发事件，避免锁顺序问题
	for _, ev := range events {
		if m.app.sec == nil {
			break
		}
		switch ev.kind {
		case "new_device":
			m.app.sec.OnNewDevice(ev.ip, ev.name, now)
		case "device_online":
			m.app.sec.OnDeviceOnline(ev.ip, ev.name, now)
		case "device_offline":
			m.app.sec.OnDeviceOffline(ev.ip, ev.name, now)
		}
	}
}

// displayNameLocked 展示名：主机名 > IP。
func (m *DeviceMgr) displayNameLocked(st *DeviceState) string {
	if st.Hostname != "" {
		return st.Hostname
	}
	return st.IP
}

// recordFirstSeen 持久化首次发现时间与厂商。
func (m *DeviceMgr) recordFirstSeen(ip string, now int64) {
	if m.app == nil || m.app.store == nil {
		return
	}
	m.app.store.UpdateDeviceMeta(ip, func(meta *DeviceMeta) {
		if meta.FirstSeen == 0 {
			meta.FirstSeen = now
		}
	})
}

// Seed 演示模式：静默预置设备。
func (m *DeviceMgr) Seed(list []*DeviceState) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, st := range list {
		if st == nil {
			continue
		}
		cp := *st
		m.devices[cp.IP] = &cp
		m.known[cp.IP] = true
	}
}

// ipLess 按 IPv4 数值比较（非法 IP 退化为字符串比较）。
func ipLess(a, b string) bool {
	ai, ok1 := parseIPv4([]byte(a))
	bi, ok2 := parseIPv4([]byte(b))
	if ok1 && ok2 {
		return ai < bi
	}
	return a < b
}

// parseIPv4Str 解析点分 IPv4 字符串为 uint32。
func parseIPv4Str(s string) (uint32, bool) { return parseIPv4([]byte(s)) }

// ---------------- 租约 / 邻居表解析（纯函数，可单测） ----------------

// readDHCPSLeases 读取 dhcp 租约文件。
func readDHCPSLeases(path string) []dhcpLease {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	return parseDHCPLeases(f)
}

// parseDHCPLeases 解析租约文件：expiry mac ip hostname clientid。
func parseDHCPLeases(r interface{ Read([]byte) (int, error) }) []dhcpLease {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 16*1024), 256*1024)
	var out []dhcpLease
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		expiry, _ := strconv.ParseInt(fields[0], 10, 64)
		mac := strings.ToLower(fields[1])
		ip := fields[2]
		host := fields[3]
		if host == "*" || host == "?" {
			host = ""
		}
		if _, ok := parseIPv4Str(ip); !ok {
			continue
		}
		out = append(out, dhcpLease{Expiry: expiry, MAC: mac, IP: ip, Hostname: host})
	}
	return out
}

// parseNeigh 解析 `ip neigh show` 输出。
func parseNeigh(out string) []neighEntry {
	var list []neighEntry
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 1 {
			continue
		}
		if _, ok := parseIPv4Str(fields[0]); !ok {
			continue
		}
		e := neighEntry{IP: fields[0]}
		for i := 1; i < len(fields); i++ {
			switch fields[i] {
			case "dev":
				if i+1 < len(fields) {
					e.Dev = fields[i+1]
					i++
				}
			case "lladdr":
				if i+1 < len(fields) {
					e.MAC = strings.ToLower(fields[i+1])
					i++
				}
			default:
				up := strings.ToUpper(fields[i])
				switch up {
				case "REACHABLE", "STALE", "DELAY", "PROBE", "PERMANENT", "NOARP":
					e.State = up
				case "FAILED", "INCOMPLETE":
					e.State = up
				}
			}
		}
		list = append(list, e)
	}
	return list
}

// isNeighOnline 邻居状态是否表示设备「此刻确实在场」。
//
// 关键：STALE 不算在线。STALE 只表示这条邻居记录本身还没失效，
// 内核不会主动删它 —— 设备关机、离开网络后，条目可能还会挂很久。
// 旧实现把 STALE 也当成在线，于是每一条陈旧邻居都会变成一个「设备」，
// 实机表现为 br-lan 上 64 条邻居（其中 32 条 STALE）被算成了一大堆设备。
//
// REACHABLE/DELAY/PROBE 是内核正在或刚刚确认过可达的状态，才算在线；
// PERMANENT 是静态条目（如手工配置的 ARP），也视为在场。
func isNeighOnline(state string) bool {
	switch strings.ToUpper(state) {
	case "REACHABLE", "DELAY", "PROBE", "PERMANENT":
		return true
	}
	return false
}

// isInternalNetwork 是否属于需要展示的设备网络。
// 口径（用户确认）：本地 DHCP 网段（lan）算内网；ZeroTier 另算（保留展示与单独计数）；
// 其他网络（vpn/tailscale、docker、未知私网段等）一律不算设备。
func isInternalNetwork(network string) bool {
	switch network {
	case "lan", "zerotier":
		return true
	}
	return false
}

// Clear 清空运行时设备状态（关闭采集开关时调用）。
func (m *DeviceMgr) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.devices = map[string]*DeviceState{}
	m.known = map[string]bool{}
}
