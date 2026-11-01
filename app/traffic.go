package main

// 流量聚合。
//
// 内存结构（全部有上限，防止长期运行内存爬升）：
//   - buckets：1min 聚合桶环，容量 maxBuckets（真机 1500 ≈ 24h，演示模式 12000 ≈ 8天）
//   - recent：最近 120 个采样点（2s 粒度，约 2 分钟）
//   - conns：最近活跃连接明细，容量 maxConns（2000）
//   - iDomain：当前采样区间内按域名聚合的增量
//
// 采样：conntrack 差分回调 AddDual 累加增量；每个采集周期 Tick 计算速率快照并滚动分钟桶。
// 分钟桶结束时通过 sink 回调追加 JSONL（每分钟一行，不做全量重写）。

import (
	"math"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
)

// Bucket 1 分钟聚合桶。
type Bucket struct {
	T       int64               // 分钟起始 Unix 秒
	Up      int64               // 上传字节
	Down    int64               // 下载字节
	CatUp   map[string]int64    // 分类上传字节
	CatDown map[string]int64    // 分类下载字节
	ByDev   map[string][2]int64 // 设备 -> [up, down]
}

func newBucket(t int64) *Bucket {
	return &Bucket{
		T:       t,
		CatUp:   map[string]int64{},
		CatDown: map[string]int64{},
		ByDev:   map[string][2]int64{},
	}
}

// ByCatTotal 分类总字节（落盘 byCat 字段）。
func (b *Bucket) ByCatTotal() map[string]int64 {
	out := make(map[string]int64, len(b.CatUp)+len(b.CatDown))
	for k, v := range b.CatUp {
		out[k] += v
	}
	for k, v := range b.CatDown {
		out[k] += v
	}
	return out
}

// Clone 深拷贝（避免把内部 map 交给 IO 后又被修改）。
func (b *Bucket) Clone() *Bucket {
	cp := newBucket(b.T)
	cp.Up, cp.Down = b.Up, b.Down
	for k, v := range b.CatUp {
		cp.CatUp[k] = v
	}
	for k, v := range b.CatDown {
		cp.CatDown[k] = v
	}
	for k, v := range b.ByDev {
		cp.ByDev[k] = v
	}
	return cp
}

// TrendPoint 采样点（速率，单位 bit/s）。
type TrendPoint struct {
	T    int64 `json:"t"`
	Up   int64 `json:"up"`
	Down int64 `json:"down"`
}

// Connection 连接明细（api.md §4 契约）。
type Connection struct {
	ID          string `json:"id"`
	Proto       string `json:"proto"`
	SrcIP       string `json:"srcIp"`
	SrcPort     int    `json:"srcPort"`
	DstIP       string `json:"dstIp"`
	DstPort     int    `json:"dstPort"`
	Domain      string `json:"domain"`
	App         string `json:"app"`
	Category    string `json:"category"`
	Path        string `json:"path"`
	Iface       string `json:"iface"`
	UpBytes     int64  `json:"upBytes"`
	DownBytes   int64  `json:"downBytes"`
	State       string `json:"state"`
	StartedAt   int64  `json:"startedAt"`
	LastSeenAt  int64  `json:"lastSeenAt"`
	DurationSec int64  `json:"durationSec"`
	DeviceName  string `json:"deviceName"`
}

// ConnUpdate 一次 flow 采样带来的连接更新。
type ConnUpdate struct {
	Key        string
	Proto      string
	SrcIP      string
	SrcPort    int
	DstIP      string
	DstPort    int
	DeviceIP   string
	State      string
	UpBytes    int64 // 累计
	DownBytes  int64 // 累计
	StartedAt  int64
	Now        int64
	Domain     string
	App        string
	Category   string
	Path       string
	Iface      string
	DeviceName string
}

// IntervalRates 一个采样周期的速率快照（各 map 发布后不再修改，可并发读）。
type IntervalRates struct {
	UpBps           int64
	DownBps         int64
	CatBps          map[string][2]int64
	DevBps          map[string][2]int64
	DevCatBps       map[string]map[string][2]int64
	DevDomainBps    map[string]map[string][2]int64
	DomainBps       map[string][2]int64
	DstBps          map[string][2]int64 // 目的 IP -> [up,down] bit/s（拓扑按网络拆分流量用）
	PathBps         map[string][2]int64 // 流向 -> [up,down] bit/s（direct/proxy/zerotier/vpn/lan）
	NewConnsLastMin int
}

const (
	recentCap     = 120
	defaultConns  = 2000
	defaultBucket = 1500
	maxDomainsIn  = 5000

	// maxDevDomainIn 单个采样区间内「设备×域名」条目的全局上限。
	// 每设备原本另有 256 上限，但设备数无上限，单区间仍可膨胀到数万项，
	// 每次 Tick 复制这些 map 会放大内存与 CPU 开销（N1 只有 1GB 内存）。
	maxDevDomainIn = 20000
	// maxDomainsPerDev 单设备保留的域名数上限（保持原有 256 的行为）。
	maxDomainsPerDev = 256
	// maxRateValue 速率类输出上限：int64 的一半，给后续累加/显示留余量，
	// 避免极端校准系数或异常增量在 float64→int64 转换时溢出为负值。
	maxRateValue = int64(1) << 62
)

// Agg 流量聚合器。
type Agg struct {
	mu sync.Mutex
	// sinkMu 串行化 sink 调用：sink 在 mu 之外执行（磁盘 IO 不能阻塞读 Agg 的 API），
	// 但仍需保证同一时刻只有一个落盘写。
	sinkMu     sync.Mutex
	maxBuckets int
	maxConns   int

	buckets []*Bucket // 升序
	cur     *Bucket

	recent []TrendPoint

	// 当前采样区间增量
	iUp, iDown int64
	iCatUp     map[string]int64
	iCatDown   map[string]int64
	iDev       map[string][2]int64
	iDevCat    map[string]map[string][2]int64
	iDevDomain map[string]map[string][2]int64
	// iDevDomainN 本区间「设备×域名」条目总数（受 maxDevDomainIn 限制）。
	iDevDomainN int
	iDomain     map[string][2]int64
	iDst        map[string][2]int64
	iPath       map[string][2]int64

	// lastRaw 最近一次速率快照（不可变，发布后只读）。Tick 在锁外构建完整快照后
	// 用 atomic.Pointer 发布，RawRates/LastRates 的读路径不再与采集协程争用 mu。
	lastRaw atomic.Pointer[IntervalRates]
	// scaledCache 按校准系数缩放后的快照缓存，键为（原始快照指针, 系数）：
	// 同一采样周期内的多次请求共享同一份 map，不必每次复制 5~7 张 map。
	scaledCache atomic.Pointer[scaledSnapshot]
	scaleMu     sync.Mutex // 串行化 scaledCache 未命中时的重建

	// lastTickAt 上一轮 Tick 的采样时刻（Unix 秒），用于按实测间隔换算速率：
	// 定时器在上一轮采集结束后才重新计时，实际两次采样间隔 = 标称间隔 + 采集耗时
	//（N1 上 100~300ms），继续用标称间隔做除数会让速率系统性偏高 5~15%。
	lastTickAt int64

	// scaleBits 校准系数（float64 位模式，无锁发布）。
	// 校准含义：conntrack 归因统计与物理接口速率的比例（由 App 用接口计数校准）。
	// conntrack 在 UDP 打洞/端口复用场景下会重复计入，绝对值不可信；
	// 这里用它做「相对权重」，乘以系数后锚定到物理真实速率。
	scaleBits atomic.Uint64

	conns        map[string]*Connection
	newConnTimes []int64

	sink func(*Bucket)
}

// scaledSnapshot 已按校准系数缩放的速率快照缓存（不可变）。
// raw 为来源快照指针，scale 为构建时使用的系数：两者任一变化即视为过期。
type scaledSnapshot struct {
	raw   *IntervalRates
	scale float64
	rates IntervalRates
}

// emptyRates 空速率快照（各 map 非 nil，读路径无需判空）。
func emptyRates() IntervalRates {
	return IntervalRates{
		CatBps:       map[string][2]int64{},
		DevBps:       map[string][2]int64{},
		DevCatBps:    map[string]map[string][2]int64{},
		DevDomainBps: map[string]map[string][2]int64{},
		DomainBps:    map[string][2]int64{},
		DstBps:       map[string][2]int64{},
		PathBps:      map[string][2]int64{},
	}
}

// NewAgg 创建聚合器，maxBuckets 为分钟桶保留数量。
func NewAgg(maxBuckets int) *Agg {
	if maxBuckets <= 0 {
		maxBuckets = defaultBucket
	}
	g := &Agg{
		maxBuckets: maxBuckets,
		maxConns:   defaultConns,
		conns:      map[string]*Connection{},
	}
	g.resetIntervalLocked()
	empty := emptyRates()
	g.lastRaw.Store(&empty)
	return g
}

func (g *Agg) resetIntervalLocked() {
	g.iUp, g.iDown = 0, 0
	g.iCatUp = map[string]int64{}
	g.iCatDown = map[string]int64{}
	g.iDev = map[string][2]int64{}
	g.iDevCat = map[string]map[string][2]int64{}
	g.iDevDomain = map[string]map[string][2]int64{}
	g.iDevDomainN = 0
	g.iDomain = map[string][2]int64{}
	g.iDst = map[string][2]int64{}
	g.iPath = map[string][2]int64{}
}

// AddPathBytes 按流向累计本区间流量（拓扑链路拆分用）。
// 设备连接由 onDelta 在 AddDelta 之外调用；非设备（docker0/本机）代理流量也会计入 proxy。
func (g *Agg) AddPathBytes(path string, up, down int64) {
	if path == "" || (up == 0 && down == 0) {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	p := g.iPath[path]
	p[0] += up
	p[1] += down
	g.iPath[path] = p
}

// SetSink 设置分钟桶落盘回调。
func (g *Agg) SetSink(fn func(*Bucket)) {
	g.mu.Lock()
	g.sink = fn
	g.mu.Unlock()
}

// SetMaxBuckets 调整保留桶数（演示模式预填历史时使用）。
func (g *Agg) SetMaxBuckets(n int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if n > 0 {
		g.maxBuckets = n
	}
}

// LoadHistory 载入历史桶（启动时从 JSONL 读取最近 24h）。
func (g *Agg) LoadHistory(buckets []*Bucket) {
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, b := range buckets {
		if b == nil || b.T >= timeNowMinute() {
			continue
		}
		g.buckets = append(g.buckets, b)
	}
	sort.Slice(g.buckets, func(i, j int) bool { return g.buckets[i].T < g.buckets[j].T })
	if len(g.buckets) > g.maxBuckets {
		g.buckets = g.buckets[len(g.buckets)-g.maxBuckets:]
	}
}

func timeNowMinute() int64 {
	return nowUnix() / 60 * 60
}

// sealBucketLocked 跨分钟时封存当前分钟桶，返回被封存的桶（nil 表示未跨分钟）。
// 落盘（sink）不在这里做：由调用方在锁外调用 flushSink，避免磁盘 IO 阻塞读 Agg 的 API。
// 没有数据的分钟不创建空桶（与原行为一致），有数据时由 ensureBucketLocked 创建。
func (g *Agg) sealBucketLocked(now int64) *Bucket {
	if g.cur == nil {
		return nil
	}
	minute := now / 60 * 60
	if minute < g.cur.T {
		// 系统时钟回拨（NTP 校时/手工改时间）：当前桶属于"未来"的分钟，
		// 不封存、也不新建更早的桶，继续在当前桶累加。
		// 否则会产生重复 T 的桶并打乱 buckets 升序，OldestBucketT 会取错最旧桶。
		return nil
	}
	if g.cur.T == minute {
		return nil
	}
	old := g.cur
	g.cur = nil
	g.buckets = append(g.buckets, old)
	// 正常时序下旧桶必然晚于队尾；仅异常序列（回拨后前进）可能乱序，此时保序，
	// 保证 OldestBucketT / BucketsSince 依赖的升序假设成立。
	if n := len(g.buckets); n > 1 && g.buckets[n-2].T > g.buckets[n-1].T {
		sort.Slice(g.buckets, func(i, j int) bool { return g.buckets[i].T < g.buckets[j].T })
	}
	if len(g.buckets) > g.maxBuckets {
		drop := len(g.buckets) - g.maxBuckets
		g.buckets = append([]*Bucket(nil), g.buckets[drop:]...)
	}
	return old
}

// ensureBucketLocked 取当前分钟桶，必要时新建。
// 时钟回拨保护：
//   - 已有当前桶时（now < cur.T 即回拨）不新建更早的桶，继续累加，避免出现重复 T；
//   - 当前桶已被 Tick 封存后时钟回拨的窄窗口里，新桶起点至少比最后一个已封存桶晚 1 分钟，
//     保证 buckets 始终升序、无重复 T。
func (g *Agg) ensureBucketLocked(now int64) *Bucket {
	if g.cur != nil {
		return g.cur
	}
	minute := now / 60 * 60
	if n := len(g.buckets); n > 0 && minute <= g.buckets[n-1].T {
		minute = g.buckets[n-1].T + 60
	}
	g.cur = newBucket(minute)
	return g.cur
}

// flushSink 落盘分钟桶（必须在 g.mu 之外调用）。
func (g *Agg) flushSink(b *Bucket) {
	if b == nil {
		return
	}
	g.mu.Lock()
	fn := g.sink
	g.mu.Unlock()
	if fn == nil {
		return
	}
	g.sinkMu.Lock()
	defer g.sinkMu.Unlock()
	fn(b.Clone())
}

// AddDelta 累加一段流量增量。cat 为分类键，domain 可为空。
func (g *Agg) AddDelta(devIP, dstIP, cat, domain string, up, down, now int64) {
	if up == 0 && down == 0 {
		return
	}
	if cat == "" {
		cat = "other"
	}
	g.mu.Lock()
	sealed := g.sealBucketLocked(now)
	b := g.ensureBucketLocked(now)
	b.Up += up
	b.Down += down
	b.CatUp[cat] += up
	b.CatDown[cat] += down
	d := b.ByDev[devIP]
	d[0] += up
	d[1] += down
	b.ByDev[devIP] = d
	g.iUp += up
	g.iDown += down
	g.iCatUp[cat] += up
	g.iCatDown[cat] += down
	iv := g.iDev[devIP]
	iv[0] += up
	iv[1] += down
	g.iDev[devIP] = iv

	// 目的 IP 维度增量（网络拓扑按 zt/vpn/direct 拆分流量用；上限控制）
	if dstIP != "" {
		if len(g.iDst) < maxDomainsIn {
			di := g.iDst[dstIP]
			di[0] += up
			di[1] += down
			g.iDst[dstIP] = di
		}
	}

	if g.iDevCat[devIP] == nil {
		g.iDevCat[devIP] = map[string][2]int64{}
	}
	cv := g.iDevCat[devIP][cat]
	cv[0] += up
	cv[1] += down
	g.iDevCat[devIP][cat] = cv

	if domain != "" {
		if len(g.iDomain) < maxDomainsIn {
			dv := g.iDomain[domain]
			dv[0] += up
			dv[1] += down
			g.iDomain[domain] = dv
		}
		dm := g.iDevDomain[devIP]
		if dm == nil && g.iDevDomainN < maxDevDomainIn {
			dm = make(map[string][2]int64)
			g.iDevDomain[devIP] = dm
		}
		if dm != nil && len(dm) < maxDomainsPerDev {
			dd, exists := dm[domain]
			if !exists && g.iDevDomainN >= maxDevDomainIn {
				// 达到全局条目上限：不再新增（已有条目继续累加），
				// 避免单区间膨胀到数万项并在每轮 Tick 复制时放大内存/CPU。
			} else {
				if !exists {
					g.iDevDomainN++
				}
				dd[0] += up
				dd[1] += down
				dm[domain] = dd
			}
		}
	}
	g.mu.Unlock()
	// 落盘在锁外做：磁盘 IO 不阻塞读 Agg 的 API
	g.flushSink(sealed)
}

// UpsertConn 更新/新建连接明细（有容量上限）。
func (g *Agg) UpsertConn(u ConnUpdate) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if c, ok := g.conns[u.Key]; ok {
		c.State = u.State
		c.UpBytes = u.UpBytes
		c.DownBytes = u.DownBytes
		c.LastSeenAt = u.Now
		c.DurationSec = u.Now - c.StartedAt
		if u.Domain != "" {
			c.Domain = u.Domain
		}
		if u.Category != "" {
			c.Category = u.Category
		}
		if u.App != "" {
			c.App = u.App
		}
		if u.DeviceName != "" {
			c.DeviceName = u.DeviceName
		}
		if u.Path != "" {
			c.Path = u.Path
		}
		if u.Iface != "" {
			c.Iface = u.Iface
		}
		return
	}
	c := &Connection{
		ID:          u.Key,
		Proto:       u.Proto,
		SrcIP:       u.SrcIP,
		SrcPort:     u.SrcPort,
		DstIP:       u.DstIP,
		DstPort:     u.DstPort,
		Domain:      u.Domain,
		App:         u.App,
		Category:    u.Category,
		Path:        u.Path,
		Iface:       u.Iface,
		UpBytes:     u.UpBytes,
		DownBytes:   u.DownBytes,
		State:       u.State,
		StartedAt:   u.StartedAt,
		LastSeenAt:  u.Now,
		DurationSec: u.Now - u.StartedAt,
		DeviceName:  u.DeviceName,
	}
	g.conns[u.Key] = c
	g.newConnTimes = append(g.newConnTimes, u.Now)
	if len(g.conns) > g.maxConns {
		g.evictConnsLocked()
	}
}

// evictConnsLocked 连接数超限时淘汰最久未活跃的 10%。
func (g *Agg) evictConnsLocked() {
	list := make([]*Connection, 0, len(g.conns))
	for _, c := range g.conns {
		list = append(list, c)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].LastSeenAt < list[j].LastSeenAt })
	n := len(list) / 10
	if n < 1 {
		n = 1
	}
	for i := 0; i < n && i < len(list); i++ {
		delete(g.conns, list[i].ID)
	}
}

// DropConn 删除连接（conntrack 条目消失时调用）。
func (g *Agg) DropConn(key string) {
	g.mu.Lock()
	delete(g.conns, key)
	g.mu.Unlock()
}

// Tick 结算一个采样周期：计算速率、追加趋势点、清理过期连接。
// intervalSec 为标称采样间隔秒数；实际除数按上一轮 Tick 的时刻实测（见下）。
// 同时显式封存分钟桶：即使本周期没有新流量，跨分钟也会把上一分钟封存并落盘
// （否则收尾分钟永远不会落盘，进程重启即丢）。
func (g *Agg) Tick(intervalSec, now int64) IntervalRates {
	if intervalSec <= 0 {
		intervalSec = 2
	}

	g.mu.Lock()
	// 实测采样间隔：Timer 在上一轮采集结束后才重新计时，两次采样之间的真实间隔
	// = 标称间隔 + 采集耗时（N1 上 100~300ms）。用标称间隔做除数会让速率系统性
	// 偏高 5~15%，这里改用与上一轮 Tick 的真实时间差。
	div := intervalSec
	if g.lastTickAt > 0 {
		if d := now - g.lastTickAt; d >= 1 && d <= intervalSec*4 {
			div = d
		}
		// d <= 0（时钟回拨）或 d 异常大（进程暂停/时钟跳变）时，本区间数据与
		// 时间轴不可比，回退到标称间隔，避免速率失真。
	}
	g.lastTickAt = now

	sealed := g.sealBucketLocked(now)

	// 取走本区间增量（resetIntervalLocked 会换成新 map），快照构建放到锁外，
	// 缩短持锁时间：AddDelta/UpsertConn 不被 map 复制阻塞。
	iUp, iDown := g.iUp, g.iDown
	iCatUp, iCatDown := g.iCatUp, g.iCatDown
	iDev, iDevCat, iDevDomain := g.iDev, g.iDevCat, g.iDevDomain
	iDomain, iDst, iPath := g.iDomain, g.iDst, g.iPath
	g.resetIntervalLocked()

	// 最近 1 分钟新连接数
	cut := now - 60
	idx := 0
	for idx < len(g.newConnTimes) && g.newConnTimes[idx] < cut {
		idx++
	}
	if idx > 0 {
		g.newConnTimes = append([]int64(nil), g.newConnTimes[idx:]...)
	}
	newConns := len(g.newConnTimes)

	// 清理 60s 无活动的连接
	for k, c := range g.conns {
		if c.LastSeenAt < cut {
			delete(g.conns, k)
		}
	}
	g.mu.Unlock()

	// 构建对外快照（锁外；i* 已由本函数独占，不会再有并发修改）
	r := IntervalRates{
		UpBps:           bps(iUp, div),
		DownBps:         bps(iDown, div),
		CatBps:          make(map[string][2]int64, len(iCatUp)+len(iCatDown)),
		DevBps:          pairsBps(iDev, div),
		DevCatBps:       devCatsBps(iDevCat, div),
		DevDomainBps:    devCatsBps(iDevDomain, div),
		DomainBps:       pairsBps(iDomain, div),
		DstBps:          pairsBps(iDst, div),
		PathBps:         pairsBps(iPath, div),
		NewConnsLastMin: newConns,
	}
	for k, v := range iCatUp {
		cur := r.CatBps[k]
		cur[0] = bps(v, div)
		r.CatBps[k] = cur
	}
	for k, v := range iCatDown {
		cur := r.CatBps[k]
		cur[1] = bps(v, div)
		r.CatBps[k] = cur
	}

	// 发布不可变快照并追加趋势点：读路径（LastRates/RawRates）无锁、零复制；
	// 缩放副本由 LastRates 按（快照, 系数）惰性生成并缓存。
	g.mu.Lock()
	g.recent = append(g.recent, TrendPoint{T: now, Up: r.UpBps, Down: r.DownBps})
	if len(g.recent) > recentCap {
		g.recent = g.recent[len(g.recent)-recentCap:]
	}
	g.lastRaw.Store(&r)
	g.mu.Unlock()

	// 落盘在锁外做：磁盘 IO 不阻塞读 Agg 的 API
	g.flushSink(sealed)
	return r
}

// bps 字节增量 -> bit/s（div 为实测间隔秒数）。
func bps(v, div int64) int64 {
	if div <= 0 {
		div = 1
	}
	return clampRate(v * 8 / div)
}

// pairsBps 把 [up,down] 字节增量映射换算成 bit/s。
func pairsBps(m map[string][2]int64, div int64) map[string][2]int64 {
	out := make(map[string][2]int64, len(m))
	for k, v := range m {
		out[k] = [2]int64{bps(v[0], div), bps(v[1], div)}
	}
	return out
}

// devCatsBps 嵌套 map 的字节 -> bit/s 换算。
func devCatsBps(m map[string]map[string][2]int64, div int64) map[string]map[string][2]int64 {
	out := make(map[string]map[string][2]int64, len(m))
	for dev, cats := range m {
		out[dev] = pairsBps(cats, div)
	}
	return out
}

// SetScale 设置校准系数（conntrack 权重 → 物理速率的比例）。
// 限幅 [0.05, 20]：conntrack 表被清空/归因骤降时的极端比值（实测可达 1e3~1e5）
// 视为异常样本直接丢弃，避免全站速率被放大数个数量级。
// NaN/Inf 同样拒绝：旧写法对 NaN 的比较恒为 false，会把系数污染成 NaN。
func (g *Agg) SetScale(f float64) {
	if !(f >= 0.05 && f <= 20) {
		return
	}
	g.scaleBits.Store(math.Float64bits(f))
}

// RawRates 返回未经校准缩放的原始速率快照（用于计算校准系数）。读路径无锁。
func (g *Agg) RawRates() IntervalRates {
	if p := g.lastRaw.Load(); p != nil {
		return *p
	}
	return emptyRates()
}

// Scale 当前校准系数。读路径无锁。
func (g *Agg) Scale() float64 {
	return g.effectiveScale()
}

// effectiveScale 当前生效系数（未设置/非法时按 1 处理）。
func (g *Agg) effectiveScale() float64 {
	f := math.Float64frombits(g.scaleBits.Load())
	if f <= 0 {
		return 1
	}
	return f
}

// LastRates 最近一次速率快照（map 只读）。返回前按校准系数缩放到物理真实量级。
// 读路径无锁：原始快照由 Tick 原子发布后不再修改；缩放副本按（快照指针, 系数）
// 缓存在 scaledCache，同一采样周期内的多次请求共享同一份 map，不再重复复制。
func (g *Agg) LastRates() IntervalRates {
	raw := g.lastRaw.Load()
	if raw == nil {
		return emptyRates()
	}
	f := g.effectiveScale()
	if f == 1 {
		return *raw // 系数为 1：直接共享原始快照（零复制）
	}
	if p := g.scaledCache.Load(); p != nil && p.raw == raw && p.scale == f {
		return p.rates
	}
	g.scaleMu.Lock()
	defer g.scaleMu.Unlock()
	// 双重检查：并发未命中时只构建一次
	if p := g.scaledCache.Load(); p != nil && p.raw == raw && p.scale == f {
		return p.rates
	}
	snap := &scaledSnapshot{raw: raw, scale: f, rates: scaleRates(*raw, f)}
	g.scaledCache.Store(snap)
	return snap.rates
}

// scaleRates 返回按系数缩放的完整快照；f==1 时直接返回入参（零复制）。
func scaleRates(r IntervalRates, f float64) IntervalRates {
	if f == 1 {
		return r
	}
	out := r
	out.UpBps = scaleValue(r.UpBps, f)
	out.DownBps = scaleValue(r.DownBps, f)
	out.CatBps = scalePairs(r.CatBps, f)
	out.DevBps = scalePairs(r.DevBps, f)
	out.DomainBps = scalePairs(r.DomainBps, f)
	out.DstBps = scalePairs(r.DstBps, f)
	out.PathBps = scalePairs(r.PathBps, f)
	out.DevCatBps = scaleDevCats(r.DevCatBps, f)
	out.DevDomainBps = scaleDevCats(r.DevDomainBps, f)
	return out
}

// clampRate 把速率钳制到 [0, maxRateValue]：异常增量/极端系数下
// float64→int64 转换可能溢出为负或巨值，统一饱和，避免负数进入 API。
func clampRate(v int64) int64 {
	if v < 0 {
		return 0
	}
	if v > maxRateValue {
		return maxRateValue
	}
	return v
}

// scaleValue 按系数缩放单个速率并饱和钳制。
func scaleValue(v int64, f float64) int64 {
	if v <= 0 || f <= 0 || math.IsNaN(f) {
		return 0
	}
	scaled := float64(v) * f
	if math.IsInf(scaled, 1) || scaled >= float64(maxRateValue) {
		return maxRateValue
	}
	if scaled <= 0 {
		return 0
	}
	return int64(scaled)
}

// scalePairs 按系数缩放 [2]int64 映射。
func scalePairs(m map[string][2]int64, f float64) map[string][2]int64 {
	if len(m) == 0 {
		return m
	}
	out := make(map[string][2]int64, len(m))
	for k, v := range m {
		out[k] = [2]int64{scaleValue(v[0], f), scaleValue(v[1], f)}
	}
	return out
}

// scaleDevCats 按系数缩放 嵌套的 [2]int64 映射。
func scaleDevCats(m map[string]map[string][2]int64, f float64) map[string]map[string][2]int64 {
	if len(m) == 0 {
		return m
	}
	out := make(map[string]map[string][2]int64, len(m))
	for dev, cats := range m {
		out[dev] = scalePairs(cats, f)
	}
	return out
}

// RecentTrend 最近趋势点（最多 60 个）。已按校准系数缩放。
func (g *Agg) RecentTrend(limit int) []TrendPoint {
	g.mu.Lock()
	if limit <= 0 || limit > len(g.recent) {
		limit = len(g.recent)
	}
	out := make([]TrendPoint, limit)
	copy(out, g.recent[len(g.recent)-limit:])
	g.mu.Unlock()
	if f := g.effectiveScale(); f != 1 {
		for i := range out {
			out[i].Up = scaleValue(out[i].Up, f)
			out[i].Down = scaleValue(out[i].Down, f)
		}
	}
	return out
}

// BucketsSince 返回时间 >= from 的分钟桶（含当前未完成桶）。
//
// 性能/所有权约定：已封存的桶在封存后不再修改，这里直接返回内部指针（零拷贝），
// 调用方只能读取，绝不能修改返回的 Bucket（包括其 map）。当前未完成的桶仍在累加，
// 返回其深拷贝，避免与采集协程并发读写 map。
func (g *Agg) BucketsSince(from int64) []*Bucket {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make([]*Bucket, 0, len(g.buckets)+1)
	for _, b := range g.buckets {
		if b.T >= from {
			out = append(out, b) // 共享只读（已封存桶不可变）
		}
	}
	if g.cur != nil && g.cur.T >= from {
		out = append(out, g.cur.Clone())
	}
	return out
}

// OldestBucketT 最旧分钟桶起点（无数据返回 0）。
func (g *Agg) OldestBucketT() int64 {
	g.mu.Lock()
	defer g.mu.Unlock()
	if len(g.buckets) > 0 {
		return g.buckets[0].T
	}
	if g.cur != nil {
		return g.cur.T
	}
	return 0
}

// ConnList 连接列表（按最后活跃时间倒序），支持过滤与分页上限。
func (g *Agg) ConnList(limit int, q, device string) ([]Connection, int) {
	g.mu.Lock()
	list := make([]Connection, 0, len(g.conns))
	for _, c := range g.conns {
		list = append(list, *c)
	}
	g.mu.Unlock()
	if q != "" {
		q = strings.ToLower(q)
		filtered := list[:0]
		for _, c := range list {
			if strings.Contains(strings.ToLower(c.Domain), q) ||
				strings.Contains(strings.ToLower(c.App), q) ||
				strings.Contains(strings.ToLower(c.DstIP), q) ||
				strings.Contains(strings.ToLower(c.SrcIP), q) ||
				strings.Contains(strings.ToLower(c.DeviceName), q) {
				filtered = append(filtered, c)
			}
		}
		list = filtered
	}
	if device != "" {
		filtered := list[:0]
		for _, c := range list {
			if strings.EqualFold(c.SrcIP, device) || strings.Contains(strings.ToLower(c.DeviceName), strings.ToLower(device)) {
				filtered = append(filtered, c)
			}
		}
		list = filtered
	}
	sort.Slice(list, func(i, j int) bool { return list[i].LastSeenAt > list[j].LastSeenAt })
	total := len(list)
	if limit <= 0 {
		limit = 200
	}
	if limit > 500 {
		limit = 500
	}
	if len(list) > limit {
		list = list[:limit]
	}
	return list, total
}

// ConnByID 按 ID 查连接。
func (g *Agg) ConnByID(id string) (Connection, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if c, ok := g.conns[id]; ok {
		return *c, true
	}
	return Connection{}, false
}

// DeviceConnCount 每设备连接数。
func (g *Agg) DeviceConnCount() map[string]int {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make(map[string]int, len(g.conns))
	for _, c := range g.conns {
		out[c.SrcIP]++
	}
	return out
}

// DeviceConns 某设备连接列表。
func (g *Agg) DeviceConns(ip string) []Connection {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make([]Connection, 0, 16)
	for _, c := range g.conns {
		if c.SrcIP == ip {
			out = append(out, *c)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LastSeenAt > out[j].LastSeenAt })
	if len(out) > 50 {
		out = out[:50]
	}
	return out
}

// Clear 清空全部运行时聚合数据（关闭采集开关时调用，回到空状态并释放内存）。
func (g *Agg) Clear() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.buckets = nil
	g.cur = nil
	g.recent = nil
	g.conns = map[string]*Connection{}
	g.newConnTimes = nil
	g.resetIntervalLocked()
	empty := emptyRates()
	g.lastRaw.Store(&empty)
}

// DeviceDstBytes 每设备到各目标 IP 的累计字节（用于设备详情 topDsts）。
// 只统计当前活跃连接，天然有上限。
func (g *Agg) DeviceDstBytes(ip string) map[string]int64 {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := map[string]int64{}
	for _, c := range g.conns {
		if c.SrcIP == ip {
			out[c.DstIP] += c.UpBytes + c.DownBytes
		}
	}
	return out
}
