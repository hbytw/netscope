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
	"sort"
	"strings"
	"sync"
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
	iDomain    map[string][2]int64
	iDst       map[string][2]int64
	iPath      map[string][2]int64

	last IntervalRates

	// scale 校准系数：conntrack 归因统计与物理接口速率的比例（由 App 用接口计数校准）。
	// conntrack 在 UDP 打洞/端口复用场景下会重复计入，绝对值不可信；
	// 这里用它做「相对权重」，乘以系数后锚定到物理真实速率。
	scale float64

	conns        map[string]*Connection
	newConnTimes []int64

	sink func(*Bucket)
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
	g.last = IntervalRates{
		CatBps:       map[string][2]int64{},
		DevBps:       map[string][2]int64{},
		DevCatBps:    map[string]map[string][2]int64{},
		DevDomainBps: map[string]map[string][2]int64{},
		DomainBps:    map[string][2]int64{},
		DstBps:       map[string][2]int64{},
		PathBps:      map[string][2]int64{},
	}
	return g
}

func (g *Agg) resetIntervalLocked() {
	g.iUp, g.iDown = 0, 0
	g.iCatUp = map[string]int64{}
	g.iCatDown = map[string]int64{}
	g.iDev = map[string][2]int64{}
	g.iDevCat = map[string]map[string][2]int64{}
	g.iDevDomain = map[string]map[string][2]int64{}
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
// 没有数据的分钟不创建空桶（与原行为一致），有数据时由 AddDelta 创建。
func (g *Agg) sealBucketLocked(now int64) *Bucket {
	minute := now / 60 * 60
	if g.cur == nil || g.cur.T == minute {
		return nil
	}
	old := g.cur
	g.cur = nil
	g.buckets = append(g.buckets, old)
	if len(g.buckets) > g.maxBuckets {
		drop := len(g.buckets) - g.maxBuckets
		g.buckets = append([]*Bucket(nil), g.buckets[drop:]...)
	}
	return old
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
	b := g.cur
	if b == nil {
		b = newBucket(now / 60 * 60)
		g.cur = b
	}
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
		if g.iDevDomain[devIP] == nil {
			g.iDevDomain[devIP] = map[string][2]int64{}
		}
		if len(g.iDevDomain[devIP]) < 256 {
			dd := g.iDevDomain[devIP][domain]
			dd[0] += up
			dd[1] += down
			g.iDevDomain[devIP][domain] = dd
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
// intervalSec 为采样间隔秒数。
// 同时显式封存分钟桶：即使本周期没有新流量，跨分钟也会把上一分钟封存并落盘
// （否则收尾分钟永远不会落盘，进程重启即丢）。
func (g *Agg) Tick(intervalSec, now int64) IntervalRates {
	if intervalSec <= 0 {
		intervalSec = 2
	}
	g.mu.Lock()
	div := intervalSec
	sealed := g.sealBucketLocked(now)

	r := IntervalRates{
		UpBps:           g.iUp * 8 / div,
		DownBps:         g.iDown * 8 / div,
		CatBps:          map[string][2]int64{},
		DevBps:          g.iDev,
		DevCatBps:       g.iDevCat,
		DevDomainBps:    g.iDevDomain,
		DomainBps:       g.iDomain,
		NewConnsLastMin: 0,
	}
	for k, v := range g.iCatUp {
		cur := r.CatBps[k]
		cur[0] = v * 8 / div
		r.CatBps[k] = cur
	}
	for k, v := range g.iCatDown {
		cur := r.CatBps[k]
		cur[1] = v * 8 / div
		r.CatBps[k] = cur
	}
	// 设备/域名增量转速率（就地换算出新 map，发布后不再修改）
	devBps := make(map[string][2]int64, len(g.iDev))
	for k, v := range g.iDev {
		devBps[k] = [2]int64{v[0] * 8 / div, v[1] * 8 / div}
	}
	r.DevBps = devBps
	domBps := make(map[string][2]int64, len(g.iDomain))
	for k, v := range g.iDomain {
		domBps[k] = [2]int64{v[0] * 8 / div, v[1] * 8 / div}
	}
	r.DomainBps = domBps
	devCatBps := make(map[string]map[string][2]int64, len(g.iDevCat))
	for dev, cats := range g.iDevCat {
		m := make(map[string][2]int64, len(cats))
		for c, v := range cats {
			m[c] = [2]int64{v[0] * 8 / div, v[1] * 8 / div}
		}
		devCatBps[dev] = m
	}
	r.DevCatBps = devCatBps
	devDomBps := make(map[string]map[string][2]int64, len(g.iDevDomain))
	for dev, doms := range g.iDevDomain {
		m := make(map[string][2]int64, len(doms))
		for d, v := range doms {
			m[d] = [2]int64{v[0] * 8 / div, v[1] * 8 / div}
		}
		devDomBps[dev] = m
	}
	r.DevDomainBps = devDomBps

	dstBps := make(map[string][2]int64, len(g.iDst))
	for k, v := range g.iDst {
		dstBps[k] = [2]int64{v[0] * 8 / div, v[1] * 8 / div}
	}
	r.DstBps = dstBps

	pathBps := make(map[string][2]int64, len(g.iPath))
	for k, v := range g.iPath {
		pathBps[k] = [2]int64{v[0] * 8 / div, v[1] * 8 / div}
	}
	r.PathBps = pathBps

	g.recent = append(g.recent, TrendPoint{T: now, Up: r.UpBps, Down: r.DownBps})
	if len(g.recent) > recentCap {
		g.recent = g.recent[len(g.recent)-recentCap:]
	}

	// 最近 1 分钟新连接数
	cut := now - 60
	idx := 0
	for idx < len(g.newConnTimes) && g.newConnTimes[idx] < cut {
		idx++
	}
	if idx > 0 {
		g.newConnTimes = append([]int64(nil), g.newConnTimes[idx:]...)
	}
	r.NewConnsLastMin = len(g.newConnTimes)

	// 清理 60s 无活动的连接
	for k, c := range g.conns {
		if c.LastSeenAt < cut {
			delete(g.conns, k)
		}
	}

	g.last = r
	g.resetIntervalLocked()
	g.mu.Unlock()
	// 落盘在锁外做：磁盘 IO 不阻塞读 Agg 的 API
	g.flushSink(sealed)
	return r
}

// SetScale 设置校准系数（conntrack 权重 → 物理速率的比例）。
// 限幅 [0.05, 20]：conntrack 表被清空/归因骤降时的极端比值（实测可达 1e3~1e5）
// 视为异常样本直接丢弃，避免全站速率被放大数个数量级。
func (g *Agg) SetScale(f float64) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if f < 0.05 || f > 20 {
		return
	}
	g.scale = f
}

// RawRates 返回未经校准缩放的原始速率快照（用于计算校准系数）。
func (g *Agg) RawRates() IntervalRates {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.last
}

// Scale 当前校准系数。
func (g *Agg) Scale() float64 {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.scale <= 0 {
		return 1
	}
	return g.scale
}

// LastRates 最近一次速率快照（map 只读）。返回前按校准系数缩放到物理真实量级。
func (g *Agg) LastRates() IntervalRates {
	g.mu.Lock()
	defer g.mu.Unlock()
	r := g.last
	if g.scale > 0 && g.scale != 1 {
		r.UpBps = int64(float64(r.UpBps) * g.scale)
		r.DownBps = int64(float64(r.DownBps) * g.scale)
		r.CatBps = scalePairs(r.CatBps, g.scale)
		r.DevBps = scalePairs(r.DevBps, g.scale)
		r.DomainBps = scalePairs(r.DomainBps, g.scale)
		r.DstBps = scalePairs(r.DstBps, g.scale)
		r.PathBps = scalePairs(r.PathBps, g.scale)
		r.DevCatBps = scaleDevCats(r.DevCatBps, g.scale)
		r.DevDomainBps = scaleDevCats(r.DevDomainBps, g.scale)
	}
	return r
}

// scalePairs 按系数缩放 [2]int64 映射。
func scalePairs(m map[string][2]int64, f float64) map[string][2]int64 {
	if len(m) == 0 {
		return m
	}
	out := make(map[string][2]int64, len(m))
	for k, v := range m {
		out[k] = [2]int64{int64(float64(v[0]) * f), int64(float64(v[1]) * f)}
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
	defer g.mu.Unlock()
	if limit <= 0 || limit > len(g.recent) {
		limit = len(g.recent)
	}
	out := make([]TrendPoint, limit)
	copy(out, g.recent[len(g.recent)-limit:])
	if g.scale > 0 && g.scale != 1 {
		for i := range out {
			out[i].Up = int64(float64(out[i].Up) * g.scale)
			out[i].Down = int64(float64(out[i].Down) * g.scale)
		}
	}
	return out
}

// BucketsSince 返回时间 >= from 的分钟桶（深拷贝，含当前未完成桶）。
func (g *Agg) BucketsSince(from int64) []*Bucket {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make([]*Bucket, 0, len(g.buckets)+1)
	for _, b := range g.buckets {
		if b.T >= from {
			out = append(out, b.Clone())
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
	g.last = IntervalRates{
		CatBps:       map[string][2]int64{},
		DevBps:       map[string][2]int64{},
		DevCatBps:    map[string]map[string][2]int64{},
		DevDomainBps: map[string]map[string][2]int64{},
		DomainBps:    map[string][2]int64{},
		DstBps:       map[string][2]int64{},
		PathBps:      map[string][2]int64{},
	}
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
