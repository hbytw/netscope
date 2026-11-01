package main

// 系统指标采集：/proc/stat、/proc/meminfo、/proc/net/dev、/proc/loadavg、
// thermal_zone、nf_conntrack_count、/proc/uptime、进程 RSS。
//
// 接口速率口径（/proc/net/dev）：
//   - 有真 WAN 口（默认路由出口非内网桥/隧道，复用 topology.go 的 wanIface 判定）
//     时优先取 WAN 口计数：WAN RX=外网→用户=下行、WAN TX=用户→外网=上行，每字节只计一次；
//   - 无真 WAN（旁路由，出口是 br-lan）时 br-lan 是中转桥：RX≈TX≈总流量（每字节计两次），
//     此时 WanRxBps/WanTxBps 仅作总量观察，KPI 的 NetUpBps/NetDownBps 改用
//     conntrack 归因的设备侧外发链路速率（见 Sample 内注释）。
//
// 演示模式生成平滑合成值，不读 /proc。

import (
	"math"
	"math/rand"
	"os"
	"strings"
	"sync"
	"time"
)

// SysSnapshot 系统指标快照。
type SysSnapshot struct {
	CPUPct     float64
	MemPct     float64
	MemUsedMb  int64
	MemTotalMb int64
	MemFreeMb  int64
	Load1      float64
	UptimeSec  int64
	TempC      float64
	// WanRxBps/WanTxBps：物理接口速率（bit/s）。
	//   有真 WAN 口：WAN 口 RX/TX 计数（RX=下行、TX=上行，每字节各计一次）；
	//   无真 WAN（旁路由）：退化为 br-lan/eth0 中转计数，RX≈TX≈总流量（中转桥每字节计两次），
	//   仅作总量观察，不代表用户上下行（KPI 上下行见 NetUpBps/NetDownBps）。
	WanRxBps int64
	WanTxBps int64
	// NetUpBps/NetDownBps：KPI 用户视角上下行速率（bit/s），前端 upBps/downBps 直接取值。
	//   采到真 WAN 口计数：NetUpBps = WAN TX（用户→外网）、NetDownBps = WAN RX（外网→用户）；
	//   未采到 WAN 计数（旁路由形态，或 WAN 口临时缺失）：物理计数无法区分用户方向
	//     （br-lan RX≈TX≈中转总量），改用 conntrack 归因的设备侧外发链路速率
	//     （direct/proxy/zerotier/vpn 之和，不含 lan 内网互访），再经 updateScale 锚定物理量级。
	//   两种情形都是「用户上网上下行」，不含本机/docker 流量。
	NetUpBps   int64
	NetDownBps int64
	// PhysTotalBps：物理基准总量（bit/s，单方向口径），仅供 updateScale 校准与总量校验，
	// 不作为对外 KPI。conntrack 是「每连接一次计数」，而旁路由中转下 br-lan 的
	// RX+TX 每字节计两次（直接相加比较会得到约 2 倍的系统性放大），因此这里：
	//   有真 WAN 口（拓扑判定，与本轮计数是否读到无关）：RX+TX，
	//     WAN 或 br-lan/eth0 每字节都只在其方向上计一次；
	//   无真 WAN（旁路由）：(br-lan RX + br-lan TX)/2（取均值还原单方向总量）。
	PhysTotalBps int64
	ConnCount    int64
	DiskFreeMb   int64
	RSSMb        int64
	Model        string
	Arch         string
	Kernel       string
	OpenWrt      string
	Hostname     string
}

// SysInfo 系统采样器。
type SysInfo struct {
	app  *App
	demo bool

	mu sync.Mutex
	s  SysSnapshot

	// 采样差分
	prevCPU   cpuTimes
	prevNetRx int64
	prevNetTx int64
	prevIface string // 上次差分所用接口（WAN 口出现/消失时重新登记基准）
	havePrev  bool

	// 静态信息缓存（model/arch/kernel/openwrt/hostname）：读到一次后不再读文件
	staticMu   sync.Mutex
	static     staticInfo
	staticDone bool

	// 低频指标缓存（负载 / 运行时间 / conntrack 条数 / 进程 RSS）
	slow      SysSnapshot
	slowAt    int64
	slowValid bool

	diskFreeMb int64
	diskAt     int64
	sampleN    int64
	demoStart  time.Time
}

// slowSampleSec 低频指标采样间隔（秒）。
//
// CPU / 内存 / 温度 / 接口流量保持每轮采样（采集间隔，默认 2s）；
// 负载、运行时间、conntrack 条数、进程 RSS 变化慢，且每项都要读一个小文件，
// 降到 6s 一次后其余轮次直接复用缓存值。
const slowSampleSec = 6

// staticInfo 不常变化的系统信息（首次读到后缓存，进程生命周期内不再重读）。
type staticInfo struct {
	model    string
	arch     string
	kernel   string
	openwrt  string
	hostname string
}

type cpuTimes struct {
	total uint64
	idle  uint64
}

// NewSysInfo 创建采样器。
func NewSysInfo(a *App, demo bool) *SysInfo {
	return &SysInfo{app: a, demo: demo, demoStart: time.Now()}
}

// Sample 采集一次系统指标。intervalSec 为采样间隔（用于接口速率计算）。
func (s *SysInfo) Sample(intervalSec int64) {
	if s.demo {
		s.sampleDemo(intervalSec)
		return
	}
	if intervalSec <= 0 {
		intervalSec = 2
	}
	now := time.Now().Unix()
	var snap SysSnapshot

	// CPU
	if b, err := os.ReadFile("/proc/stat"); err == nil {
		line := firstLine(string(b))
		if cur, ok := parseProcStat(line); ok {
			if s.havePrev && cur.total > s.prevCPU.total {
				dt := cur.total - s.prevCPU.total
				di := cur.idle - s.prevCPU.idle
				if dt > 0 {
					busy := 100.0 * float64(dt-di) / float64(dt)
					if busy < 0 {
						busy = 0
					}
					if busy > 100 {
						busy = 100
					}
					snap.CPUPct = math.Round(busy*10) / 10
				}
			}
			s.prevCPU = cur
		}
	}
	// 内存
	if b, err := os.ReadFile("/proc/meminfo"); err == nil {
		if total, avail, ok := parseMemInfo(string(b)); ok {
			snap.MemTotalMb = total / 1024
			snap.MemFreeMb = avail / 1024
			snap.MemUsedMb = snap.MemTotalMb - snap.MemFreeMb
			if snap.MemTotalMb > 0 {
				snap.MemPct = math.Round(float64(snap.MemUsedMb)*1000/float64(snap.MemTotalMb)) / 10
			}
		}
	}
	// 负载 / 运行时间 / conntrack 条数 / 进程 RSS：低频采样（每 slowSampleSec 一次）
	s.fillSlow(&snap, now)
	// 温度
	if b, err := os.ReadFile("/sys/class/thermal/thermal_zone0/temp"); err == nil {
		milli, ok := atoi64OK(trimSpaceBytes(b))
		if ok && milli > 0 {
			snap.TempC = math.Round(float64(milli)/100) / 10
		}
	}
	// 接口速率（真 WAN 口优先；无真 WAN 的旁路由形态用 br-lan/eth0 中转计数）
	usedWAN := false
	if b, err := os.ReadFile("/proc/net/dev"); err == nil {
		// 只解析一次（与 topology.go 共用 parseNetDevAll），后续按接口名查表
		dev := parseNetDevAll(string(b))
		// 真 WAN 口判定：复用 topology.go 的 wanIface（默认路由出口且非内网桥/隧道），
		// interfaces()/routeLines() 走 10s 共享命令缓存，采样周期内不会反复 fork。
		wanName := ""
		if s.app != nil {
			wanName = wanIface(s.app.interfaces(), s.app.routeLines())
		}
		var physRx, physTx int64
		iface := ""
		if wanName != "" {
			if c, ok := dev[wanName]; ok {
				physRx, physTx, iface, usedWAN = c[0], c[1], wanName, true
			}
		}
		if iface == "" {
			if c, ok := dev["br-lan"]; ok {
				physRx, physTx, iface = c[0], c[1], "br-lan"
			} else if c, ok := dev["eth0"]; ok {
				physRx, physTx, iface = c[0], c[1], "eth0"
			}
		}
		if iface != "" {
			// prevIface 记录上次差分基准：WAN 口出现/消失时基准切换，
			// 跳过一次差分重新登记，避免两个不同计数器相减产生假尖峰。
			if s.havePrev && s.prevIface == iface && intervalSec > 0 {
				drx := physRx - s.prevNetRx
				dtx := physTx - s.prevNetTx
				if drx < 0 {
					drx = 0
				}
				if dtx < 0 {
					dtx = 0
				}
				rxBps := drx * 8 / intervalSec
				txBps := dtx * 8 / intervalSec
				snap.WanRxBps = rxBps
				snap.WanTxBps = txBps
				if wanName != "" {
					// 有真 WAN 口的形态：所采接口（WAN 优先；WAN 计数临时读不到时
					// br-lan/eth0 兜底）每个字节只在其方向上计一次，与 conntrack 同量纲。
					snap.PhysTotalBps = rxBps + txBps
					if usedWAN {
						// WAN RX=外网→用户=下行，TX=用户→外网=上行
						snap.NetDownBps = rxBps
						snap.NetUpBps = txBps
					}
				} else {
					// 无真 WAN（旁路由）：br-lan 是中转桥，RX≈TX≈总流量（每字节计两次），
					// 物理基准取单方向均值；KPI 上下行改由 conntrack path 归因（见下）
					snap.PhysTotalBps = (rxBps + txBps) / 2
				}
			}
			s.prevNetRx, s.prevNetTx, s.prevIface = physRx, physTx, iface
		}
	}
	s.havePrev = true
	// KPI 上下行（未采到 WAN 计数时）：conntrack 归因的设备侧外发链路速率
	//（direct/proxy/zerotier/vpn 之和，不含 lan 内网互访与本机流量），
	// 再由 updateScale 锚定到 PhysTotalBps 的物理量级。
	// 旁路由形态下物理计数只做总量校验（br-lan 无法区分用户方向）。
	if !usedWAN && s.app != nil && s.app.agg != nil {
		var kpiUp, kpiDown int64
		for p, v := range s.app.agg.LastRates().PathBps {
			if p == "lan" || p == "docker" {
				continue
			}
			kpiUp += v[0]
			kpiDown += v[1]
		}
		snap.NetUpBps = kpiUp
		snap.NetDownBps = kpiDown
	}
	// 磁盘占用（60s 更新一次，避免频繁 fork df）
	s.sampleN++
	if s.sampleN%30 == 1 || now-s.diskAt > 60 {
		s.diskFreeMb = s.queryDiskFree()
		s.diskAt = now
	}
	snap.DiskFreeMb = s.diskFreeMb
	// 静态信息（model/arch/kernel/openwrt/hostname）：首次读到后缓存
	s.fillStatic(&snap)

	s.mu.Lock()
	s.s = snap
	s.mu.Unlock()
}

// fillSlow 填充低频指标（负载 / 运行时间 / conntrack 条数 / 进程 RSS）。
//
// 这几项变化慢、但每项每轮都要读一个小文件；按 slowSampleSec 节拍采样并缓存，
// 其余轮次直接用上次值（CPU / 内存 / 温度 / 接口流量仍每轮采样）。
// 运行时间按「上次采样值 + 已过秒数」推算：展示仍是逐秒递增，不会出现 6s 一跳。
func (s *SysInfo) fillSlow(snap *SysSnapshot, now int64) {
	if !s.slowValid || now-s.slowAt >= slowSampleSec || now < s.slowAt {
		s.sampleSlow(now)
	}
	snap.Load1, snap.ConnCount, snap.RSSMb = s.slow.Load1, s.slow.ConnCount, s.slow.RSSMb
	up := s.slow.UptimeSec
	if up > 0 {
		if d := now - s.slowAt; d > 0 {
			up += d
		}
	}
	snap.UptimeSec = up
}

// sampleSlow 采样一次低频指标并写入缓存。
func (s *SysInfo) sampleSlow(now int64) {
	var v SysSnapshot
	// 负载
	if b, err := os.ReadFile("/proc/loadavg"); err == nil {
		var l1 float64
		if _, err := fmtSscan(string(b), &l1); err == nil {
			v.Load1 = math.Round(l1*100) / 100
		}
	}
	// 运行时间
	if b, err := os.ReadFile("/proc/uptime"); err == nil {
		fields := strings.Fields(string(b))
		if len(fields) > 0 {
			if sec, err := parseFloat(fields[0]); err == nil {
				v.UptimeSec = int64(sec)
			}
		}
	}
	// conntrack 条数
	if b, err := os.ReadFile("/proc/sys/net/netfilter/nf_conntrack_count"); err == nil {
		n, _ := atoi64OK(trimSpaceBytes(b))
		v.ConnCount = n
	}
	// 进程 RSS
	v.RSSMb = readProcessRSSMb()
	s.slow, s.slowAt, s.slowValid = v, now, true
}

// fillStatic 填充不常变化的系统信息：每个字段首次读到后缓存，不再每轮读文件。
//
// 旧实现每轮（默认 2s）都重读 /tmp/sysinfo/model、/proc/sys/kernel/osrelease、
// /etc/openwrt_release 并调用 os.Hostname（快照每轮是新的空结构，字段永远为空，
// 因此「只填空字段」从未生效）。现在：
//   - 读到的字段立刻缓存，后续轮次零文件读取；
//   - 读不到的字段下轮再试（保持「失败即重试」的自愈行为，如 model 文件晚出现）；
//   - 全部到齐后完全不再碰这些文件。
func (s *SysInfo) fillStatic(snap *SysSnapshot) {
	s.staticMu.Lock()
	defer s.staticMu.Unlock()
	if !s.staticDone {
		st := &s.static
		if st.model == "" {
			if b, err := os.ReadFile("/tmp/sysinfo/model"); err == nil {
				st.model = strings.TrimSpace(string(b))
			}
		}
		if st.kernel == "" {
			if b, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
				st.kernel = strings.TrimSpace(string(b))
			}
		}
		if st.openwrt == "" {
			if b, err := os.ReadFile("/etc/openwrt_release"); err == nil {
				for _, line := range strings.Split(string(b), "\n") {
					line = strings.TrimSpace(line)
					if strings.HasPrefix(line, "DISTRIB_DESCRIPTION=") {
						st.openwrt = strings.Trim(strings.TrimPrefix(line, "DISTRIB_DESCRIPTION="), "'\"")
						break
					}
				}
			}
		}
		if st.hostname == "" {
			if h, err := os.Hostname(); err == nil {
				st.hostname = h
			}
		}
		if st.arch == "" {
			st.arch = goArchName()
		}
		s.staticDone = st.model != "" && st.kernel != "" && st.openwrt != "" &&
			st.hostname != "" && st.arch != ""
	}
	snap.Model, snap.Arch, snap.Kernel, snap.OpenWrt, snap.Hostname =
		s.static.model, s.static.arch, s.static.kernel, s.static.openwrt, s.static.hostname
}

// Snapshot 返回最新系统快照。
func (s *SysInfo) Snapshot() SysSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.s
}

// sampleDemo 演示模式合成数据（平滑正弦 + 小幅抖动）。
func (s *SysInfo) sampleDemo(intervalSec int64) {
	s.mu.Lock()
	elapsed := time.Since(s.demoStart).Seconds()
	s.mu.Unlock()
	base := func(v, amp, period, phase float64) float64 {
		return v + amp*math.Sin(elapsed/period+phase)
	}
	snap := SysSnapshot{
		CPUPct:     round1(base(22, 12, 5, 0) + rand.Float64()*3),
		MemTotalMb: 1844,
		MemPct:     round1(base(41, 5, 9, 1)),
		Load1:      round2(base(0.45, 0.25, 7, 2)),
		TempC:      round1(base(51, 4, 11, 3)),
		UptimeSec:  int64(base(3600, 0, 100, 0)) + s.demoStart.Unix()%1000,
		Model:      "Phicomm N1",
		Arch:       "aarch64",
		Kernel:     "6.1.114-flippy-92+o",
		OpenWrt:    "SNAPSHOT R2024.11.05",
		Hostname:   "Ytwos-N1",
		DiskFreeMb: 4200,
		RSSMb:      int64(18 + rand.Intn(4)),
	}
	snap.MemFreeMb = int64(float64(snap.MemTotalMb) * (100 - snap.MemPct) / 100)
	snap.MemUsedMb = snap.MemTotalMb - snap.MemFreeMb
	snap.ConnCount = int64(13500 + rand.Intn(2500))
	if s.app != nil && s.app.agg != nil {
		r := s.app.agg.LastRates()
		snap.WanRxBps = r.DownBps
		snap.WanTxBps = r.UpBps
		snap.NetUpBps = r.UpBps
		snap.NetDownBps = r.DownBps
		// 演示模式无物理计数：校准基准直接取上下行合计（与 ct 同量纲，
		// updateScale 会得到固定点系数 ≈1，保持展示值不变）
		snap.PhysTotalBps = r.UpBps + r.DownBps
	}
	s.mu.Lock()
	s.s = snap
	s.mu.Unlock()
}

// queryDiskFree 通过 df 查询数据目录所在分区剩余空间（MB）。
func (s *SysInfo) queryDiskFree() int64 {
	if s.app == nil {
		return 0
	}
	// 采集类命令：3s 超时（df 是本地读取，正常毫秒级完成）。
	// 一条慢命令若按默认 60s 超时执行，会占住 execMu 把采集一起冻结。
	// 路径必须安全引用：DataDir 含空格/引号时裸拼接会让 df 的参数错位（解析到别的分区）。
	out, err := s.app.shellQuietOutput("df -k "+shSingleQuote(s.app.cfg.DataDir)+" 2>/dev/null | tail -1", 3*time.Second)
	if err != nil {
		return 0
	}
	fields := strings.Fields(out)
	if len(fields) < 4 {
		return 0
	}
	kb, err := parseInt64(fields[3])
	if err != nil {
		return 0
	}
	return kb / 1024
}

// ---------------- /proc 解析（纯函数，可单测） ----------------

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

// parseProcStat 解析 /proc/stat 的 cpu 行。
func parseProcStat(line string) (cpuTimes, bool) {
	fields := strings.Fields(line)
	if len(fields) < 5 || fields[0] != "cpu" {
		return cpuTimes{}, false
	}
	var vals [8]uint64
	for i := 0; i < 8 && i+1 < len(fields); i++ {
		v, err := parseUint64(fields[i+1])
		if err != nil {
			return cpuTimes{}, false
		}
		vals[i] = v
	}
	var total uint64
	for _, v := range vals {
		total += v
	}
	return cpuTimes{total: total, idle: vals[3] + vals[4]}, true
}

// parseMemInfo 解析 /proc/meminfo，返回 MemTotal 与可用内存（KB）。
func parseMemInfo(text string) (totalKB, availKB int64, ok bool) {
	var memFree int64
	for _, line := range strings.Split(text, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		v, err := parseInt64(fields[1])
		if err != nil {
			continue
		}
		switch fields[0] {
		case "MemTotal:":
			totalKB = v
		case "MemAvailable:":
			availKB = v
		case "MemFree:":
			memFree = v
		}
	}
	if availKB == 0 {
		availKB = memFree
	}
	return totalKB, availKB, totalKB > 0
}

// parseNetDevAll 解析 /proc/net/dev，返回每个接口的累计 rx/tx 字节。
//
// 这是 /proc/net/dev 的唯一解析实现：系统采样（sysinfo.go）与拓扑接口速率
// （topology.go 的 readIfaceCounters）共用，避免两处口径漂移。
// 接口名取冒号前的部分并 TrimSpace（/proc/net/dev 会把名字右对齐补空格）。
func parseNetDevAll(text string) map[string][2]int64 {
	out := map[string][2]int64{}
	for _, line := range strings.Split(text, "\n") {
		colon := strings.IndexByte(line, ':')
		if colon < 0 {
			continue
		}
		name := strings.TrimSpace(line[:colon])
		if name == "" {
			continue
		}
		fields := strings.Fields(line[colon+1:])
		if len(fields) < 9 {
			continue
		}
		r, err1 := parseInt64(fields[0])
		t, err2 := parseInt64(fields[8])
		if err1 != nil || err2 != nil {
			continue
		}
		out[name] = [2]int64{r, t}
	}
	return out
}

// netDevIfCounters 取 /proc/net/dev 中指定接口的 rx/tx 累计字节（接口名精确匹配）。
func netDevIfCounters(text, name string) (rx, tx int64, ok bool) {
	if name == "" {
		return 0, 0, false
	}
	c, ok := parseNetDevAll(text)[name]
	if !ok {
		return 0, 0, false
	}
	return c[0], c[1], true
}

// parseNetDev 解析 /proc/net/dev，返回 br-lan（或 eth0 兜底）的 rx/tx 累计字节。
func parseNetDev(text string) (rx, tx int64, ok bool) {
	if rx, tx, ok = netDevIfCounters(text, "br-lan"); ok {
		return rx, tx, true
	}
	return netDevIfCounters(text, "eth0")
}

// readProcessRSSMb 读取当前进程 RSS（MB）。
func readProcessRSSMb() int64 {
	b, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "VmRSS:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				kb, err := parseInt64(fields[1])
				if err == nil {
					return kb / 1024
				}
			}
		}
	}
	return 0
}

// goArchName 运行架构别名（api 契约使用 aarch64）。
func goArchName() string {
	switch goGOARCH() {
	case "arm64":
		return "aarch64"
	case "amd64":
		return "x86_64"
	case "arm":
		return "armv7"
	case "386":
		return "i386"
	}
	return goGOARCH()
}

func round1(v float64) float64 { return math.Round(v*10) / 10 }
func round2(v float64) float64 { return math.Round(v*100) / 100 }

// shSingleQuote 把任意字符串包成 /bin/sh 的单引号字面量（内部单引号按 POSIX 规则转义）。
//
// 用于把路径等外部数据安全拼进 shell 命令：含空格/引号/$/反引号时
// 不加引号会被 shell 拆词或展开，命令参数错位（df 甚至会解析到别的分区）。
func shSingleQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
