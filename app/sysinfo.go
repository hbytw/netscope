package main

// 系统指标采集：/proc/stat、/proc/meminfo、/proc/net/dev、/proc/loadavg、
// thermal_zone、nf_conntrack_count、/proc/uptime、进程 RSS。
//
// 旁路由形态下 WAN 吞吐取 br-lan 双向合计（eth0 兜底）。
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
	WanRxBps   int64
	WanTxBps   int64
	ConnCount  int64
	DiskFreeMb int64
	RSSMb      int64
	Model      string
	Arch       string
	Kernel     string
	OpenWrt    string
	Hostname   string
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
	havePrev  bool

	diskFreeMb int64
	diskAt     int64
	sampleN    int64
	demoStart  time.Time
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
	// 负载
	if b, err := os.ReadFile("/proc/loadavg"); err == nil {
		var l1 float64
		if _, err := fmtSscan(string(b), &l1); err == nil {
			snap.Load1 = math.Round(l1*100) / 100
		}
	}
	// 温度
	if b, err := os.ReadFile("/sys/class/thermal/thermal_zone0/temp"); err == nil {
		milli, ok := atoi64OK(trimSpaceBytes(b))
		if ok && milli > 0 {
			snap.TempC = math.Round(float64(milli)/100) / 10
		}
	}
	// 运行时间
	if b, err := os.ReadFile("/proc/uptime"); err == nil {
		fields := strings.Fields(string(b))
		if len(fields) > 0 {
			if sec, err := parseFloat(fields[0]); err == nil {
				snap.UptimeSec = int64(sec)
			}
		}
	}
	// conntrack 条数
	if b, err := os.ReadFile("/proc/sys/net/netfilter/nf_conntrack_count"); err == nil {
		n, _ := atoi64OK(trimSpaceBytes(b))
		snap.ConnCount = n
	}
	// 接口速率（br-lan 优先，eth0 兜底）
	if b, err := os.ReadFile("/proc/net/dev"); err == nil {
		rx, tx, ok := parseNetDev(string(b))
		if ok {
			if s.havePrev && intervalSec > 0 {
				drx := rx - s.prevNetRx
				dtx := tx - s.prevNetTx
				if drx < 0 {
					drx = 0
				}
				if dtx < 0 {
					dtx = 0
				}
				snap.WanRxBps = drx * 8 / intervalSec
				snap.WanTxBps = dtx * 8 / intervalSec
			}
			s.prevNetRx, s.prevNetTx = rx, tx
		}
	}
	s.havePrev = true
	// 磁盘占用（60s 更新一次，避免频繁 fork df）
	s.sampleN++
	if s.sampleN%30 == 1 || time.Now().Unix()-s.diskAt > 60 {
		s.diskFreeMb = s.queryDiskFree()
		s.diskAt = time.Now().Unix()
	}
	snap.DiskFreeMb = s.diskFreeMb
	// 进程 RSS
	snap.RSSMb = readProcessRSSMb()
	s.fillStatic(&snap)

	s.mu.Lock()
	s.s = snap
	s.mu.Unlock()
}

// fillStatic 填充不常变化的系统信息（每轮覆盖，开销极低）。
func (s *SysInfo) fillStatic(snap *SysSnapshot) {
	if snap.Model == "" {
		if b, err := os.ReadFile("/tmp/sysinfo/model"); err == nil {
			snap.Model = strings.TrimSpace(string(b))
		}
	}
	if b, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil && snap.Kernel == "" {
		snap.Kernel = strings.TrimSpace(string(b))
	}
	if b, err := os.ReadFile("/etc/openwrt_release"); err == nil && snap.OpenWrt == "" {
		for _, line := range strings.Split(string(b), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "DISTRIB_DESCRIPTION=") {
				snap.OpenWrt = strings.Trim(strings.TrimPrefix(line, "DISTRIB_DESCRIPTION="), "'\"")
				break
			}
		}
	}
	if snap.Hostname == "" {
		if h, err := os.Hostname(); err == nil {
			snap.Hostname = h
		}
	}
	snap.Arch = goArchName()
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
	out, err := s.app.shellQuietOutput("df -k " + s.app.cfg.DataDir + " 2>/dev/null | tail -1")
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

// parseNetDev 解析 /proc/net/dev，返回 br-lan（或 eth0）的 rx/tx 累计字节。
func parseNetDev(text string) (rx, tx int64, ok bool) {
	for _, line := range strings.Split(text, "\n") {
		colon := strings.IndexByte(line, ':')
		if colon < 0 {
			continue
		}
		name := strings.TrimSpace(line[:colon])
		if name != "br-lan" && name != "eth0" {
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
		// br-lan 优先；若同时存在则 br-lan 直接返回
		rx, tx, ok = r, t, true
		if name == "br-lan" {
			return rx, tx, true
		}
	}
	return rx, tx, ok
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
