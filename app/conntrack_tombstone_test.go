package main

import (
	"strings"
	"testing"
)

// TestConnTombstoneNoPhantom 回归测试：快照被容量淘汰后，同一流重现不得把
// 全生命周期累计字节当成增量（历史 bug：淘汰后重建 → 数百 MB 幻影尖峰）。
func TestConnTombstoneNoPhantom(t *testing.T) {
	eng := NewConnEngine("192.168.1.0/24")
	// 造一条设备侧 TCP 流，累计 10MB
	line := func(bytesMB int) string {
		return "ipv4 2 tcp 6 431999 ESTABLISHED " +
			"src=192.168.1.106 dst=1.2.3.4 sport=51930 dport=443 " +
			"packets=100 bytes=" + itoa(int64(bytesMB)*1024*1024) + " " +
			"src=1.2.3.4 dst=192.168.1.106 sport=443 dport=51930 packets=100 bytes=0"
	}
	collect := func(bytesMB int) int64 {
		var total int64
		_, err := eng.Collect(strings.NewReader(line(bytesMB)+"\n"), 1000, func(d FlowDelta) {
			total += d.UpDelta + d.DownDelta
		}, func(string) {})
		if err != nil {
			t.Fatalf("collect: %v", err)
		}
		return total
	}

	// 第 1 轮是 baseline：只登记，不计数
	if got := collect(10); got != 0 {
		t.Fatalf("baseline 轮应计入 0，实际 %d", got)
	}
	// 第 2 轮：正常差分，增量 1MB
	if got := collect(11); got != 1024*1024 {
		t.Fatalf("第 2 轮应差分出 1MB，实际 %d", got)
	}
	// 模拟容量淘汰：该流快照转入墓碑
	eng.mu.Lock()
	for k, s := range eng.flows {
		eng.retire(k, s)
	}
	eng.mu.Unlock()
	if len(eng.flows) != 0 || len(eng.retired) != 1 {
		t.Fatalf("淘汰后应 flows=0 retired=1，实际 flows=%d retired=%d", len(eng.flows), len(eng.retired))
	}
	// 第 3 轮：墓碑命中，只能差分出 1MB，绝不能把 11MB 全量计入
	if got := collect(12); got != 1024*1024 {
		t.Fatalf("墓碑命中后应差分出 1MB（不得全量计入），实际 %d", got)
	}
	// 第 4 轮：继续正常差分
	if got := collect(13); got != 1024*1024 {
		t.Fatalf("第 4 轮应差分出 1MB，实际 %d", got)
	}
}

// TestConnTombstoneCounterReset 墓碑命中但累计值倒退（端口复用/新连接）：
// 应按新流处理，不得把倒退后的累计值当增量。
func TestConnTombstoneCounterReset(t *testing.T) {
	eng := NewConnEngine("192.168.1.0/24")
	line := func(bytes int64) string {
		return "ipv4 2 tcp 6 431999 ESTABLISHED " +
			"src=192.168.1.106 dst=1.2.3.4 sport=51930 dport=443 " +
			"packets=100 bytes=" + itoa(bytes) + " " +
			"src=1.2.3.4 dst=192.168.1.106 sport=443 dport=51930 packets=100 bytes=0"
	}
	collect := func(bytes int64) int64 {
		var total int64
		eng.Collect(strings.NewReader(line(bytes)+"\n"), 1000, func(d FlowDelta) {
			total += d.UpDelta + d.DownDelta
		}, func(string) {})
		return total
	}
	collect(10 * 1024 * 1024) // baseline
	collect(10*1024*1024 + 1024)
	eng.mu.Lock()
	for k, s := range eng.flows {
		eng.retire(k, s)
	}
	eng.mu.Unlock()
	// 计数器倒退到 8KB（< smallFlowBytes）：按新建小流处理，立即计入 8KB，
	// 而不是把 (10MB-8KB) 这种无意义的差值计入。
	if got := collect(8 * 1024); got != 8*1024 {
		t.Fatalf("计数器重置后应按新流计入 8KB，实际 %d", got)
	}
}

// itoa 小工具（避免测试里引 strconv 造成与实现文件重复 import 的噪声）
func itoa(v int64) string {
	if v == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	neg := v < 0
	if neg {
		v = -v
	}
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
