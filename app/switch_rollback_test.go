package main

// 开关变更失败回滚的单测（switch-rollback 模块）。
//
// 覆盖：
//  1. 第二个动作失败时，第一个动作（已撤销的开关）必须按旧值回滚恢复；
//  2. 回滚本身失败时（部分成功），必须按路由器实际状态落库并如实标注；
//  3. 设备级 DNS 回退只对「走代理」的连接生效（显式流向判断）。

import (
	"errors"
	"strings"
	"testing"
)

// ---------------- 回滚算法（纯逻辑） ----------------

// TestSwitchStepsRollbackRestoresOldState 第二个动作失败时，已撤销的开关按旧值回滚恢复。
func TestSwitchStepsRollbackRestoresOldState(t *testing.T) {
	var order []string
	steps := []switchStep{
		{
			key: "deviceControl", label: "设备管控", turnOn: false, desc: "撤销设备管控",
			run:    func() error { order = append(order, "revoke-deviceControl"); return nil },
			revert: func() error { order = append(order, "restore-deviceControl"); return nil },
		},
		{
			key: "dnsTap", label: "DNS 日志旁挂", turnOn: true, desc: "启用 dnsTap",
			run:    func() error { order = append(order, "enable-dnsTap"); return errors.New("模拟 dnsmasq 重启失败") },
			revert: func() error { order = append(order, "revert-dnsTap"); return nil },
		},
	}
	res := runSwitchSteps(steps)
	if res.Err == nil {
		t.Fatalf("第二个动作失败时应返回错误")
	}
	if res.Failed != "dnsTap" {
		t.Errorf("失败动作字段 = %q，期望 dnsTap", res.Failed)
	}
	if len(res.Undone) != 0 {
		t.Errorf("回滚全部成功时不应有未恢复项: %+v", res.Undone)
	}
	want := "revoke-deviceControl,enable-dnsTap,restore-deviceControl"
	if got := strings.Join(order, ","); got != want {
		t.Errorf("执行顺序 = %q，期望 %q", got, want)
	}
}

// TestSwitchStepsPartialSuccessReported 回滚失败必须如实上报（部分成功）。
func TestSwitchStepsPartialSuccessReported(t *testing.T) {
	steps := []switchStep{
		{
			key: "deviceControl", label: "设备管控", turnOn: false, desc: "撤销设备管控",
			run:    func() error { return nil },
			revert: func() error { return errors.New("模拟恢复失败") },
		},
		{
			key: "dnsTap", label: "DNS 日志旁挂", turnOn: true, desc: "启用 dnsTap",
			run: func() error { return errors.New("模拟启用失败") },
		},
	}
	res := runSwitchSteps(steps)
	if res.Err == nil {
		t.Fatalf("动作失败时应返回错误")
	}
	if len(res.Undone) != 1 || res.Undone[0].Key != "deviceControl" || res.Undone[0].Label != "设备管控" {
		t.Errorf("回滚失败项应如实上报: %+v", res.Undone)
	}
}

// TestSwitchStepsSuccessKeepsOrder 全部成功时动作描述按顺序返回。
func TestSwitchStepsSuccessKeepsOrder(t *testing.T) {
	steps := []switchStep{
		{key: "deviceControl", label: "设备管控", turnOn: false, desc: "撤销设备管控", run: func() error { return nil }},
		{key: "dnsTap", label: "DNS 日志旁挂", turnOn: true, desc: "启用 dnsTap", run: func() error { return nil }},
	}
	res := runSwitchSteps(steps)
	if res.Err != nil {
		t.Fatalf("全部成功不应返回错误: %v", res.Err)
	}
	if len(res.Revoked) != 1 || res.Revoked[0] != "撤销设备管控" {
		t.Errorf("撤销描述错误: %v", res.Revoked)
	}
	if len(res.Applied) != 1 || res.Applied[0] != "启用 dnsTap" {
		t.Errorf("启用描述错误: %v", res.Applied)
	}
}

// ---------------- ApplySwitchPatch 级别 ----------------

// newRollbackTestApp 构造一个「设备管控已开 + 有设备处于断网状态」的 App。
func newRollbackTestApp(t *testing.T) *App {
	t.Helper()
	a := newTestApp(t, false) // dry-run：外部命令只记录不执行
	a.store.UpdateSettings(func(s *Settings) {
		s.Enabled = true
		s.Collect = true
		s.DeviceControl = true
		s.Schedule = true
		s.DNSTap = false
	})
	if _, err := a.enf.SetBlocked("192.168.1.31", true); err != nil {
		t.Fatalf("封禁设备失败: %v", err)
	}
	a.store.UpdateDeviceMeta("192.168.1.31", func(m *DeviceMeta) {
		m.Blocked = true
		m.BlockedAt = 1700000000
	})
	return a
}

// TestApplySwitchPatchRollbackRestoresDeviceControl
// 撤销设备管控成功、随后启用 dnsTap 失败时：
//   - 设备管控必须被回滚恢复（断网规则重新下发，界面显示与实际一致）；
//   - 设置保持旧值（不落库），落库状态 == 路由器实际状态。
func TestApplySwitchPatchRollbackRestoresDeviceControl(t *testing.T) {
	a := newRollbackTestApp(t)
	if !a.enf.IsBlocked("192.168.1.31") {
		t.Fatalf("前置条件失败：设备应处于断网状态")
	}

	// 注入 dnsTap 启用失败（第二个动作失败）
	a.dnsTapApply = func(enabled bool) error {
		if enabled {
			return errors.New("模拟 dnsmasq 重启失败")
		}
		return nil
	}

	off, on := false, true
	out, _, _, err := a.ApplySwitchPatch(settingsPatch{DeviceControl: &off, DNSTap: &on})
	if err == nil {
		t.Fatalf("dnsTap 启用失败应返回错误")
	}
	if !strings.Contains(err.Error(), "已回滚") {
		t.Errorf("错误信息应说明已回滚到操作前状态: %v", err)
	}
	if !out.DeviceControl {
		t.Errorf("回滚成功后返回的设置应保持设备管控开启，实际 %+v", out)
	}
	if !a.store.Settings().DeviceControl {
		t.Errorf("回滚成功后不应落库（设置应保持旧值）")
	}
	if !a.enf.IsBlocked("192.168.1.31") {
		t.Errorf("设备管控未恢复：断网规则应重新下发")
	}
	if a.store.Settings().DNSTap {
		t.Errorf("dnsTap 启用失败后应仍为关闭")
	}
}

// TestApplySwitchPatchPartialSuccessPersistsActualState
// 回滚也失败时（部分成功）：必须按路由器实际状态落库，并在错误信息中标注「部分成功」。
func TestApplySwitchPatchPartialSuccessPersistsActualState(t *testing.T) {
	a := newRollbackTestApp(t)

	a.dnsTapApply = func(enabled bool) error {
		if enabled {
			return errors.New("模拟 dnsmasq 重启失败")
		}
		return nil
	}
	// 注入回滚失败：设备管控未能恢复
	a.deviceControlRestore = func() error { return errors.New("模拟恢复失败") }

	off, on := false, true
	out, _, _, err := a.ApplySwitchPatch(settingsPatch{DeviceControl: &off, DNSTap: &on})
	if err == nil {
		t.Fatalf("dnsTap 启用失败应返回错误")
	}
	if !strings.Contains(err.Error(), "部分成功") {
		t.Errorf("错误信息应明确标注「部分成功」: %v", err)
	}
	if !strings.Contains(err.Error(), "设备管控") {
		t.Errorf("错误信息应指出未能恢复的开关: %v", err)
	}
	if out.DeviceControl {
		t.Errorf("设备管控实际已关闭，返回设置不应显示开启: %+v", out)
	}
	if a.store.Settings().DeviceControl {
		t.Errorf("部分成功时应按路由器实际状态落库（设备管控=关闭）")
	}
	if a.store.Settings().DNSTap {
		t.Errorf("dnsTap 启用失败后应仍为关闭")
	}
}

// TestApplySwitchPatchDNSTapRevokeFailureKeepsOldState
// dnsTap 撤销失败（第一个动作失败）：设置保持旧值，不落库。
func TestApplySwitchPatchDNSTapRevokeFailureKeepsOldState(t *testing.T) {
	a := newTestApp(t, false)
	a.store.UpdateSettings(func(s *Settings) {
		s.Enabled = true
		s.Collect = true
		s.DNSTap = true
	})
	a.dnsTapApply = func(enabled bool) error {
		if enabled {
			return nil
		}
		return errors.New("模拟关闭 dnsmasq 日志失败")
	}
	off := false
	out, _, _, err := a.ApplySwitchPatch(settingsPatch{DNSTap: &off})
	if err == nil {
		t.Fatalf("dnsTap 撤销失败应返回错误")
	}
	if !out.DNSTap {
		t.Errorf("撤销失败时设置应保持旧值（dnsTap=开启）")
	}
	if !a.store.Settings().DNSTap {
		t.Errorf("撤销失败时不应落库")
	}
}

// TestApplySwitchPatchRollbackRestoresDomainBlock
// 撤销域名封堵成功、随后启用 dnsTap 失败时：域名封堵必须按快照回滚恢复
// （ipset 重新创建、域名重新封堵），设置保持旧值。
func TestApplySwitchPatchRollbackRestoresDomainBlock(t *testing.T) {
	a := newTestApp(t, false)
	a.store.UpdateSettings(func(s *Settings) {
		s.Enabled = true
		s.Collect = true
		s.DeviceControl = true
		s.DomainBlock = true
		s.DNSTap = false
	})
	// 预置一个已封堵域名（模拟策略下发的结果：10.0.0.1）
	a.enf.mu.Lock()
	a.enf.dnsDomains = map[string]bool{"ads.example.com": true}
	a.enf.domainIPs = map[string][]uint32{"ads.example.com": {0x0a000001}}
	a.enf.mu.Unlock()

	a.dnsTapApply = func(enabled bool) error {
		if enabled {
			return errors.New("模拟 dnsmasq 重启失败")
		}
		return nil
	}

	off, on := false, true
	out, _, _, err := a.ApplySwitchPatch(settingsPatch{DomainBlock: &off, DNSTap: &on})
	if err == nil {
		t.Fatalf("dnsTap 启用失败应返回错误")
	}
	if !out.DomainBlock {
		t.Errorf("回滚成功后设置应保持域名封堵开启")
	}
	if !a.store.Settings().DomainBlock {
		t.Errorf("回滚成功后不应落库")
	}
	if st := a.enf.Status(); st.DNSBlockedDomains != 1 {
		t.Errorf("域名封堵未恢复，已封堵域名数 = %d，期望 1", st.DNSBlockedDomains)
	}
	found := false
	for _, d := range a.enf.BlockedDomains() {
		if d == "ads.example.com" {
			found = true
		}
	}
	if !found {
		t.Errorf("回滚后应重新封堵 ads.example.com，实际 %v", a.enf.BlockedDomains())
	}
	cmds := strings.Join(a.recordedCommands(), "\n")
	if !strings.Contains(cmds, "ipset create ubm_block") {
		t.Errorf("回滚应重新创建 ipset，实际命令:\n%s", cmds)
	}
}

// ---------------- 设备级 DNS 回退的流向限制 ----------------

// TestDeviceDNSFallbackOnlyForProxyPath
// 设备级 DNS 回退只对「走代理」的连接生效：直连连接不得回退到设备最近查询的域名。
func TestDeviceDNSFallbackOnlyForProxyPath(t *testing.T) {
	a := newTestApp(t, true)
	now := nowUnix()
	a.dns.HandleRecord(dnsRecord{Kind: "query", QType: "A", Name: "www.youtube.com", SrcIP: "192.168.1.106"}, now)

	key := "tcp-192.168.1.106-51001-8.8.8.8-443"
	a.onDelta(FlowDelta{
		Key: key, DeviceIP: "192.168.1.106", DstIP: "8.8.8.8", DPort: 443, SPort: 51001,
		Proto: "tcp", Path: "direct", Iface: "br-lan",
		TotalUp: 1000, TotalDown: 9000, UpDelta: 100, DownDelta: 900,
		Started: now - 5, New: true,
	})
	conn, ok := a.agg.ConnByID(key)
	if !ok {
		t.Fatalf("连接未写入明细")
	}
	if strings.Contains(conn.Domain, "youtube") {
		t.Errorf("直连连接不应回退到设备最近查询域名，实际 domain=%q", conn.Domain)
	}
}

// TestDeviceDNSFallbackProxyPathStillWorks 代理连接仍可用设备级 DNS 回退（回归）。
func TestDeviceDNSFallbackProxyPathStillWorks(t *testing.T) {
	a := newTestApp(t, true)
	now := nowUnix()
	a.dns.HandleRecord(dnsRecord{Kind: "query", QType: "A", Name: "www.youtube.com", SrcIP: "192.168.1.106"}, now)

	key := "tcp-192.168.1.106-51000-129.225.146.84-443"
	a.onDelta(FlowDelta{
		Key: key, DeviceIP: "192.168.1.106", DstIP: "129.225.146.84", DPort: 443, SPort: 51000,
		Proto: "tcp", Path: "proxy", Iface: "br-lan",
		TotalUp: 1000, TotalDown: 9000, UpDelta: 100, DownDelta: 900,
		Started: now - 5, New: true,
	})
	conn, ok := a.agg.ConnByID(key)
	if !ok {
		t.Fatalf("连接未写入明细")
	}
	if !strings.Contains(conn.Domain, "youtube") {
		t.Errorf("代理连接应回退到设备最近查询域名，实际 domain=%q", conn.Domain)
	}
	if conn.Category != "video" {
		t.Errorf("代理 YouTube 连接分类 = %q，期望 video", conn.Category)
	}
}
