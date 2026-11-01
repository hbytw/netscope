package main

// 状态持久化。
//
// 内存态：设置、设备别名/分组/策略/事件、手工封堵域名。
// 落盘：<data>/state.json —— 只存小体量元数据；脏标记 + SaveIfDirty 定时合并写（默认 30s），
// 进程退出时强制写。设备历史统计不写入 state.json，避免文件膨胀。
// 流量：<data>/traffic-YYYY-MM-DD.jsonl，每分钟追加一行 1min 聚合桶。

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// LimitKbps 限速值（0=不限）。
type LimitKbps struct {
	Down int `json:"down"`
	Up   int `json:"up"`
}

// Targets 策略目标。
type Targets struct {
	IPs    []string `json:"ips"`
	Groups []string `json:"groups"`
	All    bool     `json:"all"`
}

// Schedule 生效时段。Days 1=周一..7=周日，空=每天；Start/End 为 HH:MM，允许跨零点。
type Schedule struct {
	Days  []int  `json:"days"`
	Start string `json:"start"`
	End   string `json:"end"`
}

// Policy 访问控制策略。
type Policy struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	Enabled    bool      `json:"enabled"`
	Targets    Targets   `json:"targets"`
	Schedule   Schedule  `json:"schedule"`
	Action     string    `json:"action"` // block / limit / allow
	Categories []string  `json:"categories"`
	Domains    []string  `json:"domains"`
	LimitKbps  LimitKbps `json:"limitKbps"`
	Hits       int64     `json:"hits"`
	CreatedAt  int64     `json:"createdAt"`
	UpdatedAt  int64     `json:"updatedAt"`
}

// AlertSettings 告警阈值。
type AlertSettings struct {
	Enable            bool `json:"enable"`
	ScanPorts         int  `json:"scanPorts"`
	TrafficMbPerHour  int  `json:"trafficMbPerHour"`
	ThreatUpdateHours int  `json:"threatUpdateHours"` // 威胁情报库自动更新间隔（小时，默认 6）
}

// Settings 业务设置（GET /api/settings 契约字段 + 版本/数据目录）。
//
// 两级开关（docs/api.md §7.1）：Enabled 为总开关，其余为功能开关，全部默认关闭。
// 关闭时服务不采集、不修改系统配置、不下发管控规则，仅保留 Web 服务。
type Settings struct {
	Enabled            bool          `json:"enabled"`
	Collect            bool          `json:"collect"`
	DNSTap             bool          `json:"dnsTap"`
	DeviceControl      bool          `json:"deviceControl"`
	DomainBlock        bool          `json:"domainBlock"`
	Schedule           bool          `json:"schedule"`
	Alerts             bool          `json:"alerts"`
	History            bool          `json:"history"`
	CollectIntervalSec int           `json:"collectIntervalSec"`
	RetentionDays      int           `json:"retentionDays"`
	Alert              AlertSettings `json:"alert"`
	Version            string        `json:"version"`
	DataDir            string        `json:"dataDir"`
}

// normalizeSwitches 应用开关依赖关系：
// enabled 关闭 → 全部子开关关闭；collect 关闭 → domainBlock/alerts/history 关闭；
// deviceControl 关闭 → schedule 关闭。
func normalizeSwitches(s *Settings) {
	if !s.Enabled {
		s.Collect = false
		s.DNSTap = false
		s.DeviceControl = false
		s.DomainBlock = false
		s.Schedule = false
		s.Alerts = false
		s.History = false
		return
	}
	if !s.Collect {
		s.DomainBlock = false
		s.Alerts = false
		s.History = false
	}
	if !s.DeviceControl {
		s.Schedule = false
	}
}

// DeviceMeta 设备持久化元信息（别名/分组/封禁/限速/首次发现/是否被移除）。
type DeviceMeta struct {
	Alias     string    `json:"alias"`
	Group     string    `json:"group"`
	Blocked   bool      `json:"blocked"`
	BlockedAt int64     `json:"blockedAt,omitempty"`
	LimitKbps LimitKbps `json:"limitKbps"`
	LimitAt   int64     `json:"limitAt,omitempty"`
	FirstSeen int64     `json:"firstSeen"`
	Hidden    bool      `json:"hidden"`
}

// Event 安全事件。
type Event struct {
	ID         string                 `json:"id"`
	Ts         int64                  `json:"ts"`
	Severity   string                 `json:"severity"`
	Type       string                 `json:"type"`
	Title      string                 `json:"title"`
	Detail     string                 `json:"detail"`
	DeviceIP   string                 `json:"deviceIp"`
	DeviceName string                 `json:"deviceName"`
	Acked      bool                   `json:"acked"`
	Evidence   map[string]interface{} `json:"evidence"`
}

// EventSummary 事件分级统计。
type EventSummary struct {
	Critical int `json:"critical"`
	Warn     int `json:"warn"`
	Info     int `json:"info"`
	Total    int `json:"total"`
}

// WhitelistEntry 告警白名单项（同 type+target 不再产生新事件）。
type WhitelistEntry struct {
	ID     string `json:"id"`
	Type   string `json:"type"`
	Target string `json:"target"`
	Note   string `json:"note"`
	At     int64  `json:"at"`
}

// persistedState state.json 结构。
type persistedState struct {
	Settings     Settings               `json:"settings"`
	Devices      map[string]*DeviceMeta `json:"devices"`
	Policies     []*Policy              `json:"policies"`
	Events       []*Event               `json:"events"`
	DomainBlocks []string               `json:"domainBlocks"`
	DstBlocks    map[string]int64       `json:"dstBlocks,omitempty"` // 目标 IP 封禁：ip -> 封禁时间
	Whitelist    []*WhitelistEntry      `json:"whitelist,omitempty"` // 告警白名单
	Seq          int64                  `json:"seq"`
}

// trafficLine 每分钟聚合桶的落盘行（byCat 为字节总数，catUp/catDown 为附加方向明细）。
type trafficLine struct {
	T       int64               `json:"t"`
	Up      int64               `json:"up"`
	Down    int64               `json:"down"`
	ByCat   map[string]int64    `json:"byCat,omitempty"`
	ByDev   map[string][2]int64 `json:"byDev,omitempty"`
	CatUp   map[string]int64    `json:"catUp,omitempty"`
	CatDown map[string]int64    `json:"catDown,omitempty"`
}

// Store 线程安全的状态存储。
type Store struct {
	mu        sync.Mutex
	saveMu    sync.Mutex // 写盘串行化（防止并发写坏 state.json）
	dir       string
	statePath string

	settings     Settings
	devices      map[string]*DeviceMeta
	policies     []*Policy
	events       []*Event
	domainBlocks map[string]bool
	dstBlocks    map[string]int64
	whitelist    []*WhitelistEntry
	seq          int64
	dirty        bool
	dirtyGen     int64 // 每次 markDirty 递增；Save 用它判断快照之后是否又有新变更

	trafficMu      sync.Mutex
	trafficCacheMu sync.Mutex // 与 trafficMu 分离：读缓存不阻塞分钟桶落盘
	trafficCache   map[trafficCacheKey]trafficCacheEnt
}

// NewStore 创建存储。
func NewStore(dir string) *Store {
	return &Store{
		dir:          dir,
		statePath:    filepath.Join(dir, "state.json"),
		devices:      map[string]*DeviceMeta{},
		domainBlocks: map[string]bool{},
		dstBlocks:    map[string]int64{},
	}
}

// Load 读取 state.json 并填默认值。
//
// 加固：
//   - 主文件缺失/损坏时自动回退 state.json.bak 并记日志（单点损坏不再丢全部状态）；
//   - 解码分节/分元素容错：单个字段类型错误只丢对应小节/条目，不整体清零；
//   - alert.enable 缺字段（老版本/手改文件）时补默认开启，避免告警静默失效。
func (s *Store) Load() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.settings = Settings{
		CollectIntervalSec: 2,
		RetentionDays:      14,
		Alert:              AlertSettings{Enable: true, ScanPorts: 20, TrafficMbPerHour: 500, ThreatUpdateHours: 6},
		Version:            Version,
		DataDir:            s.dir,
	}
	data, usedBak, err := s.readStateBytes()
	if err != nil {
		if os.IsNotExist(err) {
			// 主文件与备份都不存在：首次启动
			s.dirty = true
			return nil
		}
		return err
	}
	st, settingsOK, err := decodeState(data)
	if err != nil {
		return fmt.Errorf("解析 state.json 失败: %w", err)
	}
	if usedBak {
		// 回退备份后置脏：30s 内用解码出的状态重写主文件，自愈损坏的 state.json
		s.dirty = true
	}
	if settingsOK {
		s.settings = st.Settings
	}
	if s.settings.CollectIntervalSec <= 0 {
		s.settings.CollectIntervalSec = 2
	}
	if s.settings.RetentionDays <= 0 {
		s.settings.RetentionDays = 14
	}
	if s.settings.Alert.ScanPorts <= 0 {
		s.settings.Alert.ScanPorts = 20
	}
	if s.settings.Alert.TrafficMbPerHour <= 0 {
		s.settings.Alert.TrafficMbPerHour = 500
	}
	if h := s.settings.Alert.ThreatUpdateHours; h <= 0 || h > 168 {
		s.settings.Alert.ThreatUpdateHours = 6
	}
	// alert.enable 缺省兜底：老版本/手改 state.json 缺该字段时若按零值走，
	// 所有安全告警会被静默关闭；字段存在且为 false（用户主动关闭）则保持不变。
	var probe struct {
		Settings struct {
			Alert struct {
				Enable *bool `json:"enable"`
			} `json:"alert"`
		} `json:"settings"`
	}
	if json.Unmarshal(data, &probe) == nil && probe.Settings.Alert.Enable == nil {
		s.settings.Alert.Enable = true
	}
	// 老版本 state.json 中没有开关字段：保持默认关闭（安全默认）
	normalizeSwitches(&s.settings)
	s.settings.Version = Version
	s.settings.DataDir = s.dir

	if st.Devices != nil {
		// 过滤 nil 元素：state.json 被截断/手工编辑后可能出现 "ip": null，
		// 直接保留会在后续解引用时 panic（启动即崩，连 /healthz 都起不来）
		devs := make(map[string]*DeviceMeta, len(st.Devices))
		for ip, m := range st.Devices {
			if m == nil {
				continue
			}
			devs[ip] = m
		}
		s.devices = devs
	}
	for _, p := range st.Policies {
		if p != nil {
			s.policies = append(s.policies, p)
		}
	}
	// 事件同样过滤 nil
	evs := make([]*Event, 0, len(st.Events))
	for _, e := range st.Events {
		if e != nil {
			evs = append(evs, e)
		}
	}
	s.events = evs
	if len(s.events) > maxEvents {
		s.events = s.events[:maxEvents]
	}
	for _, d := range st.DomainBlocks {
		if d = strings.TrimSpace(d); d != "" {
			s.domainBlocks[d] = true
		}
	}
	for ip, at := range st.DstBlocks {
		if ip = strings.TrimSpace(ip); ip != "" {
			s.dstBlocks[ip] = at
		}
	}
	for _, w := range st.Whitelist {
		if w != nil && w.Type != "" && w.Target != "" {
			cp := *w
			s.whitelist = append(s.whitelist, &cp)
		}
	}
	s.seq = st.Seq
	return nil
}

// readStateBytes 读取 state.json 内容。
// 主文件缺失或语法损坏时回退 state.json.bak 并记日志；两者都不可用时返回错误
// （主文件缺失且无备份 = 首次启动，返回 os.ErrNotExist 语义的错误）。
// usedBak 表示本次读到的是备份内容。
func (s *Store) readStateBytes() (data []byte, usedBak bool, err error) {
	primary, perr := os.ReadFile(s.statePath)
	if perr == nil && json.Valid(primary) {
		return primary, false, nil
	}
	bakPath := s.statePath + ".bak"
	bak, berr := os.ReadFile(bakPath)
	bakOK := berr == nil && json.Valid(bak)
	if perr == nil {
		// 主文件存在但内容损坏
		if !bakOK {
			return nil, false, fmt.Errorf("state.json 损坏且无可用备份")
		}
		logf("state.json 损坏，已回退 state.json.bak")
		return bak, true, nil
	}
	if !os.IsNotExist(perr) {
		return nil, false, fmt.Errorf("读取 state.json 失败: %w", perr)
	}
	// 主文件缺失：正常是首次启动，但异常中断/手工删除时可能只剩备份
	if bakOK {
		logf("state.json 缺失，已回退 state.json.bak")
		return bak, true, nil
	}
	return nil, false, perr
}

// decodeState 解析 state.json 内容。
// 快路径整体解码；失败时分节/分元素容错，避免单个字段类型错误把
// 策略/断网/白名单等整节丢光（只丢损坏的那一条/那一节，并记日志）。
// settingsOK 表示 settings 节是否成功解码（false 时调用方保留默认设置）。
func decodeState(data []byte) (st persistedState, settingsOK bool, err error) {
	trim := bytes.TrimSpace(data)
	if len(trim) == 0 || trim[0] != '{' {
		return persistedState{}, false, fmt.Errorf("顶层不是 JSON 对象")
	}
	if uerr := json.Unmarshal(data, &st); uerr == nil {
		return st, true, nil
	} else {
		logf("state.json 整体解码失败（%v），改用分节容错解析", uerr)
	}
	var top map[string]json.RawMessage
	if uerr := json.Unmarshal(data, &top); uerr != nil {
		return persistedState{}, false, uerr
	}
	// 快路径失败时 st 可能已被部分填充，重置后逐节重建，避免半截数据与容错结果叠加
	st = persistedState{}

	// settings 节
	if raw, ok := top["settings"]; ok {
		var sec Settings
		if json.Unmarshal(raw, &sec) == nil {
			st.Settings = sec
			settingsOK = true
		} else {
			logf("state.json settings 节解析失败，使用默认设置")
		}
	}
	// 逐元素解码的数组节：单条损坏只丢该条
	decodeList := func(key string, apply func(json.RawMessage) bool) {
		raw, ok := top[key]
		if !ok {
			return
		}
		var items []json.RawMessage
		if json.Unmarshal(raw, &items) != nil {
			logf("state.json %s 节不可解析，整节跳过", key)
			return
		}
		bad := 0
		for _, it := range items {
			if !apply(it) {
				bad++
			}
		}
		if bad > 0 {
			logf("state.json %s 节容错解析：跳过 %d 条损坏项", key, bad)
		}
	}
	decodeList("policies", func(it json.RawMessage) bool {
		var p *Policy
		if json.Unmarshal(it, &p) != nil {
			return false
		}
		if p == nil {
			return true // null 元素与旧版一致静默跳过
		}
		st.Policies = append(st.Policies, p)
		return true
	})
	decodeList("events", func(it json.RawMessage) bool {
		var e *Event
		if json.Unmarshal(it, &e) != nil {
			return false
		}
		if e == nil {
			return true
		}
		st.Events = append(st.Events, e)
		return true
	})
	decodeList("whitelist", func(it json.RawMessage) bool {
		var w *WhitelistEntry
		if json.Unmarshal(it, &w) != nil {
			return false
		}
		if w == nil {
			return true
		}
		st.Whitelist = append(st.Whitelist, w)
		return true
	})
	decodeList("domainBlocks", func(it json.RawMessage) bool {
		var d string
		if json.Unmarshal(it, &d) != nil {
			return false
		}
		st.DomainBlocks = append(st.DomainBlocks, d)
		return true
	})
	// devices 节（map，逐台解码）
	if raw, ok := top["devices"]; ok {
		var items map[string]json.RawMessage
		if json.Unmarshal(raw, &items) != nil {
			logf("state.json devices 节不可解析，整节跳过")
		} else {
			bad := 0
			devs := make(map[string]*DeviceMeta, len(items))
			for ip, it := range items {
				var m *DeviceMeta
				if json.Unmarshal(it, &m) != nil {
					bad++
					continue
				}
				if m == nil {
					continue
				}
				devs[ip] = m
			}
			if bad > 0 {
				logf("state.json devices 节容错解析：跳过 %d 台损坏设备", bad)
			}
			st.Devices = devs
		}
	}
	// dstBlocks 节（map，逐条解码）
	if raw, ok := top["dstBlocks"]; ok {
		var items map[string]json.RawMessage
		if json.Unmarshal(raw, &items) != nil {
			logf("state.json dstBlocks 节不可解析，整节跳过")
		} else {
			bad := 0
			st.DstBlocks = make(map[string]int64, len(items))
			for ip, it := range items {
				var at int64
				if json.Unmarshal(it, &at) != nil {
					bad++
					continue
				}
				st.DstBlocks[ip] = at
			}
			if bad > 0 {
				logf("state.json dstBlocks 节容错解析：跳过 %d 条损坏记录", bad)
			}
		}
	}
	// seq
	if raw, ok := top["seq"]; ok {
		if json.Unmarshal(raw, &st.Seq) != nil {
			logf("state.json seq 字段解析失败，按 0 处理")
			st.Seq = 0
		}
	}
	return st, settingsOK, nil
}

const maxEvents = 500

// Save 原子写入 state.json。
func (s *Store) Save() error {
	// 写盘串行化：定时保存与 HTTP 触发的保存可能并发，
	// 同时 O_TRUNC 同一个 tmp 文件会造成 state.json 截断/损坏
	s.saveMu.Lock()
	defer s.saveMu.Unlock()

	s.mu.Lock()
	st := persistedState{
		Settings:     s.settings,
		Devices:      make(map[string]*DeviceMeta, len(s.devices)),
		Policies:     make([]*Policy, 0, len(s.policies)),
		Events:       make([]*Event, len(s.events)),
		DomainBlocks: make([]string, 0, len(s.domainBlocks)),
		Seq:          s.seq,
	}
	for k, v := range s.devices {
		cp := *v
		st.Devices[k] = &cp
	}
	for _, p := range s.policies {
		cp := *p
		cp.Targets.IPs = append([]string(nil), p.Targets.IPs...)
		cp.Targets.Groups = append([]string(nil), p.Targets.Groups...)
		cp.Schedule.Days = append([]int(nil), p.Schedule.Days...)
		cp.Categories = append([]string(nil), p.Categories...)
		cp.Domains = append([]string(nil), p.Domains...)
		st.Policies = append(st.Policies, &cp)
	}
	for i, e := range s.events {
		cp := *e
		st.Events[i] = &cp
	}
	for d := range s.domainBlocks {
		st.DomainBlocks = append(st.DomainBlocks, d)
	}
	sort.Strings(st.DomainBlocks)
	st.DstBlocks = make(map[string]int64, len(s.dstBlocks))
	for ip, at := range s.dstBlocks {
		st.DstBlocks[ip] = at
	}
	st.Whitelist = make([]*WhitelistEntry, 0, len(s.whitelist))
	for _, w := range s.whitelist {
		cp := *w
		st.Whitelist = append(st.Whitelist, &cp)
	}
	// 注意：这里不清理脏标记 —— 写盘可能失败，失败时必须保留 dirty 让定时保存重试，
	// 否则本次变更永久丢失；清理只在下方 rename 成功后做（唯一清理点）。
	gen := s.dirtyGen
	s.mu.Unlock()

	data, err := json.MarshalIndent(&st, "", " ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(s.dir, 0o755); err != nil {
		return err
	}
	// 落盘前把上一份可用的 state.json 留作 .bak（损坏的主文件不覆盖好备份）。
	// 备份失败只记日志，不阻断本次保存。
	if old, rerr := os.ReadFile(s.statePath); rerr == nil && json.Valid(old) {
		if berr := writeFileSync(s.statePath+".bak", old, 0o600); berr != nil {
			logf("写入 state.json.bak 失败: %v", berr)
		}
	}
	tmp := s.statePath + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, s.statePath); err != nil {
		return err
	}
	// 落盘成功后才清脏标记（唯一清理点）：失败时保留 dirty，让定时保存重试（否则本次变更永久丢失）。
	// 若快照之后又有新变更（dirtyGen 变化），保留脏标记，由下一轮保存落盘。
	s.mu.Lock()
	if s.dirtyGen == gen {
		s.dirty = false
	}
	s.mu.Unlock()
	return nil
}

// writeFileSync 原子写文件：写临时文件 + sync + rename，避免半截文件。
func writeFileSync(path string, data []byte, perm os.FileMode) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// SaveIfDirty 仅在脏时写盘（30s 定时调用）。
func (s *Store) SaveIfDirty() error {
	s.mu.Lock()
	dirty := s.dirty
	s.mu.Unlock()
	if !dirty {
		return nil
	}
	return s.Save()
}

func (s *Store) markDirtyLocked() {
	s.dirty = true
	s.dirtyGen++
}

// Settings 返回设置快照。
func (s *Store) Settings() Settings {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.settings
}

// UpdateSettings 以回调方式修改设置，返回修改后的快照。
func (s *Store) UpdateSettings(fn func(*Settings)) Settings {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn(&s.settings)
	s.settings.Version = Version
	s.settings.DataDir = s.dir
	s.markDirtyLocked()
	return s.settings
}

// DeviceMeta 返回设备元信息拷贝（不存在返回零值）。
func (s *Store) DeviceMeta(ip string) DeviceMeta {
	s.mu.Lock()
	defer s.mu.Unlock()
	if m, ok := s.devices[ip]; ok {
		return *m
	}
	return DeviceMeta{}
}

// UpdateDeviceMeta 修改设备元信息。
func (s *Store) UpdateDeviceMeta(ip string, fn func(*DeviceMeta)) DeviceMeta {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, ok := s.devices[ip]
	if !ok {
		m = &DeviceMeta{FirstSeen: time.Now().Unix()}
		s.devices[ip] = m
	}
	fn(m)
	s.markDirtyLocked()
	return *m
}

// DeleteDeviceMeta 删除设备元信息（清理历史外网设备等）。
func (s *Store) DeleteDeviceMeta(ip string) {
	s.mu.Lock()
	delete(s.devices, ip)
	s.markDirtyLocked()
	s.mu.Unlock()
}

// AllDeviceMeta 返回全部设备元信息拷贝。
func (s *Store) AllDeviceMeta() map[string]DeviceMeta {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]DeviceMeta, len(s.devices))
	for k, v := range s.devices {
		out[k] = *v
	}
	return out
}

// Policies 返回策略列表拷贝（保持创建顺序）。
func (s *Store) Policies() []Policy {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Policy, 0, len(s.policies))
	for _, p := range s.policies {
		out = append(out, clonePolicy(p))
	}
	return out
}

func clonePolicy(p *Policy) Policy {
	cp := *p
	cp.Targets.IPs = append([]string(nil), p.Targets.IPs...)
	cp.Targets.Groups = append([]string(nil), p.Targets.Groups...)
	cp.Schedule.Days = append([]int(nil), p.Schedule.Days...)
	cp.Categories = append([]string(nil), p.Categories...)
	cp.Domains = append([]string(nil), p.Domains...)
	return cp
}

// PolicyByID 按 ID 取策略拷贝。
func (s *Store) PolicyByID(id string) (Policy, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, p := range s.policies {
		if p.ID == id {
			return clonePolicy(p), true
		}
	}
	return Policy{}, false
}

// UpsertPolicy 新建（ID 为空）或全量更新策略。
func (s *Store) UpsertPolicy(p Policy) Policy {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().Unix()
	if p.ID == "" {
		s.seq++
		p.ID = fmt.Sprintf("p-%d-%d", now, s.seq)
		p.CreatedAt = now
		p.Hits = 0
		s.policies = append(s.policies, &p)
		s.markDirtyLocked()
		return clonePolicy(&p)
	}
	for i, old := range s.policies {
		if old.ID == p.ID {
			p.CreatedAt = old.CreatedAt
			p.Hits = old.Hits
			p.UpdatedAt = now
			cp := p
			s.policies[i] = &cp
			s.markDirtyLocked()
			return clonePolicy(&cp)
		}
	}
	// ID 不存在时视为新建
	p.CreatedAt = now
	s.policies = append(s.policies, &p)
	s.markDirtyLocked()
	return clonePolicy(&p)
}

// DeletePolicy 删除策略。
func (s *Store) DeletePolicy(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, p := range s.policies {
		if p.ID == id {
			s.policies = append(s.policies[:i], s.policies[i+1:]...)
			s.markDirtyLocked()
			return true
		}
	}
	return false
}

// SetPolicyEnabled 开关策略。
func (s *Store) SetPolicyEnabled(id string, enabled bool) (Policy, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, p := range s.policies {
		if p.ID == id {
			p.Enabled = enabled
			p.UpdatedAt = time.Now().Unix()
			s.markDirtyLocked()
			return clonePolicy(p), true
		}
	}
	return Policy{}, false
}

// IncrementPolicyHits 命中次数 +1。
func (s *Store) IncrementPolicyHits(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, p := range s.policies {
		if p.ID == id {
			p.Hits++
			s.markDirtyLocked()
			return
		}
	}
}

// AddEvent 追加事件（最新在前，最多 500 条），返回带 ID 的事件。
func (s *Store) AddEvent(ev Event) Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ev.ID == "" {
		s.seq++
		ev.ID = fmt.Sprintf("e-%d-%d", ev.Ts, s.seq)
	}
	if ev.Ts == 0 {
		ev.Ts = time.Now().Unix()
	}
	if ev.Evidence == nil {
		ev.Evidence = map[string]interface{}{}
	}
	s.events = append([]*Event{&ev}, s.events...)
	if len(s.events) > maxEvents {
		s.events = s.events[:maxEvents]
	}
	s.markDirtyLocked()
	return ev
}

// Events 按过滤条件查询事件与分级汇总。
// ack: all / unacked / acked。
func (s *Store) Events(limit int, severity, typ, ack string) ([]Event, EventSummary) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if limit <= 0 {
		limit = 100
	}
	if limit > 500 {
		limit = 500
	}
	out := make([]Event, 0, limit)
	var sum EventSummary
	for _, e := range s.events {
		if severity != "" && e.Severity != severity {
			continue
		}
		if typ != "" && e.Type != typ {
			continue
		}
		switch ack {
		case "unacked":
			if e.Acked {
				continue
			}
		case "acked":
			if !e.Acked {
				continue
			}
		}
		sum.Total++
		switch e.Severity {
		case "critical":
			sum.Critical++
		case "warn":
			sum.Warn++
		default:
			sum.Info++
		}
		if len(out) < limit {
			cp := *e
			out = append(out, cp)
		}
	}
	return out, sum
}

// RecentUnacked 最近未确认事件（overview alerts 用）。
func (s *Store) RecentUnacked(limit int) []Event {
	events, _ := s.Events(limit, "", "", "unacked")
	return events
}

// UnackedCount 未确认事件数。
func (s *Store) UnackedCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, e := range s.events {
		if !e.Acked {
			n++
		}
	}
	return n
}

// AckEvent 确认/取消确认事件。
func (s *Store) AckEvent(id string, acked bool) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range s.events {
		if e.ID == id {
			e.Acked = acked
			s.markDirtyLocked()
			return true
		}
	}
	return false
}

// ClearEvents 清空事件，返回删除条数。
func (s *Store) ClearEvents() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := len(s.events)
	s.events = nil
	s.markDirtyLocked()
	return n
}

// DomainBlocks 手工封堵域名列表。
func (s *Store) DomainBlocks() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.domainBlocks))
	for d := range s.domainBlocks {
		out = append(out, d)
	}
	sort.Strings(out)
	return out
}

// SetDomainBlocks 覆盖手工封堵域名列表。
func (s *Store) SetDomainBlocks(domains []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.domainBlocks = map[string]bool{}
	for _, d := range domains {
		if d = strings.TrimSpace(d); d != "" {
			s.domainBlocks[d] = true
		}
	}
	s.markDirtyLocked()
}

// DstBlocks 目标 IP 封禁记录（ip -> 封禁时间戳），用于封禁列表展示与重启恢复。
func (s *Store) DstBlocks() map[string]int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]int64, len(s.dstBlocks))
	for ip, at := range s.dstBlocks {
		out[ip] = at
	}
	return out
}

// PutDstBlock 新增/更新目标 IP 封禁记录。
func (s *Store) PutDstBlock(ip string, at int64) {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return
	}
	s.mu.Lock()
	if at <= 0 {
		at = time.Now().Unix()
	}
	s.dstBlocks[ip] = at
	s.markDirtyLocked()
	s.mu.Unlock()
}

// DeleteDstBlock 删除目标 IP 封禁记录。
func (s *Store) DeleteDstBlock(ip string) {
	s.mu.Lock()
	delete(s.dstBlocks, ip)
	s.markDirtyLocked()
	s.mu.Unlock()
}

// ClearDstBlocks 清空目标 IP 封禁记录（enforce/reset 用）。
func (s *Store) ClearDstBlocks() {
	s.mu.Lock()
	s.dstBlocks = map[string]int64{}
	s.markDirtyLocked()
	s.mu.Unlock()
}

// wlKey 白名单去重键：type|target。
func wlKey(typ, target string) string { return typ + "|" + target }

// wlID 白名单项稳定 ID（同 type+target 幂等）。
func wlID(typ, target string) string {
	sum := sha256.Sum256([]byte(wlKey(typ, target)))
	return "wl-" + fmt.Sprintf("%x", sum[:5])
}

// Whitelist 返回白名单列表（按加白时间升序）。
func (s *Store) Whitelist() []WhitelistEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]WhitelistEntry, 0, len(s.whitelist))
	for _, w := range s.whitelist {
		out = append(out, *w)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].At < out[j].At })
	return out
}

// PutWhitelist 加白（同 type+target 幂等，重复调用返回已有项）。
func (s *Store) PutWhitelist(typ, target, note string, at int64) WhitelistEntry {
	typ = strings.TrimSpace(typ)
	target = strings.TrimSpace(target)
	if at <= 0 {
		at = time.Now().Unix()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, w := range s.whitelist {
		if w.Type == typ && w.Target == target {
			return *w
		}
	}
	w := &WhitelistEntry{ID: wlID(typ, target), Type: typ, Target: target, Note: strings.TrimSpace(note), At: at}
	s.whitelist = append(s.whitelist, w)
	s.markDirtyLocked()
	return *w
}

// DeleteWhitelist 按 ID 取消加白。
func (s *Store) DeleteWhitelist(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, w := range s.whitelist {
		if w.ID == id {
			s.whitelist = append(s.whitelist[:i], s.whitelist[i+1:]...)
			s.markDirtyLocked()
			return true
		}
	}
	return false
}

// WhitelistKeySet 返回白名单键集合（type|target）供研判 emit 快速过滤。
func (s *Store) WhitelistKeySet() map[string]bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]bool, len(s.whitelist))
	for _, w := range s.whitelist {
		out[wlKey(w.Type, w.Target)] = true
	}
	return out
}

// Dir 数据目录。
func (s *Store) Dir() string { return s.dir }

// trafficPath 某天的流量文件路径。
func (s *Store) trafficPath(t time.Time) string {
	return filepath.Join(s.dir, "traffic-"+t.Format("2006-01-02")+".jsonl")
}

// AppendTrafficBucket 追加一个已完成的分钟聚合桶。
func (s *Store) AppendTrafficBucket(b *Bucket) error {
	if b == nil {
		return nil
	}
	s.trafficMu.Lock()
	defer s.trafficMu.Unlock()
	line := trafficLine{
		T:       b.T,
		Up:      b.Up,
		Down:    b.Down,
		ByCat:   b.ByCatTotal(),
		ByDev:   b.ByDev,
		CatUp:   b.CatUp,
		CatDown: b.CatDown,
	}
	data, err := json.Marshal(&line)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if err := os.MkdirAll(s.dir, 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(s.trafficPath(time.Unix(b.T, 0)), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(data)
	return err
}

const (
	// trafficCacheTTL 流量历史查询结果的缓存时长。
	// 前端 30s 轮询 + 重复切换范围时挡住整段 JSONL 重放（N1 上是 CPU/内存尖峰）；
	// 稳态下磁盘段是已封存的历史数据（不随追加变化），内存段仍由调用方实时合并，
	// 因此 60s 内的陈旧只影响“内存为空”这一过渡场景，可接受。
	trafficCacheTTL = 60 * time.Second
	// trafficCacheMax 缓存条数上限（1h/6h/24h/7d 各一条 + 网格漂移余量），超出按最旧淘汰。
	trafficCacheMax = 8
)

// trafficCacheKey 按分钟网格对齐的查询区间。
// 裸 (from,to) 随 now 每秒滑动，直接做键永远不命中；对齐后同一范围的相邻轮询落进同一键。
type trafficCacheKey struct {
	from, to int64
}

// trafficCacheEnt 一个区间键对应的解析结果（buckets 按 T 升序，覆盖 [key.from, key.to]）。
type trafficCacheEnt struct {
	at      time.Time
	buckets []*Bucket
}

// LoadTrafficBuckets 从 JSONL 读取 [from, to] 区间内的分钟桶（按时间升序）。
// 结果按分钟网格键做短 TTL LRU 缓存：命中时只做区间截取，不再重放数天文件。
func (s *Store) LoadTrafficBuckets(from, to int64) []*Bucket {
	if from > to {
		return []*Bucket{}
	}
	// 缓存键向分钟网格对齐并向右留 60s 余量：from/to 随 now 滑动，
	// 对齐后 30s 轮询才能落进同一键；右侧余量覆盖下一次轮询的 to。
	keyFrom := floor60(from)
	keyTo := ceil60(to) + 60

	now := time.Now()
	s.trafficCacheMu.Lock()
	for k, e := range s.trafficCache {
		if now.Sub(e.at) >= trafficCacheTTL {
			delete(s.trafficCache, k) // 顺手清理过期项，避免长期占用内存
			continue
		}
		if k.from <= from && k.to >= to {
			out := filterBuckets(e.buckets, from, to)
			s.trafficCacheMu.Unlock()
			return out
		}
	}
	s.trafficCacheMu.Unlock()

	buckets := s.readTrafficBuckets(keyFrom, keyTo)

	s.trafficCacheMu.Lock()
	if s.trafficCache == nil {
		s.trafficCache = map[trafficCacheKey]trafficCacheEnt{}
	}
	// 超上限按最旧淘汰（键数量很少，扫描即可，等价 LRU）
	for len(s.trafficCache) >= trafficCacheMax {
		var oldestK trafficCacheKey
		var oldestAt time.Time
		first := true
		for k, e := range s.trafficCache {
			if first || e.at.Before(oldestAt) {
				oldestK, oldestAt, first = k, e.at, false
			}
		}
		delete(s.trafficCache, oldestK)
	}
	s.trafficCache[trafficCacheKey{from: keyFrom, to: keyTo}] = trafficCacheEnt{at: now, buckets: buckets}
	s.trafficCacheMu.Unlock()

	return filterBuckets(buckets, from, to)
}

// floor60/ceil60 时间戳按分钟网格向下/向上取整（对负数同样成立，Go 的 / 朝零截断）。
func floor60(t int64) int64 {
	r := t % 60
	if r < 0 {
		r += 60
	}
	return t - r
}

func ceil60(t int64) int64 {
	f := floor60(t)
	if f == t {
		return t
	}
	return f + 60
}

// filterBuckets 截取按 T 升序序列中落在 [from, to] 的连续窗口，返回新切片
// （不共享底层数组，调用方 append 不会污染缓存）。
func filterBuckets(buckets []*Bucket, from, to int64) []*Bucket {
	lo := sort.Search(len(buckets), func(i int) bool { return buckets[i].T >= from })
	hi := sort.Search(len(buckets), func(i int) bool { return buckets[i].T > to })
	out := make([]*Bucket, 0, hi-lo)
	out = append(out, buckets[lo:hi]...)
	return out
}

// readTrafficBuckets 解析 [from, to] 区间的分钟桶（不做缓存）。
// trafficMu 只在“打开文件快照”时持有，逐行解析在锁外进行：
// 避免多天 JSONL 解析期间阻塞分钟桶落盘（AppendTrafficBucket 与它互斥）。
func (s *Store) readTrafficBuckets(from, to int64) []*Bucket {
	fromT := time.Unix(from, 0)
	toT := time.Unix(to, 0)
	type snap struct {
		name string
		f    *os.File
	}
	var files []snap
	s.trafficMu.Lock()
	for day := time.Date(fromT.Year(), fromT.Month(), fromT.Day(), 0, 0, 0, 0, time.Local); !day.After(toT); day = day.AddDate(0, 0, 1) {
		path := s.trafficPath(day)
		f, err := os.Open(path)
		if err != nil {
			if !os.IsNotExist(err) {
				// 缺文件是常态（当天还没写/已清理），其它错误要留痕，避免静默丢数据
				logf("打开流量历史文件失败 %s: %v", filepath.Base(path), err)
			}
			continue
		}
		files = append(files, snap{name: filepath.Base(path), f: f})
	}
	s.trafficMu.Unlock()

	byT := map[int64]*Bucket{}
	for _, sf := range files {
		sc := bufio.NewScanner(sf.f)
		sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		for sc.Scan() {
			var line trafficLine
			if json.Unmarshal(sc.Bytes(), &line) != nil {
				continue
			}
			if line.T < from || line.T > to {
				continue
			}
			b := &Bucket{
				T:       line.T,
				Up:      line.Up,
				Down:    line.Down,
				CatUp:   line.CatUp,
				CatDown: line.CatDown,
				ByDev:   line.ByDev,
			}
			if b.CatUp == nil || b.CatDown == nil {
				// 兼容旧格式：仅有 byCat 总数时全部归到下行
				b.CatUp = map[string]int64{}
				b.CatDown = map[string]int64{}
				for k, v := range line.ByCat {
					b.CatDown[k] = v
				}
			}
			byT[line.T] = b
		}
		// 扫描中断（超长行/IO 错误）时已解析的行保留，但必须留日志：
		// 否则该文件后半段被静默丢弃、曲面缺一段没人发现
		if err := sc.Err(); err != nil {
			logf("读取流量历史文件 %s 中断: %v", sf.name, err)
		}
		sf.f.Close()
	}
	out := make([]*Bucket, 0, len(byT))
	for _, b := range byT {
		out = append(out, b)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].T < out[j].T })
	return out
}

// PurgeOldTraffic 删除超过留存天数的流量文件。
func (s *Store) PurgeOldTraffic(retentionDays int) {
	if retentionDays <= 0 {
		retentionDays = 14
	}
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return
	}
	cutoff := time.Now().AddDate(0, 0, -(retentionDays - 1))
	cutoffDay := time.Date(cutoff.Year(), cutoff.Month(), cutoff.Day(), 0, 0, 0, 0, time.Local)
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, "traffic-") || !strings.HasSuffix(name, ".jsonl") {
			continue
		}
		day, err := time.ParseInLocation("2006-01-02", strings.TrimSuffix(strings.TrimPrefix(name, "traffic-"), ".jsonl"), time.Local)
		if err != nil {
			continue
		}
		if day.Before(cutoffDay) {
			os.Remove(filepath.Join(s.dir, name))
		}
	}
}
