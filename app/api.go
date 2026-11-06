package main

// HTTP 层：路由、会话鉴权、REST 契约实现、SSE 接入、静态资源。
//
// 契约以 docs/api.md 为准：字段名 / 类型 / 分类键与色值严格一致；
// 时间戳统一 Unix 秒，速率单位 bit/s（Bps 后缀），流量累计单位字节。

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"mime"
	"net"
	"net/http"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	sessionCookie = "gl_session"
	sessionTTL    = int64(86400)
	maxBodyBytes  = 1 << 20
)

// ---------------- 会话与登录限流 ----------------

// Sessions 内存会话表（token -> 过期时间）。
type Sessions struct {
	mu     sync.Mutex
	tokens map[string]int64
}

func NewSessions() *Sessions { return &Sessions{tokens: map[string]int64{}} }

// New 签发 24h 会话。
func (s *Sessions) New(now int64) string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		copy(b, fmt.Sprintf("%d-%d", now, time.Now().UnixNano()))
	}
	tok := hex.EncodeToString(b)
	s.mu.Lock()
	s.tokens[tok] = now + sessionTTL
	// 顺手清理过期 token
	for t, exp := range s.tokens {
		if exp < now {
			delete(s.tokens, t)
		}
	}
	s.mu.Unlock()
	return tok
}

// Valid 校验会话。
func (s *Sessions) Valid(tok string, now int64) bool {
	if tok == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	exp, ok := s.tokens[tok]
	if !ok {
		return false
	}
	if exp < now {
		delete(s.tokens, tok)
		return false
	}
	return true
}

// Drop 注销会话。
func (s *Sessions) Drop(tok string) {
	s.mu.Lock()
	delete(s.tokens, tok)
	s.mu.Unlock()
}

// DropAllExcept 注销除 keep 之外的全部会话（改密后调用，避免旧会话继续可用）。
func (s *Sessions) DropAllExcept(keep string) {
	s.mu.Lock()
	for t := range s.tokens {
		if t != keep {
			delete(s.tokens, t)
		}
	}
	s.mu.Unlock()
}

type loginState struct {
	fails   int
	lockEnd int64
}

// LoginGuard 登录失败限流：连续 5 次失败锁 60s。
type LoginGuard struct {
	mu    sync.Mutex
	state map[string]*loginState
}

func NewLoginGuard() *LoginGuard { return &LoginGuard{state: map[string]*loginState{}} }

// Locked 是否处于锁定中。
func (g *LoginGuard) Locked(ip string, now int64) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	st := g.state[ip]
	if st == nil {
		return false
	}
	if st.lockEnd > now {
		return true
	}
	if st.lockEnd != 0 && st.lockEnd <= now {
		delete(g.state, ip)
	}
	return false
}

// Fail 记录一次失败，达到 5 次锁定 60s。
func (g *LoginGuard) Fail(ip string, now int64) {
	g.mu.Lock()
	defer g.mu.Unlock()
	st := g.state[ip]
	if st == nil {
		st = &loginState{}
		g.state[ip] = st
	}
	st.fails++
	if st.fails >= 5 {
		st.lockEnd = now + 60
		st.fails = 0
	}
}

// Success 清除失败计数。
func (g *LoginGuard) Success(ip string) {
	g.mu.Lock()
	delete(g.state, ip)
	g.mu.Unlock()
}

// ---------------- JSON / 请求辅助 ----------------

func writeJSON(w http.ResponseWriter, code int, v interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg, machine string) {
	body := map[string]string{"error": msg, "code": machine}
	if machine == "" {
		body = map[string]string{"error": msg}
	}
	writeJSON(w, code, body)
}

// writeEnforceErr 管控类错误：功能开关关闭/受保护 IP 返回 400，其余 500（已自动回滚）。
func writeEnforceErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errSwitchOff):
		writeErr(w, http.StatusBadRequest, err.Error(), "switch_off")
	case errors.Is(err, errProtectedIP):
		writeErr(w, http.StatusBadRequest, err.Error(), "protected_ip")
	default:
		writeErr(w, http.StatusInternalServerError, err.Error(), "enforce_failed")
	}
}

func requireMethod(w http.ResponseWriter, r *http.Request, method string) bool {
	if r.Method != method {
		w.Header().Set("Allow", method)
		writeErr(w, http.StatusMethodNotAllowed, "不支持的请求方法", "method_not_allowed")
		return false
	}
	return true
}

// decodeJSON 解析写请求的 JSON 请求体。
//
// 加固：
//   - 媒体类型校验：docs/api.md §9 约定 POST/PUT/DELETE 一律 application/json；
//     带其它 Content-Type（表单/纯文本/multipart）的写请求直接 415 拒绝，避免
//     「浏览器表单/跨站简单请求」绕过预期的 JSON 通道。缺省 Content-Type 仍按 JSON
//     解析（兼容 curl、脚本与老客户端），不会把既有集成打断。
//   - 尾随内容校验：只接受单个 JSON 值。解出一个值后再探一次 token，若还有内容
//     （如 `{"a":1}{"b":2}`）则拒绝 —— 原实现会静默忽略尾随数据，调用方以为
//     参数生效，实际只应用了前半段。
func decodeJSON(w http.ResponseWriter, r *http.Request, dst interface{}) bool {
	if ct := strings.TrimSpace(r.Header.Get("Content-Type")); ct != "" {
		mt, _, err := mime.ParseMediaType(ct)
		if err != nil || (mt != "application/json" && !strings.HasSuffix(mt, "+json")) {
			writeErr(w, http.StatusUnsupportedMediaType, "请求体必须是 application/json", "bad_content_type")
			return false
		}
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(dst); err != nil {
		writeErr(w, http.StatusBadRequest, "请求体 JSON 解析失败", "bad_request")
		return false
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		writeErr(w, http.StatusBadRequest, "请求体 JSON 之后存在多余内容", "bad_request")
		return false
	}
	return true
}

// clientIP 取请求来源 IP（登录限流用）。
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// ---------------- 路由 ----------------

// Handler 返回完整 HTTP 处理器（含日志、recover）。
func (a *App) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", a.handleHealthz)
	mux.HandleFunc("/api/", a.apiDispatch)
	mux.HandleFunc("/", a.serveStatic)
	return a.recoverMiddleware(a.logMiddleware(mux))
}

func (a *App) logMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		lw := &logWriter{ResponseWriter: w, status: 200}
		next.ServeHTTP(lw, r)
		if strings.HasPrefix(r.URL.Path, "/api/stream") {
			return // SSE 长连接本来就不会正常结束，不记
		}
		dur := time.Since(start)
		// 只记「异常请求」：非 2xx 状态码，或者慢请求（>=1s）。
		//
		// 为什么不记全部：仪表盘会持续轮询 /api/devices、/api/settings、/api/overview，
		// 每个请求一行，页面开着时约 10~20 行/分钟，几个小时就把内核日志缓冲区
		// （logd 默认 64KB）刷满，真正有用的告警和开机日志全被挤掉 ——
		// 实测正是这个现象导致故障现场无法回溯。
		// 正常的 200 快速响应没有诊断价值，异常与慢请求才值得记。
		//
		// 401 单独排除：浏览器标签页开久了会话必然过期，前端会继续轮询并持续拿 401，
		// 这属于客户端登录状态问题，登录失败本身由 LoginGuard 单独记录并限频；
		// 写进访问日志只会变成另一股噪声。
		if lw.status >= 400 && lw.status != 401 || dur >= time.Second {
			logf("%s %s %d %s", r.Method, r.URL.Path, lw.status, dur.Round(time.Millisecond))
		}
	})
}

func (a *App) recoverMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				logf("panic: %v (%s %s)", rec, r.Method, r.URL.Path)
				writeErr(w, http.StatusInternalServerError, "服务器内部错误", "internal")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

type logWriter struct {
	http.ResponseWriter
	status int
}

func (l *logWriter) WriteHeader(code int) {
	l.status = code
	l.ResponseWriter.WriteHeader(code)
}

func (l *logWriter) Flush() {
	if f, ok := l.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// apiDispatch /api/* 路由分发。
func (a *App) apiDispatch(w http.ResponseWriter, r *http.Request) {
	trimmed := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api"), "/")
	parts := []string{}
	if trimmed != "" {
		parts = strings.Split(trimmed, "/")
	}
	if len(parts) == 0 {
		writeErr(w, http.StatusNotFound, "接口不存在", "not_found")
		return
	}
	// 免鉴权接口
	switch parts[0] {
	case "login":
		a.handleLogin(w, r)
		return
	case "session":
		a.handleSession(w, r)
		return
	}
	if !a.authed(r) {
		writeErr(w, http.StatusUnauthorized, "登录已失效，请重新登录", "unauthorized")
		return
	}
	switch parts[0] {
	case "logout":
		a.handleLogout(w, r)
	case "password":
		a.handlePassword(w, r)
	case "overview":
		a.handleOverview(w, r)
	case "devices":
		a.handleDevices(w, r, parts[1:])
	case "traffic":
		a.handleTraffic(w, r, parts[1:])
	case "policies":
		a.handlePolicies(w, r, parts[1:])
	case "enforce":
		a.handleEnforce(w, r, parts[1:])
	case "events":
		a.handleEvents(w, r, parts[1:])
	case "security":
		if len(parts) >= 2 {
			switch parts[1] {
			case "risk":
				a.handleRisk(w, r)
				return
			case "whitelist":
				a.handleWhitelist(w, r, parts[2:])
				return
			}
		}
		writeErr(w, http.StatusNotFound, "接口不存在", "not_found")
	case "settings":
		a.handleSettings(w, r, parts[1:])
	case "system":
		a.handleSystem(w, r)
	case "topology":
		a.handleTopology(w, r)
	case "threats":
		a.handleThreats(w, r, parts[1:])
	case "stream":
		if requireMethod(w, r, http.MethodGet) {
			a.hub.Serve(w, r)
		}
	default:
		writeErr(w, http.StatusNotFound, "接口不存在", "not_found")
	}
}

// authed 校验会话 Cookie。
func (a *App) authed(r *http.Request) bool {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return false
	}
	return a.sessions.Valid(c.Value, nowUnix())
}

// sessionToken 取当前请求的会话 token（改密后需要保留当前会话、注销其它会话）。
func sessionToken(r *http.Request) string {
	if c, err := r.Cookie(sessionCookie); err == nil {
		return c.Value
	}
	return ""
}

// ---------------- 鉴权接口 ----------------

func (a *App) handleLogin(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	ip := clientIP(r)
	now := nowUnix()
	if a.login.Locked(ip, now) {
		writeErr(w, http.StatusTooManyRequests, "尝试过于频繁，请稍后再试", "locked")
		return
	}
	var req struct {
		Password string `json:"password"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if !a.cfg.VerifyPassword(req.Password) {
		a.login.Fail(ip, now)
		writeErr(w, http.StatusUnauthorized, "密码错误", "bad_password")
		return
	}
	a.login.Success(ip)
	tok := a.sessions.New(now)
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    tok,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(sessionTTL),
		Expires:  time.Now().Add(24 * time.Hour),
	})
	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true, "expiresIn": sessionTTL})
}

func (a *App) handleLogout(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	if c, err := r.Cookie(sessionCookie); err == nil {
		a.sessions.Drop(c.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: "", Path: "/", HttpOnly: true,
		SameSite: http.SameSiteLaxMode, MaxAge: -1, Expires: time.Unix(0, 0),
	})
	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true})
}

func (a *App) handleSession(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet) {
		return
	}
	if a.authed(r) {
		writeJSON(w, http.StatusOK, map[string]interface{}{"authed": true, "username": "admin"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"authed": false})
}

func (a *App) handlePassword(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	var req struct {
		Old string `json:"old"`
		New string `json:"new"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if err := a.cfg.SetPassword(req.Old, req.New); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error(), "bad_password")
		return
	}
	// 修改密码后注销其他会话，仅保留当前会话
	if tok := sessionToken(r); tok != "" {
		a.sessions.DropAllExcept(tok)
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true})
}

func (a *App) handleHealthz(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok":        true,
		"uptimeSec": int64(time.Since(a.started).Seconds()),
		"enabled":   a.settings().Enabled,
	})
}

// ---------------- 数据模型（契约） ----------------

// DeviceJSON GET /api/devices 契约结构。
type DeviceJSON struct {
	IP        string `json:"ip"`
	MAC       string `json:"mac"`
	Hostname  string `json:"hostname"`
	Alias     string `json:"alias"`
	Vendor    string `json:"vendor"`
	Network   string `json:"network"` // 所属网络：lan / zerotier / vpn
	Group     string `json:"group"`
	Online    bool   `json:"online"`
	FirstSeen int64  `json:"firstSeen"`
	LastSeen  int64  `json:"lastSeen"`
	// 设备上下线时间（只记录，不产生安全告警）
	LastOnlineAt  int64     `json:"lastOnlineAt"`
	LastOfflineAt int64     `json:"lastOfflineAt"`
	OnlineCount   int64     `json:"onlineCount"`
	UpBps         int64     `json:"upBps"`
	DownBps       int64     `json:"downBps"`
	TotalUp       int64     `json:"totalUp"`
	TotalDown     int64     `json:"totalDown"`
	Conns         int       `json:"conns"`
	Risk          float64   `json:"risk"`
	Blocked       bool      `json:"blocked"`
	LimitKbps     LimitKbps `json:"limitKbps"`
	TopCat        string    `json:"topCat"`
	TopDomain     string    `json:"topDomain"`
	PolicyIds     []string  `json:"policyIds"`
}

const (
	sevCritical = "critical"
	sevWarn     = "warn"
	sevInfo     = "info"
)

// ---------------- 总览 ----------------

func (a *App) handleOverview(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet) {
		return
	}
	writeJSON(w, http.StatusOK, a.buildOverview())
}

type kpiJSON struct {
	Online  int `json:"online"`
	Devices int `json:"devices"`
	// ZeroTier 设备单独计数（口径：lan 才是内网设备，zerotier 另算）
	ZtDevices int     `json:"ztDevices"`
	ZtOnline  int     `json:"ztOnline"`
	Conns     int64   `json:"conns"`
	NewConns  int     `json:"newConns"`
	DNSQps    float64 `json:"dnsQps"`
	Alerts    int     `json:"alerts"`
	UpBps     int64   `json:"upBps"`
	DownBps   int64   `json:"downBps"`
	RiskLevel string  `json:"riskLevel"`
}

type sysJSON struct {
	CPUPct    float64 `json:"cpuPct"`
	MemPct    float64 `json:"memPct"`
	MemUsedMb int64   `json:"memUsedMb"`
	Load1     float64 `json:"load1"`
	UptimeSec int64   `json:"uptimeSec"`
	TempC     float64 `json:"tempC"`
	WanRxBps  int64   `json:"wanRxBps"`
	WanTxBps  int64   `json:"wanTxBps"`
	ConnCount int64   `json:"connCount"`
}

type categoryBrief struct {
	Key     string  `json:"key"`
	Label   string  `json:"label"`
	UpBps   int64   `json:"upBps"`
	DownBps int64   `json:"downBps"`
	Share   float64 `json:"share"`
	Color   string  `json:"color"`
}

// topDeviceJSON 总览里的 Top 设备快照。
// online/blocked/conns 必须来自设备真实状态（与 /api/devices、SSE tick 同源），
// 否则 3D 大屏只能靠「字段缺失即在线」的乐观默认，导致离线/被断网设备被显示成正常在线。
type topDeviceJSON struct {
	IP        string  `json:"ip"`
	Name      string  `json:"name"`
	Alias     string  `json:"alias"`
	Online    bool    `json:"online"`  // 设备当前是否在线
	Blocked   bool    `json:"blocked"` // 是否被断网/封禁
	UpBps     int64   `json:"upBps"`
	DownBps   int64   `json:"downBps"`
	Conns     int     `json:"conns"` // 当前连接数
	TotalDown int64   `json:"totalDown"`
	Risk      float64 `json:"risk"`
}

type topDomainJSON struct {
	Domain   string `json:"domain"`
	Label    string `json:"label"`
	Category string `json:"category"`
	Hits     int64  `json:"hits"`
	DownBps  int64  `json:"downBps"`
}

type overviewResp struct {
	Ts         int64           `json:"ts"`
	KPI        kpiJSON         `json:"kpi"`
	Sys        sysJSON         `json:"sys"`
	Categories []categoryBrief `json:"categories"`
	Trend      []TrendPoint    `json:"trend"`
	TopDevices []topDeviceJSON `json:"topDevices"`
	TopDomains []topDomainJSON `json:"topDomains"`
	Alerts     []Event         `json:"alerts"`
}

// deviceJSON 组装 API Device 结构。
func (a *App) deviceJSON(st DeviceState, meta DeviceMeta, conns int, pols []Policy) DeviceJSON {
	topCat := st.TopCat
	if topCat == "" {
		topCat = "other"
	}
	d := DeviceJSON{
		IP: st.IP, MAC: st.MAC, Hostname: st.Hostname, Vendor: st.Vendor,
		Network: st.Network, Alias: meta.Alias, Group: meta.Group, Online: st.Online,
		FirstSeen: st.FirstSeen, LastSeen: st.LastSeen,
		LastOnlineAt: meta.LastOnlineAt, LastOfflineAt: meta.LastOfflineAt, OnlineCount: meta.OnlineCount,
		UpBps: st.UpBps, DownBps: st.DownBps,
		TotalUp: st.TotalUp, TotalDown: st.TotalDown,
		Conns: conns, Risk: st.Risk, Blocked: meta.Blocked, LimitKbps: meta.LimitKbps,
		TopCat: topCat, TopDomain: st.TopDomain, PolicyIds: []string{},
	}
	if d.Network == "" {
		d.Network, _ = a.networkForIP(st.IP)
	}
	for _, p := range pols {
		if policyTargets(p, st.IP, meta.Group) {
			d.PolicyIds = append(d.PolicyIds, p.ID)
		}
	}
	if d.Vendor == "" {
		d.Vendor = "未知"
	}
	return d
}

func (a *App) buildOverview() overviewResp {
	now := nowUnix()
	if !a.dataActive() {
		return a.emptyOverview(now)
	}
	sys := a.sys.Snapshot()
	rates := a.agg.LastRates()
	states := a.devs.States()
	metas := a.store.AllDeviceMeta()
	connCounts := a.agg.DeviceConnCount()
	pols := a.store.Policies()

	devJSON := make([]DeviceJSON, 0, len(states))
	online := 0
	ztDevices, ztOnline := 0, 0
	for _, st := range states {
		meta := metas[st.IP]
		if meta.Hidden || !isInternalNetwork(st.Network) {
			continue
		}
		// 口径：KPI 的设备数/在线只算本地 DHCP 网段（lan）；ZeroTier 另算
		if st.Network == "zerotier" {
			ztDevices++
			if st.Online {
				ztOnline++
			}
			continue
		}
		dj := a.deviceJSON(st, meta, connCounts[st.IP], pols)
		devJSON = append(devJSON, dj)
		if st.Online {
			online++
		}
	}

	// 分类占比（固定 8 项）
	cats := make([]categoryBrief, 0, len(Categories))
	var totalCat int64
	pairs := make(map[string][2]int64, len(Categories))
	for _, c := range Categories {
		pair := rates.CatBps[c.Key]
		pairs[c.Key] = pair
		totalCat += pair[0] + pair[1]
	}
	for _, c := range Categories {
		pair := pairs[c.Key]
		share := 0.0
		if totalCat > 0 {
			share = float64(pair[0]+pair[1]) / float64(totalCat)
		}
		cats = append(cats, categoryBrief{
			Key: c.Key, Label: c.Label, UpBps: pair[0], DownBps: pair[1],
			Share: roundShare(share), Color: c.Color,
		})
	}

	// 趋势固定 60 点（不足时前面补零）
	trend := a.agg.RecentTrend(60)
	if len(trend) < 60 {
		pad := make([]TrendPoint, 0, 60-len(trend))
		base := now - int64(len(trend))*2
		if len(trend) > 0 {
			base = trend[0].T
		}
		for i := 60 - len(trend); i > 0; i-- {
			pad = append(pad, TrendPoint{T: base - int64(i)*2})
		}
		trend = append(pad, trend...)
	}

	// Top 设备
	sortedDev := append([]DeviceJSON(nil), devJSON...)
	sortDeviceBySpeed(sortedDev)
	topDevices := make([]topDeviceJSON, 0, 10)
	for i := 0; i < len(sortedDev) && i < 10; i++ {
		d := sortedDev[i]
		topDevices = append(topDevices, topDeviceJSON{
			IP: d.IP, Name: displayName(d.Hostname, d.IP), Alias: d.Alias,
			// 状态字段必须透传真实状态：在线 / 被断网 / 当前连接数
			Online: d.Online, Blocked: d.Blocked, Conns: d.Conns,
			UpBps: d.UpBps, DownBps: d.DownBps, TotalDown: d.TotalDown, Risk: d.Risk,
		})
	}

	// Top 域名（按当前下行速率）
	topDomains := a.buildTopDomains(rates, 5)

	alerts := a.store.RecentUnacked(5)
	if alerts == nil {
		alerts = []Event{}
	}
	return overviewResp{
		Ts: now,
		KPI: kpiJSON{
			Online: online, Devices: len(devJSON),
			ZtDevices: ztDevices, ZtOnline: ztOnline,
			Conns:    sys.ConnCount,
			NewConns: rates.NewConnsLastMin, DNSQps: round1f(a.dns.QPS(now)),
			Alerts: a.store.UnackedCount(),
			// 实时上下行：有真 WAN 口时取 WAN 接口计数（每字节只计一次）；
			// 旁路由（无 WAN）时取 conntrack 归因的外发链路速率，
			// 物理 br-lan 计数只做总量校验（中转桥每字节进出各计一次，不能直接当上下行）。
			UpBps: sys.NetUpBps, DownBps: sys.NetDownBps,
			RiskLevel: a.sec.Level(),
		},
		Sys:        sysToJSON(sys),
		Categories: cats,
		Trend:      trend,
		TopDevices: topDevices,
		TopDomains: topDomains,
		Alerts:     alerts,
	}
}

// emptyOverview 未启用/未采集时的空总览（200 正常返回，前端显示"系统未启用"）。
func (a *App) emptyOverview(now int64) overviewResp {
	cats := make([]categoryBrief, 0, len(Categories))
	for _, c := range Categories {
		cats = append(cats, categoryBrief{Key: c.Key, Label: c.Label, Color: c.Color})
	}
	return overviewResp{
		Ts:         now,
		KPI:        kpiJSON{RiskLevel: "low"},
		Sys:        sysToJSON(a.sys.Snapshot()),
		Categories: cats,
		Trend:      []TrendPoint{},
		TopDevices: []topDeviceJSON{},
		TopDomains: []topDomainJSON{},
		Alerts:     []Event{},
	}
}

// emptyTraffic 未启用/未采集时的空流量分析。
func (a *App) emptyTraffic(rangeParam string, bucketSec int64) trafficResp {
	cats := make([]trafficCat, 0, len(Categories))
	for _, c := range Categories {
		cats = append(cats, trafficCat{Key: c.Key, Label: c.Label, Color: c.Color})
	}
	return trafficResp{
		Range: rangeParam, BucketSec: bucketSec,
		Series: []trafficSeriesPoint{}, ByCategory: cats, ByDevice: []trafficDev{}, ByApp: cats,
	}
}

func sysToJSON(s SysSnapshot) sysJSON {
	return sysJSON{
		CPUPct: s.CPUPct, MemPct: s.MemPct, MemUsedMb: s.MemUsedMb, Load1: s.Load1,
		UptimeSec: s.UptimeSec, TempC: s.TempC, WanRxBps: s.WanRxBps,
		WanTxBps: s.WanTxBps, ConnCount: s.ConnCount,
	}
}

func (a *App) buildTopDomains(rates IntervalRates, limit int) []topDomainJSON {
	type pair struct {
		domain string
		down   int64
	}
	list := make([]pair, 0, len(rates.DomainBps))
	for d, v := range rates.DomainBps {
		list = append(list, pair{d, v[1]})
	}
	sort.Slice(list, func(i, j int) bool { return list[i].down > list[j].down })
	out := make([]topDomainJSON, 0, limit)
	for i := 0; i < len(list) && i < limit; i++ {
		hits, label, cat, ok := a.dns.DomainHits(list[i].domain)
		if !ok {
			cat = "other"
			label = list[i].domain
		}
		out = append(out, topDomainJSON{
			Domain: list[i].domain, Label: label, Category: cat,
			Hits: hits, DownBps: list[i].down,
		})
	}
	return out
}

func displayName(hostname, ip string) string {
	if hostname != "" {
		return hostname
	}
	return ip
}

// ---------------- 设备 ----------------

type deviceListResp struct {
	Devices []DeviceJSON `json:"devices"`
}

type deviceDetailResp struct {
	Device     DeviceJSON     `json:"device"`
	Trend      []TrendPoint   `json:"trend"`
	TopDomains []deviceDomain `json:"topDomains"`
	TopDsts    []deviceDst    `json:"topDsts"`
	Conns      []Connection   `json:"conns"`
}

type deviceDomain struct {
	Domain   string `json:"domain"`
	URL      string `json:"url"`
	Label    string `json:"label"`
	Category string `json:"category"`
	Hits     int64  `json:"hits"`
	Bytes    int64  `json:"bytes"`
}

type deviceDst struct {
	IP      string `json:"ip"`
	Country string `json:"country"`
	Bytes   int64  `json:"bytes"`
}

// deviceFor 取设备 JSON（含元信息）；只返回内网设备（公网/docker 邻居不对外）。
func (a *App) deviceFor(ip string) (DeviceJSON, DeviceState, DeviceMeta, bool) {
	st, ok := a.devs.State(ip)
	if !ok {
		return DeviceJSON{}, DeviceState{}, DeviceMeta{}, false
	}
	if !isInternalNetwork(st.Network) {
		return DeviceJSON{}, DeviceState{}, DeviceMeta{}, false
	}
	meta := a.store.DeviceMeta(ip)
	conns := a.agg.DeviceConnCount()[ip]
	return a.deviceJSON(st, meta, conns, a.store.Policies()), st, meta, true
}

func (a *App) handleDevices(w http.ResponseWriter, r *http.Request, parts []string) {
	if len(parts) == 0 {
		if !requireMethod(w, r, http.MethodGet) {
			return
		}
		if !a.dataActive() {
			writeJSON(w, http.StatusOK, deviceListResp{Devices: []DeviceJSON{}})
			return
		}
		states := a.devs.States()
		metas := a.store.AllDeviceMeta()
		conns := a.agg.DeviceConnCount()
		pols := a.store.Policies()
		out := make([]DeviceJSON, 0, len(states))
		for _, st := range states {
			meta := metas[st.IP]
			if meta.Hidden || !isInternalNetwork(st.Network) {
				continue
			}
			out = append(out, a.deviceJSON(st, meta, conns[st.IP], pols))
		}
		writeJSON(w, http.StatusOK, deviceListResp{Devices: out})
		return
	}
	ip := parts[0]
	if net.ParseIP(ip) == nil {
		writeErr(w, http.StatusBadRequest, "设备 IP 不合法", "bad_ip")
		return
	}
	// /api/devices/{ip}
	if len(parts) == 1 {
		if !requireMethod(w, r, http.MethodGet) {
			return
		}
		if !a.dataActive() {
			writeErr(w, http.StatusNotFound, "设备不存在（系统未启用或采集未开启）", "not_found")
			return
		}
		dj, st, _, ok := a.deviceFor(ip)
		if !ok {
			writeErr(w, http.StatusNotFound, "设备不存在", "not_found")
			return
		}
		trend := st.Trend
		if len(trend) > 60 {
			trend = trend[len(trend)-60:]
		}
		if trend == nil {
			trend = []TrendPoint{}
		}
		now := nowUnix()
		domAgg := a.dns.DeviceTopDomains(ip, now-6*3600, 20)
		topDomains := make([]deviceDomain, 0, len(domAgg))
		// 域名字节按校准系数缩放，与设备/分类流量口径一致
		dsc := a.agg.Scale()
		scDomBytes := func(v int64) int64 {
			if dsc > 0 && dsc != 1 {
				return int64(float64(v) * dsc)
			}
			return v
		}
		for _, d := range domAgg {
			u, _ := buildDomainURL(d.Domain, d.Port)
			topDomains = append(topDomains, deviceDomain{
				Domain: d.Domain, URL: u, Label: d.Label, Category: d.Category, Hits: d.Hits, Bytes: scDomBytes(d.Bytes),
			})
		}
		dstBytes := a.agg.DeviceDstBytes(ip)
		topDsts := make([]deviceDst, 0, len(dstBytes))
		for dst, b := range dstBytes {
			country := "CN"
			if isForeignIP(dst) {
				country = "境外"
			}
			topDsts = append(topDsts, deviceDst{IP: dst, Country: country, Bytes: b})
		}
		sortDstBytes(topDsts)
		if len(topDsts) > 10 {
			topDsts = topDsts[:10]
		}
		conns := a.agg.DeviceConns(ip)
		if conns == nil {
			conns = []Connection{}
		}
		writeJSON(w, http.StatusOK, deviceDetailResp{
			Device: dj, Trend: trend, TopDomains: topDomains, TopDsts: topDsts, Conns: conns,
		})
		return
	}
	// /api/devices/{ip}/{action}
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	action := parts[1]
	switch action {
	case "alias":
		var req struct {
			Alias string `json:"alias"`
		}
		if !decodeJSON(w, r, &req) {
			return
		}
		if len([]rune(req.Alias)) > 32 {
			writeErr(w, http.StatusBadRequest, "别名最长 32 个字符", "bad_alias")
			return
		}
		if _, _, _, ok := a.deviceFor(ip); !ok {
			writeErr(w, http.StatusNotFound, "设备不存在", "not_found")
			return
		}
		a.store.UpdateDeviceMeta(ip, func(m *DeviceMeta) { m.Alias = req.Alias })
		dj, _, _, _ := a.deviceFor(ip)
		writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true, "applied": []string{}, "device": dj})
	case "group":
		var req struct {
			Group string `json:"group"`
		}
		if !decodeJSON(w, r, &req) {
			return
		}
		// 与 alias 分支保持一致：校验设备存在 + 限制长度，避免写入任意 IP / 超长分组
		if len([]rune(req.Group)) > 32 {
			writeErr(w, http.StatusBadRequest, "分组名最长 32 个字符", "bad_group")
			return
		}
		if _, _, _, ok := a.deviceFor(ip); !ok {
			writeErr(w, http.StatusNotFound, "设备不存在", "not_found")
			return
		}
		a.store.UpdateDeviceMeta(ip, func(m *DeviceMeta) { m.Group = req.Group })
		dj, _, _, _ := a.deviceFor(ip)
		writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true, "applied": []string{}, "device": dj})
	case "block":
		var req struct {
			Blocked bool `json:"blocked"`
		}
		if !decodeJSON(w, r, &req) {
			return
		}
		if !a.deviceControlOn() {
			writeErr(w, http.StatusBadRequest, errSwitchOff.Error(), "switch_off")
			return
		}
		if req.Blocked && a.isProtectedIP(ip) {
			writeErr(w, http.StatusBadRequest, errProtectedIP.Error(), "protected_ip")
			return
		}
		if _, _, _, ok := a.deviceFor(ip); !ok {
			writeErr(w, http.StatusNotFound, "设备不存在", "not_found")
			return
		}
		applied, err := a.enf.SetBlocked(ip, req.Blocked)
		if err != nil {
			writeEnforceErr(w, err)
			return
		}
		a.store.UpdateDeviceMeta(ip, func(m *DeviceMeta) {
			m.Blocked = req.Blocked
			if req.Blocked {
				if m.BlockedAt == 0 {
					m.BlockedAt = nowUnix()
				}
			} else {
				m.BlockedAt = 0
			}
		})
		dj, _, _, _ := a.deviceFor(ip)
		writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true, "applied": applied, "device": dj})
	case "limit":
		var req struct {
			DownKbps int `json:"downKbps"`
			UpKbps   int `json:"upKbps"`
		}
		if !decodeJSON(w, r, &req) {
			return
		}
		if req.DownKbps < 0 || req.UpKbps < 0 || req.DownKbps > 1000000 || req.UpKbps > 1000000 {
			writeErr(w, http.StatusBadRequest, "限速值范围 0~1000000 Kbps", "bad_limit")
			return
		}
		if (req.DownKbps > 0 || req.UpKbps > 0) && a.isProtectedIP(ip) {
			writeErr(w, http.StatusBadRequest, errProtectedIP.Error(), "protected_ip")
			return
		}
		if !a.deviceControlOn() {
			writeErr(w, http.StatusBadRequest, errSwitchOff.Error(), "switch_off")
			return
		}
		if _, _, _, ok := a.deviceFor(ip); !ok {
			writeErr(w, http.StatusNotFound, "设备不存在", "not_found")
			return
		}
		applied, err := a.enf.SetLimit(ip, req.DownKbps, req.UpKbps)
		if err != nil {
			writeEnforceErr(w, err)
			return
		}
		a.store.UpdateDeviceMeta(ip, func(m *DeviceMeta) {
			m.LimitKbps = LimitKbps{Down: req.DownKbps, Up: req.UpKbps}
			if req.DownKbps > 0 || req.UpKbps > 0 {
				if m.LimitAt == 0 {
					m.LimitAt = nowUnix()
				}
			} else {
				m.LimitAt = 0
			}
		})
		dj, _, _, _ := a.deviceFor(ip)
		writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true, "applied": applied, "device": dj})
	case "forget":
		// 与同组其它 action（alias/group/block/limit）保持一致：先校验设备存在，
		// 避免给任意 IP 写入 hidden 元数据
		if _, _, _, ok := a.deviceFor(ip); !ok {
			writeErr(w, http.StatusNotFound, "设备不存在", "not_found")
			return
		}
		a.store.UpdateDeviceMeta(ip, func(m *DeviceMeta) { m.Hidden = true })
		writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true, "applied": []string{}})
	default:
		writeErr(w, http.StatusNotFound, "接口不存在", "not_found")
	}
}

// ---------------- 流量分析 ----------------

type trafficSeriesPoint struct {
	T     int64            `json:"t"`
	Up    int64            `json:"up"`
	Down  int64            `json:"down"`
	ByCat map[string]int64 `json:"byCat"`
}

type trafficCat struct {
	Key   string  `json:"key"`
	Label string  `json:"label"`
	Up    int64   `json:"up"`
	Down  int64   `json:"down"`
	Share float64 `json:"share"`
	Color string  `json:"color"`
}

type trafficDev struct {
	IP    string  `json:"ip"`
	Name  string  `json:"name"`
	Alias string  `json:"alias"`
	Up    int64   `json:"up"`
	Down  int64   `json:"down"`
	Share float64 `json:"share"`
}

type trafficResp struct {
	Range      string               `json:"range"`
	BucketSec  int64                `json:"bucketSec"`
	Series     []trafficSeriesPoint `json:"series"`
	ByCategory []trafficCat         `json:"byCategory"`
	ByDevice   []trafficDev         `json:"byDevice"`
	ByApp      []trafficCat         `json:"byApp"`
}

type domainDevBriefJSON struct {
	IP       string `json:"ip"`
	Name     string `json:"name"`
	Alias    string `json:"alias"`
	Hits     int64  `json:"hits"`
	Bytes    int64  `json:"bytes"`
	LastSeen int64  `json:"lastSeen"`
}

type domainEntryJSON struct {
	Domain string `json:"domain"`
	// URL 完整访问地址（scheme://host[:port]/）；HTTP(S) 路径属加密内容不可见
	URL      string `json:"url"`
	Scheme   string `json:"scheme"`
	Port     int    `json:"port"`
	Label    string `json:"label"`
	Category string `json:"category"`
	// Blocked 是否已被手工封禁（列表/详情可直接展示与解封）
	Blocked    bool                 `json:"blocked"`
	Hits       int64                `json:"hits"`
	Bytes      int64                `json:"bytes"`
	Devices    int                  `json:"devices"`
	LastSeen   int64                `json:"lastSeen"`
	DeviceList []domainDevBriefJSON `json:"deviceList"`
	// Paths 明文 HTTP（http://）观测到的完整 URL 路径（含查询串），按次数降序
	Paths []httpPathJSON `json:"paths,omitempty"`
}

type httpPathJSON struct {
	URL      string `json:"url"`
	Hits     int64  `json:"hits"`
	LastSeen int64  `json:"lastSeen"`
	Devices  int    `json:"devices"`
}

type domainsResp struct {
	Domains []domainEntryJSON `json:"domains"`
}

type connsResp struct {
	Conns []Connection `json:"conns"`
	Total int          `json:"total"`
}

// rangeSpec 时间范围 -> 时长与基础桶宽。
// 注意：底层统计桶是「分钟桶」(now/60*60)，基础桶宽必须是 60 的倍数，
// 否则聚合会错位（30 秒桶只能装下半分钟数据，速率显示会翻倍并出现锯齿）。
func rangeSpec(r string) (dur int64, bucketSec int64, ok bool) {
	switch r {
	case "", "1h":
		return 3600, 60, true
	case "6h":
		return 6 * 3600, 120, true
	case "24h":
		return 24 * 3600, 300, true
	case "7d":
		return 7 * 24 * 3600, 1800, true
	}
	return 0, 0, false
}

// bucketsForRange 取时间范围内的分钟桶（内存不足时从磁盘补齐历史）。
func (a *App) bucketsForRange(from, now int64) []*Bucket {
	mem := a.agg.BucketsSince(from)
	if len(mem) == 0 {
		if a.cfg.Demo {
			return nil
		}
		return a.store.LoadTrafficBuckets(from, now)
	}
	oldest := a.agg.OldestBucketT()
	if oldest <= from || a.cfg.Demo {
		return mem
	}
	disk := a.store.LoadTrafficBuckets(from, oldest-1)
	if len(disk) == 0 {
		return mem
	}
	seen := make(map[int64]bool, len(mem))
	for _, b := range mem {
		seen[b.T] = true
	}
	out := make([]*Bucket, 0, len(disk)+len(mem))
	for _, b := range disk {
		if !seen[b.T] {
			out = append(out, b)
		}
	}
	out = append(out, mem...)
	return out
}

func (a *App) handleTraffic(w http.ResponseWriter, r *http.Request, parts []string) {
	if len(parts) > 0 {
		switch parts[0] {
		case "domains":
			a.handleTrafficDomains(w, r)
			return
		case "conns":
			if len(parts) >= 3 && parts[2] == "block" {
				a.handleConnBlock(w, r, parts[1])
				return
			}
			a.handleTrafficConns(w, r)
			return
		}
		writeErr(w, http.StatusNotFound, "接口不存在", "not_found")
		return
	}
	if !requireMethod(w, r, http.MethodGet) {
		return
	}
	rangeParam := r.URL.Query().Get("range")
	dur, bucketSec, ok := rangeSpec(rangeParam)
	if !ok {
		writeErr(w, http.StatusBadRequest, "range 仅支持 1h/6h/24h/7d", "bad_range")
		return
	}
	if rangeParam == "" {
		rangeParam = "1h"
	}
	if !a.dataActive() {
		writeJSON(w, http.StatusOK, a.emptyTraffic(rangeParam, bucketSec))
		return
	}
	// 结果缓存（key = range + 数据版本，TTL 30s）：命中时直接返回上次渲染结果，
	// 不再重放 JSONL、也不再做分类/设备全量汇总 —— 前端 30s 轮询下这是最重的一步。
	// 版本号在「分钟桶落盘 / 历史清理 / 设置（开关）变更」时递增，因此开关切换、
	// 数据清空后不会返回旧结果。
	ver := a.store.DataVersion()
	if cached, ok := a.store.CachedTrafficResult(rangeParam, ver); ok {
		if resp, ok := cached.(trafficResp); ok {
			writeJSON(w, http.StatusOK, resp)
			return
		}
	}
	now := nowUnix()
	from := now - dur
	buckets := a.bucketsForRange(from, now)

	// 聚合到目标桶宽；点数超过 200 时自动加大桶宽
	series := aggregateSeries(buckets, bucketSec)
	for len(series) > 200 && bucketSec < 86400 {
		bucketSec *= 2
		series = aggregateSeries(buckets, bucketSec)
	}
	// 按校准系数缩放到物理真实量级（conntrack 归因的绝对值不可信，比例可用）
	// 注意：byCat 与 up/down 必须同口径缩放，否则堆叠图历史段与 byCategory/overview 相差 sc 倍。
	sc := a.agg.Scale()
	if sc > 0 && sc != 1 {
		for i := range series {
			series[i].Up = int64(float64(series[i].Up) * sc)
			series[i].Down = int64(float64(series[i].Down) * sc)
			for k, v := range series[i].ByCat {
				series[i].ByCat[k] = int64(float64(v) * sc)
			}
		}
	}

	// 分类/应用总量
	byCat := map[string][2]int64{}
	var totalCat int64
	for _, b := range buckets {
		for k, v := range b.CatUp {
			p := byCat[k]
			p[0] += v
			byCat[k] = p
			totalCat += v
		}
		for k, v := range b.CatDown {
			p := byCat[k]
			p[1] += v
			byCat[k] = p
			totalCat += v
		}
	}
	byCategory := make([]trafficCat, 0, len(Categories))
	for _, c := range Categories {
		p := byCat[c.Key]
		share := 0.0
		if totalCat > 0 {
			share = float64(p[0]+p[1]) / float64(totalCat)
		}
		byCategory = append(byCategory, trafficCat{
			Key: c.Key, Label: c.Label,
			Up:    int64(float64(p[0]) * sc),
			Down:  int64(float64(p[1]) * sc),
			Share: roundShare(share), Color: c.Color,
		})
	}

	// 设备总量
	devTotals := map[string][2]int64{}
	var totalDev int64
	for _, b := range buckets {
		for ip, p := range b.ByDev {
			cur := devTotals[ip]
			cur[0] += p[0]
			cur[1] += p[1]
			devTotals[ip] = cur
			totalDev += p[0] + p[1]
		}
	}
	metas := a.store.AllDeviceMeta()
	byDevice := make([]trafficDev, 0, len(devTotals))
	for ip, p := range devTotals {
		name := ""
		if st, ok := a.devs.State(ip); ok {
			name = st.Hostname
		}
		share := 0.0
		if totalDev > 0 {
			share = float64(p[0]+p[1]) / float64(totalDev)
		}
		byDevice = append(byDevice, trafficDev{
			IP: ip, Name: displayName(name, ip), Alias: metas[ip].Alias,
			Up: int64(float64(p[0]) * sc), Down: int64(float64(p[1]) * sc), Share: roundShare(share),
		})
	}
	sortTrafficDev(byDevice)
	if len(byDevice) > 20 {
		byDevice = byDevice[:20]
	}

	resp := trafficResp{
		Range: rangeParam, BucketSec: bucketSec,
		Series: series, ByCategory: byCategory, ByDevice: byDevice, ByApp: byCategory,
	}
	// 记录本次结果（版本取计算开始前的 ver：期间若有新数据落盘，索引会立即失效，
	// 下一次请求重建 —— 宁可少命中一次，也不返回跨版本的结果）。
	a.store.PutTrafficResult(rangeParam, ver, resp)
	writeJSON(w, http.StatusOK, resp)
}

// aggregateSeries 按桶宽聚合分钟桶（up/down 输出平均 bit/s，byCat 输出字节）。
func aggregateSeries(buckets []*Bucket, bucketSec int64) []trafficSeriesPoint {
	if bucketSec <= 0 {
		bucketSec = 60
	}
	type acc struct {
		up, down int64
		cat      map[string]int64
	}
	groups := map[int64]*acc{}
	var order []int64
	for _, b := range buckets {
		t := b.T / bucketSec * bucketSec
		g := groups[t]
		if g == nil {
			g = &acc{cat: map[string]int64{}}
			groups[t] = g
			order = append(order, t)
		}
		g.up += b.Up
		g.down += b.Down
		for k, v := range b.CatUp {
			g.cat[k] += v
		}
		for k, v := range b.CatDown {
			g.cat[k] += v
		}
	}
	sortInt64s(order)
	out := make([]trafficSeriesPoint, 0, len(order))
	for _, t := range order {
		g := groups[t]
		byCat := make(map[string]int64, len(Categories))
		for _, c := range Categories {
			byCat[c.Key] = g.cat[c.Key]
		}
		out = append(out, trafficSeriesPoint{
			T:     t,
			Up:    g.up * 8 / bucketSec,
			Down:  g.down * 8 / bucketSec,
			ByCat: byCat,
		})
	}
	return out
}

// buildDomainURL 由域名 + 观测到的目的端口还原可读的完整 URL。
//
// 说明：HTTPS 的路径（/video/xxx）在 TLS 内加密，DNS 与 conntrack 都看不到，
// 因此最多能还原到 scheme://host[:port]/；HTTP 明文的路径同样需要抓包才能获得。
// 这里给出协议、主机与端口，已是无 DPI 条件下能得到的最完整地址。
func buildDomainURL(domain string, port int) (string, string) {
	scheme := "https"
	hostPort := ""
	switch {
	case port == 80:
		scheme = "http"
	case port == 443 || port == 0:
		scheme = "https"
	case port > 0 && port <= 65535:
		scheme = "https"
		hostPort = ":" + strconv.Itoa(port)
	}
	return scheme + "://" + domain + hostPort + "/", scheme
}
func (a *App) handleTrafficDomains(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet) {
		return
	}
	rangeParam := r.URL.Query().Get("range")
	dur, _, ok := rangeSpec(rangeParam)
	if !ok {
		writeErr(w, http.StatusBadRequest, "range 仅支持 1h/6h/24h/7d", "bad_range")
		return
	}
	limit := queryInt(r, "limit", 50, 1, 500)
	if !a.dataActive() {
		writeJSON(w, http.StatusOK, domainsResp{Domains: []domainEntryJSON{}})
		return
	}
	now := nowUnix()
	list := a.dns.TopDomains(now-dur, limit)
	metas := a.store.AllDeviceMeta()
	// 域名字节来自 dns.AddBytes（conntrack 原始值），与其他流量出口一样按校准系数缩放，
	// 否则同一页「域名流量」与「分类/设备流量」口径不一致（相差 sc 倍）。
	sc := a.agg.Scale()
	scBytes := func(v int64) int64 {
		if sc > 0 && sc != 1 {
			return int64(float64(v) * sc)
		}
		return v
	}
	out := make([]domainEntryJSON, 0, len(list))
	for _, d := range list {
		devList := make([]domainDevBriefJSON, 0, len(d.DevList))
		for _, dev := range d.DevList {
			st, ok := a.devs.State(dev.IP)
			name := dev.IP
			if ok && st.Hostname != "" {
				name = displayName(st.Hostname, dev.IP)
			}
			devList = append(devList, domainDevBriefJSON{
				IP: dev.IP, Name: name, Alias: metas[dev.IP].Alias,
				Hits: dev.Hits, Bytes: scBytes(dev.Bytes), LastSeen: dev.LastSeen,
			})
		}
		urlStr, scheme := buildDomainURL(d.Domain, d.Port)
		// 明文 HTTP 有路径记录时：优先展示「http://host/path」，并把路径列表带出去
		var paths []httpPathJSON
		if briefs := a.dns.HTTPURLsFor(d.Domain, 5); len(briefs) > 0 {
			paths = make([]httpPathJSON, 0, len(briefs))
			for _, b := range briefs {
				paths = append(paths, httpPathJSON{URL: b.URL, Hits: b.Hits, LastSeen: b.LastSeen, Devices: b.Devices})
			}
			urlStr, scheme = briefs[0].URL, "http"
		}
		out = append(out, domainEntryJSON{
			Domain: d.Domain, URL: urlStr, Scheme: scheme, Port: d.Port,
			Label: d.Label, Category: d.Category,
			Blocked: a.store.IsDomainBlock(d.Domain),
			Hits:    d.Hits, Bytes: scBytes(d.Bytes), Devices: d.Devices, LastSeen: d.LastSeen,
			DeviceList: devList, Paths: paths,
		})
	}
	writeJSON(w, http.StatusOK, domainsResp{Domains: out})
}

func (a *App) handleTrafficConns(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet) {
		return
	}
	if !a.dataActive() {
		writeJSON(w, http.StatusOK, connsResp{Conns: []Connection{}, Total: 0})
		return
	}
	limit := queryInt(r, "limit", 200, 1, 500)
	q := r.URL.Query().Get("q")
	device := r.URL.Query().Get("device")
	conns, total := a.agg.ConnList(limit, q, device)
	if conns == nil {
		conns = []Connection{}
	}
	writeJSON(w, http.StatusOK, connsResp{Conns: conns, Total: total})
}

// handleConnBlock 封禁目标 IP 或断设备。
func (a *App) handleConnBlock(w http.ResponseWriter, r *http.Request, id string) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	var req struct {
		Scope string `json:"scope"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	c, ok := a.agg.ConnByID(id)
	if !ok {
		// 连接可能刚结束，尝试从 ID 解析目标 IP
		parts := strings.Split(id, "-")
		if len(parts) >= 5 {
			c.DstIP = parts[len(parts)-2]
			c.SrcIP = parts[1]
		}
	}
	if c.DstIP == "" {
		writeErr(w, http.StatusNotFound, "连接不存在", "not_found")
		return
	}
	switch req.Scope {
	case "device":
		if c.SrcIP == "" {
			writeErr(w, http.StatusBadRequest, "无法确定设备", "bad_request")
			return
		}
		applied, err := a.enf.SetBlocked(c.SrcIP, true)
		if err != nil {
			writeEnforceErr(w, err)
			return
		}
		a.store.UpdateDeviceMeta(c.SrcIP, func(m *DeviceMeta) { m.Blocked = true })
		writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true, "applied": applied})
	case "dst":
		applied, err := a.enf.BlockDst(c.DstIP)
		if err != nil {
			writeEnforceErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true, "applied": applied})
	default:
		writeErr(w, http.StatusBadRequest, "scope 仅支持 dst/device", "bad_scope")
	}
}

// ---------------- 策略 ----------------

type policiesResp struct {
	Policies []Policy `json:"policies"`
}

func (a *App) handlePolicies(w http.ResponseWriter, r *http.Request, parts []string) {
	if len(parts) == 0 {
		switch r.Method {
		case http.MethodGet:
			pols := a.store.Policies()
			if pols == nil {
				pols = []Policy{}
			}
			writeJSON(w, http.StatusOK, policiesResp{Policies: pols})
		case http.MethodPost:
			var req policyRequest
			if !decodeJSON(w, r, &req) {
				return
			}
			p, err := req.toPolicy(Policy{}, true)
			if err != nil {
				writeErr(w, http.StatusBadRequest, err.Error(), "bad_policy")
				return
			}
			p = a.store.UpsertPolicy(p)
			a.enf.ReconcilePolicies(time.Now())
			writeJSON(w, http.StatusOK, map[string]interface{}{"policy": p})
		default:
			writeErr(w, http.StatusMethodNotAllowed, "不支持的请求方法", "method_not_allowed")
		}
		return
	}
	id := parts[0]
	if len(parts) == 2 && parts[1] == "toggle" {
		if !requireMethod(w, r, http.MethodPost) {
			return
		}
		var req struct {
			Enabled bool `json:"enabled"`
		}
		if !decodeJSON(w, r, &req) {
			return
		}
		p, ok := a.store.SetPolicyEnabled(id, req.Enabled)
		if !ok {
			writeErr(w, http.StatusNotFound, "策略不存在", "not_found")
			return
		}
		a.enf.ReconcilePolicies(time.Now())
		writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true, "policy": p})
		return
	}
	old, found := a.store.PolicyByID(id)
	if !found {
		writeErr(w, http.StatusNotFound, "策略不存在", "not_found")
		return
	}
	switch r.Method {
	case http.MethodPut:
		var req policyRequest
		if !decodeJSON(w, r, &req) {
			return
		}
		p, err := req.toPolicy(old, false)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error(), "bad_policy")
			return
		}
		p.ID = id
		p = a.store.UpsertPolicy(p)
		a.enf.ReconcilePolicies(time.Now())
		writeJSON(w, http.StatusOK, map[string]interface{}{"policy": p})
	case http.MethodDelete:
		if !a.store.DeletePolicy(id) {
			writeErr(w, http.StatusNotFound, "策略不存在", "not_found")
			return
		}
		a.enf.ReconcilePolicies(time.Now())
		writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true})
	default:
		writeErr(w, http.StatusMethodNotAllowed, "不支持的请求方法", "method_not_allowed")
	}
}

// policyRequest 创建/更新策略的请求体（enabled 用指针区分「未传」）。
type policyRequest struct {
	Name       string    `json:"name"`
	Enabled    *bool     `json:"enabled"`
	Targets    Targets   `json:"targets"`
	Schedule   Schedule  `json:"schedule"`
	Action     string    `json:"action"`
	Categories []string  `json:"categories"`
	Domains    []string  `json:"domains"`
	LimitKbps  LimitKbps `json:"limitKbps"`
}

func (req policyRequest) toPolicy(base Policy, create bool) (Policy, error) {
	p := base
	if req.Name != "" {
		p.Name = strings.TrimSpace(req.Name)
	}
	if p.Name == "" {
		p.Name = "未命名策略"
	}
	if req.Enabled != nil {
		p.Enabled = *req.Enabled
	} else if create {
		p.Enabled = true
	}
	p.Targets = req.Targets
	p.Schedule = req.Schedule
	if p.Schedule.Start == "" {
		p.Schedule.Start = "00:00"
	}
	if p.Schedule.End == "" {
		p.Schedule.End = "23:59"
	}
	switch req.Action {
	case "block", "limit", "allow":
		p.Action = req.Action
	case "":
		if create {
			p.Action = "block"
		}
	default:
		return p, fmt.Errorf("action 仅支持 block/limit/allow")
	}
	// 分类校验（支持 blocked:gambling 形式）
	cats := make([]string, 0, len(req.Categories))
	for _, c := range req.Categories {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		if validCategory(c) || strings.HasPrefix(c, "blocked:") {
			cats = append(cats, c)
		} else {
			return p, fmt.Errorf("未知分类: %s", c)
		}
	}
	p.Categories = cats
	domains := make([]string, 0, len(req.Domains))
	for _, d := range req.Domains {
		if nd := normalizeDomainRule(d); nd != "" {
			domains = append(domains, nd)
		}
	}
	p.Domains = domains
	if req.LimitKbps.Down < 0 || req.LimitKbps.Up < 0 {
		return p, fmt.Errorf("限速值不能为负")
	}
	p.LimitKbps = req.LimitKbps
	for _, d := range p.Schedule.Days {
		if d < 1 || d > 7 {
			return p, fmt.Errorf("days 取值 1-7（周一=1）")
		}
	}
	return p, nil
}

// ---------------- 管控状态 ----------------

func (a *App) handleEnforce(w http.ResponseWriter, r *http.Request, parts []string) {
	if len(parts) == 0 {
		writeErr(w, http.StatusNotFound, "接口不存在", "not_found")
		return
	}
	switch parts[0] {
	case "status":
		if !requireMethod(w, r, http.MethodGet) {
			return
		}
		writeJSON(w, http.StatusOK, a.enf.Status())
	case "reset":
		if !requireMethod(w, r, http.MethodPost) {
			return
		}
		removed, err := a.enf.Reset()
		if err != nil {
			writeEnforceErr(w, err)
			return
		}
		if removed == nil {
			removed = []string{}
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true, "removed": removed})
	case "dns":
		// 行为页「DNS 拦截域名列表」展示用；契约 §5 只有 dnsBlockedDomains 计数，
		// 此端点作为只读补充（不改既有契约），返回当前实际封堵的域名明细。
		if !requireMethod(w, r, http.MethodGet) {
			return
		}
		domains := a.enf.BlockedDomains()
		if domains == nil {
			domains = []string{}
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"domains": domains})
	case "domains":
		// 手工封禁/解封域名：可直接贴完整 URL（取其主机名）。
		a.handleEnforceDomains(w, r)
	case "blocks":
		a.handleEnforceBlocks(w, r, parts[1:])
	default:
		writeErr(w, http.StatusNotFound, "接口不存在", "not_found")
	}
}

// blockDomainRe 手工封禁的域名格式：多级标签 + 至少两字母 TLD（含 punycode）。
var blockDomainRe = regexp.MustCompile(`^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]{2,59})$`)

// blockTargetHost 从用户输入（完整 URL 或裸域名）提取要封禁的主机名。
//
// 说明：HTTPS 的路径在 TLS 内加密、明文 HTTP 的路径也不参与拦截（dnsmasq/ipset
// 只能按域名生效），所以封禁一律以域名为单位；这里接受 `http://evil.com/a/b?x=1`
// 这类完整 URL 并自动去掉 scheme/路径/端口。
func blockTargetHost(raw string) (string, error) {
	s := strings.ToLower(strings.TrimSpace(raw))
	if s == "" {
		return "", fmt.Errorf("请输入要封禁的 URL 或域名")
	}
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	// 去端口（仅 host:port；出现多个冒号按 IPv6 拒绝）
	if i := strings.LastIndex(s, ":"); i >= 0 {
		if strings.Contains(s[i+1:], ":") {
			return "", fmt.Errorf("不支持 IPv6，请输入域名")
		}
		if port := s[i+1:]; port != "" && isAllDigits(port) {
			s = s[:i]
		}
	}
	s = strings.TrimSuffix(s, ".")
	if s == "" {
		return "", fmt.Errorf("请输入要封禁的 URL 或域名")
	}
	if ip := net.ParseIP(s); ip != nil {
		return "", fmt.Errorf("请输入域名而不是 IP（IP 请在设备/连接列表里直接封禁）")
	}
	if len(s) > 253 || !blockDomainRe.MatchString(s) {
		return "", fmt.Errorf("域名格式不正确：%s", s)
	}
	return s, nil
}

func isAllDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return len(s) > 0
}

// handleEnforceDomains 手工封禁/解封域名。
//
//	POST /api/enforce/domains  {"url":"http://evil.com/path","action":"add|remove"}
//
// action 留空按 add 处理。返回 {ok,domain,effective[,hint]}：
// effective=false 表示已保存但「域名封堵」开关未开启（开启后自动生效）。
func (a *App) handleEnforceDomains(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	var req struct {
		URL    string `json:"url"`
		Action string `json:"action"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "请求体不是合法 JSON", "bad_json")
		return
	}
	host, err := blockTargetHost(req.URL)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error(), "bad_domain")
		return
	}
	switch strings.ToLower(strings.TrimSpace(req.Action)) {
	case "", "add":
		a.store.AddDomainBlock(host)
	case "remove":
		a.store.RemoveDomainBlock(host)
	default:
		writeErr(w, http.StatusBadRequest, "action 仅支持 add / remove", "bad_action")
		return
	}
	effective := a.enf.ApplyManualDomains()
	resp := map[string]interface{}{"ok": true, "domain": host, "effective": effective}
	if !effective {
		resp["hint"] = "域名封堵开关未开启：已保存到列表，开启「域名封堵」后自动生效"
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleEnforceBlocks 封禁列表 / 解封。
//
//	GET  /api/enforce/blocks
//	POST /api/enforce/blocks/{ip}/unblock[?type=device|dst|limit]
func (a *App) handleEnforceBlocks(w http.ResponseWriter, r *http.Request, parts []string) {
	if len(parts) == 0 {
		if !requireMethod(w, r, http.MethodGet) {
			return
		}
		blocks := a.enf.Blocks()
		if blocks == nil {
			blocks = []BlockEntry{}
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"blocks": blocks})
		return
	}
	ip := strings.TrimSpace(parts[0])
	if net.ParseIP(ip) == nil {
		writeErr(w, http.StatusBadRequest, "IP 不合法", "bad_ip")
		return
	}
	if len(parts) < 2 || parts[1] != "unblock" {
		writeErr(w, http.StatusNotFound, "接口不存在", "not_found")
		return
	}
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	wantType := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("type")))
	if wantType != "" && wantType != "device" && wantType != "dst" && wantType != "limit" {
		writeErr(w, http.StatusBadRequest, "type 仅支持 device/dst/limit（留空=全部解封）", "bad_type")
		return
	}
	doDevice := wantType == "" || wantType == "device"
	doDst := wantType == "" || wantType == "dst"
	doLimit := wantType == "" || wantType == "limit"

	var applied, revoked []string
	matched := false
	var firstErr error

	if doDevice && a.enf.IsBlocked(ip) {
		matched = true
		if ap, err := a.enf.SetBlocked(ip, false); err != nil {
			firstErr = err
		} else {
			applied = append(applied, ap...)
			a.store.UpdateDeviceMeta(ip, func(m *DeviceMeta) {
				m.Blocked = false
				m.BlockedAt = 0
			})
			revoked = append(revoked, "已解封设备断网："+ip)
		}
	}
	if doDst && a.enf.IsDstBlocked(ip) {
		matched = true
		if ap, err := a.enf.UnblockDst(ip); err != nil {
			firstErr = err
		} else {
			applied = append(applied, ap...)
			revoked = append(revoked, "已解封目标 IP："+ip)
		}
	}
	if doLimit && a.enf.IsLimited(ip) {
		matched = true
		if ap, err := a.enf.SetLimit(ip, 0, 0); err != nil {
			firstErr = err
		} else {
			applied = append(applied, ap...)
			a.store.UpdateDeviceMeta(ip, func(m *DeviceMeta) {
				m.LimitKbps = LimitKbps{}
				m.LimitAt = 0
			})
			revoked = append(revoked, "已取消限速："+ip)
		}
	}
	if firstErr != nil {
		writeEnforceErr(w, firstErr)
		return
	}
	if !matched {
		writeErr(w, http.StatusNotFound, "该 IP 没有可解封的记录", "not_found")
		return
	}
	if applied == nil {
		applied = []string{}
	}
	if revoked == nil {
		revoked = []string{}
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true, "applied": applied, "revoked": revoked})
}

// ---------------- 事件与安全态势 ----------------

type eventsResp struct {
	Events  []Event      `json:"events"`
	Summary EventSummary `json:"summary"`
}

func (a *App) handleEvents(w http.ResponseWriter, r *http.Request, parts []string) {
	if len(parts) == 0 {
		if !requireMethod(w, r, http.MethodGet) {
			return
		}
		limit := queryInt(r, "limit", 100, 1, 500)
		severity := r.URL.Query().Get("severity")
		typ := r.URL.Query().Get("type")
		ack := r.URL.Query().Get("ack")
		if ack == "" {
			ack = "all"
		}
		events, summary := a.store.Events(limit, severity, typ, ack)
		if events == nil {
			events = []Event{}
		}
		writeJSON(w, http.StatusOK, eventsResp{Events: events, Summary: summary})
		return
	}
	switch parts[0] {
	case "clear":
		if !requireMethod(w, r, http.MethodPost) {
			return
		}
		n := a.store.ClearEvents()
		writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true, "cleared": n})
	default:
		if len(parts) == 2 && parts[1] == "ack" {
			if !requireMethod(w, r, http.MethodPost) {
				return
			}
			var req struct {
				Acked bool `json:"acked"`
			}
			if !decodeJSON(w, r, &req) {
				return
			}
			if !a.store.AckEvent(parts[0], req.Acked) {
				writeErr(w, http.StatusNotFound, "事件不存在", "not_found")
				return
			}
			writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true})
			return
		}
		writeErr(w, http.StatusNotFound, "接口不存在", "not_found")
	}
}

type riskReasonJSON struct {
	Type   string `json:"type"`
	Count  int    `json:"count"`
	LastTs int64  `json:"lastTs"`
}

type riskDeviceJSON struct {
	IP      string           `json:"ip"`
	Name    string           `json:"name"`
	Risk    float64          `json:"risk"`
	Reasons []riskReasonJSON `json:"reasons"`
}

type riskResp struct {
	Level   string           `json:"level"`
	Devices []riskDeviceJSON `json:"devices"`
}

func (a *App) handleRisk(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet) {
		return
	}
	if !a.alertsOn() {
		writeJSON(w, http.StatusOK, riskResp{Level: "low", Devices: []riskDeviceJSON{}})
		return
	}
	list := a.sec.RiskDevices()
	out := make([]riskDeviceJSON, 0, len(list))
	for _, d := range list {
		reasons := make([]riskReasonJSON, 0, len(d.Reasons))
		for _, rr := range d.Reasons {
			reasons = append(reasons, riskReasonJSON{Type: rr.Type, Count: rr.Count, LastTs: rr.LastTs})
		}
		out = append(out, riskDeviceJSON{IP: d.IP, Name: d.Name, Risk: d.Risk, Reasons: reasons})
	}
	writeJSON(w, http.StatusOK, riskResp{Level: a.sec.Level(), Devices: out})
}

// ---------------- 告警白名单 ----------------

type whitelistResp struct {
	Items []WhitelistEntry `json:"items"`
}

// validWhitelistType 校验白名单 type：与事件 type 同构的标识符。
//
// 事件类型（port_scan / blacklist_domain / bad_ip …）定义在 security.go，且前端在
// 事件缺 type 时会兜底提交 "other"，因此这里不采用封闭枚举（新增事件类型会导致
// 对应加白请求被拒），而是收敛到「小写标识符 + 长度上限」：既能挡住垃圾/超长/注入式
// 输入，又不会因为事件类型扩充而失效。
func validWhitelistType(t string) bool {
	if len(t) < 2 || len(t) > 32 {
		return false
	}
	for i := 0; i < len(t); i++ {
		c := t[i]
		switch {
		case c >= 'a' && c <= 'z':
		case i > 0 && (c == '_' || c >= '0' && c <= '9'):
		default:
			return false
		}
	}
	return true
}

// handleWhitelist 告警白名单（用户把"判断不是威胁"的事件加白，以后不再告警）。
//
//	GET    /api/security/whitelist
//	POST   /api/security/whitelist            body {type,target,note}
//	DELETE /api/security/whitelist/{id}
func (a *App) handleWhitelist(w http.ResponseWriter, r *http.Request, parts []string) {
	if len(parts) == 0 {
		switch r.Method {
		case http.MethodGet:
			items := a.store.Whitelist()
			if items == nil {
				items = []WhitelistEntry{}
			}
			writeJSON(w, http.StatusOK, whitelistResp{Items: items})
		case http.MethodPost:
			var req struct {
				Type   string `json:"type"`
				Target string `json:"target"`
				Note   string `json:"note"`
			}
			if !decodeJSON(w, r, &req) {
				return
			}
			// type 统一小写（事件 type 全小写；大小写混写会造出永远匹配不上的白名单项）
			req.Type = strings.ToLower(strings.TrimSpace(req.Type))
			req.Target = strings.TrimSpace(req.Target)
			if req.Type == "" || req.Target == "" {
				writeErr(w, http.StatusBadRequest, "type 与 target 不能为空", "bad_whitelist")
				return
			}
			if !validWhitelistType(req.Type) {
				writeErr(w, http.StatusBadRequest, "type 需为事件类型标识符（小写字母/数字/下划线，2~32 位）", "bad_whitelist")
				return
			}
			if len([]rune(req.Target)) > 128 || len([]rune(req.Note)) > 128 {
				writeErr(w, http.StatusBadRequest, "target/note 过长", "bad_whitelist")
				return
			}
			item := a.store.PutWhitelist(req.Type, req.Target, req.Note, nowUnix())
			a.sec.RestoreWhitelist()
			a.saveWhitelistNow()
			writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true, "item": item})
		default:
			writeErr(w, http.StatusMethodNotAllowed, "不支持的请求方法", "method_not_allowed")
		}
		return
	}
	// DELETE /api/security/whitelist/{id}
	if len(parts) == 1 && r.Method == http.MethodDelete {
		if !a.store.DeleteWhitelist(parts[0]) {
			writeErr(w, http.StatusNotFound, "白名单项不存在", "not_found")
			return
		}
		a.sec.RestoreWhitelist()
		a.saveWhitelistNow()
		writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true})
		return
	}
	writeErr(w, http.StatusNotFound, "接口不存在", "not_found")
}

// saveWhitelistNow 白名单变更后立即落盘（小文件低频率，保证重启/断电不丢）。
func (a *App) saveWhitelistNow() {
	if a.store == nil {
		return
	}
	if err := a.store.Save(); err != nil {
		logf("保存告警白名单失败: %v", err)
	}
}

// ---------------- 设置与系统 ----------------

func (a *App) handleSettings(w http.ResponseWriter, r *http.Request, parts []string) {
	// POST /api/settings/toggle
	if len(parts) == 1 && parts[0] == "toggle" {
		if !requireMethod(w, r, http.MethodPost) {
			return
		}
		var req struct {
			Key   string `json:"key"`
			Value bool   `json:"value"`
		}
		if !decodeJSON(w, r, &req) {
			return
		}
		patch, err := togglePatch(req.Key, req.Value)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error(), "bad_switch")
			return
		}
		a.applySettingsAndRespond(w, patch)
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, a.store.Settings())
	case http.MethodPut:
		var patch settingsPatch
		if !decodeJSON(w, r, &patch) {
			return
		}
		a.applySettingsAndRespond(w, patch)
	default:
		writeErr(w, http.StatusMethodNotAllowed, "不支持的请求方法", "method_not_allowed")
	}
}

// applySettingsAndRespond 应用设置补丁并按 §7.2 返回 {ok,settings,applied,revoked}。
// 额外附带 pending（仍关闭的子开关）与 hint（中文提示），用于前端表达"总开关已开但功能未开"。
func (a *App) applySettingsAndRespond(w http.ResponseWriter, patch settingsPatch) {
	// 变更前的设置快照：用于区分「完全回滚」（设置未落库，仍是旧值）与
	// 「部分成功」（已按路由器实际状态落库，需要前端刷新确认）。
	before := a.store.Settings()
	out, applied, revoked, err := a.ApplySwitchPatch(patch)
	if err != nil {
		status := http.StatusBadRequest
		var se *switchError
		if errors.As(err, &se) {
			status = se.status
		}
		// 错误码细分：
		//   settings_partial —— 部分动作未能回滚，设置已按路由器实际状态落库（前端应刷新确认）；
		//   settings_failed  —— 全部回滚/未做任何变更，设置仍是旧值（前端可提示重试）。
		if cur := a.store.Settings(); cur != before {
			writeJSON(w, status, map[string]interface{}{
				"error": err.Error(), "code": "settings_partial", "settings": cur,
			})
			return
		}
		writeErr(w, status, err.Error(), "settings_failed")
		return
	}
	if applied == nil {
		applied = []string{}
	}
	if revoked == nil {
		revoked = []string{}
	}
	pending := pendingSwitches(out)
	hint := ""
	switch {
	case !out.Enabled:
		hint = "系统未启用：不采集、不管控、不影响路由器现有功能"
	case len(pending) == 7:
		hint = "系统已启用，但功能开关均未开启，数据仍为空；请按需开启流量采集等开关"
	case len(pending) > 0:
		hint = "系统已启用；以下功能开关仍为关闭状态：" + strings.Join(pending, ", ")
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok": true, "settings": out, "applied": applied, "revoked": revoked,
		"pending": pending, "hint": hint,
	})
}

// pendingSwitches 返回仍处于关闭状态的功能开关 key（固定顺序）。
func pendingSwitches(s Settings) []string {
	type item struct {
		key string
		on  bool
	}
	list := []item{
		{"collect", s.Collect},
		{"dnsTap", s.DNSTap},
		{"deviceControl", s.DeviceControl},
		{"domainBlock", s.DomainBlock},
		{"schedule", s.Schedule},
		{"alerts", s.Alerts},
		{"history", s.History},
	}
	out := make([]string, 0, len(list))
	for _, it := range list {
		if !it.on {
			out = append(out, it.key)
		}
	}
	return out
}

// togglePatch 把便捷开关请求转成设置补丁。
func togglePatch(key string, value bool) (settingsPatch, error) {
	p := settingsPatch{}
	switch key {
	case "enabled":
		p.Enabled = &value
	case "collect":
		p.Collect = &value
	case "dnsTap":
		p.DNSTap = &value
	case "deviceControl":
		p.DeviceControl = &value
	case "domainBlock":
		p.DomainBlock = &value
	case "schedule":
		p.Schedule = &value
	case "alerts":
		p.Alerts = &value
	case "history":
		p.History = &value
	case "httpTap":
		p.HTTPTap = &value
	default:
		return p, fmt.Errorf("未知开关 key: %s", key)
	}
	return p, nil
}

// settingsPatch 设置补丁（开关 + 阈值，全部可选）。
type settingsPatch struct {
	Enabled            *bool `json:"enabled"`
	Collect            *bool `json:"collect"`
	DNSTap             *bool `json:"dnsTap"`
	DeviceControl      *bool `json:"deviceControl"`
	DomainBlock        *bool `json:"domainBlock"`
	Schedule           *bool `json:"schedule"`
	Alerts             *bool `json:"alerts"`
	HTTPTap            *bool `json:"httpTap"`
	History            *bool `json:"history"`
	CollectIntervalSec *int  `json:"collectIntervalSec"`
	RetentionDays      *int  `json:"retentionDays"`
	// Timezone 定时策略使用的 IANA 时区（如 Asia/Shanghai）
	Timezone *string     `json:"timezone"`
	Alert    *alertPatch `json:"alert"`
}

type alertPatch struct {
	Enable            *bool `json:"enable"`
	ScanPorts         *int  `json:"scanPorts"`
	TrafficMbPerHour  *int  `json:"trafficMbPerHour"`
	ThreatUpdateHours *int  `json:"threatUpdateHours"`
}

type systemResp struct {
	Model      string  `json:"model"`
	Arch       string  `json:"arch"`
	Kernel     string  `json:"kernel"`
	OpenWrt    string  `json:"openwrt"`
	UptimeSec  int64   `json:"uptimeSec"`
	MemTotalMb int64   `json:"memTotalMb"`
	MemFreeMb  int64   `json:"memFreeMb"`
	DiskFreeMb int64   `json:"diskFreeMb"`
	Hostname   string  `json:"hostname"`
	RSSMb      int64   `json:"rssMb"`
	CPUPct     float64 `json:"cpuPct"`
}

func (a *App) handleSystem(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet) {
		return
	}
	s := a.sys.Snapshot()
	writeJSON(w, http.StatusOK, systemResp{
		Model: s.Model, Arch: s.Arch, Kernel: s.Kernel, OpenWrt: s.OpenWrt,
		UptimeSec: s.UptimeSec, MemTotalMb: s.MemTotalMb, MemFreeMb: s.MemFreeMb,
		DiskFreeMb: s.DiskFreeMb, Hostname: s.Hostname, RSSMb: s.RSSMb, CPUPct: s.CPUPct,
	})
}

// handleTopology GET /api/topology：网络节点与链路（LAN/ZeroTier/VPN/Docker/互联网/代理）。
func (a *App) handleTopology(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet) {
		return
	}
	writeJSON(w, http.StatusOK, a.buildTopology())
}

// ---------------- 威胁情报更新（单飞 + 异步） ----------------

// threatUpdateGate 手动更新的单飞闸门：同一时刻只允许一个更新任务在跑。
// 一次全量拉取要跑数分钟，原实现同步执行且可并发重入 —— 多个请求会排队各跑一遍，
// 把 N1 的 CPU/内存与出网带宽反复压满。现在：已在更新则立即返回 409 + 状态。
type threatUpdateGate struct {
	mu      sync.Mutex
	running bool
	started int64 // 本轮开始的 Unix 秒（0 = 未在跑）
}

var threatUpdateFlight = &threatUpdateGate{}

// tryStart 尝试抢占更新权；已在更新时返回 false 与本轮开始时间。
func (g *threatUpdateGate) tryStart(now int64) (bool, int64) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.running {
		return false, g.started
	}
	g.running = true
	g.started = now
	return true, now
}

// finish 释放更新权。
func (g *threatUpdateGate) finish() {
	g.mu.Lock()
	g.running = false
	g.started = 0
	g.mu.Unlock()
}

// status 当前是否有手动更新在跑，以及开始时间。
func (g *threatUpdateGate) status() (bool, int64) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.running, g.started
}

// threatsUpdating 是否有更新在进行（手动任务或定时任务）。
// 定时任务走 threats_update.go 的同一个更新互斥锁，这里用 TryLock 探测（探测后立即释放，
// 不会影响真正持锁的更新），因此 /api/threats 的 updating 对两条路径都如实。
func threatsUpdating() (bool, int64) {
	if running, started := threatUpdateFlight.status(); running {
		return true, started
	}
	if threatUpdateMu.TryLock() {
		threatUpdateMu.Unlock()
		return false, 0
	}
	return true, 0
}

// runThreatUpdateAsync 后台执行一次威胁情报库更新（单飞；panic 只丢这一轮）。
func (a *App) runThreatUpdateAsync() {
	defer threatUpdateFlight.finish()
	defer func() {
		if rec := recover(); rec != nil {
			logf("威胁情报更新 panic: %v", rec)
		}
	}()
	res := a.updateThreatsNow()
	if !res.Ok {
		logf("威胁情报库手动更新失败（保留旧库）: %v", res.Errors)
		return
	}
	logf("威胁情报库手动更新完成：域名 %d、IP %d（错误源 %d 个）", res.Domains, res.IPs, len(res.Errors))
}

// handleThreats 开源威胁情报库。
//
//	GET  /api/threats           列表 + counts + updatedAt + errors + updating
//	POST /api/threats/update    触发一次手动更新（异步：立即返回 202，已在更新返回 409 + 状态）
func (a *App) handleThreats(w http.ResponseWriter, r *http.Request, parts []string) {
	if len(parts) > 0 {
		if parts[0] != "update" || len(parts) > 1 {
			writeErr(w, http.StatusNotFound, "接口不存在", "not_found")
			return
		}
		if !requireMethod(w, r, http.MethodPost) {
			return
		}
		now := nowUnix()
		at, errs := ThreatStatus()
		if errs == nil {
			errs = []string{}
		}
		curD, curI := ThreatCounts()
		if ok, startedAt := threatUpdateFlight.tryStart(now); !ok {
			// 单飞：正在跑就不排队重入，直接把当前进度告诉调用方
			// （前端据此显示"更新中"，并用 GET /api/threats 的 updating/updatedAt 跟踪）。
			writeJSON(w, http.StatusConflict, map[string]interface{}{
				"ok": false, "code": "threats_updating",
				"updating": true, "startedAt": startedAt,
				"updatedAt": at, "domains": curD, "ips": curI,
				"errors": []string{"威胁情报库正在更新中，请稍候（完成后刷新即可看到最新条目）"},
			})
			return
		}
		go a.runThreatUpdateAsync()
		// 异步执行：一次全量拉取要数分钟，同步接口会一直占着连接并让前端请求超时。
		// 响应保留 UpdateResult 的字段形状（ok/updatedAt/domains/ips/errors 为「当前库」快照），
		// 另加 accepted/updating 让调用方知道这是"已受理"，进度用 GET /api/threats 查询。
		writeJSON(w, http.StatusAccepted, map[string]interface{}{
			"ok": true, "accepted": true, "updating": true, "startedAt": now,
			"updatedAt": at, "domains": curD, "ips": curI, "errors": errs,
		})
		return
	}
	if !requireMethod(w, r, http.MethodGet) {
		return
	}
	updating, updateStartedAt := threatsUpdating()
	// 查询窗口：q 非空 → 只返回匹配项（不返回分页列表）
	if q := strings.TrimSpace(r.URL.Query().Get("search")); q != "" {
		doms, ips, matchedD, matchedI, totalD, totalI := ThreatSearch(q, 500)
		if doms == nil {
			doms = []ThreatRule{}
		}
		if ips == nil {
			ips = []ThreatRule{}
		}
		updatedAt, errs := ThreatStatus()
		if errs == nil {
			errs = []string{}
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"query":           q,
			"domains":         doms,
			"ips":             ips,
			"counts":          map[string]int{"domains": totalD, "ips": totalI},
			"matched":         map[string]int{"domains": matchedD, "ips": matchedI},
			"updatedAt":       updatedAt,
			"errors":          errs,
			"updating":        updating,
			"updateStartedAt": updateStartedAt,
		})
		return
	}
	// 完整库可达 5 万/3 万条，默认只返回前 N 条供展示（counts 始终为真实总数）
	limit := queryInt(r, "limit", 1000, 1, 5000)
	domains, ips, dCount, iCount := ThreatSample(limit)
	truncated := dCount > len(domains) || iCount > len(ips)
	updatedAt, errs := ThreatStatus()
	if errs == nil {
		errs = []string{}
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"domains":         domains,
		"ips":             ips,
		"counts":          map[string]int{"domains": dCount, "ips": iCount},
		"returned":        map[string]int{"domains": len(domains), "ips": len(ips)},
		"limit":           limit,
		"truncated":       truncated,
		"updatedAt":       updatedAt,
		"errors":          errs,
		"updating":        updating,
		"updateStartedAt": updateStartedAt,
	})
}

// ---------------- SSE 帧构造 ----------------

type tickDevice struct {
	IP      string  `json:"ip"`
	Name    string  `json:"name"`
	Alias   string  `json:"alias"`
	Network string  `json:"network"`
	Online  bool    `json:"online"`
	UpBps   int64   `json:"upBps"`
	DownBps int64   `json:"downBps"`
	Conns   int     `json:"conns"`
	Risk    float64 `json:"risk"`
	Blocked bool    `json:"blocked"`
	TopCat  string  `json:"topCat"`
}

type tickCat struct {
	Key     string  `json:"key"`
	UpBps   int64   `json:"upBps"`
	DownBps int64   `json:"downBps"`
	Share   float64 `json:"share"`
}

type tickWan struct {
	RxBps int64 `json:"rxBps"`
	TxBps int64 `json:"txBps"`
}

type tickFrame struct {
	Ts          int64        `json:"ts"`
	KPI         kpiJSON      `json:"kpi"`
	Sys         sysJSON      `json:"sys"`
	Devices     []tickDevice `json:"devices"`
	Removed     []string     `json:"removed,omitempty"` // 增量帧中已消失（遗忘/隐藏）的设备 IP
	Full        bool         `json:"full"`
	DeviceCount int          `json:"deviceCount"`
	Categories  []tickCat    `json:"categories"`
	TrendPoint  TrendPoint   `json:"trendPoint"`
	Wan         tickWan      `json:"wan"`
	// NetUp/NetDown：用户视角上下行速率（bit/s），来自 LAN 接口计数（物理真实值）。
	// 前端用它绘制 2 秒实时曲线与实时速率显示，避免 conntrack 归因误差影响实时数字。
	NetUp   int64 `json:"netUp"`
	NetDown int64 `json:"netDown"`
}

// buildTick 构造 tick 帧。
// last 非 nil 时按增量输出（只含本帧变化的设备），并更新 last；full=true 输出全量。
func (a *App) buildTick(now int64, full bool, last map[string]tickDevice) tickFrame {
	if !a.dataActive() {
		return a.emptyTick(now)
	}
	states := a.devs.States()
	metas := a.store.AllDeviceMeta()
	connCounts := a.agg.DeviceConnCount()
	rates := a.agg.LastRates()
	sys := a.sys.Snapshot()

	devices := make([]tickDevice, 0, len(states))
	seen := make(map[string]bool, len(states))
	visible := 0 // KPI 口径：只算 lan（本地 DHCP 网段）
	ztDevices, ztOnline := 0, 0
	for _, st := range states {
		meta := metas[st.IP]
		if meta.Hidden || !isInternalNetwork(st.Network) {
			continue
		}
		if st.Network == "zerotier" {
			// ZeroTier 另算：不进 KPI 设备数，但设备行仍下发（设备页需要实时更新）
			ztDevices++
			if st.Online {
				ztOnline++
			}
		} else {
			visible++
		}
		topCat := st.TopCat
		if topCat == "" {
			topCat = "other"
		}
		td := tickDevice{
			IP: st.IP, Name: displayName(st.Hostname, st.IP), Alias: meta.Alias,
			Network: st.Network,
			Online:  st.Online, UpBps: st.UpBps, DownBps: st.DownBps,
			Conns: connCounts[st.IP], Risk: st.Risk, Blocked: meta.Blocked, TopCat: topCat,
		}
		if last != nil {
			seen[td.IP] = true
			prev, ok := last[td.IP]
			last[td.IP] = td
			if !full && ok && tickDeviceEqual(prev, td) {
				continue
			}
		}
		devices = append(devices, td)
	}
	// 增量帧告知客户端哪些设备已消失（被遗忘/隐藏），避免等下一次全量才移除
	var removed []string
	if last != nil {
		for ip := range last {
			if seen[ip] {
				continue
			}
			delete(last, ip)
			if !full {
				removed = append(removed, ip)
			}
		}
		sort.Strings(removed)
	}

	cats := make([]tickCat, 0, len(Categories))
	var totalCat int64
	pairs := make(map[string][2]int64, len(Categories))
	for _, c := range Categories {
		p := rates.CatBps[c.Key]
		pairs[c.Key] = p
		totalCat += p[0] + p[1]
	}
	for _, c := range Categories {
		p := pairs[c.Key]
		share := 0.0
		if totalCat > 0 {
			share = float64(p[0]+p[1]) / float64(totalCat)
		}
		cats = append(cats, tickCat{Key: c.Key, UpBps: p[0], DownBps: p[1], Share: roundShare(share)})
	}

	trend := a.agg.RecentTrend(1)
	tp := TrendPoint{T: now}
	if len(trend) > 0 {
		tp = trend[0]
	}
	if tp.T == 0 {
		tp.T = now
	}

	return tickFrame{
		Ts: now,
		KPI: kpiJSON{
			Online: countOnline(states, metas), Devices: visible,
			ZtDevices: ztDevices, ZtOnline: ztOnline,
			Conns: sys.ConnCount, NewConns: rates.NewConnsLastMin,
			DNSQps: round1f(a.dns.QPS(now)), Alerts: a.store.UnackedCount(),
			// 有真 WAN 取 WAN 计数；旁路由取 conntrack 外发链路速率（详见 buildOverview 注释）
			UpBps: sys.NetUpBps, DownBps: sys.NetDownBps, RiskLevel: a.sec.Level(),
		},
		Sys:         sysToJSON(sys),
		Devices:     devices,
		Removed:     removed,
		Full:        full,
		DeviceCount: visible,
		Categories:  cats,
		TrendPoint:  tp,
		Wan:         tickWan{RxBps: sys.WanRxBps, TxBps: sys.WanTxBps},
		NetUp:       sys.NetUpBps,
		NetDown:     sys.NetDownBps,
	}
}

// emptyTick 未启用/未采集时的空 tick 帧。
func (a *App) emptyTick(now int64) tickFrame {
	cats := make([]tickCat, 0, len(Categories))
	for _, c := range Categories {
		cats = append(cats, tickCat{Key: c.Key})
	}
	return tickFrame{
		Ts:          now,
		KPI:         kpiJSON{RiskLevel: "low"},
		Sys:         sysToJSON(a.sys.Snapshot()),
		Devices:     []tickDevice{},
		Full:        true,
		DeviceCount: 0,
		Categories:  cats,
		TrendPoint:  TrendPoint{T: now},
	}
}

func tickDeviceEqual(a, b tickDevice) bool {
	return a.IP == b.IP && a.Name == b.Name && a.Alias == b.Alias && a.Network == b.Network &&
		a.Online == b.Online &&
		a.UpBps == b.UpBps && a.DownBps == b.DownBps && a.Conns == b.Conns &&
		a.Risk == b.Risk && a.Blocked == b.Blocked && a.TopCat == b.TopCat
}

// countOnline 统计在线设备数。
// 口径与 buildOverview 的「在线设备」保持一致：只统计未隐藏的 LAN 设备
// （本地 DHCP 网段）；ZeroTier 由 KPI 的 ztOnline 单独计数。
func countOnline(states []DeviceState, metas map[string]DeviceMeta) int {
	n := 0
	for _, st := range states {
		if metas[st.IP].Hidden {
			continue
		}
		if st.Network != "lan" {
			continue
		}
		if st.Online {
			n++
		}
	}
	return n
}

// ---------------- 静态资源 ----------------

var mimeTypes = map[string]string{
	".html":  "text/html; charset=utf-8",
	".css":   "text/css; charset=utf-8",
	".js":    "text/javascript; charset=utf-8",
	".mjs":   "text/javascript; charset=utf-8",
	".json":  "application/json; charset=utf-8",
	".svg":   "image/svg+xml",
	".png":   "image/png",
	".jpg":   "image/jpeg",
	".jpeg":  "image/jpeg",
	".gif":   "image/gif",
	".webp":  "image/webp",
	".ico":   "image/x-icon",
	".woff":  "font/woff",
	".woff2": "font/woff2",
	".ttf":   "font/ttf",
	".map":   "application/json",
	".txt":   "text/plain; charset=utf-8",
	".wasm":  "application/wasm",
}

// serveStatic 静态资源与 SPA hash 路由回退。
func (a *App) serveStatic(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeErr(w, http.StatusMethodNotAllowed, "不支持的请求方法", "method_not_allowed")
		return
	}
	p := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
	if p == "" || p == "." {
		p = "index.html"
	}
	if data, ok := a.readWebFile(p); ok {
		a.writeWebFile(w, r, p, data)
		return
	}
	// SPA 回退：未知路径返回 index.html（前端用 hash 路由）
	if data, ok := a.readWebFile("index.html"); ok {
		a.writeWebFile(w, r, "index.html", data)
		return
	}
	// 前端尚未构建时的占位页
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = w.Write([]byte(`<!doctype html><html><head><meta charset="utf-8"><title>观澜 NetScope</title></head>
<body style="background:#05070d;color:#e8eefc;font-family:system-ui;padding:40px">
<h1>观澜 NetScope</h1><p>前端资源尚未就绪（app/web/ 为空）。</p>
<p>请将 index.html / css / js 放入 app/web/ 后重新编译，或使用 <code>-web &lt;dir&gt;</code> 指向开发目录。</p>
</body></html>`))
}

func (a *App) readWebFile(name string) ([]byte, bool) {
	if a.cfg.WebDir != "" {
		f, err := a.webFS.Open(name)
		if err != nil {
			return nil, false
		}
		defer f.Close()
		st, err := f.Stat()
		if err != nil || st.IsDir() {
			return nil, false
		}
		data, err := readAll(f)
		if err != nil {
			return nil, false
		}
		return data, true
	}
	data, err := fs.ReadFile(a.webFS, name)
	if err != nil {
		return nil, false
	}
	return data, true
}

// staticETagCache 内嵌静态资源的强 ETag 缓存（name -> ETag）。
// 内嵌资源随二进制固定，按 name 缓存内容哈希，避免每次请求重算 1.3MB 的 three.module.js；
// -web 开发模式（磁盘目录）下同名文件内容会变，故意不缓存，逐次按内容计算。
var staticETagCache sync.Map

// etagFor 计算内容强 ETag（内容 sha256 前 8 字节）。
func (a *App) etagFor(name string, data []byte) string {
	if a.cfg.WebDir == "" {
		if v, ok := staticETagCache.Load(name); ok {
			return v.(string)
		}
	}
	sum := sha256.Sum256(data)
	tag := `"` + hex.EncodeToString(sum[:8]) + `"`
	if a.cfg.WebDir == "" {
		staticETagCache.Store(name, tag)
	}
	return tag
}

// etagMatch 判断 If-None-Match 是否命中（支持逗号列表、W/ 弱前缀与 *）。
func etagMatch(r *http.Request, tag string) bool {
	inm := strings.TrimSpace(r.Header.Get("If-None-Match"))
	if inm == "" {
		return false
	}
	if inm == "*" {
		return true
	}
	for _, part := range strings.Split(inm, ",") {
		part = strings.TrimPrefix(strings.TrimSpace(part), "W/")
		if part == tag {
			return true
		}
	}
	return false
}

// hasContentHash 文件名里是否含内容哈希段（如 app.3f2a91cd.js、theme-9b1c7d2e.css）。
// 哈希段长度 ≥8 且全为小写十六进制，视为内容指纹：内容与 URL 绑定，可长期缓存。
func hasContentHash(base string) bool {
	for _, seg := range strings.Split(base, ".") {
		if len(seg) < 8 {
			continue
		}
		hexOnly := true
		for i := 0; i < len(seg); i++ {
			c := seg[i]
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
				hexOnly = false
				break
			}
		}
		if hexOnly {
			return true
		}
	}
	return false
}

// writeWebFile 输出静态资源。
//
// 缓存策略（首屏最大文件是 js/vendor/three.module.js，约 1.3MB）：
//   - /js/vendor/ 下的第三方库、以及文件名带内容哈希的构建产物：public,max-age=1y,immutable
//     —— 内容随二进制发布且与 URL 绑定，刷新/二次打开直接用本地缓存，不再重下；
//   - 其它 JS/CSS（业务代码，内容随版本变但 URL 不变）：no-cache + ETag
//     —— 每次协商，未变更返回 304（省掉重复传输，又不会拿到旧代码）；
//   - 其它类型：沿用 no-cache + ETag。
//
// 开发模式（-web 磁盘目录）一律不设长缓存：文件随时被改写，长缓存会让浏览器看不到新内容。
func (a *App) writeWebFile(w http.ResponseWriter, r *http.Request, name string, data []byte) {
	ext := strings.ToLower(path.Ext(name))
	ct := mimeTypes[ext]
	if ct == "" {
		ct = mime.TypeByExtension(ext)
	}
	if ct == "" {
		ct = "application/octet-stream"
	}
	w.Header().Set("Content-Type", ct)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	tag := a.etagFor(name, data)
	w.Header().Set("ETag", tag)
	immutable := a.cfg.WebDir == "" &&
		(strings.HasPrefix(name, "js/vendor/") || hasContentHash(path.Base(name)))
	if immutable {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	} else {
		w.Header().Set("Cache-Control", "no-cache")
	}
	if etagMatch(r, tag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write(data)
	}
}

// ---------------- 查询参数工具 ----------------

func queryInt(r *http.Request, name string, def, min, max int) int {
	raw := r.URL.Query().Get(name)
	if raw == "" {
		return def
	}
	v, err := strconv.Atoi(raw)
	if err != nil {
		return def
	}
	if v < min {
		return min
	}
	if v > max {
		return max
	}
	return v
}

func roundShare(v float64) float64 {
	return float64(int(v*1000+0.5)) / 1000
}

func round1f(v float64) float64 { return float64(int(v*10+0.5)) / 10 }

func sortDeviceBySpeed(list []DeviceJSON) {
	sort.Slice(list, func(i, j int) bool {
		return list[i].UpBps+list[i].DownBps > list[j].UpBps+list[j].DownBps
	})
}

func sortTrafficDev(list []trafficDev) {
	sort.Slice(list, func(i, j int) bool {
		return list[i].Up+list[i].Down > list[j].Up+list[j].Down
	})
}

func sortDstBytes(list []deviceDst) {
	sort.Slice(list, func(i, j int) bool { return list[i].Bytes > list[j].Bytes })
}

func sortInt64s(list []int64) {
	sort.Slice(list, func(i, j int) bool { return list[i] < list[j] })
}
