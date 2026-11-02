//go:build linux

package main

// HTTP 明文 URL 抓取（可选功能，默认关闭）。
//
// 为什么需要它：HTTPS 的路径在 TLS 内加密，DNS 与 conntrack 都看不到；
// 只有明文 HTTP（TCP 80）的请求行与 Host 头是可读的。本模块用 AF_PACKET
// 原始套接字 + 内核 BPF 过滤器（只放行 IPv4/TCP/目的端口 80/非分片）抓取
// HTTP 请求，解析出「http://host/path」形式的完整 URL 供「最近访问 URL」展示。
//
// 开销与边界：
//   - 过滤在内核完成，用户态只收到 80 端口的 HTTP 包；
//   - 只解析请求行与 Host 头，不落盘原文，只记录 URL 与次数；
//   - 不触碰 443/其它端口，不做任何解密。
import (
	"encoding/binary"
	"net"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

// httpTap 全局单例状态（由 App 生命周期控制）。
type httpTapState struct {
	mu      sync.Mutex
	fd      int
	running bool
	stopCh  chan struct{}
}

var httpTap = &httpTapState{fd: -1}

// 抓包诊断计数（仅日志用）
var (
	tapPkts      int
	tapURLs      int
	tapErrLogs   int
	tapAll       int    // 收到的原始包总数（诊断）
	tapParseDbg  int    // 解析调试计数
	tapDebug     bool   // GUANLAN_TAP_DEBUG=1 时输出诊断日志
	tapBound     string // 绑定的接口名（日志用）
	tapKernelBPF bool   // 是否启用内核 BPF
)

// httpMethods 只识别这些方法的请求行，避免误把响应体当请求。
var httpMethods = []string{"GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS ", "PATCH "}

// StartHTTPTap 启动抓取。失败返回错误（调用方记日志并继续运行）。
func (a *App) StartHTTPTap() error {
	httpTap.mu.Lock()
	if httpTap.running {
		httpTap.mu.Unlock()
		return nil
	}
	httpTap.mu.Unlock()

	// AF_PACKET/SOCK_RAW/ETH_P_ALL：与 tcpdump 一致。
	// 只用 ETH_P_IP 会收不全（lo 与部分出站路径的协议匹配不同），
	// 真正的端口过滤交给下面的内核 cBPF。
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(0x0003)))
	if err != nil {
		return err
	}
	// 优先绑定到 LAN 接口（只看局域网侧流量，减少无关包）
	// 诊断：GUANLAN_TAP_NOBIND=1 时不绑定（可看到 lo，便于自测）
	if name := a.LanIfaceName(); name != "" && os.Getenv("GUANLAN_TAP_NOBIND") != "1" {
		if ifi, ierr := net.InterfaceByName(name); ierr == nil {
			sa := &syscall.SockaddrLinklayer{Protocol: htons(0x0003), Ifindex: ifi.Index}
			if berr := syscall.Bind(fd, sa); berr != nil {
				logf("HTTP 抓包绑定 %s 失败（继续未绑定模式）: %v", name, berr)
			} else {
				tapBound = name
			}
		}
	}
	// 内核 BPF（固定偏移版，避开 ldxb 的编码陷阱）：
	// IPv4 && TCP && 目的端口 80。IP 头假定无选项（IHL=20），
	// 因此目的端口固定在以太头 14 + IP 20 + TCP 2 = 36。
	filters := []syscall.SockFilter{
		{Code: 0x28, Jt: 0, Jf: 0, K: 12},     // 0 ldh [12]   ethertype
		{Code: 0x15, Jt: 0, Jf: 5, K: 0x0800}, // 1 jeq 0x800  -> 2 else 7
		{Code: 0x30, Jt: 0, Jf: 0, K: 23},     // 2 ldb [23]   protocol
		{Code: 0x15, Jt: 0, Jf: 3, K: 6},      // 3 jeq 6 tcp  -> 4 else 7
		{Code: 0x28, Jt: 0, Jf: 0, K: 36},     // 4 ldh [36]   目的端口（IHL=20 时固定偏移）
		{Code: 0x15, Jt: 0, Jf: 1, K: 80},     // 5 jeq 80     -> 6 else 7
		{Code: 0x06, Jt: 0, Jf: 0, K: 262144}, // 6 ret 262144 accept
		{Code: 0x06, Jt: 0, Jf: 0, K: 0},      // 7 ret 0      drop
	}
	// 过滤策略：默认挂内核 cBPF（只把 TCP:80 的包投递到用户态，开销最低）。
	// 若挂载失败（内核/架构差异），回退到用户态过滤，保证功能可用。
	// GUANLAN_TAP_BPF=0 可强制用户态过滤（排查用）；
	// GUANLAN_TAP_DEBUG=1 输出诊断日志。
	tapDebug = os.Getenv("GUANLAN_TAP_DEBUG") == "1"
	if os.Getenv("GUANLAN_TAP_BPF") != "0" {
		prog := syscall.SockFprog{Len: uint16(len(filters)), Filter: &filters[0]}
		_, _, errno := syscall.Syscall6(syscall.SYS_SETSOCKOPT, uintptr(fd),
			uintptr(syscall.SOL_SOCKET), uintptr(syscall.SO_ATTACH_FILTER),
			uintptr(unsafe.Pointer(&prog)), unsafe.Sizeof(prog), 0)
		if errno != 0 {
			logf("HTTP 抓包：内核过滤器挂载失败（%v），回退用户态过滤", errno)
		} else {
			tapKernelBPF = true
		}
	}
	// 读超时：让 Read 周期性返回，便于检查停止信号
	tv := syscall.Timeval{Sec: 1}
	_ = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)

	stopCh := make(chan struct{})
	httpTap.mu.Lock()
	httpTap.fd = fd
	httpTap.running = true
	httpTap.stopCh = stopCh
	httpTap.mu.Unlock()

	go a.httpTapLoop(fd, stopCh)
	if tapBound != "" {
		logf("HTTP 明文 URL 抓取已启动（接口 %s，仅 TCP 80，内核过滤）", tapBound)
	} else {
		logf("HTTP 明文 URL 抓取已启动（全部接口，仅 TCP 80，内核过滤）")
	}
	return nil
}

// StopHTTPTap 停止抓取并关闭套接字。
func (a *App) StopHTTPTap() {
	httpTap.mu.Lock()
	if !httpTap.running {
		httpTap.mu.Unlock()
		return
	}
	fd := httpTap.fd
	ch := httpTap.stopCh
	httpTap.running = false
	httpTap.fd = -1
	httpTap.stopCh = nil
	httpTap.mu.Unlock()
	if ch != nil {
		close(ch)
	}
	if fd >= 0 {
		syscall.Close(fd)
	}
	logf("HTTP 明文 URL 抓取已停止")
}

// HTTPTapRunning 是否在运行（供状态展示/单测）。
func HTTPTapRunning() bool {
	httpTap.mu.Lock()
	defer httpTap.mu.Unlock()
	return httpTap.running
}

func (a *App) httpTapLoop(fd int, stopCh chan struct{}) {
	buf := make([]byte, 65536)
	for {
		select {
		case <-stopCh:
			return
		default:
		}
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			if err == syscall.EAGAIN || err == syscall.EINTR || err == syscall.EWOULDBLOCK {
				continue // 读超时：正常，继续等包
			}
			if err == syscall.EBADF || err == syscall.ENOTSOCK {
				return // 套接字已被关闭
			}
			// 其它错误：记录后短暂退避继续，避免抓包线程静默退出
			if tapErrLogs < 5 {
				tapErrLogs++
				logf("HTTP 抓包读取异常（第 %d 次，继续运行）: %v", tapErrLogs, err)
			}
			time.Sleep(200 * time.Millisecond)
			continue
		}
		if n <= 0 {
			continue
		}
		if !a.dataActive() || !a.settings().HTTPTap {
			continue // 开关关闭时直接丢弃，不解析
		}
		tapAll++
		if tapDebug && (tapAll <= 3 || tapAll%5000 == 0) {
			logf("HTTP 抓包统计：累计收到 %d 包（80 端口 %d，URL %d）", tapAll, tapPkts, tapURLs)
		}
		if !tapKernelBPF && !quickTCP80(buf[:n]) {
			continue // 用户态预过滤：非 IPv4/TCP/80 直接跳过
		}
		tapPkts++
		if tapDebug && tapPkts <= 3 {
			logf("HTTP 抓包首包预览: %q", httpPayloadPreview(buf[:n]))
		}
		a.parseHTTPPacket(buf[:n])
	}
}

// httpPayloadPreview 取出 TCP 载荷前 48 字节（诊断用）。
func httpPayloadPreview(pkt []byte) string {
	if len(pkt) < 42 {
		return ""
	}
	ihl := int(pkt[14]&0x0f) * 4
	if ihl < 20 || len(pkt) < 14+ihl+20 {
		return ""
	}
	tcpOff := 14 + ihl
	dataOff := int(pkt[tcpOff+12]>>4) * 4
	if tcpOff+dataOff >= len(pkt) {
		return ""
	}
	pl := pkt[tcpOff+dataOff:]
	if len(pl) > 48 {
		pl = pl[:48]
	}
	return string(pl)
}

// quickTCP80 极便宜的预过滤：IPv4 && TCP && 目的端口 80（不做深解析）。
func quickTCP80(pkt []byte) bool {
	if len(pkt) < 14+20 {
		return false
	}
	if pkt[12] != 0x08 || pkt[13] != 0x00 { // ethertype 0x0800
		return false
	}
	ihl := int(pkt[14]&0x0f) * 4
	if ihl < 20 || len(pkt) < 14+ihl+4 {
		return false
	}
	if pkt[23] != 6 { // TCP
		return false
	}
	return binary.BigEndian.Uint16(pkt[14+ihl+2:]) == 80 // 目的端口
}

// parseHTTPPacket 从以太帧里提取 HTTP 请求的 Host 与路径，拼成完整 URL。
// 只处理「请求行 + Host 头同在一个 TCP 段」的情况（正常 GET 请求即如此）。
func (a *App) parseHTTPPacket(pkt []byte) {
	if pv := httpPayloadPreview(pkt); tapDebug && pv != "" && tapParseDbg < 8 {
		tapParseDbg++
		logf("parse 调试 #%d: len=%d preview=%q", tapParseDbg, len(pkt), pv)
	}
	if len(pkt) < 14+20+20 {
		return
	}
	if binary.BigEndian.Uint16(pkt[12:14]) != 0x0800 {
		return
	}
	ipOff := 14
	ihl := int(pkt[ipOff]&0x0f) * 4
	if ihl < 20 || len(pkt) < ipOff+ihl+20 {
		return
	}
	if pkt[ipOff+9] != 6 { // TCP
		return
	}
	srcIP := ip4String(binary.BigEndian.Uint32(pkt[ipOff+12 : ipOff+16]))
	tcpOff := ipOff + ihl
	dataOff := int(pkt[tcpOff+12]>>4) * 4
	payload := pkt[tcpOff+dataOff:]
	if len(payload) < 16 {
		return
	}
	// 请求行：GET /path HTTP/1.1
	text := string(payload)
	methodOK := false
	for _, m := range httpMethods {
		if strings.HasPrefix(text, m) {
			methodOK = true
			break
		}
	}
	if !methodOK {
		return
	}
	lineEnd := strings.Index(text, "\r\n")
	if lineEnd <= 0 {
		return
	}
	reqLine := text[:lineEnd]
	fields := strings.Fields(reqLine)
	if len(fields) < 2 {
		return
	}
	path := fields[1]
	// Host 头（HTTP/1.1 必需；HTTP/1.0 可能缺失，缺失则放弃）。
	// 注意：必须从 lineEnd+2 开始切（跳过请求行末尾的 \r\n），
	// 否则第一个元素是空串，会被误判为「头部结束」而漏掉 Host。
	host := ""
	for _, line := range strings.Split(text[lineEnd+2:], "\r\n") {
		if line == "" {
			break // 头部结束
		}
		if len(line) >= 5 && strings.EqualFold(line[:5], "host:") {
			host = strings.TrimSpace(line[5:])
			break
		}
	}
	if host == "" || strings.ContainsAny(host, " \t/") {
		return
	}
	// 去掉默认端口与非法字符
	host = strings.ToLower(host)
	if strings.HasSuffix(host, ":80") {
		host = strings.TrimSuffix(host, ":80")
	}
	if len(host) > 200 || len(path) > 400 {
		return
	}
	url := "http://" + host + path
	a.dns.NoteHTTPURL(url, host, srcIP, nowUnix())
	tapURLs++
	if tapDebug && tapURLs <= 5 {
		logf("HTTP 抓取样例: %s (来自 %s)", url, srcIP)
	}
}

func htons(v uint16) uint16 { return v<<8 | v>>8 }

// 保持 time 包被引用（抓取循环里用不到，但保留给未来的速率统计）。
var _ = time.Now
