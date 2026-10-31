package main

// SSE 实时推送。
//
// 帧类型（api.md §8）：
//   hello —— 连接后立即发送，携带版本与采样间隔；
//   tick  —— 每 2s 一帧；为控制序列化与网络开销，默认只推「本帧有变化」的设备，
//           每 10 帧推一次全量，客户端首次连接立即补一帧全量（full=true）；
//   alert —— 安全事件产生时即时推送。
// 25s 无数据时发送注释心跳（tick 本身 2s 一次，正常不会触发）。
// JSON 使用紧凑编码（json.Marshal 不缩进）。

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

type sseMessage struct {
	event string
	data  []byte
}

type sseClient struct {
	ch chan sseMessage
}

// Hub SSE 客户端管理。
type Hub struct {
	mu         sync.Mutex
	clients    map[*sseClient]bool
	initial    func() interface{} // 首次连接补全量 tick
	closed     bool
	intervalMS int
}

// NewHub 创建 Hub。
func NewHub(intervalMS int) *Hub {
	return &Hub{clients: map[*sseClient]bool{}, intervalMS: intervalMS}
}

// SetInitial 注册首帧全量构造函数。
func (h *Hub) SetInitial(fn func() interface{}) {
	h.mu.Lock()
	h.initial = fn
	h.mu.Unlock()
}

// Broadcast 广播事件（一次序列化，分发给所有客户端；慢客户端丢帧）。
func (h *Hub) Broadcast(event string, data interface{}) {
	payload, err := json.Marshal(data)
	if err != nil {
		logf("SSE 序列化失败: %v", err)
		return
	}
	msg := sseMessage{event: event, data: payload}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return
	}
	for c := range h.clients {
		select {
		case c.ch <- msg:
		default: // 客户端过慢，丢弃当前帧，等下一次
		}
	}
}

// Serve 处理 GET /api/stream。
func (h *Hub) Serve(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeErr(w, http.StatusInternalServerError, "当前连接不支持流式推送", "no_flusher")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	writeSSE := func(event string, data []byte) bool {
		if _, err := fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, data); err != nil {
			return false
		}
		flusher.Flush()
		return true
	}
	writeRaw := func(s string) bool {
		if _, err := fmt.Fprint(w, s); err != nil {
			return false
		}
		flusher.Flush()
		return true
	}

	hello, _ := json.Marshal(map[string]interface{}{
		"version":    Version,
		"intervalMs": h.intervalMS,
	})
	if !writeSSE("hello", hello) {
		return
	}

	h.mu.Lock()
	initial := h.initial
	h.mu.Unlock()
	if initial != nil {
		if payload, err := json.Marshal(initial()); err == nil {
			if !writeSSE("tick", payload) {
				return
			}
		}
	}

	c := &sseClient{ch: make(chan sseMessage, 16)}
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return
	}
	h.clients[c] = true
	h.mu.Unlock()
	defer func() {
		h.mu.Lock()
		delete(h.clients, c)
		h.mu.Unlock()
	}()

	heartbeat := time.NewTicker(25 * time.Second)
	defer heartbeat.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-heartbeat.C:
			if !writeRaw(": heartbeat\n\n") {
				return
			}
		case msg := <-c.ch:
			if !writeSSE(msg.event, msg.data) {
				return
			}
		}
	}
}

// ClientCount 当前 SSE 客户端数（/api/system 可选展示）。
func (h *Hub) ClientCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.clients)
}

// Close 标记关闭（HTTP server 关闭时各请求的 Context 会结束，Serve 随之退出）。
// 注意：不关闭客户端 channel，避免与 Broadcast 并发发送产生 panic。
func (h *Hub) Close() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.closed = true
	h.clients = map[*sseClient]bool{}
}
