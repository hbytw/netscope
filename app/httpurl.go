package main

// 明文 HTTP 完整 URL 统计（配合 httptap.go）。
//
// 只记录 http:// 站点（HTTPS 路径在 TLS 内加密，任何非解密方案都拿不到），
// 用途：把「最近访问 URL」从域名级细化到「域名 + 路径」级。
// 存储有上限与 TTL，避免长期运行膨胀。

import (
	"sort"
	"strings"
)

// httpURLStat 单条完整 URL 的统计。
type httpURLStat struct {
	URL      string
	Host     string
	Hits     int64
	LastSeen int64
	Devs     map[string]int64 // 设备 IP -> 次数
}

// httpURLCap 上限：超过后按最久未见淘汰 20%。
const httpURLCap = 4000

// NoteHTTPURL 记录一条明文 HTTP 完整 URL。
func (d *DNSResolver) NoteHTTPURL(url, host, devIP string, now int64) {
	if url == "" || host == "" {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.httpURLs == nil {
		d.httpURLs = map[string]*httpURLStat{}
	}
	st := d.httpURLs[url]
	if st == nil {
		if len(d.httpURLs) >= httpURLCap {
			d.evictHTTPURLsLocked(now)
		}
		st = &httpURLStat{URL: url, Host: host, Devs: map[string]int64{}}
		d.httpURLs[url] = st
	}
	// 补建域名统计：即使 DNS 旁挂关闭（或该站点没有 DNS 记录），
	// 也要让「最近访问 URL」里能看到这个域名及其路径。
	cat, label, _, _ := classifyHost(host)
	dst := d.statLocked(host, cat, label, "", now)
	if now > dst.LastSeen {
		dst.LastSeen = now
	}
	if devIP != "" {
		if dv := dst.Devices[devIP]; dv == nil {
			dst.Devices[devIP] = &DomainDev{Hits: 1, LastSeen: now}
		} else if now > dv.LastSeen {
			dv.LastSeen = now
		}
	}
	st.Hits++
	if now > st.LastSeen {
		st.LastSeen = now
	}
	if devIP != "" {
		if len(st.Devs) < 64 || st.Devs[devIP] > 0 {
			st.Devs[devIP]++
		}
	}
}

// evictHTTPURLsLocked 淘汰最久未见的一批（锁内调用）。
func (d *DNSResolver) evictHTTPURLsLocked(now int64) {
	type pair struct {
		k string
		t int64
	}
	list := make([]pair, 0, len(d.httpURLs))
	for k, v := range d.httpURLs {
		list = append(list, pair{k, v.LastSeen})
	}
	sort.Slice(list, func(i, j int) bool { return list[i].t < list[j].t })
	drop := len(list)/5 + 1
	for i := 0; i < drop && i < len(list); i++ {
		delete(d.httpURLs, list[i].k)
	}
}

// HTTPURLsFor 返回某域名下最近的明文 HTTP 完整 URL（按次数降序，最多 limit 条）。
// 返回的每一项是 {url, hits, lastSeen, devices}。
type httpURLBrief struct {
	URL      string
	Hits     int64
	LastSeen int64
	Devices  int
}

func (d *DNSResolver) HTTPURLsFor(host string, limit int) []httpURLBrief {
	h := strings.ToLower(strings.TrimSpace(host))
	if h == "" {
		return nil
	}
	if limit <= 0 {
		limit = 5
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	out := make([]httpURLBrief, 0, limit)
	for _, st := range d.httpURLs {
		if st.Host != h {
			continue
		}
		out = append(out, httpURLBrief{URL: st.URL, Hits: st.Hits, LastSeen: st.LastSeen, Devices: len(st.Devs)})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Hits != out[j].Hits {
			return out[i].Hits > out[j].Hits
		}
		return out[i].LastSeen > out[j].LastSeen
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

// TopHTTPURLLast 返回该域名下最近一次出现的完整 URL（无则空）。
func (d *DNSResolver) TopHTTPURLLast(host string) string {
	list := d.HTTPURLsFor(host, 1)
	if len(list) == 0 {
		return ""
	}
	return list[0].URL
}

// cleanupHTTPURLsLocked 清理过期明文 URL（调用方已持写锁）。
func (d *DNSResolver) cleanupHTTPURLsLocked(now int64) {
	cut := now - 2*3600
	for k, st := range d.httpURLs {
		if st.LastSeen < cut {
			delete(d.httpURLs, k)
		}
	}
}
