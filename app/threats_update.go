package main

// 威胁情报库更新：从公开 IOC 源（ThreatFox/URLhaus/Phishing.Database/Feodo/
// Spamhaus/AbuseIPDB/IPsum/C2IntelFeeds）拉取完整列表，与现有库增量合并后原子落盘。
// 纯 Go 标准库（net/http + encoding/json），CGO_ENABLED=0；更新在独立 goroutine，
// 不阻塞采集/SSE。落盘：<data>/threats.json {updatedAt, domains, ips}。
//
// 说明：
//   - ThreatFox Community API 需要 Auth-Key（401），通过环境变量 THREATFOX_AUTH_KEY
//     配置后启用；未配置时跳过并记录 warning，其余公开源照常更新。
//   - URLhaus/Feodo/Spamhaus 使用公开镜像/导出；PhishTank 需 API key（403）暂不启用。
//   - 加载上限：域名 50000、IP/CIDR 30000；超限按「源配额」截断（每个源先均分上限、
//     用不完的份额回收再分），组内才按 confidence 降序保留 —— 避免 URLhaus 等
//     conf=100 大源按纯置信度独占上限、其它源与内置快照被整体丢弃且此后进不来（库冻结）。
//     内置 curated 规则（内置黑名单）不受配额限制、始终全额保留。
//   - 内存（N1 仅 1GB）：并发拉取限 2 路、单源解析条数设上限、落盘/加载走流式读写，
//     更新峰值内存控制在 ~30MB 量级。

import (
	"bufio"
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	defaultThreatUpdateHours = 6
	threatFetchTimeout       = 30 * time.Second
	threatFetchMaxBytes      = 32 * 1024 * 1024 // 单源响应上限
	threatUpdateFile         = "threats.json"

	// 内存保护（N1 仅 1GB，更新峰值要求 <30MB）：
	//   - 单源解析条数上限：解析结果先按源截断再进合并，避免全量 IOC 同时驻留；
	//     取库总上限的一半，正常情况下各源均分（50000/6≈8300）远低于该值，
	//     只有半数以上源失败时才触顶，此时仍能保留可用规模。
	//   - 并发拉取上限：9 路并发 × 32MB 响应缓冲是原内存峰值的主要来源。
	threatPerSourceDomainCap = maxThreatDomains / 2 // 单源域名上限 25000
	threatPerSourceIPCap     = maxThreatIPs / 2     // 单源 IP/CIDR 上限 15000
	threatUpdateParallel     = 2                    // 并发拉取源数（内存/耗时折中）
)

// UpdateResult 一次情报库更新结果。
type UpdateResult struct {
	Ok        bool     `json:"ok"`
	UpdatedAt int64    `json:"updatedAt"`
	Domains   int      `json:"domains"`
	IPs       int      `json:"ips"`
	Errors    []string `json:"errors"`
}

// threatFile threats.json 结构。
type threatFile struct {
	UpdatedAt int64        `json:"updatedAt"`
	Domains   []ThreatRule `json:"domains"`
	IPs       []ThreatRule `json:"ips"`
}

// threatSource 一个开源情报源（可多个 URL 作为镜像回退）。
type threatSource struct {
	name     string
	urls     []string
	postBody string // 非空则 POST JSON（ThreatFox Community API）
	authEnv  string // 需要鉴权的环境变量名（如 THREATFOX_AUTH_KEY）
	kind     ThreatKind
	conf     int
	parse    func(src threatSource, data []byte) ([]ThreatRule, error)
}

// threatSources 更新源。
var threatSources = []threatSource{
	{
		// ThreatFox 全量 IOC（开源最大 C2/恶意域名+IP 库）；无 Auth-Key 时自动跳过
		name:     "ThreatFox",
		urls:     []string{"https://threatfox-api.abuse.ch/api/v1/"},
		postBody: `{"query":"get_iocs","limit":100000,"confidence_level":50}`,
		authEnv:  "THREATFOX_AUTH_KEY",
		kind:     ThreatC2,
		conf:     75,
		parse:    parseThreatFoxJSON,
	},
	{
		name: "Abuse.ch URLhaus",
		urls: []string{
			"https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-online.txt",
			"https://urlhaus.abuse.ch/downloads/hostfile/",
		},
		kind:  ThreatMalware,
		conf:  100,
		parse: parseURLhausFeed,
	},
	{
		name: "Phishing.Database",
		urls: []string{
			"https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt",
		},
		kind:  ThreatPhishing,
		conf:  60,
		parse: parsePhishingFeed,
	},
	{
		name:  "Feodo Tracker",
		urls:  []string{"https://feodotracker.abuse.ch/downloads/ipblocklist.csv"},
		kind:  ThreatC2,
		conf:  100,
		parse: parseFeodoCSV,
	},
	{
		name:  "Spamhaus DROP",
		urls:  []string{"https://www.spamhaus.org/drop/drop.txt"},
		kind:  ThreatBotnet,
		conf:  100,
		parse: parseSpamhausDROP,
	},
	{
		// AbuseIPDB 公开聚合镜像（真实滥用 IP 列表，约 13 万条）
		name:  "AbuseIPDB aggregated blocklist",
		urls:  []string{"https://raw.githubusercontent.com/borestad/blocklist-abuseipdb/main/abuseipdb-s100-30d.ipv4"},
		kind:  ThreatBotnet,
		conf:  80,
		parse: parseIPList,
	},
	{
		// IPsum 聚合公共黑名单（level 3 约 1.8 万 IP）
		name:  "IPsum aggregated blocklists",
		urls:  []string{"https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt"},
		kind:  ThreatBotnet,
		conf:  60,
		parse: parseIPList,
	},
	{
		// C2IntelFeeds：ThreatFox/Abuse.ch 等公开 C2 情报聚合（Cobalt Strike 等）
		name:  "C2IntelFeeds C2 IP",
		urls:  []string{"https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/master/feeds/IPC2s-30day.csv"},
		kind:  ThreatC2,
		conf:  90,
		parse: parseC2IntelIPCSV,
	},
	{
		name:  "C2IntelFeeds C2 Domain",
		urls:  []string{"https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/master/feeds/domainC2s-30day.csv"},
		kind:  ThreatC2,
		conf:  90,
		parse: parseC2IntelDomainCSV,
	},
}

// 更新互斥：手动 + 定时不并发拉取。
var threatUpdateMu sync.Mutex

// httpFetchThreat 拉取一个源（GET 或 POST JSON；30s 超时，响应上限 32MB）。
func httpFetchThreat(src threatSource, u string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	if src.postBody != "" {
		req, err = http.NewRequest(http.MethodPost, u, strings.NewReader(src.postBody))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		if src.authEnv != "" {
			key := strings.TrimSpace(os.Getenv(src.authEnv))
			if key == "" {
				return nil, fmt.Errorf("未配置 %s（该 API 需要 Auth-Key）", src.authEnv)
			}
			req.Header.Set("Auth-Key", key)
		}
	}
	req.Header.Set("User-Agent", "GuanLan-NetScope/1.0 (+threat-intel-update)")
	client := &http.Client{Timeout: threatFetchTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, threatFetchMaxBytes))
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, errors.New("空响应")
	}
	return data, nil
}

// threatValidDomain 基础域名合法性（与威胁库生成脚本一致，避免噪声）。
func threatValidDomain(d string) bool {
	d = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(d, ".")))
	if d == "" || len(d) > 80 || !strings.Contains(d, ".") {
		return false
	}
	if strings.HasPrefix(d, "0.0.0.") || strings.HasPrefix(d, "www.") {
		return false
	}
	labels := strings.Split(d, ".")
	last := labels[len(labels)-1]
	if len(last) < 2 || len(last) > 24 {
		return false
	}
	for _, r := range last {
		if r < 'a' || r > 'z' {
			return false
		}
	}
	for _, label := range labels {
		if label == "" || len(label) > 63 {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') {
				return false
			}
		}
	}
	if strings.Contains(d, "example.com") || strings.Contains(d, "example.org") ||
		strings.Contains(d, "test.com") || strings.Contains(d, "localhost") {
		return false
	}
	return true
}

// threatBenignSuffixes 常见托管/CDN 后缀：整域匹配会被入侵子域污染，更新解析时跳过（宁缺勿假）。
var threatBenignSuffixes = []string{
	"aliyuncs.com", "amazonaws.com", "cloudfront.net", "azurewebsites.net", "appspot.com",
	"github.io", "pages.dev", "vercel.app", "netlify.app", "workers.dev", "weebly.com",
	"weeblysite.com", "000webhostapp.com", "myqcloud.com", "blob.core.windows.net",
	"repl.co", "replit.dev", "glitch.me", "webflow.io", "shopify.com", "myshopify.com",
	"duckdns.org", "ddns.net", "hopto.org", "no-ip.org", "dynv6.net", "herokuapp.com",
	"wixsite.com", "godaddysites.com", "mystrikingly.com", "square.site", "azureedge.net",
	"githubusercontent.com", "googleusercontent.com", "akamaized.net", "fastly.net",
	"softlayer.net", "linodeobjects.com", "cloudaccess.host", "web.core.windows.net",
	"r.appspot.com", "sslip.io",
}

func threatBenignHost(d string) bool {
	for _, s := range threatBenignSuffixes {
		if d == s || strings.HasSuffix(d, "."+s) {
			return true
		}
	}
	return false
}

// parseURLhausFeed 解析 URLhaus 在线恶意 URL 过滤列表（host/IP 每行一个）。
func parseURLhausFeed(src threatSource, data []byte) ([]ThreatRule, error) {
	var out []ThreatRule
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 2*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "!") || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.Fields(line)[0]
		if strings.Contains(line, "://") || strings.Contains(line, "/") {
			if u, err := url.Parse(line); err == nil && u.Hostname() != "" {
				line = u.Hostname()
			} else {
				continue
			}
		}
		host := strings.ToLower(strings.TrimSuffix(line, "."))
		if addr, err := netip.ParseAddr(host); err == nil {
			if addr.Is4() && !isPrivateIPStr(host) {
				out = append(out, ThreatRule{Target: host, Kind: ThreatMalware, Source: "Abuse.ch URLhaus", Confidence: 100})
			}
			continue
		}
		if threatValidDomain(host) && !threatBenignHost(host) {
			out = append(out, ThreatRule{Target: host, Kind: ThreatMalware, Source: "Abuse.ch URLhaus", Confidence: 100})
		}
	}
	return out, sc.Err()
}

// parsePhishingFeed 解析 Phishing.Database 纯域名列表。
func parsePhishingFeed(src threatSource, data []byte) ([]ThreatRule, error) {
	var out []ThreatRule
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 2*1024*1024)
	for sc.Scan() {
		d := strings.TrimSpace(sc.Text())
		if d == "" || strings.HasPrefix(d, "#") {
			continue
		}
		d = strings.ToLower(strings.TrimSuffix(d, "."))
		if threatValidDomain(d) && !threatBenignHost(d) {
			out = append(out, ThreatRule{Target: d, Kind: ThreatPhishing, Source: "Phishing.Database (open source)", Confidence: 60})
		}
	}
	return out, sc.Err()
}

// parseFeodoCSV 解析 Feodo Tracker CSV（dst_ip 第 2 列、malware 第 6 列）。
func parseFeodoCSV(src threatSource, data []byte) ([]ThreatRule, error) {
	var out []ThreatRule
	r := csv.NewReader(bytes.NewReader(data))
	r.FieldsPerRecord = -1
	r.Comment = '#'
	for {
		row, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue
		}
		if len(row) < 6 {
			continue
		}
		ip := strings.TrimSpace(row[1])
		if addr, err := netip.ParseAddr(ip); err != nil || !addr.Is4() || isPrivateIPStr(ip) {
			continue
		}
		mal := strings.TrimSpace(row[5])
		if mal == "" {
			mal = "botnet C2"
		}
		out = append(out, ThreatRule{Target: ip, Kind: ThreatC2, Source: "Feodo Tracker (abuse.ch) - " + mal, Confidence: 100})
	}
	return out, nil
}

// parseSpamhausDROP 解析 Spamhaus DROP 网段列表（`CIDR ; SBL...`）。
func parseSpamhausDROP(src threatSource, data []byte) ([]ThreatRule, error) {
	var out []ThreatRule
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, ";") {
			continue
		}
		cidr := strings.TrimSpace(strings.SplitN(line, ";", 2)[0])
		if cidr == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil || !prefix.Addr().Is4() {
			continue
		}
		out = append(out, ThreatRule{Target: prefix.Masked().String(), Kind: ThreatBotnet, Source: "Spamhaus DROP", Confidence: 100})
	}
	return out, sc.Err()
}

// parseIPList 解析纯 IP 列表（AbuseIPDB 镜像 / IPsum 等）。
func parseIPList(src threatSource, data []byte) ([]ThreatRule, error) {
	var out []ThreatRule
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 2*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		line = strings.Fields(line)[0]
		kind := src.kind
		if kind == "" {
			kind = ThreatBotnet
		}
		if strings.Contains(line, "/") {
			prefix, err := netip.ParsePrefix(line)
			if err != nil || !prefix.Addr().Is4() {
				continue
			}
			out = append(out, ThreatRule{Target: prefix.Masked().String(), Kind: kind, Source: src.name, Confidence: src.conf})
			continue
		}
		addr, err := netip.ParseAddr(line)
		if err != nil || !addr.Is4() || isPrivateIPStr(line) {
			continue
		}
		out = append(out, ThreatRule{Target: line, Kind: kind, Source: src.name, Confidence: src.conf})
	}
	return out, sc.Err()
}

// parseC2IntelIPCSV 解析 C2IntelFeeds IP CSV（#ip,ioc 注释 + ip,描述）。
func parseC2IntelIPCSV(src threatSource, data []byte) ([]ThreatRule, error) {
	var out []ThreatRule
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		ip := strings.TrimSpace(strings.SplitN(line, ",", 2)[0])
		addr, err := netip.ParseAddr(ip)
		if err != nil || !addr.Is4() || isPrivateIPStr(ip) {
			continue
		}
		out = append(out, ThreatRule{Target: ip, Kind: ThreatC2, Source: "C2IntelFeeds (" + src.name + ")", Confidence: src.conf})
	}
	return out, sc.Err()
}

// parseC2IntelDomainCSV 解析 C2IntelFeeds 域名 CSV。
func parseC2IntelDomainCSV(src threatSource, data []byte) ([]ThreatRule, error) {
	var out []ThreatRule
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		d := strings.ToLower(strings.TrimSpace(strings.SplitN(line, ",", 2)[0]))
		if threatValidDomain(d) && !threatBenignHost(d) {
			out = append(out, ThreatRule{Target: d, Kind: ThreatC2, Source: "C2IntelFeeds (" + src.name + ")", Confidence: src.conf})
		}
	}
	return out, sc.Err()
}

// parseThreatFoxJSON 解析 ThreatFox Community API get_iocs 响应。
func parseThreatFoxJSON(src threatSource, data []byte) ([]ThreatRule, error) {
	var resp struct {
		QueryStatus string `json:"query_status"`
		Data        []struct {
			IOC             string `json:"ioc"`
			IOCType         string `json:"ioc_type"`
			ThreatType      string `json:"threat_type"`
			Malware         string `json:"malware"`
			ConfidenceLevel int    `json:"confidence_level"`
			FirstSeen       string `json:"first_seen"`
		} `json:"data"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, err
	}
	if resp.QueryStatus != "" && resp.QueryStatus != "ok" {
		return nil, fmt.Errorf("ThreatFox 查询失败: %s", resp.QueryStatus)
	}
	var out []ThreatRule
	for _, d := range resp.Data {
		ioc := strings.TrimSpace(d.IOC)
		if ioc == "" {
			continue
		}
		kind := ThreatMalware
		tt := strings.ToLower(d.ThreatType)
		mal := strings.ToLower(d.Malware)
		switch {
		case strings.Contains(mal, "miner"), strings.Contains(mal, "mining"), strings.Contains(tt, "mining"):
			kind = ThreatMining
		case strings.Contains(tt, "phishing"):
			kind = ThreatPhishing
		case strings.Contains(tt, "botnet"), strings.Contains(tt, "c2"), strings.Contains(tt, "cc"):
			kind = ThreatC2
		}
		conf := d.ConfidenceLevel
		if conf <= 0 {
			conf = src.conf
		}
		source := "ThreatFox (abuse.ch)"
		if d.Malware != "" {
			source += " - " + d.Malware
		}
		it := strings.ToLower(d.IOCType)
		switch {
		case strings.Contains(it, "domain"), strings.Contains(it, "hostname"):
			if threatValidDomain(ioc) && !threatBenignHost(ioc) {
				out = append(out, ThreatRule{Target: strings.ToLower(ioc), Kind: kind, Source: source, Confidence: conf})
			}
		case strings.Contains(it, "ip"):
			ip := ioc
			if i := strings.LastIndex(ip, ":"); i > 0 && !strings.Contains(ip, "]") {
				ip = ip[:i]
			}
			if addr, err := netip.ParseAddr(ip); err == nil && addr.Is4() && !isPrivateIPStr(ip) {
				out = append(out, ThreatRule{Target: ip, Kind: kind, Source: source, Confidence: conf})
			}
		case strings.Contains(it, "url"):
			if u, err := url.Parse(ioc); err == nil && u.Hostname() != "" {
				host := strings.ToLower(u.Hostname())
				if addr, err := netip.ParseAddr(host); err == nil && addr.Is4() {
					out = append(out, ThreatRule{Target: host, Kind: kind, Source: source, Confidence: conf})
				} else if threatValidDomain(host) && !threatBenignHost(host) {
					out = append(out, ThreatRule{Target: host, Kind: kind, Source: source, Confidence: conf})
				}
			}
		}
	}
	return out, nil
}

// mergeThreatRules 合并：内置博彩/矿池域名 + 现有库 + 抓取条目，去重 + 按源配额截断 + 上限。
func mergeThreatRules(fetchedDomains, fetchedIPs []ThreatRule) ([]ThreatRule, []ThreatRule) {
	return mergeThreatRulesWithBase(nil, nil, fetchedDomains, fetchedIPs)
}

func mergeThreatRulesWithBase(baseD, baseI, fetchedD, fetchedI []ThreatRule) ([]ThreatRule, []ThreatRule) {
	// 域名：收集顺序 curated → 本次抓取 → 现有库。
	// 抓取排在现有库前：同源同置信度时新数据优先（稳定排序保持插入序），
	// 避免「现有库条目永远钉死配额、新 IOC 进不来」的库内冻结。
	// 超限时按源配额截断（而非纯置信度全局截断，防止 URLhaus conf=100 独占上限）。
	doms := make([]ThreatRule, 0, maxThreatDomains)
	seenD := make(map[string]bool, len(fetchedD)+len(baseD)+64)
	addD := func(r ThreatRule) {
		t := strings.ToLower(strings.TrimSpace(strings.TrimSuffix(r.Target, ".")))
		if t == "" || seenD[t] || !threatValidDomain(t) {
			return
		}
		r.Target = t
		if r.Kind == "" {
			r.Kind = ThreatMalware
		}
		seenD[t] = true
		doms = append(doms, r)
		if len(doms) >= maxThreatDomains*2 {
			doms = truncateBySourceQuota(doms, maxThreatDomains)
		}
	}
	for _, r := range curatedThreatRules() {
		addD(r)
	}
	for _, r := range fetchedD {
		addD(r)
	}
	for _, r := range baseD {
		addD(r)
	}
	if len(doms) > maxThreatDomains {
		doms = truncateBySourceQuota(doms, maxThreatDomains)
	}
	sort.Slice(doms, func(i, j int) bool { return doms[i].Target < doms[j].Target })

	ips := make([]ThreatRule, 0, maxThreatIPs)
	seenI := make(map[string]bool, len(fetchedI)+len(baseI)+64)
	addI := func(r ThreatRule) {
		t := strings.TrimSpace(r.Target)
		if t == "" || seenI[t] {
			return
		}
		if strings.Contains(t, "/") {
			prefix, err := netip.ParsePrefix(t)
			if err != nil || !prefix.Addr().Is4() {
				return
			}
			t = prefix.Masked().String()
		} else {
			addr, err := netip.ParseAddr(t)
			if err != nil || !addr.Is4() || isPrivateIPStr(t) {
				return
			}
		}
		r.Target = t
		if r.Kind == "" {
			r.Kind = ThreatMalware
		}
		seenI[t] = true
		ips = append(ips, r)
		if len(ips) >= maxThreatIPs*2 {
			ips = truncateBySourceQuota(ips, maxThreatIPs)
		}
	}
	for _, r := range fetchedI {
		addI(r)
	}
	for _, r := range baseI {
		addI(r)
	}
	if len(ips) > maxThreatIPs {
		ips = truncateBySourceQuota(ips, maxThreatIPs)
	}
	sort.Slice(ips, func(i, j int) bool { return ips[i].Target < ips[j].Target })
	return doms, ips
}

// isCuratedRule 判断是否为内置 curated 规则（内置黑名单：矿池/赌博域名）。
// 这类规则置信度为 0（未知），但按"内置黑名单始终保留"的约定不受配额限制。
func isCuratedRule(r ThreatRule) bool {
	return strings.HasPrefix(r.Source, "内置黑名单")
}

// curatedSourceKey 内置 curated 规则在按源分组时使用的固定组名。
const curatedSourceKey = "内置黑名单"

// threatSourceKey 规则 → 源分组键（按源配额截断用）。
// ThreatFox/Feodo 等 Source 带 malware 后缀，按前缀归组；
// 未知来源按完整 Source 独立成组（不与已知源抢占份额）。
func threatSourceKey(r ThreatRule) string {
	if isCuratedRule(r) {
		return curatedSourceKey
	}
	s := r.Source
	for _, p := range []string{
		"ThreatFox", "Abuse.ch URLhaus", "Phishing.Database", "Feodo Tracker",
		"Spamhaus DROP", "AbuseIPDB", "IPsum", "C2IntelFeeds",
	} {
		if strings.HasPrefix(s, p) {
			return p
		}
	}
	return s
}

// allocateSourceQuotas max-min 公平配额：各源先均分上限，需求不超过份额的源
// 取走实际数量并把剩余份额回收，再分给仍有余量的源，直到分完或所有源满足。
// 保证总和不超过 max；输入总量 ≤ max 时各源全额分配。
func allocateSourceQuotas(counts map[string]int, max int) map[string]int {
	quotas := make(map[string]int, len(counts))
	if max <= 0 {
		return quotas
	}
	var list []string
	total := 0
	for s, n := range counts {
		if n > 0 {
			list = append(list, s)
			total += n
		}
	}
	sort.Strings(list) // 确定性顺序，避免配额随 map 遍历顺序抖动
	if total <= max {
		for _, s := range list {
			quotas[s] = counts[s]
		}
		return quotas
	}
	remaining := max
	for len(list) > 0 && remaining > 0 {
		share := remaining / len(list)
		if share <= 0 {
			// 剩余不足每源 1 条：按确定性顺序逐条分完即止
			for _, s := range list {
				if remaining <= 0 {
					break
				}
				quotas[s]++
				remaining--
			}
			break
		}
		var next []string
		for _, s := range list {
			if counts[s] <= share {
				quotas[s] = counts[s]
				remaining -= counts[s]
			} else {
				next = append(next, s)
			}
		}
		if len(next) == len(list) {
			// 所有剩余源都超过均分份额：均分后收尾
			for _, s := range list {
				quotas[s] = share
			}
			break
		}
		list = next
	}
	return quotas
}

// truncateBySourceQuota 超限时按源配额截断：
// 内置 curated（内置黑名单快照）不受配额限制、全额保留；剩余上限在各源间
// max-min 均分（防止 URLhaus conf=100 这类大源按纯置信度独占全部上限，
// 导致 Phishing/C2/内置快照被整体丢弃且此后永远进不来——库永久冻结）；
// 组内再按置信度降序保留（稳定排序：同置信度保持原顺序，调用方已把
// 本次抓取排在现有库之前，故同置信度下新数据优先）。
func truncateBySourceQuota(rules []ThreatRule, max int) []ThreatRule {
	if max <= 0 {
		return nil
	}
	if len(rules) <= max {
		return rules
	}
	groups := make(map[string][]ThreatRule, 8)
	var order []string
	for _, r := range rules {
		k := threatSourceKey(r)
		if _, ok := groups[k]; !ok {
			order = append(order, k)
		}
		groups[k] = append(groups[k], r)
	}
	sort.Strings(order)

	out := make([]ThreatRule, 0, max)
	// 内置 curated 全额保留（快照量小，恒远低于上限）
	if g, ok := groups[curatedSourceKey]; ok {
		keep := len(g)
		if keep > max {
			keep = max
		}
		out = append(out, g[:keep]...)
		max -= keep
	}
	if max <= 0 {
		return out
	}
	counts := make(map[string]int, len(order))
	for _, s := range order {
		if s == curatedSourceKey {
			continue
		}
		counts[s] = len(groups[s])
	}
	quotas := allocateSourceQuotas(counts, max)
	for _, s := range order {
		if s == curatedSourceKey {
			continue
		}
		g := groups[s]
		q := quotas[s]
		if q > len(g) {
			q = len(g)
		}
		if q <= 0 {
			continue
		}
		sort.SliceStable(g, func(i, j int) bool { return g[i].Confidence > g[j].Confidence })
		out = append(out, g[:q]...)
	}
	return out
}

// saveThreatFile 原子写 threats.json（tmp + rename）。
// 用 json.Encoder 流式写入临时文件，避免 json.Marshal 整段序列化缓冲
// （5 万域名 + 3 万 IP 约 10~20MB，是更新内存峰值的一部分）。
func saveThreatFile(path string, doms, ips []ThreatRule, at int64) error {
	f := threatFile{UpdatedAt: at, Domains: doms, IPs: ips}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	out, err := os.Create(tmp)
	if err != nil {
		return err
	}
	if err := json.NewEncoder(out).Encode(&f); err != nil {
		out.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// LoadThreats 启动时加载 <data>/threats.json；失败（缺失/损坏）回退内置静态库。
// 流式解码：避免 os.ReadFile 把整个文件（10~20MB）再整段读进内存。
func LoadThreats(path string) error {
	fh, err := os.Open(path)
	if err != nil {
		return err
	}
	defer fh.Close()
	var f threatFile
	if err := json.NewDecoder(fh).Decode(&f); err != nil {
		resetThreatLibraryForTest()
		return err
	}
	if len(f.Domains) == 0 && len(f.IPs) == 0 {
		resetThreatLibraryForTest()
		return errors.New("威胁情报文件为空")
	}
	doms, ips := mergeThreatRules(f.Domains, f.IPs)
	swapThreatLibrary(doms, ips)
	setThreatStatus(f.UpdatedAt, nil)
	logf("已加载威胁情报库（更新于 %s）：域名 %d、IP/CIDR %d",
		time.Unix(f.UpdatedAt, 0).Format("2006-01-02 15:04"), len(doms), len(ips))
	return nil
}

// threatStorePath 威胁情报文件路径。
func threatStorePath(dataDir string) string {
	return filepath.Join(dataDir, threatUpdateFile)
}

// UpdateThreats 拉取完整开源源并更新（手动/定时共用；demo 模式 mock 不改数据）。
func UpdateThreats(dataDir string, demo bool) UpdateResult {
	return updateThreatsWithFetcher(dataDir, demo, httpFetchThreat)
}

// updateThreatsWithFetcher 可注入 fetch 便于测试。
func updateThreatsWithFetcher(dataDir string, demo bool, fetch func(threatSource, string) ([]byte, error)) UpdateResult {
	threatUpdateMu.Lock()
	defer threatUpdateMu.Unlock()

	at, lastErrs := ThreatStatus()
	curD, curI := ThreatCounts()
	if demo {
		// demo/mock：不改数据，直接返回当前库
		return UpdateResult{Ok: true, UpdatedAt: at, Domains: curD, IPs: curI, Errors: append([]string(nil), lastErrs...)}
	}

	type fetchOut struct {
		name string
		doms []ThreatRule
		ips  []ThreatRule
		errs []string
	}
	outs := make(chan fetchOut, len(threatSources))
	var wg sync.WaitGroup
	// 并发拉取限流：9 路并发各自持有响应缓冲是更新内存峰值的主要来源（N1 仅 1GB）
	sem := make(chan struct{}, threatUpdateParallel)
	for _, src := range threatSources {
		wg.Add(1)
		go func(src threatSource) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			res := fetchOut{name: src.name}
			var lastErr error
			for _, u := range src.urls {
				data, err := fetch(src, u)
				if err != nil {
					lastErr = err
					continue
				}
				rules, err := src.parse(src, data)
				if err != nil {
					lastErr = err
					continue
				}
				for _, r := range rules {
					// 单源解析条数上限：先截断再进合并，避免全量 IOC 同时驻留内存
					if len(res.doms) >= threatPerSourceDomainCap && len(res.ips) >= threatPerSourceIPCap {
						break
					}
					if strings.Contains(r.Target, "/") {
						if len(res.ips) < threatPerSourceIPCap {
							res.ips = append(res.ips, r)
						}
						continue
					}
					if addr, err := netip.ParseAddr(r.Target); err == nil && addr.Is4() {
						if len(res.ips) < threatPerSourceIPCap {
							res.ips = append(res.ips, r)
						}
					} else if threatValidDomain(r.Target) {
						if len(res.doms) < threatPerSourceDomainCap {
							res.doms = append(res.doms, r)
						}
					}
				}
				lastErr = nil
				break
			}
			if lastErr != nil {
				res.errs = append(res.errs, fmt.Sprintf("%s: %v", src.name, lastErr))
			}
			outs <- res
		}(src)
	}
	wg.Wait()
	close(outs)

	var fetchedD, fetchedI []ThreatRule
	var errs []string
	for res := range outs {
		fetchedD = append(fetchedD, res.doms...)
		fetchedI = append(fetchedI, res.ips...)
		errs = append(errs, res.errs...)
	}
	if len(fetchedD) == 0 && len(fetchedI) == 0 {
		// 全部源失败：保留旧库，仅记录错误
		setThreatStatus(at, errs)
		return UpdateResult{Ok: false, UpdatedAt: at, Domains: curD, IPs: curI, Errors: errs}
	}
	// 增量合并：现有库 + 本次抓取（去重、置信度截断、上限保护）
	baseD, baseI := ThreatLists()
	doms, ips := mergeThreatRulesWithBase(baseD, baseI, fetchedD, fetchedI)
	now := nowUnix()
	if err := saveThreatFile(threatStorePath(dataDir), doms, ips, now); err != nil {
		errs = append(errs, "写入 threats.json 失败: "+err.Error())
		setThreatStatus(at, errs)
		return UpdateResult{Ok: false, UpdatedAt: at, Domains: curD, IPs: curI, Errors: errs}
	}
	swapThreatLibrary(doms, ips)
	setThreatStatus(now, errs)
	logf("威胁情报库已更新：域名 %d、IP/CIDR %d（错误 %d 个源）", len(doms), len(ips), len(errs))
	return UpdateResult{Ok: true, UpdatedAt: now, Domains: len(doms), IPs: len(ips), Errors: errs}
}
