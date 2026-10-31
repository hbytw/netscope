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
//   - 加载上限：域名 50000、IP/CIDR 30000；超限按 confidence 降序截断保留高置信度。

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

// mergeThreatRules 合并：内置博彩/矿池域名 + 现有库 + 抓取条目，去重 + 置信度截断 + 上限。
func mergeThreatRules(fetchedDomains, fetchedIPs []ThreatRule) ([]ThreatRule, []ThreatRule) {
	return mergeThreatRulesWithBase(nil, nil, fetchedDomains, fetchedIPs)
}

func mergeThreatRulesWithBase(baseD, baseI, fetchedD, fetchedI []ThreatRule) ([]ThreatRule, []ThreatRule) {
	// 域名：收集到 2 倍上限后按置信度裁剪，避免异常源撑爆内存
	doms := make([]ThreatRule, 0, maxThreatDomains)
	seenD := make(map[string]bool, len(fetchedD)+len(baseD)+64)
	var addD func(r ThreatRule)
	addD = func(r ThreatRule) {
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
			doms = truncateByConfidence(doms, maxThreatDomains)
		}
	}
	for _, r := range curatedThreatRules() {
		addD(r)
	}
	for _, r := range baseD {
		addD(r)
	}
	for _, r := range fetchedD {
		addD(r)
	}
	if len(doms) > maxThreatDomains {
		doms = truncateByConfidence(doms, maxThreatDomains)
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
			ips = truncateByConfidence(ips, maxThreatIPs)
		}
	}
	for _, r := range baseI {
		addI(r)
	}
	for _, r := range fetchedI {
		addI(r)
	}
	if len(ips) > maxThreatIPs {
		ips = truncateByConfidence(ips, maxThreatIPs)
	}
	sort.Slice(ips, func(i, j int) bool { return ips[i].Target < ips[j].Target })
	return doms, ips
}

// truncateByConfidence 超限时按置信度降序保留（同置信度保留原顺序），再按需截断。
func truncateByConfidence(rules []ThreatRule, max int) []ThreatRule {
	sort.SliceStable(rules, func(i, j int) bool { return rules[i].Confidence > rules[j].Confidence })
	if len(rules) > max {
		rules = rules[:max]
	}
	return rules
}

// saveThreatFile 原子写 threats.json（tmp + rename）。
func saveThreatFile(path string, doms, ips []ThreatRule, at int64) error {
	f := threatFile{UpdatedAt: at, Domains: doms, IPs: ips}
	data, err := json.Marshal(&f)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// LoadThreats 启动时加载 <data>/threats.json；失败（缺失/损坏）回退内置静态库。
func LoadThreats(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var f threatFile
	if err := json.Unmarshal(data, &f); err != nil {
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
	for _, src := range threatSources {
		wg.Add(1)
		go func(src threatSource) {
			defer wg.Done()
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
					if strings.Contains(r.Target, "/") {
						res.ips = append(res.ips, r)
						continue
					}
					if addr, err := netip.ParseAddr(r.Target); err == nil && addr.Is4() {
						res.ips = append(res.ips, r)
					} else if threatValidDomain(r.Target) {
						res.doms = append(res.doms, r)
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
