package main

// 开源威胁情报库（离线静态嵌入 + 可定期/手动更新，不依赖运行时外网、不改路由/防火墙）。
//
// 数据源（公开 IOC，快照见 threats_data.go 注释）：
//   - Abuse.ch URLhaus：恶意 URL 的 host（域名/IP），kind=malware；
//   - Feodo Tracker (abuse.ch)：僵尸网络 C2 IP，kind=c2；
//   - Spamhaus DROP：恶意网段 CIDR，kind=botnet；
//   - Phishing.Database (open source)：钓鱼域名，kind=phishing；
//   - 项目内置黑名单（赌博/矿池域名）：kind=scam/mining（更新时保留）。
//
// 匹配规则：域名按最长后缀匹配（与 classifyHost 一致）；IP 先精确匹配，再按 CIDR 前缀匹配。
// 注意：走代理时 dst 是代理服务器 IP，隧道内的真实恶意目标无法检测（文档已说明）。

import (
	"net/netip"
	"net/url"
	"sort"
	"strings"
	"sync"
)

// ThreatKind 威胁类型。
type ThreatKind string

const (
	ThreatC2       ThreatKind = "c2"
	ThreatPhishing ThreatKind = "phishing"
	ThreatMining   ThreatKind = "mining"
	ThreatBotnet   ThreatKind = "botnet"
	ThreatMalware  ThreatKind = "malware"
	ThreatScam     ThreatKind = "scam"
)

// ThreatRule 一条威胁情报规则。
type ThreatRule struct {
	Target     string     `json:"target"`               // 域名 或 IP/CIDR
	Kind       ThreatKind `json:"kind"`                 // c2/phishing/mining/botnet/malware/scam
	Source     string     `json:"source"`               // 情报来源标注
	Confidence int        `json:"confidence,omitempty"` // 置信度（ThreatFox 等提供；0=未知/内置）
}

// 更新后的库上限（防异常源撑爆内存/磁盘；N1 设备内存足够）。
const (
	maxThreatDomains = 50000
	maxThreatIPs     = 30000
)

// threatRawGroup 生成文件中的原始分组：同 source/kind 的一批 target（换行分隔）。
type threatRawGroup struct {
	source string
	kind   string
	data   string
}

// threatCIDR 预计算网段（uint32，快速匹配）。
type threatCIDR struct {
	net  uint32
	mask uint32
	bits int
	rule ThreatRule
}

var (
	threatMu          sync.RWMutex
	threatDomains     []ThreatRule
	threatIPs         []ThreatRule
	threatDomainIndex map[string]ThreatRule
	threatExact       map[uint32]ThreatRule
	threatCIDRs       []threatCIDR

	threatStatusMu   sync.RWMutex
	threatUpdatedAt  int64
	threatLastErrors []string
)

func init() {
	doms, ips := builtinThreatRules()
	swapThreatLibrary(doms, ips)
	setThreatStatus(0, nil)
}

// parseThreatKind 字符串转 ThreatKind（未知按 malware）。
func parseThreatKind(s string) ThreatKind {
	switch ThreatKind(strings.TrimSpace(s)) {
	case ThreatC2:
		return ThreatC2
	case ThreatPhishing:
		return ThreatPhishing
	case ThreatMining:
		return ThreatMining
	case ThreatBotnet:
		return ThreatBotnet
	case ThreatMalware:
		return ThreatMalware
	case ThreatScam:
		return ThreatScam
	}
	return ThreatMalware
}

// curatedThreatRules 项目内置的博彩/矿池域名（更新时始终保留，不被开源源覆盖）。
func curatedThreatRules() []ThreatRule {
	var out []ThreatRule
	seen := map[string]bool{}
	add := func(target, kind, source string) {
		d := strings.ToLower(strings.TrimSpace(target))
		if d == "" || seen[d] {
			return
		}
		seen[d] = true
		out = append(out, ThreatRule{Target: d, Kind: parseThreatKind(kind), Source: source})
	}
	for _, d := range blockDomains["mining"] {
		add(d, string(ThreatMining), "内置黑名单（矿池域名）")
	}
	for _, d := range blockDomains["gambling"] {
		add(d, string(ThreatScam), "内置黑名单（赌博域名）")
	}
	return out
}

// builtinThreatRules 内置静态库：公开快照 + 项目内置赌博/矿池域名。
func builtinThreatRules() ([]ThreatRule, []ThreatRule) {
	idx := make(map[string]ThreatRule)
	var doms []ThreatRule
	addDomain := func(target, kind, source string) {
		d := strings.ToLower(strings.TrimSpace(strings.TrimSuffix(target, ".")))
		if d == "" {
			return
		}
		if _, exists := idx[d]; exists {
			return
		}
		r := ThreatRule{Target: d, Kind: parseThreatKind(kind), Source: source}
		idx[d] = r
		doms = append(doms, r)
	}
	for _, g := range rawThreatDomainGroups {
		for _, line := range strings.Split(g.data, "\n") {
			addDomain(line, g.kind, g.source)
		}
	}
	for _, r := range curatedThreatRules() {
		addDomain(r.Target, string(r.Kind), r.Source)
	}
	sort.Slice(doms, func(i, j int) bool { return doms[i].Target < doms[j].Target })

	var ips []ThreatRule
	for _, g := range rawThreatIPGroups {
		for _, line := range strings.Split(g.data, "\n") {
			t := strings.TrimSpace(line)
			if t == "" {
				continue
			}
			if strings.Contains(t, "/") {
				if p, err := netip.ParsePrefix(t); err != nil || !p.Addr().Is4() {
					continue
				}
			} else {
				if a, err := netip.ParseAddr(t); err != nil || !a.Is4() {
					continue
				}
			}
			ips = append(ips, ThreatRule{Target: t, Kind: parseThreatKind(g.kind), Source: g.source})
		}
	}
	sort.Slice(ips, func(i, j int) bool { return ips[i].Target < ips[j].Target })
	return doms, ips
}

// swapThreatLibrary 构建索引并原子替换当前库（并发安全）。
func swapThreatLibrary(doms, ips []ThreatRule) {
	idx := make(map[string]ThreatRule, len(doms))
	for _, r := range doms {
		idx[r.Target] = r
	}
	exact := make(map[uint32]ThreatRule)
	var cidrs []threatCIDR
	for _, r := range ips {
		t := strings.TrimSpace(r.Target)
		if strings.Contains(t, "/") {
			prefix, err := netip.ParsePrefix(t)
			if err != nil || !prefix.Addr().Is4() {
				continue
			}
			bits := prefix.Bits()
			mask := ^uint32(0)
			if bits < 32 {
				mask = ^uint32(0) << (32 - bits)
			}
			cidrs = append(cidrs, threatCIDR{net: ip4ToUint32(prefix.Addr().As4()) & mask, mask: mask, bits: bits, rule: r})
		} else if addr, err := netip.ParseAddr(t); err == nil && addr.Is4() {
			exact[ip4ToUint32(addr.As4())] = r
		}
	}
	sort.Slice(cidrs, func(i, j int) bool { return cidrs[i].bits > cidrs[j].bits })
	sort.Slice(doms, func(i, j int) bool { return doms[i].Target < doms[j].Target })
	sort.Slice(ips, func(i, j int) bool { return ips[i].Target < ips[j].Target })

	threatMu.Lock()
	threatDomains, threatIPs = doms, ips
	threatDomainIndex, threatExact, threatCIDRs = idx, exact, cidrs
	threatMu.Unlock()
}

// setThreatStatus 记录最近一次更新的时间与错误。
func setThreatStatus(updatedAt int64, errs []string) {
	threatStatusMu.Lock()
	threatUpdatedAt = updatedAt
	threatLastErrors = append([]string(nil), errs...)
	threatStatusMu.Unlock()
}

// ThreatStatus 返回最近更新时间与错误（供 API）。
func ThreatStatus() (int64, []string) {
	threatStatusMu.RLock()
	defer threatStatusMu.RUnlock()
	return threatUpdatedAt, append([]string(nil), threatLastErrors...)
}

// resetThreatLibraryForTest 恢复内置静态库（仅测试用）。
func resetThreatLibraryForTest() {
	doms, ips := builtinThreatRules()
	swapThreatLibrary(doms, ips)
	setThreatStatus(0, nil)
}

// ThreatDomainLookup 域名最长后缀匹配威胁库。
func ThreatDomainLookup(host string) (ThreatRule, bool) {
	host = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(host, ".")))
	if host == "" {
		return ThreatRule{}, false
	}
	threatMu.RLock()
	defer threatMu.RUnlock()
	if len(threatDomainIndex) == 0 {
		return ThreatRule{}, false
	}
	labels := strings.Split(host, ".")
	for i := 0; i < len(labels); i++ {
		if r, ok := threatDomainIndex[strings.Join(labels[i:], ".")]; ok {
			return r, true
		}
	}
	return ThreatRule{}, false
}

// ThreatIPLookup 公网 IPv4 精确/CIDR 匹配威胁库（内网不会命中）。
func ThreatIPLookup(ip string) (ThreatRule, bool) {
	addr, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil || !addr.Is4() || isPrivateIPStr(addr.String()) {
		return ThreatRule{}, false
	}
	v := ip4ToUint32(addr.As4())
	threatMu.RLock()
	defer threatMu.RUnlock()
	if r, ok := threatExact[v]; ok {
		return r, true
	}
	for _, c := range threatCIDRs {
		if v&c.mask == c.net {
			return c.rule, true
		}
	}
	return ThreatRule{}, false
}

// ThreatLookup 先按域名、再按 IP 命中威胁库。
func ThreatLookup(domain, ip string) (ThreatRule, bool) {
	if r, ok := ThreatDomainLookup(domain); ok {
		return r, true
	}
	return ThreatIPLookup(ip)
}

// ThreatCounts 返回威胁库规模（域名数、IP/CIDR 数）。
func ThreatCounts() (domains, ips int) {
	threatMu.RLock()
	defer threatMu.RUnlock()
	return len(threatDomains), len(threatIPs)
}

// ThreatSample 返回前 limit 条明细与完整计数（供 /api/threats，避免每次复制全库）。
func ThreatSample(limit int) ([]ThreatRule, []ThreatRule, int, int) {
	threatMu.RLock()
	defer threatMu.RUnlock()
	if limit <= 0 || limit > len(threatDomains) {
		limit = len(threatDomains)
	}
	doms := make([]ThreatRule, limit)
	copy(doms, threatDomains[:limit])
	n := limit
	if n > len(threatIPs) {
		n = len(threatIPs)
	}
	ips := make([]ThreatRule, n)
	copy(ips, threatIPs[:n])
	return doms, ips, len(threatDomains), len(threatIPs)
}

// ThreatSearch 威胁库查询（前端"查询窗口"）：q 为空返回 nil。
//   - 域名：忽略大小写子串匹配 + 最长后缀命中；
//   - IP：精确命中 + CIDR 包含；也支持输入 CIDR 查询其覆盖/包含的规则。
//
// 返回匹配明细（每类最多 limit 条，默认/上限 500）、命中总数与库总数。
func ThreatSearch(q string, limit int) ([]ThreatRule, []ThreatRule, int, int, int, int) {
	q = strings.TrimSpace(q)
	if q == "" {
		return nil, nil, 0, 0, 0, 0
	}
	if limit <= 0 || limit > 500 {
		limit = 500
	}
	if strings.Contains(q, "://") {
		if u, err := url.Parse(q); err == nil && u.Hostname() != "" {
			q = u.Hostname()
		}
	}
	q = strings.ToLower(strings.TrimSuffix(q, "."))
	addr, addrErr := netip.ParseAddr(q)
	prefix, prefixErr := netip.ParsePrefix(q)
	isIPQuery := addrErr == nil || prefixErr == nil

	threatMu.RLock()
	defer threatMu.RUnlock()

	var doms, ips []ThreatRule
	matchedD, matchedI := 0, 0
	if !isIPQuery {
		for _, r := range threatDomains {
			if !strings.Contains(r.Target, q) {
				continue
			}
			matchedD++
			if len(doms) < limit {
				doms = append(doms, r)
			}
		}
		// 最长后缀命中（输入本身是恶意域名但子串已覆盖时去重）
		if r, ok := threatDomainSuffixLocked(q); ok {
			found := false
			for _, d := range doms {
				if d.Target == r.Target {
					found = true
					break
				}
			}
			if !found {
				matchedD++
				if len(doms) < limit {
					doms = append(doms, r)
				}
			}
		}
	} else {
		var v uint32
		if addrErr == nil && addr.Is4() {
			v = ip4ToUint32(addr.As4())
		}
		for _, r := range threatIPs {
			match := false
			target := strings.TrimSpace(r.Target)
			if strings.Contains(target, "/") {
				if tp, err := netip.ParsePrefix(target); err == nil {
					switch {
					case prefixErr == nil:
						// 查询是 CIDR：规则网段被查询网段包含，或规则网段包含查询网段
						match = prefix.Contains(tp.Addr()) || tp.Contains(prefix.Addr())
					case addrErr == nil && addr.Is4():
						match = tp.Contains(addr)
					}
				}
			} else if ta, err := netip.ParseAddr(target); err == nil && ta.Is4() {
				switch {
				case prefixErr == nil:
					match = prefix.Contains(ta)
				case addrErr == nil && addr.Is4():
					match = ip4ToUint32(ta.As4()) == v
				}
			} else if addrErr == nil {
				match = strings.EqualFold(target, q)
			}
			if match {
				matchedI++
				if len(ips) < limit {
					ips = append(ips, r)
				}
			}
		}
	}
	return doms, ips, matchedD, matchedI, len(threatDomains), len(threatIPs)
}

// threatDomainSuffixLocked 调用方需持有读锁；最长后缀匹配。
func threatDomainSuffixLocked(host string) (ThreatRule, bool) {
	if host == "" || len(threatDomainIndex) == 0 {
		return ThreatRule{}, false
	}
	labels := strings.Split(host, ".")
	for i := 0; i < len(labels); i++ {
		if r, ok := threatDomainIndex[strings.Join(labels[i:], ".")]; ok {
			return r, true
		}
	}
	return ThreatRule{}, false
}

// ThreatLists 返回威胁库全部条目（只读拷贝，供内部/测试使用）。
func ThreatLists() ([]ThreatRule, []ThreatRule) {
	threatMu.RLock()
	defer threatMu.RUnlock()
	doms := make([]ThreatRule, len(threatDomains))
	copy(doms, threatDomains)
	ips := make([]ThreatRule, len(threatIPs))
	copy(ips, threatIPs)
	return doms, ips
}

// threatKindLabel 威胁类型中文名。
func threatKindLabel(k ThreatKind) string {
	switch k {
	case ThreatC2:
		return "僵尸网络 C2"
	case ThreatPhishing:
		return "钓鱼"
	case ThreatMining:
		return "矿池"
	case ThreatBotnet:
		return "僵尸网络"
	case ThreatMalware:
		return "恶意软件"
	case ThreatScam:
		return "诈骗/赌博"
	}
	return "恶意"
}

// threatSeverity 威胁类型 → 事件级别。
func threatSeverity(k ThreatKind) string {
	switch k {
	case ThreatC2, ThreatBotnet, ThreatMining, ThreatMalware:
		return sevCritical
	}
	return sevWarn
}
