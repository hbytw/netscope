# 观澜 NetScope · API 契约 v1（冻结）

所有接口默认返回 `application/json; charset=utf-8`。除 `/api/login`、`/api/session`、`/healthz`、静态资源外，均需会话 Cookie `gl_session`；未登录返回 `401 {"error":"unauthorized"}`。
错误统一：`HTTP 4xx/5xx` + `{"error":"人类可读中文信息","code":"machine_code"}`。
时间戳统一为 **Unix 秒**（`int64`），速率单位为 **bit/s**（`Bps` 后缀），流量累计单位为 **字节**（`bytes`）。

---

## 1. 鉴权

| 方法 | 路径 | 请求 | 响应 |
|---|---|---|---|
| POST | `/api/login` | `{"password":"***"}` | `{"ok":true,"expiresIn":86400}` + `Set-Cookie: gl_session=...; Path=/; HttpOnly; SameSite=Lax` |
| POST | `/api/logout` | — | `{"ok":true}` |
| GET | `/api/session` | — | `{"authed":true,"username":"admin"}` 或 `{"authed":false}` |
| POST | `/api/password` | `{"old":"***","new":"***"}` | `{"ok":true}` |

登录失败连续 5 次锁定 60 s：`429 {"error":"尝试过于频繁，请稍后再试"}`。

---

## 2. 总览

### GET `/api/overview`
```json
{
  "ts": 1761900000,
  "kpi": {"online":11,"devices":14,"conns":14559,"newConns":42,"dnsQps":3.5,
          "alerts":2,"upBps":123456,"downBps":8901234,"riskLevel":"low"},
  "sys": {"cpuPct":23.4,"memPct":41.2,"memUsedMb":760,"load1":0.42,"uptimeSec":3600,
          "tempC":52.0,"wanRxBps":123456,"wanTxBps":23456,"connCount":14559},
  "categories": [{"key":"video","label":"视频流媒体","upBps":1200,"downBps":5200000,"share":0.42,"color":"#22d3ee"}],
  "trend": [{"t":1761899000,"up":1200,"down":5200000}],
  "topDevices": [{"ip":"192.168.1.31","name":"MEIZU-Note-16","alias":"妈妈的手机",
                  "upBps":1234,"downBps":5678,"totalDown":1048576,"risk":0.2}],
  "topDomains": [{"domain":"bilibili.com","label":"哔哩哔哩","category":"video","hits":123,"downBps":520000}],
  "alerts": [Event]
}
```
- `trend` 固定 60 点、2 s 间隔（最近 2 分钟）。
- `categories` 固定 8 项、顺序固定（见 §8），无流量项也返回（值为 0）。

---

## 3. 设备

### GET `/api/devices`
```json
{"devices":[Device]}
```
### GET `/api/devices/{ip}`
```json
{"device":Device,
 "trend":[{"t":1761899000,"up":0,"down":0}],
 "topDomains":[{"domain":"bilibili.com","label":"哔哩哔哩","category":"video","hits":12,"bytes":1024}],
 "topDsts":[{"ip":"1.2.3.4","country":"CN","bytes":1024}],
 "conns":[Connection]}
```
### 写操作
| 方法 | 路径 | 请求 | 说明 |
|---|---|---|---|
| POST | `/api/devices/{ip}/alias` | `{"alias":"客厅电视"}` | 空串=清除 |
| POST | `/api/devices/{ip}/group` | `{"group":"家人"}` | 分组标签 |
| POST | `/api/devices/{ip}/block` | `{"blocked":true}` | 断网/恢复（iptables） |
| POST | `/api/devices/{ip}/limit` | `{"downKbps":2000,"upKbps":0}` | 0=取消限速（tc） |
| POST | `/api/devices/{ip}/forget` | — | 从列表移除（保留历史） |

写操作响应：`{"ok":true,"applied":["iptables -I UBM_FWD ..."],"device":Device}`

### Device 结构
```json
{"ip":"192.168.1.31","mac":"90:f0:52:d5:9a:cb","hostname":"MEIZU-Note-16","alias":"妈妈的手机",
 "vendor":"魅族","network":"lan","group":"家人","online":true,"firstSeen":1761800000,"lastSeen":1761900000,
 "upBps":1234,"downBps":5678,"totalUp":1024,"totalDown":2048,"conns":12,"risk":0.2,
 "blocked":false,"limitKbps":{"down":0,"up":0},"topCat":"video","topDomain":"bilibili.com",
 "policyIds":["p-1"]}
```
- `network`：设备所属网络，取值 `lan` / `zerotier` / `vpn`。设备列表只返回内网设备：
  DHCP 租约 + 内网接口（`br-lan`/`zt*`/`tun*`/`wg*`/`tailscale0`/`ppp*`）上的私网邻居；
  `docker0` 等非内网接口、公网 IP、FAILED/INCOMPLETE 邻居不会出现在列表中。
- 本机接口地址、默认网关、回环/链路本地、内网网络/广播地址受保护：对其调用断网/限速/封禁目标
  会返回 `400 {"error":"不能封禁本机/网关/关键内网地址，已拒绝","code":"protected_ip"}`。

---

## 4. 流量分析

### GET `/api/traffic?range=1h|6h|24h|7d`
```json
{"range":"1h","bucketSec":60,
 "series":[{"t":1761899000,"up":1234,"down":5678,"byCat":{"video":5000,"game":0}}],
 "byCategory":[{"key":"video","label":"视频流媒体","up":1234,"down":5678,"share":0.4,"color":"#22d3ee"}],
 "byDevice":[{"ip":"192.168.1.31","name":"MEIZU-Note-16","alias":"妈妈的手机","up":1,"down":2,"share":0.3}],
 "byApp":[{"key":"video","label":"视频流媒体","up":1,"down":2,"share":0.3}]}
```
- `bucketSec`：`1h→30`、`6h→120`、`24h→300`、`7d→1800`（服务端自动）。
- `series` 长度上限 200；超出按 bucket 聚合。

### GET `/api/traffic/domains?range=1h&limit=50`
```json
{"domains":[{"domain":"bilibili.com","label":"哔哩哔哩","category":"video","hits":123,
             "bytes":1048576,"devices":3,"lastSeen":1761900000,
             "deviceList":[{"ip":"192.168.1.31","name":"MEIZU-Note-16","alias":"妈妈的手机",
                            "hits":80,"bytes":900000,"lastSeen":1761900000},
                           {"ip":"192.168.1.32","name":"iPhone-15-Pro","alias":"爸爸的手机",
                            "hits":43,"bytes":148576,"lastSeen":1761899000}]}]}
```
- `devices`：访问设备数量（兼容旧字段）；`deviceList`：访问该 URL 的设备明细，按 `bytes` 降序取前 20，含 `ip/name/alias/hits/bytes/lastSeen`（`hits` 来自 DNS 查询次数）。
### GET `/api/traffic/conns?limit=200&q=&device=`
```json
{"conns":[Connection],"total":3811}
```
### Connection 结构
```json
{"id":"tcp-192.168.1.31-55912-112.252.211.104-443","proto":"tcp","srcIp":"192.168.1.31","srcPort":55912,
 "dstIp":"112.252.211.104","dstPort":443,"domain":"bilibili.com","app":"哔哩哔哩","category":"video",
 "path":"direct","iface":"br-lan",
 "upBytes":1024,"downBytes":20480,"state":"ESTABLISHED","startedAt":1761899000,"lastSeenAt":1761900000,
 "durationSec":100,"deviceName":"MEIZU-Note-16"}
```
- `path`：连接流向，取值 `direct`（公网直连）/ `proxy`（经代理）/ `zerotier`（经 ZeroTier）/ `vpn`（经 VPN）/ `lan`（内网互访）。代理判断优先 conntrack `mark>0`（passwall/xray TPROXY 透明代理标记，**不依赖 7890 等监听端口**），其次目的端口命中常见代理端口（7890/7891/1080/8888/9090 等）。
- **连接表只包含用户设备**（LAN/ZeroTier/VPN 网段）；docker0/本机的 mark>0 代理流量不计入连接表，但会计入 `/api/topology` 的 `proxy` 链路速率。代理出口 `mark=0` 的连接不参与 direct 统计。
- `iface`：设备侧接入接口名（`br-lan` / `zt6vwy3rne` / `tun0` …）。设备可位于 LAN、ZeroTier 或 VPN 网段，服务端按多网段识别，不会丢弃 zt/vpn 设备的连接。
- `domain`/`category` 归因顺序：目的 IP 反查（dnsmasq reply）→ 6h 长 TTL 反查 → **本设备最近一次 DNS 查询（10min 内，设备级回退，解决代理隧道 dst=代理服务器 IP 无法归因的问题）** → 端口启发式（代理流量兜底归 `web`）。分类仍为固定 8 类，前端无需改动。
### POST `/api/traffic/conns/{id}/block`
`{"scope":"dst"}` → 封目标 IP；`{"scope":"device"}` → 断该设备。响应 `{"ok":true,"applied":[...]}`。

---

## 5. 策略（行为管控）

### GET `/api/policies` → `{"policies":[Policy]}`
### Policy 结构
```json
{"id":"p-1761900000-1","name":"22点后禁止刷短视频","enabled":true,
 "targets":{"ips":["192.168.1.31"],"groups":[],"all":false},
 "schedule":{"days":[1,2,3,4,5],"start":"22:00","end":"23:59"},
 "action":"block","categories":["video","game"],"domains":["douyin.com"],
 "limitKbps":{"down":0,"up":0},"hits":0,"createdAt":1761900000,"updatedAt":1761900000}
```
- `action`：`block`（禁止上网/禁止命中分类）、`limit`（限速）、`allow`（白名单放行，优先级最高）。
- `schedule`：`days` 1=周一…7=周日；空数组=全天；`start`/`end` 为 `HH:MM`；跨零点允许（start>end）。
- `categories`/`domains` 为空表示不限定（即整机断网）。

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/api/policies` | 新建（忽略 id），返回 `{"policy":Policy}` |
| PUT | `/api/policies/{id}` | 全量更新，返回 `{"policy":Policy}` |
| DELETE | `/api/policies/{id}` | `{"ok":true}` |
| POST | `/api/policies/{id}/toggle` | `{"enabled":false}` |
| GET | `/api/enforce/status` | `{"iptablesRules":3,"tcDevices":1,"dnsBlockedDomains":5,"activePolicies":2,"dnsTap":true}` |
| GET | `/api/enforce/dns` | DNS 拦截域名明细（只读，仅 GET；鉴权同其他 `/api/*`）：`{"domains":["a.com","b.com"]}`，数组元素为域名字符串、按字典序升序。口径 = 策略下发的域名集合 ∪ 手工封堵列表，去重；无封堵时返回 `{"domains":[]}`。`/api/enforce/status.dnsBlockedDomains` 仍是计数口径 |
| POST | `/api/enforce/reset` | 清空全部管控并还原 DNS 拦截，`{"ok":true,"removed":[...]}` |
| GET | `/api/enforce/blocks` | 封禁/限速列表：`{"blocks":[{"ip":"192.168.1.33","type":"device","reason":"手动断网","at":1761900000,"downKbps":0,"upKbps":0}]}`。`type` 取值 `device`（断网设备）/`dst`（封禁目标 IP）/`limit`（限速），`at` 为首次下发时间（Unix 秒） |
| POST | `/api/enforce/blocks/{ip}/unblock` | 解封/取消限速，返回 `{"ok":true,"applied":[...],"revoked":[...]}`。可选 query `?type=device|dst|limit` 只解封指定类型；不传则解封该 IP 的全部记录 |

- 封禁记录持久化在 `state.json`（设备断网/限速随 DeviceMeta，目标 IP 封禁在 dstBlocks），重启不丢；关闭总开关只撤销规则、不删除记录。
- 本机接口地址、默认网关、回环/链路本地、内网网络/广播地址受保护：断网/限速/封禁目标会返回 `400 {"error":"不能封禁本机/网关/关键内网地址，已拒绝","code":"protected_ip"}`。

### 5.1 网络拓扑

#### GET `/api/topology`（只读）
```json
{"nodes":[{"id":"br-lan","type":"lan","name":"内网 LAN","cidr":"192.168.1.0/24","up":true,"rxBps":0,"txBps":0},
          {"id":"zt6vwy3rne","type":"zerotier","name":"ZeroTier","cidr":"192.168.99.0/24","up":true,"rxBps":0,"txBps":0},
          {"id":"internet","type":"internet","name":"互联网","cidr":"","up":true,"rxBps":0,"txBps":0},
          {"id":"proxy","type":"proxy","name":"代理","cidr":"","up":false,"rxBps":0,"txBps":0}],
 "links":[{"from":"br-lan","to":"internet","kind":"direct","upBps":0,"downBps":0},
          {"from":"br-lan","to":"proxy","kind":"proxy","upBps":0,"downBps":0},
          {"from":"br-lan","to":"zt6vwy3rne","kind":"zt","upBps":0,"downBps":0}]}
```
- `nodes[].cidr` **为网段语义（网络地址/前缀，如 `192.168.1.0/24`），不是接口地址**；接口地址属于实现细节、不进契约。`internet`/`proxy` 节点 `cidr` 为空串。
- 节点 `type`：`lan` / `zerotier` / `vpn` / `docker` / `internet` / `proxy`；虚拟接口（`zt*`/`tun*`/`wg*`/`tailscale0`/`ppp*`）只要 up 就自动出现在拓扑中。
- 链路 `kind`：`direct`（直接出网）/ `proxy`（经代理）/ `zt`（ZeroTier）/ `vpn`；`upBps`/`downBps` 为**按连接流向（path）聚合的实时速率**：
  - `proxy` 链路 = `path=proxy` 的连接速率（conntrack `mark>0` 或目的端口命中代理端口；**含 docker0/本机等非用户设备的代理流量**，这类流量只计入链路、不出现在连接表/设备列表）；
  - `direct` 链路 = 设备非代理公网连接速率（代理出口的 `mark=0` 连接不会被算成 direct，避免虚增）；
  - `zt`/`vpn` 链路 = 对应流向的连接速率，无连接时用接口 rx/tx 计数器兜底。
- `proxy`/`zerotier`/`vpn` 节点的 `rxBps`/`txBps` 与对应链路一致（`rx=link.upBps`、`tx=link.downBps`）。
- `proxy` 节点是否存在/up 由本机代理监听端口（7890/7891/1080/8888/9090 等）或进程名（clash/mihomo/v2ray/xray/sing-box 等）探测；未探测到时代理节点仍返回、`up=false`。透明代理（passwall/xray TPROXY，无监听端口）可能 `up=false`，但 `proxy` 链路仍会按 mark 统计流量。
- 采集来源：`ip -br addr`（接口/CIDR/状态）、`ip route`（默认网关/虚拟网段）、`/proc/net/dev`（接口 rx/tx 速率）、`ss -lntp`/`netstat -lntp`（代理）；结果做 5–10s 缓存。

---

## 6. 安全态势

### GET `/api/events?limit=100&severity=&type=&ack=all`
```json
{"events":[Event],"summary":{"critical":1,"warn":3,"info":9,"total":13}}
```
### Event 结构
```json
{"id":"e-1761900000-1","ts":1761900000,"severity":"warn",
 "type":"port_scan","title":"疑似端口扫描：192.168.1.84",
 "detail":"60 秒内对 28 个不同目的端口发起新连接","deviceIp":"192.168.1.84",
 "deviceName":"Redmi-Turbo-3","acked":false,
 "evidence":{"ports":28,"windowSec":60,"sample":["23","445","3389"]}}
```
事件类型（`type`）：
`new_device` 新设备入网 / `device_online` / `device_offline` / `port_scan` 端口扫描 /
`bad_port` 高危端口外联 / `blacklist_domain` 黑名单域名 / `dns_tunnel` DNS 隧道嫌疑 /
`traffic_anomaly` 流量异常 / `policy_hit` 策略命中。
- `port_scan` 判定：60 秒内同一设备新连接 **>阈值（默认 20）个不同公网目的端口**；**内网/ZeroTier/VPN 目的地址与 9993/9994 控制端口不计入**（避免 ZeroTier P2P 多对等体误报）。事件 `evidence` 含 `ports`（端口数）、`portList`（前 20 个端口）、`windowSec`、`threshold`、`excluded`。

| 方法 | 路径 | 请求 |
|---|---|---|
| POST | `/api/events/{id}/ack` | `{"acked":true}` |
| POST | `/api/events/clear` | — |

### GET `/api/security/risk`
```json
{"level":"guard","devices":[{"ip":"192.168.1.84","name":"Redmi-Turbo-3","risk":0.8,
  "reasons":[{"type":"port_scan","count":2,"lastTs":1761900000},
             {"type":"blacklist_domain","count":1,"lastTs":1761900100}]}]}
```
- `level`：`low` / `guard` / `high`（由近 1 小时事件加权得出）。
- **风险定义**：风险分 = 近 1 小时**行为异常事件**加权（`critical` 0.4 / `warn` 0.2 / `info` 0.05，封顶 1.0），衡量的是"可疑行为信号"，**不是病毒/木马/杀毒检测**。`reasons` 为该设备近 1 小时各类事件次数与最近时间，前端据此展示判定依据。
- 常见 `reasons.type` 依据：`port_scan` = 60 秒内新连接 >阈值（默认 20）个**不同公网端口**（已排除内网/ZeroTier/VPN 目的与 9993/9994 控制端口）；`bad_port` = 主动外联高危端口；`blacklist_domain` = 访问内置黑名单域名（赌博/色情/矿池）；`dns_tunnel` = TXT 长标签/高频 DNS 查询；`traffic_anomaly` = 1 小时上传超限；`policy_hit` = 命中家长管控策略。

### 告警白名单
用户可对"判断不是威胁"的事件按 **事件类型 + 目标（设备 IP / 域名 / 目标 IP）** 加白；命中白名单后同类型/同目标不再产生新事件（历史已产生事件保留可查、可确认）。

```json
{"items":[{"id":"wl-1a2b3c4d5e","type":"port_scan","target":"192.168.1.84","note":"已知扫描器","at":1761900000}]}
```

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/security/whitelist` | `{"items":[{"id","type","target","note","at"}]}` |
| POST | `/api/security/whitelist` | body `{"type":"port_scan","target":"192.168.1.84","note":"已知扫描器"}` → `{"ok":true,"item":{...}}`；同 type+target 幂等，重复加白返回已有项 |
| DELETE | `/api/security/whitelist/{id}` | 取消加白，`{"ok":true}`；不存在返回 404 |

- 匹配规则：同一 `type` 且同一 `target`（`deviceIp` 或 `evidence.domain`/`dstIp`/`ip`）即视为白名单命中，`emit` 阶段直接跳过。
- 白名单持久化在 `state.json` 的 `whitelist`，重启不丢；服务端重启后自动加载。
- 加白/取消后立即生效（无需重启采集）。

### 开源威胁情报库（高危域名 / 高危 IP）
内置的是**公开 IOC 全量快照**（离线嵌入，约 5000 域名 + 3000 IP/CIDR），并支持**手动/定时更新**为更大规模的开源情报（更新后上限 5 万域名 / 3 万 IP/CIDR，按置信度截断）。

数据源（公开 IOC，每条规则带 `target/kind/source/confidence`）：
**ThreatFox Community API**（最大开源 C2/恶意 IOC 库，需环境变量 `THREATFOX_AUTH_KEY`；未配置时跳过并记 warning）、**Abuse.ch URLhaus**（恶意 URL host）、**Phishing.Database**（钓鱼域名）、**Feodo Tracker**（C2 IP）、**Spamhaus DROP**（恶意 CIDR）、**AbuseIPDB 公开聚合镜像**、**IPsum 聚合黑名单**、**C2IntelFeeds**（C2 IP/域名聚合）、项目内置赌博/矿池域名。更新成功写 `<data>/threats.json`（原子写），启动优先加载；失败保留旧库，JSON 损坏回退内置静态库。

#### GET `/api/threats?limit=1000`（只读，需登录）
```json
{"domains":[{"target":"creativit.fr","kind":"malware","source":"Abuse.ch URLhaus","confidence":100}],
 "ips":[{"target":"162.243.103.246","kind":"c2","source":"Feodo Tracker (abuse.ch) - Emotet","confidence":100}],
 "counts":{"domains":5066,"ips":3063},
 "returned":{"domains":1000,"ips":1000},
 "limit":1000,"truncated":true,
 "updatedAt":1761900000,"errors":[]}
```
- `counts` 为真实总数；默认只返回前 1000 条明细（`limit` 1~5000）供展示，`truncated` 表示是否截断。
- `updatedAt`：最近一次成功更新时间（0=内置静态库，从未更新）；`errors`：最近一次更新中失败源/告警（如 ThreatFox 未配置 Auth-Key）。

#### GET `/api/threats?search=<q>`（查询窗口，只读）
q 非空时**只返回匹配项**（不返回分页列表）：
```json
{"query":"pool.minexmr","domains":[{"target":"pool.minexmr.com","kind":"mining","source":"内置黑名单（矿池域名）"}],
 "ips":[],"counts":{"domains":5066,"ips":3063},"matched":{"domains":1,"ips":0},
 "updatedAt":1761900000,"errors":[]}
```
- 域名：忽略大小写**子串匹配**（`strings.Contains`）+ 最长后缀命中；支持直接粘贴 URL（自动提取 host）。
- IP：输入 IP 精确命中 + CIDR 包含；输入 CIDR 时返回被其包含/包含它的网段规则。
- `matched` 为命中总数；明细每类最多返回 500 条（防超大结果）；`counts` 仍为库总数。无命中时数组为空、`matched` 为 0。
- q 为空走上面的分页行为（`limit`/`counts`/`updatedAt`/`errors`）。

#### POST `/api/threats/update`（需登录）
同步拉取完整开源源并更新（每源 30s 超时，源之间并发），返回：
```json
{"ok":true,"updatedAt":1761900000,"domains":50000,"ips":30000,
 "errors":["ThreatFox: 未配置 THREATFOX_AUTH_KEY（该 API 需要 Auth-Key）"]}
```
- 任一源成功即更新该源；全部失败返回 `ok:false` 且**保留旧库**；demo 模式为 mock（返回 ok，不改数据）。
- **自动更新**：后台按设置 `alert.threatUpdateHours`（默认 6，可设 1~168 小时；设置页可选 1/6/12/24）定时拉取，独立 goroutine，不阻塞采集/SSE。
- 增量合并：现有库 + 本次抓取条目去重后按 `confidence` 降序截断到上限，避免异常源撑爆内存/磁盘。

- 匹配规则：域名按**最长后缀**匹配；IP 先精确匹配、再按 CIDR 前缀匹配；内网/回环/链路本地地址永不参与 IP 匹配。
- 命中告警：域名 → `type=blacklist_domain`，title `命中高危域名：<域名>`；IP → `type=bad_ip`，title `连接高危 IP：<IP>`；`evidence={domain/ip,kind,source}`；c2/botnet/mining/malware 为 `critical`，phishing/scam 为 `warn`，均计入风险分。
- 支持告警白名单：按 `bad_ip|<IP>` 或 `blacklist_domain|<域名>` 加白后不再产生同类事件。
- **误报提示**：URLhaus 等源包含被入侵的合法主机，开源 IOC 规模大时误报可能增加，告警**需人工确认**，确认误报可用告警白名单加白。
- **局限**：走代理（passwall/xray 等）时 dst 是代理服务器 IP，隧道内真实恶意目标不可见；代理服务器 IP 通常不在恶意库中，因此不会误报，但也检测不到隧道内命中（如需 DPI 另行评估）。

---

## 7. 设置与系统

### 7.1 开关体系（两级）

系统采用**两级开关**，默认全部关闭，任何时候关闭都不影响路由器现有功能。

**① 总开关 `enabled`（系统级）**
- 关闭时：服务不执行任何采集、不改动任何系统配置、不下发任何管控规则；前端仍可访问并显示"系统未启用"提示页。
- 开启时：按下面的功能开关逐项生效。
- 语义：`enabled=false` 时，服务的**采集与管控全部静默**，仅保留 Web 服务与静态页面。

**② 功能开关（细粒度，独立生效）**

| 开关 key | 中文名 | 关闭时的行为 | 依赖 |
|---|---|---|---|
| `collect` | 流量采集 | 不读 conntrack / DNS 日志 / DHCP 租约，设备列表为空、流量图表无数据 | — |
| `dnsTap` | DNS 行为日志 | **不开启 dnsmasq 日志旁挂**，不改 `/etc/dnsmasq.conf`、不重启 dnsmasq；无域名维度归因 | 需 `enabled` |
| `deviceControl` | 设备管控 | 不下发断网/限速规则，策略只记录不执行 | 需 `enabled` |
| `domainBlock` | 域名封堵 | 不写 ipset、不下发 iptables 拦截规则 | 需 `enabled` + `collect`（需域名归因） |
| `schedule` | 定时策略 | 不按时间窗自动启停规则 | 需 `enabled` + `deviceControl` |
| `alerts` | 安全告警 | 不做规则研判、不产生事件（历史事件仍保留可查） | 需 `enabled` + `collect` |
| `history` | 历史统计 | 不写 1min 桶 JSONL、不保留历史曲线（仅实时） | 需 `enabled` + `collect` |

**开关变更的安全规则**：
- 关闭任何开关时，**必须同步撤销该开关已经下发的一切规则**（iptables/ipset/tc/dnsmasq），回到"从未开启"的状态；
- 关闭 `dnsTap` 时执行 `uci delete dhcp.@dnsmasq[0].logqueries` + `logfacility` + `uci commit dhcp` + dnsmasq stop/start + 健康检查（失败自动回滚）；
- 关闭 `enabled` 等价于关闭全部子开关（并撤销全部已下发规则）；
- 所有开关变更走 `PUT /api/settings`，返回变更后的完整设置与"本次实际执行的撤销动作"列表。

### 7.2 接口

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/settings` | `{"enabled":false,"collect":false,"dnsTap":false,"deviceControl":false,"domainBlock":false,"schedule":false,"alerts":false,"history":false,"collectIntervalSec":2,"retentionDays":14,"alert":{"enable":true,"scanPorts":20,"trafficMbPerHour":500,"threatUpdateHours":6},"version":"1.0.0","dataDir":"/mnt/mmcblk2p4/guanlan"}` |
| PUT | `/api/settings` | 接受上述开关字段的子集；`enabled` 置 false 会级联关闭全部子开关并撤销已下发规则。响应 `{"ok":true,"settings":{...},"applied":["撤销 UBM_FWD 规则 3 条",...],"revoked":["..."]}` |
| POST | `/api/settings/toggle` | 便捷开关：`{"key":"enabled","value":false}`，语义同上 |
| GET | `/api/system` | `{"model":"Phicomm N1","arch":"aarch64","kernel":"6.1.114","openwrt":"SNAPSHOT R2024.11.05","uptimeSec":3600,"memTotalMb":1844,"memFreeMb":760,"diskFreeMb":4200,"hostname":"Ytwos-N1","rssMb":28,"cpuPct":1.2}` |
| GET | `/healthz` | `{"ok":true,"uptimeSec":3600,"enabled":false}`（免鉴权，用于探活） |

### 7.3 系统未启用时的前端行为
- `GET /api/settings` 返回 `enabled:false` → 前端在**总览页顶部**显示醒目提示条：「系统未启用，当前仅显示配置状态，不采集、不管控、不影响路由器现有功能」+「启用系统」按钮；
- 大屏页（`#/screen`）仍可进入，但 HUD 显示「未启用」占位，不发起 SSE 订阅；
- 设备/流量/行为/安全页显示空态提示，**不报错**。


---

## 8. 实时推送 SSE

`GET /api/stream`（`Content-Type: text/event-stream`，服务端每 2 s 推一帧；25 s 无数据发注释心跳）

```
event: hello
data: {"version":"1.0.0","intervalMs":2000}

event: tick
data: {"ts":1761900000,
 "kpi":{...同 overview.kpi},
 "sys":{...同 overview.sys},
 "devices":[{"ip":"192.168.1.31","name":"MEIZU-Note-16","alias":"妈妈的手机","online":true,
             "upBps":1234,"downBps":5678,"conns":12,"risk":0.2,"blocked":false,"topCat":"video"}],
 "categories":[{"key":"video","upBps":1200,"downBps":5200000,"share":0.42}],
 "trendPoint":{"t":1761900000,"up":1234,"down":5678},
 "wan":{"rxBps":123456,"txBps":23456}}

event: alert
data: {Event}
```

分类固定键与色值（前端与后端一致，勿改）：

| key | 中文 | 色值 |
|---|---|---|
| `video` | 视频流媒体 | `#22d3ee` |
| `game` | 游戏 | `#a78bfa` |
| `social` | 社交聊天 | `#f472b6` |
| `web` | 网页浏览 | `#38bdf8` |
| `download` | 下载更新 | `#fbbf24` |
| `mail` | 邮件 | `#34d399` |
| `cloud` | 云盘存储 | `#2dd4bf` |
| `other` | 其他 | `#94a3b8` |

---

## 9. 约束

- 单页静态资源由同一端口提供；SPA 路由使用 hash（`#/devices`）。
- 所有 `POST/PUT/DELETE` 请求体为 JSON，`Content-Type: application/json`。
- 时间跨度查询最多 7 天；`limit` 最大 500。
- 服务端对写操作串行化（同一时刻只执行一次 iptables/tc），失败返回 500 且自动回滚已执行步骤。
