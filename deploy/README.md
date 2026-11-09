# 观澜 NetScope · 部署与运维

本文档描述如何把观澜 NetScope 服务端构建、部署到任意 OpenWrt 旁路由（地址通过 `OWRT_HOST` 指定，不内置默认 IP），
以及如何回滚与卸载。

> **目标设备**：任意 OpenWrt 旁路由，支持 **aarch64** 与 **x86_64**（架构按本机/远端自动探测）
> **访问地址**：`http://<路由器LAN地址>:8088`（安装脚本会自动打印探测到的地址）
> **数据分区**：`/mnt/mmcblk2p4/guanlan`（overlay 仅剩 ~209 MB，数据一律落 mmcblk2p4）

---

## 1. 文件清单

| 文件 | 运行位置 | 说明 |
|---|---|---|
| `build.ps1` | Windows | 交叉编译静态二进制 → `dist/guanlan-<arch>`（默认 arm64，`-GoArch amd64` 或 `-Both` 构建两架构），输出体积与 sha256 |
| `deploy.ps1` | Windows | 构建 → 上传 → 远端执行安装 → 打印访问地址 |
| `install.sh` | 路由器 | 幂等安装：二进制、init 脚本、配置、UCI DNS 旁挂、启动自检 |
| `uninstall.sh` | 路由器 | 幂等卸载：停服务、删文件、还原 UCI、清理 iptables/tc、残留检查 |
| `rollback.sh` | 路由器 | **用户自助回退**（只做减法，随时可跑）——见 §5.4 |
| `rollback.ps1` | Windows | 用户自助回退的 Windows 侧执行器（`-Purge` / `-DryRun`） |
| `../tools/verify/rusage.sh` | 路由器 | 资源采样（RSS / VM_SIZE / 空闲 CPU），可重复调用 |

---

## 2. 快速上手

### 2.1 构建

```powershell
powershell -ExecutionPolicy Bypass -File deploy\build.ps1
```

产物：`dist/guanlan`（约 11 MB）+ `dist/build-meta.json`（体积/sha256/构建时间）。
脚本会按路由器本机架构（`uname -m`）校验 ELF 头：aarch64 需 `0xB7`、x86_64 需 `0x3E`，架构不符直接报错退出。

### 2.2 部署（构建 + 上传 + 安装 + 自检）

```powershell
powershell -ExecutionPolicy Bypass -File deploy\deploy.ps1
```

流程：

```
build.ps1
  → SFTP 上传 dist/guanlan      → /tmp/guanlan.new
  → SFTP 上传 deploy/install.sh  → /tmp/install.sh
  → SSH 执行 sh /tmp/install.sh /tmp/guanlan.new
  → 输出 healthz / free -m / df -h / ps 结果与访问地址
```

密码参数化，优先级：`-Password` > 环境变量 `OWRT_PASS`（必须设置，无内置默认值，避免密码入库）。
其他可覆盖项：`OWRT_HOST`、`OWRT_USER`。

> 二进制先落 `/tmp`（tmpfs）再由安装脚本原子 `mv` 到 `/usr/sbin`，
> 避免 overlay 写到一半断电导致文件损坏。

### 2.3 干跑（只打印命令，不改动路由器）

```powershell
powershell -ExecutionPolicy Bypass -File deploy\deploy.ps1 -DryRun
# 或直接在路由器上：
GL_APPLY=0 sh /tmp/install.sh
# 用户自助回退的干跑：
.\deploy\rollback.ps1 -DryRun
```

干跑模式下所有写操作都以 `[DRY] ...` 前缀打印，完整呈现执行流程，
**不会产生任何副作用**，可用于脚本评审与流程确认。

### 2.4 卸载 / 回退

```sh
sh uninstall.sh            # 完整卸载，保留数据目录
sh uninstall.sh --purge    # 连数据目录一起删
```

用户自助回退（随时可执行，默需协助）：

```powershell
.\deploy\rollback.ps1            # 完整回退
.\deploy\rollback.ps1 -Purge     # 连数据目录一起删
```

```sh
sh /tmp/rollback.sh               # 路由器侧（部署时已自动放好）
```

> 详见 **§5.4 用户自助回退（随时可用）**。

---

## 3. 安装布局

```
/usr/sbin/guanlan                    服务端二进制（go:embed 前端，静态链接）
/etc/init.d/guanlan                  procd 服务脚本（enable/start/stop/restart/status）
/etc/guanlan/config.json             配置（含密码哈希；已存在时保留用户改过的密码）
/mnt/mmcblk2p4/guanlan/
  ├─ data/                           状态与聚合数据（state.json / traffic-*.jsonl）
  └─ logs/                           运行日志 guanlan.log
/tmp/guanlan/                        tmpfs 运行时目录（重启即失，启动时自动重建）
  └─ dnsmasq.log                     DNS 查询日志（tmpfs，不占 overlay）
```

### procd 启动参数

```
start_stop_daemon -x /usr/sbin/guanlan -m -b -p /var/run/guanlan.pid -- \
    -addr 0.0.0.0:8088 -data /mnt/mmcblk2p4/guanlan/data -log-dir /mnt/mmcblk2p4/guanlan/logs
```

- `-m` / `-b`：后台运行并写 pid 文件
- `procd_set_param respawn 3600 5 5`：崩溃自动重启（3600 s 窗口内最多 5 次，间隔 5 s）
- 不设 CPU 亲和；不使用激进 nice 值（服务本身负载很轻）

---

## 4. DNS 查询日志旁挂（原生可逆）

### 4.1 实现方式

走 **UCI 原生选项**，不改 `/etc/dnsmasq.conf`，不在 `/tmp/dnsmasq.d/` 新增文件：

```sh
uci set dhcp.@dnsmasq[0].logqueries='1'
uci set dhcp.@dnsmasq[0].logfacility='/var/run/dnsmasq/guanlan-dns.log'
uci commit dhcp
/etc/init.d/dnsmasq stop; sleep 1; /etc/init.d/dnsmasq start
```

### 4.2 该固件的三个坑（实测，必须遵守）

| 坑 | 后果 | 正确做法 |
|---|---|---|
| `/etc/dnsmasq.conf` 自带 `log-facility=/dev/null` | 若在 `/tmp/dnsmasq.d/*.conf` 里再写 `log-facility=` → dnsmasq 启动失败（`illegal repeated keyword`）→ **全网 DNS 中断** | 绝不往 conf-dir 写 `log-facility`；只用 UCI 的 `logfacility` |
| `ubus call dnsmasq reload` 不存在 | `Method not found` | 不用 ubus reload |
| `/etc/init.d/dnsmasq reload` 有 bug | 会把 dnsmasq 停掉却拉不起来 → **全网 DNS 中断** | 只用 `stop` + `start` |

### 4.3 安全重启流程 `dns_restart_safe()`

所有 dnsmasq 重启都收敛到同一个函数：

```
stop  →  sleep 1  →  start  →  sleep 2  →  nslookup 健康检查
                                                  ├─ 成功 → 返回
                                                  └─ 失败 → uci delete 回滚
                                                             → 再次 stop/start
                                                             → 复查
```

install.sh / uninstall.sh **退出前**都会再做一次 `nslookup` 检查；
若 DNS 仍不可解析，脚本会执行紧急恢复分支并以非 0 退出，
**绝不以"DNS 已坏"的状态结束**。

### 4.4 还原

```sh
uci delete dhcp.@dnsmasq[0].logqueries
uci delete dhcp.@dnsmasq[0].logfacility
uci commit dhcp
/etc/init.d/dnsmasq stop; sleep 1; /etc/init.d/dnsmasq start
```

---

## 5. 安全红线

> 目标路由器正在被真实用户用于上网。**下列写操作会中断或影响用户连通性，
> 未获授权（team lead 明确"上机许可"）之前禁止执行。**

### 5.1 会影响用户上网的写操作（未授权禁止执行）

| 操作 | 影响 | 触发者 |
|---|---|---|
| `/etc/init.d/dnsmasq stop` / `start` / `reload` | **全网 DNS 中断**（reload 有 bug，stop 后必须能起来） | install.sh §6 / uninstall.sh §4 |
| `uci set/delete dhcp.@dnsmasq[0].logqueries\|logfacility` + `uci commit dhcp` | 需重启 dnsmasq 才生效 → 短暂 DNS 中断 | 同上 |
| 写入 `/etc/dnsmasq.conf` 或 `/tmp/dnsmasq.d/*.conf` | 重复 `log-facility` 会让 dnsmasq 起不来 | **本项目一律不写** |
| `iptables -I/-A` / `iptables -D/-F/-X` | 可能切断转发 | 后端管控功能；卸载时只清 `UBM_*` 自有链 |
| `tc qdisc add/del`、`ip link add/del ifb0` | 影响带宽与接口 | 后端限速功能；卸载时尽力而为 |
| `ifconfig` / `ip addr` / `ip route` 改动、`uci set network.*` | **断网** | **本项目一律不碰** |
| `uci set firewall.*` / 关闭防火墙 / 改 lan 区 | **断网** | **本项目一律不碰** |
| `reboot` / `sysupgrade` | 断网 + 配置风险 | **本项目一律不碰** |
| 修改 DNS 上游（`dnscache` / `resolv.conf`） | 解析异常 | **本项目一律不碰** |

**本项目只做这些最小改动**：

- 新增文件：`/usr/sbin/guanlan`、`/etc/init.d/guanlan`、`/etc/guanlan/config.json`、
  `/mnt/mmcblk2p4/guanlan/**`
- 修改 UCI：`dhcp.@dnsmasq[0].logqueries`、`dhcp.@dnsmasq[0].logfacility`（两个可逆选项）
- 新增 iptables 链：`UBM_*`（自有链，不改他人规则）
- 监听端口：`8088`（已确认空闲，lan 区认认 ACCEPT）

### 5.2 默风险的只读操作（随时可执行）

以下操作**不改变任何路由器状态**，可随时用于探测与验收取证：

```sh
uname -a; cat /proc/cpuinfo | grep -c processor
df -h / /mnt/mmcblk2p4          # 磁盘占用
free -m                          # 内存占用
ip addr; ip route                # 网络状态
netstat -lnt | grep 8088         # 端口占用
ps w | grep guanlan              # 进程状态
cat /proc/<pid>/status           # VmRSS / VmSize
cat /proc/<pid>/stat             # utime / stime（CPU 采样）
curl -s http://127.0.0.1:8088/healthz
nslookup www.baidu.com 127.0.0.1
uci show dhcp | grep -E 'logqueries|logfacility'
iptables-save; iptables -S
tc qdisc show
ls -l /etc/init.d/ /usr/sbin/
grep -n 'log-facility' /etc/dnsmasq.conf
```

配套的本地工具（只跑在 Windows 本机，不在路由器上装任何常驻进程）：

```powershell
node tools\verify\selftest.mjs    # 接口自检
node tools\verify\shots.mjs       # 默头 Chrome 截图 + console 错误采集
```

### 5.3 部署前状态快照（回滚依据）

`install.sh` 每次运行都会先记录：

```sh
iptables-save > /tmp/ubm-iptables-before.txt
uci show dhcp   > /tmp/ubm-dhcp-before.txt
free -m / df -h  > /tmp/guanlan/baseline.txt   # 内存 / 磁盘 / UCI 基线
```

### 5.4 用户自助回退（随时可用）

`deploy/rollback.sh` 是**给用户自己用的**一键回退工具：任何时候都能跑，不需要开发方协助。
它与 `uninstall.sh` **并存、互为备份**。

#### 何时用

- 用户想**立刻把路由器恢复原状**（不想要这个功能了）
- 安装后出现异常（服务起不来、端口冲突、页面异常），想先退干净再排查
- 升级了固件 / 换了配置后想"回到没装过的状态"

#### 怎么用

```powershell
# Windows 侧（推荐，一条命令）
.\deploy\rollback.ps1
.\deploy\rollback.ps1 -Purge      # 连数据目录一起删
.\deploy\rollback.ps1 -DryRun     # 只打印将要执行的动作，不真正执行
```

```sh
# 路由器侧（脚本已由部署流程放到 /tmp/rollback.sh）
sh /tmp/rollback.sh
sh /tmp/rollback.sh --purge
```

`rollback.sh` 在路由器上的两个位置：

| 路径 | 生命周期 |
|---|---|
| `/tmp/rollback.sh` | tmpfs，**路由器重启后会丢**（下次部署会重新放） |
| `/mnt/mmcblk2p4/guanlan/rollback.sh` | 持久化分区，**跨重启保留** |

#### 效果

恢复到"**从未安装过 NetScope**"的状态：

- 停止并禁用 `/etc/init.d/guanlan` 服务
- 删除 `/usr/sbin/guanlan` 与 `/etc/init.d/guanlan`
- 删除 `/etc/guanlan/` 配置目录
- 还原 DNS 旁挂（`uci delete` 两个 dnsmasq 选项 + `stop/start dnsmasq`）
- 只清理本项目自建的 `UBM_*` iptables 链（逐条删跳转 → flush → delete）
- 尽力清理 tc qdisc / ifb0
- **数据目录认认保留**；加 `--purge` / `-Purge` 才连 `/mnt/mmcblk2p4/guanlan` 一起删

#### 安全边界

- 执行期间**仅 DNS 有 1–2 秒解析空窗**（只有当 DNS 旁挂处于启用状态时才会 stop/start dnsmasq），
  其余时间网络不受影响
- **不会动**用户的 passwall / openclash / adbyby / docker 等任何配置
- 不碰 DNS 上游、不碰防火墙 lan 区、不碰网卡、**不重启路由器**
- 只做减法：只删本项目创建的东西，绝不新增或修改其它配置
- 可重复执行：跑第二遍不会出错，也不会产生额外副作用
- 退出前必须验证 DNS 可解析，否则走紧急恢复分支

#### 与 `uninstall.sh` 的区别

| | `uninstall.sh` | `rollback.sh` |
|---|---|---|
| 定位 | 开发/运维方的**完整卸载**流程 | 用户的**极速自保回退** |
| 风格 | 完整：含配置与数据选项、含详细残留检查 | 保守：**只做减法**，不新增不修改 |
| 目标读者 | 部署/验收人员 | 普通用户（默需协助） |
| 调用方式 | `sh uninstall.sh [--purge]`（需先上传到路由器） | `.\deploy\rollback.ps1` 或 `sh /tmp/rollback.sh`（部署时自动就位） |
| 残留检查 | 逐项检查并以退出码反映 | 同样会做健康检查 |

> 两者互为备份：用户自己随时能跑 `rollback.sh`；开发方做完整卸载与残留取证时用 `uninstall.sh`。

---

## 6. 验收用资源采样

`tools/verify/rusage.sh` 在路由器上直接执行，输出键值行：

```sh
sh rusage.sh guanlan
```

```
PID=12345
RSS_MB=28.44
VM_SIZE_MB=76.12
RSS_KB=29122
CPU_PCT_IDLE=0.85
CPU_PCT_CORE=3.40
CPU_CORES=4
SAMPLE_SEC=10
THREADS=9
UPTIME_SEC=3600
```

- `RSS_MB`：常驻内存，预算 **≤ 60 MB**
- `CPU_PCT_IDLE`：整机占用率（已按核数折算），预算 **≤ 3%**
- `CPU_PCT_CORE`：单核等效百分比（参考值）

采样间隔可用 `RUSAGE_SAMPLE_SEC=60` 调整（验收要求服务空闲 60 s 后采样）。

---

## 7. 故障排查

| 症状 | 排查 |
|---|---|
| 安装脚本报"找不到二进制来源" | 先确认 `dist/guanlan` 已构建并上传到 `/tmp/guanlan.new` |
| 报"不是有效的 ELF"或"架构不匹配" | 产物与本机架构不符，重新执行 `build.ps1 -GoArch <arm64\|amd64>` |
| 报"安装后大小不一致" | 上传过程中断，重新上传 |
| 服务起不来 | `cat /mnt/mmcblk2p4/guanlan/logs/guanlan.log`；`/etc/init.d/guanlan status` |
| healthz 不通 | 确认端口未被占：`netstat -lnt \| grep 8088` |
| DNS 异常 | `uci show dhcp \| grep -E 'logqueries\|logfacility'`；必要时 `uci delete` 两个选项并 `stop/start dnsmasq` |
| 3D 页面空白 | 确认 `app/web/js/vendor/three.module.js` 存在且被 go:embed 打进二进制 |

---

## 8. 编码约定（避免干提回归）

| 文件类型 | 必须使用的编码 | 原因 |
|---|---|---|
| Windows 脚本 `*.ps1` | **UTF-8 with BOM** | Windows PowerShell 5.1（Win11 认认 `powershell.exe`）读取默 BOM 的 UTF-8 时按 GBK 解码，中文会变乱码，**多字节字符的尾字节恰好吃掉引号**，导致字符串提前闭合、脚本解析失败 |
| 路由器脚本 `*.sh` | UTF-8 **without** BOM，LF 换行 | busybox ash 不识别 BOM，会在首行报 `not found`；CRLF 也会导致命令失败 |

已实际遇到的现象（已修复，引为记录）：

```
The string is missing the terminator: '.
Unexpected token 'xxx' })' in expression or statement.
```

修复命令（一行，不动任何逻辑）：

```powershell
$p = "deploy" + [IO.Path]::DirectorySeparatorChar + "your.ps1"
$txt = [System.IO.File]::ReadAllText($p, [System.Text.UTF8Encoding]::new($false))
[System.IO.File]::WriteAllText($p, $txt, [System.Text.UTF8Encoding]::new($true))
```

自检：

```powershell
powershell -ExecutionPolicy Bypass -File deploy" + [IO.Path]::DirectorySeparatorChar + "your.ps1 -DryRun
```

---

## 9. 版本与依赖

| 组件 | 版本 |
|---|---|
| Go | 1.26.1（Windows 交叉编译） |
| 目标架构 | linux/arm64（aarch64）或 linux/amd64（x86_64），CGO_ENABLED=0 |
| OpenWrt | SNAPSHOT R2024.11.05 flippy-92+o |
| Node（仅本机验收） | 24.x + playwright-core（用系统 Chrome，不下载浏览器） |
