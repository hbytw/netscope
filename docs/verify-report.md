# 观澜 NetScope · 真机验收报告

- 目标设备：Phicomm N1（OpenWrt SNAPSHOT R2024.11.05，kernel 6.1.114-flippy-92+o，aarch64）
- 部署地址：`http://192.168.1.254:8088`（旁路由 br-lan 192.168.1.254/24）
- 验收时间：2026-10-31（真机部署 + 完整验证链路）
- 二进制：`dist/guanlan`，7.88 MB，静态 ELF aarch64，sha256 `4E2300D28A62D8E677E118393BD56A6BCCBAA09A10340425A6F82197F23CB114`（= 路由器 `/usr/sbin/guanlan`，产物与仓库代码完全可复现）
- 结论：**全部通过**

---

## 1. 部署

| 项目 | 结果 |
|---|---|
| 二进制安装 | `/usr/sbin/guanlan`，ELF 校验（magic 7f454c46, machine 183/aarch64）通过 |
| init 脚本 | `/etc/init.d/guanlan`（procd，`USE_PROCD=1`，开机自启 enable，崩溃自动重启） |
| 配置 | `/etc/guanlan/config.json`（初始密码 `guanlan2026`，登录后可改） |
| 数据目录 | `/mnt/mmcblk2p4/guanlan/{data,logs}`（磁盘可用 4.2 GB） |
| 健康检查 | `/healthz` → `{"enabled":false,"ok":true}`，首次即通过 |
| 服务状态 | `pidof guanlan` 运行中，端口 8088 监听 |

## 2. 安全不变量（用户硬性要求：不打开不影响现有功能）

| 硬指标 | 期望 | 实测 | 判定 |
|---|---|---|---|
| 总开关默认 | `enabled=false` | `{"enabled":false,"ok":true}` | ✅ |
| 7 个功能开关默认 | 全关 | `collect/dnsTap/deviceControl/domainBlock/schedule/alerts/history` 全 `false` | ✅ |
| iptables 规则 | 无新增/删除链 | 前后**链集合一致**，无 `UBM_*` 链，`iptables-save` 仅时间戳/计数器差异（网络流量自然累计） | ✅ |
| ipset | 无 `ubm_block` | 不存在 | ✅ |
| tc 限速 | 无 | 无 htb/ifb 规则 | ✅ |
| dnsmasq 配置 | 未改动 | `uci logqueries` 空、`/etc/dnsmasq.conf:38 log-facility=/dev/null`（与部署前逐字节一致）、`/tmp/dnsmasq.d/` 无本项目文件 | ✅ |
| DNS 健康 | 正常 | `nslookup www.baidu.com` 通过，dnsmasq 存活 | ✅ |
| 数据采集（未启用） | 空态 | overview devices=0、kpi 全 0，**不采集** | ✅ |

## 3. 资源占用（用户要求：尽量减少资源占用）

| 指标 | 预算（方案.md §8） | 实测（60s 采样，未启用态） | 判定 |
|---|---|---|---|
| 进程 RSS | ≤ 60 MB | **6.43 MB**（约预算 10.7%） | ✅ |
| 空闲 CPU（整机 4 核） | ≤ 3% | **0.02%** | ✅ |
| 线程数 | — | 9 | — |
| 磁盘 | ≤ 60 MB/14d | 服务本体 7.88 MB + 数据（未启用不落盘） | ✅ |

## 4. 接口自检（selftest.mjs，真机 192.168.1.254:8088）

**30/30 通过**，覆盖：

- 鉴权：未登录 401、登录 `{"ok":true}` + Cookie、session `{"authed":true}`
- 数据（未启用态）：overview / devices / traffic / policies / events 全部 HTTP 200 且不报错、返回空态而非 5xx
- 管控：`/api/enforce/status`（iptablesRules=0 / tcDevices=0 / dnsBlockedDomains=0 / dnsTap=false）、`/api/enforce/dns`（domains=[]）
- 开关体系：enabled=false → pending 7 项 + hint「系统未启用」；enabled=true → applied 含总开关；开启子开关 → applied 含「已开启 dnsmasq 日志旁挂」；**恢复原开关集 → enabled 还原 false**
- 数据恢复：开启子开关后 overview `devices=5, kpiHasData=true`（真机 5 台设备实时采集，含 95 台在线连接、741 Mb/s 下行）
- 健康：`/healthz` `{"enabled":false,"ok":true}`

## 5. 3D 大屏与前端

- 顶栏「3D 大屏」入口 + 品牌区可点击 → `#/screen` 渲染 WebGL 托盘（3200×1800 @1600×900 CSS，`kind=webgl, hasGL=true`）
- 相机 (0,30,40)、min/max 24/70：托盘完整入画、四周 ≥6% 留白、8 类扇柱顶面 7/8 可辨
- 中心光晕收敛（PointLight 120→15），中心过曝像素占比 0.21–0.27%
- 截图验收：8/8 张、console error 0、pageerror 0、requestfailed 0、issues 0

## 6. 回退 / 卸载 / 重装验证（用户要求：随时可回退）

| 步骤 | 结果 |
|---|---|
| 8a `rollback.sh` 干跑 | 正确呈现全部删除动作，不实际执行 |
| 8a `rollback.sh` 实跑 | 服务停止+取消自启、二进制/init/配置删除、**DNS 旁挂未启用故未重启 dnsmasq**、回退后验证全 `[OK]`、DNS 可解析 |
| 8b `uninstall.sh --purge` | 10 项检查全 `[OK]`：端口关闭、无进程、二进制/init/配置/数据目录全移除、无 UBM 链、UCI logqueries/logfacility 清除、dnsmasq 存活、nslookup 正常 |
| 8c 重新部署 | 健康检查 `{"enabled":false,"ok":true}`，交付状态就绪 |

## 7. 关键修复记录（真机暴露，均已在部署前闭环）

1. **install.sh 预置 DNS 旁挂** → 违背「不打开不影响」，移除，改为由 dnsTap 开关控制（安装时 dnsmasq 保持原状、零 DNS 空窗）。
2. **install.sh 要求 `start_stop_daemon`** → flippy 固件无此 busybox 组件，改查 `/etc/rc.common`（procd 环境判断）。
3. **init 脚本传 `-log-dir`** → 二进制无此 flag（只有 -addr/-web/-data/-demo/-dry-run），移除。
4. **dnsTap 的 `uci logfacility` 与 `/etc/dnsmasq.conf:38 log-facility=/dev/null` 重复关键字** → dnsmasq 启动失败（`illegal repeated keyword`），后端自动回滚保住 DNS。修复：改为「UCI 只写 logqueries + 精确 sed 修改 conf 文件 log-facility（备份原值，关闭还原）」。真机开→关循环验证：旁挂正常、日志采集到真实查询、还原 `/dev/null` 无残留。
5. **后续硬化（backend-dev 复核发现的 3 处隐患，均已修复）**：
   - 备份幂等守卫写反（`grep`→`test -s`）：重复 enable 不再污染备份，disable 能精确还原 `/dev/null`（真机双重 enable→disable 验证）；
   - conf 行格式容错（容忍空白 + `grep -m1` + 替换后校验唯一行，>1 报错防重复源）；
   - 还原失败不再静默（`dnsConfRestoreLogFacility` 返回 error，disable 还原失败时反做 + 报错，避免"已关闭但仍写日志"漂移）。
6. **post-deploy 修复（backend-dev，已并入最终产物）**：硬化引入的 `grep -c` 校验在 `-demo`/`-dry-run` 下误判 → 已限定仅真实模式执行（新增 `TestDNSTapEnableDryRun` 回归）；enable 失败早退回滚补全 conf 还原。最终二进制 sha `4E2300D2...23CB114` 与仓库代码一致，已重新部署验证 30/30。

## 8. 结论

- 部署完成且可正常使用；**默认全关**，对用户现有上网功能零影响（iptables/ipset/tc/dnsmasq 全部未动，链集合逐行一致）。
- 资源占用远低于预算（RSS 6.43MB / CPU 0.02%）。
- 开关体系开→关精确还原，回退/卸载/重装全验证，**随时可一键回退**。
- 访问 `http://192.168.1.254:8088`，账号 `admin` / 初始密码 `guanlan2026`（请尽快在设置页修改）。

## 9. 待用户操作

1. 登录后**立即修改默认密码**（设置页）。
2. 确认开关体系：默认全关，按需开启「启用系统」+ 功能开关。
3. 如需完全移除：`.\deploy\rollback.ps1`（Windows）或 `sh /tmp/rollback.sh`（路由器）。
