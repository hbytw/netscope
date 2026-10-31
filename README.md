# 观澜 NetScope · 用户上网行为态势感知

面向 OpenWrt 旁路由的**上网行为管理 + 态势感知**系统。

- 3D 托盘态势大屏（Three.js，无 CDN、无 WebGL 依赖包外资源）
- 流量分析、行为管控、设备管理、安全态势、设置
- **两级开关**：总开关 + 7 个功能开关，**默认全关**；关闭时对路由器现有功能零影响

---

## 安装

### 方式 A：Release 一键安装包（推荐）

从 [Releases](https://github.com/hbytw/netscope/releases) 下载对应架构的包，上传到路由器执行：

```sh
# 1) 下载 guanlan_<version>_aarch64_generic.tar.gz 并上传到路由器 /tmp
# 2) 解压 + 一键安装（自动建目录、生成配置、注册 procd 服务并启动）
cd /tmp && tar xzf guanlan_*.tar.gz
sh install.sh ./guanlan
# 3) 打开 http://<路由器IP>:8088 ，默认账号 admin / guanlan2026（请立即修改）
```

> 也提供 `.ipk` 包；但部分 OpenWrt 固件的 `opkg` 对文件安装支持不完整，
> 若 `opkg install` 报 `Malformed package file`，请改用上面的 tar.gz 方式。

随时回退（把路由器恢复到未安装状态）：

```sh
sh /tmp/rollback.sh          # 标准回退（保留数据）
sh /tmp/rollback.sh --purge  # 连数据一起删
```

### 方式 B：源码构建（开发机）

见下方「快速开始（Windows）」。

> **安全提示**：仓库不含任何硬编码密码。部署脚本通过环境变量 `OWRT_PASS` 读取路由器密码，
> 请先 `export OWRT_PASS='你的密码'`（Windows：`$env:OWRT_PASS='你的密码'`）。

## 1. 快速开始（Windows）

```powershell
# 1) 构建（交叉编译 linux/arm64 静态二进制，约 7.9 MB）
.\deploy\build.ps1

# 2) 部署到路由器（上传 + 安装 + 自检）
.\deploy\deploy.ps1

# 3) 打开 http://192.168.1.254:8088
#    默认密码：guanlan2026   ← 请立刻在「设置」页修改
```

一键完成"部署 → 自检 → 资源采样 → 接口自检 → 截图 → 回退验证 → 卸载验证 → 重新部署"：

```powershell
.\deploy\run-verify.ps1
```

## 2. 随时回退（重要）

发现任何问题，**一条命令**把路由器恢复到"从未安装过本软件"的状态：

```powershell
.\deploy\rollback.ps1            # 干跑预览（什么都不会改）
.\deploy\rollback.ps1            # 实际回退
.\deploy\rollback.ps1 -Purge     # 连同数据目录一并删除
```

也可以直接在路由器上执行（部署时已放好一份）：

```sh
sh /tmp/rollback.sh          # /tmp 重启会丢，持久副本在 /mnt/mmcblk2p4/guanlan/rollback.sh
sh /mnt/mmcblk2p4/guanlan/rollback.sh
```

**回退的安全边界**（已实测验证，见 `docs/方案.md` §7.0）：

| 项目 | 行为 |
|---|---|
| 只做减法 | 仅删除本项目自有的 `UBM_FWD` / `UBM_IN` 链、`ubm_block` ipset、tc/ifb 限速配置 |
| 不碰他人规则 | 其他链（passwall / openclash / adbyby / docker 等）的规则**逐条保留** |
| 不改用户配置 | 不改防火墙 lan 区、不改网卡、不改 DNS 上游；`dnsmasq` 仅在旁挂过时才 stop/start，且带健康检查与自动恢复 |
| 不重启路由器 | 全程不 reboot、不 sysupgrade |
| 幂等 | 重复执行安全；已验证零残留 |

> ⚠️ `rollback.ps1` 与 `deploy.ps1` 等所有 `.ps1` 必须存为 **UTF-8 with BOM**（Windows PowerShell 5.1 对无 BOM 的 UTF-8 按 GBK 解码，中文会吃掉引号导致语法错误）。

## 3. 开关体系（默认全关）

| 级别 | 开关 | 关闭时的行为 |
|---|---|---|
| **总开关** | 启用系统 | 级联关闭全部子开关，并**撤销一切已下发的 iptables / ipset / tc / dnsmasq 变更** |
| 功能开关 | 流量采集 | 不读 conntrack / DNS / DHCP，设备与图表为空 |
| | DNS 行为日志 | **不启用 dnsmasq 日志旁挂**，不重启 dnsmasq |
| | 设备管控 | 不下发断网 / 限速 |
| | 域名封堵 | 不写 ipset、不下发拦截 |
| | 定时策略 | 不按时间窗自动启停 |
| | 安全告警 | 不做风险研判（历史事件保留） |
| | 历史统计 | 只保留实时数据，不落盘 |

**安全不变量**：任一开关关闭时，路由器行为与"从未安装本软件"完全一致。安装后服务在跑、页面能开能配置，但**默认不采集、不管控、不碰路由器任何现有配置** —— 需要时在「设置」页点「启用系统」才开始工作。

## 4. 目录结构

```
app/                  Go 服务端（零第三方依赖，纯标准库）
  *.go                16 个源文件 + 单元测试
  web/                前端（原生 ES Module + 自绘图表 + Three.js r170 本地化）
    js/3d/            3D 托盘场景与 HUD
    js/ui/            5 个管理页
    js/vendor/        Three.js（本地，不走 CDN）
deploy/               构建 / 部署 / 安装 / 卸载 / 回退脚本
docs/                 方案、API 契约、设计规范、验收报告、截图
tools/                探测与验收工具（SSH、截图、接口自检）
```

## 5. 文档

| 文档 | 内容 |
|---|---|
| [docs/方案.md](docs/方案.md) | 环境探测结论、总体架构、采集设计、功能模块、资源预算、风险控制、里程碑 |
| [docs/api.md](docs/api.md) | 冻结的 API 契约（含两级开关语义） |
| [docs/design.md](docs/design.md) | 视觉令牌、排版、组件、图表、3D 场景规范、页面规格 |
| [docs/verify-report.md](docs/verify-report.md) | 真机验收报告（资源占用、回退验证） |
| [deploy/README.md](deploy/README.md) | 部署/卸载/回退操作手册与安全红线 |

## 6. 运行环境

- 路由器：OpenWrt，aarch64（已在 Phicomm N1 / OpenWrt SNAPSHOT 实测）
- 服务端：Go 1.21+，交叉编译 `linux/arm64`，静态链接，`CGO_ENABLED=0`
- 浏览器：Chrome / Edge（需 WebGL2）
- 端口：8088（Web）；数据目录 `/mnt/mmcblk2p4/guanlan/`
