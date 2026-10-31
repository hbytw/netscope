# 观澜 NetScope · 验收取证工具

本目录提供三件套，用于部署后的自动化验收取证：

| 文件 | 运行位置 | 说明 |
|---|---|---|
| `selftest.mjs` | Windows 本机 | curl 风格接口自检，逐项探测 REST 接口并输出结果表 |
| `shots.mjs` | Windows 本机 | 无头 Chrome 登录 → 依次访问 7 个页面 → 截图 → 采集 console 错误 |
| `rusage.sh` | 路由器 | 资源采样（RSS / VM_SIZE / 空闲 CPU），输出键值行 |

> **重要**：所有浏览器/Node 进程只在 Windows 本机运行，
> **不会在路由器上安装任何常驻监控或代理进程**。

---

## 1. 安装

```powershell
cd tools\verify
npm install
```

只安装 `playwright-core`（不下载浏览器），使用系统已安装的 Chrome / Edge。

浏览器路径查找顺序（可用环境变量覆盖）：

| 环境变量 | 默认值 |
|---|---|
| `GUANLAN_CHROME` | `C:\Program Files\Google\Chrome\Application\chrome.exe` |
| `GUANLAN_EDGE` | `C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe` |

找不到任一浏览器时脚本以退出码 `2` 结束并给出提示。

---

## 2. 环境变量

| 变量 | 默认值 | 说明 |
|---|---|---|
| `GUANLAN_URL` | `http://192.168.1.254:8088` | 目标服务地址 |
| `GUANLAN_USER` | `admin` | 管理员账号 |
| `GUANLAN_PASS` | `guanlan2026` | 管理员密码 |
| `GUANLAN_PAGE_WAIT_MS` | `3500` | 每页渲染等待（毫秒） |
| `GUANLAN_TIMEOUT_MS` | `45000` | 单次请求/导航超时 |
| `GUANLAN_CHROME` / `GUANLAN_EDGE` | 见上 | 浏览器可执行文件路径 |

---

## 3. 接口自检 `selftest.mjs`

```powershell
node tools\verify\selftest.mjs
```

自检项：

| # | 接口 | 期望 |
|---|---|---|
| 1 | `GET /healthz` | HTTP 200 且 `{"ok":true}` |
| 2 | `GET /api/overview`（未登录） | HTTP 401（鉴权拦截生效） |
| 3 | `POST /api/login` | HTTP 200 `{"ok":true}` + `gl_session` Cookie |
| 4 | `GET /api/session` | HTTP 200 `{"authed":true}` |
| 5 | `GET /api/overview` | 含 `kpi` / `sys` / `categories` / `trend` / `topDevices` |
| 6 | `GET /api/devices` | `devices` 数组，含 `ip`/`mac`/`online` |
| 7 | `GET /api/traffic?range=1h` | `range=1h`，含 `series`/`bucketSec`/`byCategory` |
| 8 | `GET /api/policies` | `policies` 数组 |
| 9 | `GET /api/events` | `events` 数组 + `summary` |
| 10 | `GET /api/enforce/status` | 含 `iptablesRules`/`tcDevices`/`dnsBlockedDomains`/`activePolicies`/`dnsTap` |
| 11-13 | `GET /api/traffic?range=6h\|24h\|7d` | 各 range 正常返回 |
| 14-16 | `GET /api/settings` / `/api/system` / `/api/security/risk` | HTTP 200 + JSON |

输出：`docs/selftest-summary.json`（含每项的期望/实际/结论 + 关键 JSON 片段）。
退出码：全部通过 `0`，否则 `1`。

---

## 4. 截图 `shots.mjs`

```powershell
node tools\verify\shots.mjs
```

- **单次浏览器会话**：登录一次，依次访问 7 个页面，结束（或异常）时确保 `browser.close()`
- 视口 `1600×900`，`deviceScaleFactor: 2`（截图实际 3200×1800）
- 每页等待 3.5 s（SSE 推送 / 图表 / 3D 场景有足够时间渲染）
- 页面清单（对应 `docs/design.md` §7）：

| 路由 | 输出文件 | 说明 |
|---|---|---|
| `#/screen` | `docs/shots-screen.png` | 3D 托盘态势大屏 |
| `#/overview` | `docs/shots-overview.png` | 总览 |
| `#/devices` | `docs/shots-devices.png` | 设备管理 |
| `#/traffic` | `docs/shots-traffic.png` | 流量分析 |
| `#/behavior` | `docs/shots-behavior.png` | 行为管控 |
| `#/security` | `docs/shots-security.png` | 安全态势 |
| `#/settings` | `docs/shots-settings.png` | 设置 |

采集内容：

- `console` 事件（type=error），带页面 id、文本、来源 URL 与行号
- `pageerror`（未捕获异常），带堆栈
- `requestfailed`（请求失败），带 method/URL/原因
- HTTP ≥ 400 的响应
- 页面健康度：是否仍停留在登录页、body 文本是否过短（疑似空白）、声明图表但无 canvas
- **3D 画布着色像素占比**：读取 `<canvas>` 的 `getImageData`，统计色彩像素比例，
  比例过低判定为"3D 大屏空白"

输出：`docs/shots-summary.json`。
退出码：无 console error 且无问题项 `0`，否则 `1`。

### 无头 Chrome 参数

```
--enable-unsafe-swiftshader --disable-gpu-sandbox --no-sandbox
--disable-dev-shm-usage --ignore-gpu-blocklist --use-gl=swiftshader
```

`--enable-unsafe-swiftshader` 用于让 WebGL 在无 GPU 的 CI/桌面环境用 SwiftShader 软件渲染，
避免 `THREE.WebGLRenderer: Error creating WebGL context` 类报错。

---

## 5. 资源采样 `rusage.sh`

在路由器上执行：

```sh
sh rusage.sh guanlan
```

输出：

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

- `RSS_MB` 常驻内存，预算 **≤ 60 MB**
- `CPU_PCT_IDLE` 整机占用率（按核数折算），预算 **≤ 3%**
- 采样间隔：`RUSAGE_SAMPLE_SEC=60`（验收要求服务空闲 60 s 后采样）
- 退出码：`0` 成功；`2` 未找到进程

---

## 6. 验收报告生成 `report.mjs`

把各模块的产出聚合成 `docs/verify-report.md`（固定 6 个小节）：

```powershell
node tools\verify\report.mjs `
  --deploy-log deploy.log `
  --rusage-before before.txt `
  --rusage-after after.txt `
  --uninstall uninstall.log
```

| 数据源 | 来源 |
|---|---|
| 版本 / 体积 / sha256 | `dist/build-meta.json`（`build.ps1` 生成） |
| 接口自检结果 | `docs/selftest-summary.json`（`selftest.mjs` 生成） |
| 截图 / console 错误 | `docs/shots-summary.json`（`shots.mjs` 生成） |
| 部署日志 | `--deploy-log` |
| 资源采样 | `--rusage-before` / `--rusage-after`（`rusage.sh` 输出） |
| 卸载验证 | `--uninstall` |

报告的 6 个小节：

```
## 1. 部署概况    ## 2. 接口自检    ## 3. 资源占用
## 4. 页面截图      ## 5. 问题清单      ## 6. 回滚与卸载验证
```

---

## 7. 一次性跑完

```powershell
cd tools\verify
npm run verify      # = selftest.mjs + shots.mjs
```

或直接：

```powershell
node tools\verify\selftest.mjs ; node tools\verify\shots.mjs
```

---

## 8. 报告

两个脚本的 JSON 汇总是 `docs/verify-report.md` 的数据来源。
报告小节固定为：

```
## 1. 部署概况      2. 接口自检      3. 资源占用
## 4. 页面截图      5. 问题清单      6. 回滚与卸载验证
```
