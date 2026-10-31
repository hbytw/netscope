# 观澜 NetScope · 3D 托盘大屏模块

Three.js 本地 ESM 内置（**无运行时 CDN**）。本目录只负责「3D 托盘场景 + 大屏 HUD 页面」，
不访问后端 API、不修改页面其它区域；数据由调用方通过 `scene.update(tickData)` 注入。

```
app/web/
├── screen.html                          # 独立大屏页（新窗口打开，无导航壳；自行校验登录）
└── js/
    ├── vendor/
    │   ├── three.module.js                  # three r170（0.170.0，npm pack 本地内置）
    │   └── addons/controls/OrbitControls.js
    └── 3d/
        ├── tray.js                          # createTrayScene(container, opts) —— 3D 场景
        ├── screen.js                        # mountScreen(el, api) / unmountScreen() —— 大屏页面
        ├── _preview.html                    # 独立自测页（合成数据，不依赖 ui/api.js）
        └── README.md
```

> 大屏主入口为 **新窗口 `app/web/screen.html`**（app.js 顶栏「3D 大屏」/品牌点击 → `window.open`）；
> 旧 `#/screen` SPA 路由保留兼容，内嵌/独立两种模式共用 `mountScreen`。

## 0. 前置：importmap（由 index.html 提供）

`tray.js` / `OrbitControls.js` 统一使用裸导入 `three`，依赖 `index.html` 的 importmap：

```html
<script type="importmap">
{"imports":{"three":"./js/vendor/three.module.js","three/addons/":"./js/vendor/addons/"}}
</script>
```

`three` 版本：**r170 / 0.170.0**（`THREE.REVISION === '170'`）。

## 1. 3D 场景：`createTrayScene(container, opts)`

```js
import { createTrayScene } from './3d/tray.js';

const scene = createTrayScene(containerEl, {
  onSelectDevice: (ip) => {},   // 点击设备芯片；点击空白处传 null
  onHoverDevice: (ip) => {},    // 鼠标悬停设备芯片；离开传 null
  quality: 'high' | 'medium',   // medium：关抗锯齿/粒子、DPR ≤ 1.5
  fx: 'off' | 'bloom',          // 预留；当前版本未启用后处理（见 §6）
});

scene.update(tickData);   // docs/api.md §8 tick（含 devices/categories/trendPoint/kpi/sys/wan）
scene.setHighlight(ip);   // 外部高亮某设备（null 取消）
scene.focusDevice(ip);    // 平滑聚焦某设备（自动高亮）
scene.resetView();        // 平滑回到默认全景
scene.resize();           // 容器尺寸变化（内部已用 ResizeObserver，一般无需手动调用）
scene.dispose();          // 释放全部 GPU 资源 / 事件监听 / rAF
scene.warmup(seconds);    // 预热 N 秒逻辑并渲染一帧（无头截图、首屏稳定用）
scene.getPerf();          // { mode, fps, drawCalls, triangles, points, deviceCount, labelTextures, heapMb, ... }
```

### 1.1 数据映射（`docs/api.md §8`，字段名未做任何改动）

| tick 字段 | 场景表现 |
|---|---|
| `categories[].share` | 分类扇柱角度与高度（8 项顺序固定，键/色值严格按 api.md §8） |
| `devices[]` | 外环六边形芯片；状态色：正常 `#22d3ee` / 限速 `#fbbf24` / 断网·离线 `#fb7185` / `risk>0.6` `#a78bfa`；光柱高度 `clamp((downBps+upBps)/200000, 0.8, 7)` |
| `trendPoint` | 累计为 60 点环形缓冲，驱动托盘外缘 60 段刻度柱 |
| `trend[]`（可选） | 若整帧携带 60 点趋势则整体覆盖缓冲（overview 兼容） |
| `kpi / sys / wan` | 底座场景不直接使用，由 `screen.js` HUD 消费 |

兼容：若没有 `devices` 但传入 `topDevices`（`/api/overview` 结构），会自动降级映射。
内部所有数值均为**指数平滑**（帧率无关的 `damp`），不突变。
分类扇柱高度按 `0.8 + share × 3.4`（clamp 0.8–4.2）映射；占比 0 时保留 0.05 rad 细条。

### 1.2 场景构成（对应 `docs/design.md §6.2`）

- 深空背景（CanvasTexture 径向渐变 + 星云/星点，一次性生成）+ Fog；
- 极坐标地面（半径 30 圆盘 + 8 环 × 24 辐 `LineSegments` + 径向光斑）+ 假阴影；
- 中心路由核心：六棱柱 `CylinderGeometry(2.2,2.2,0.9,6)` 青自发光 + 棱边线框 +
  **核心光塔**（扇柱升高后仍保证视觉焦点）+ 3 个不同倾角 Torus 光环反向旋转 +
  底部 RingGeometry 脉冲扩散 ×2 + 顶部光晕 Sprite；
- 数据托盘 `CylinderGeometry(13,13,0.7,96)` 深色金属（metalness .82 / roughness .46）+
  顶面 0.12 透明玻璃 + 外缘发光细环 + 同心环刻度（3 道）+ 每 30° 短刻度线 +
  **整体 0.02 rad/s 自转**（分类扇柱 / 刻度环同盘旋转）；
- 分类扇区：环形扇 `Shape.absarc` 式顶点生成（内径 3.4 / 外径 10.4），角度=实时占比、
  高度=实时占比；**侧面压暗 + 顶面亮色**（顶点色区分）；顶面霓虹描边 + 轻微自发光；
- 设备芯片：外环 r=15.5–17 交错排布，六边形薄片 `CylinderGeometry(0.85,0.85,0.22,6)`，
  竖直光柱（实心暗柱 + 外层「底暗顶亮」加法发光柱）+ 柱底落点光晕；
- 轨道与粒子：每设备一条 QuadraticBezierCurve3（设备→高位控制点→核心），
  自定义 shader 实现虚线随时间流动（速度 ∝ 速率）；单 `Points` 粒子（≤144，沿曲线循环）；
- 刻度环：半径 11.1，60 段 `InstancedMesh`，高度=最近 60 个趋势点归一化；
- 标签：`CanvasTexture` Sprite（名称 + 下行/上行速率，深色圆角底板 + 细边框），
  仅文本变化时重绘 + LRU 缓存；屏幕空间重叠规避（优先保留悬停/选中/高流量标签，其余自动隐藏）。

### 1.3 交互

- **拖拽旋转 / 滚轮缩放**（OrbitControls：阻尼 .06、极角 0.25π–0.48π、距离 12–40、
  target (0,3,0)、自动巡航 0.25 rad/min —— 手动按 dt 旋转，与帧率无关）；
- 悬停芯片：放大 + 光点增强 + 标签强制显示；点击：`onSelectDevice(ip)`；
  点击空白：`onSelectDevice(null)`；双击芯片：`focusDevice(ip)`；
- 入场动画：1.2s 从远处推进（墙钟+帧时间双参考，标签页节流时也能按时完成）。

## 2. 大屏页面：`screen.js`

```js
import { mountScreen, unmountScreen } from './3d/screen.js';

// #/screen 路由内嵌挂载（兼容保留）：
const handle = mountScreen(containerEl, api);   // api 见下
// 路由离开：unmountScreen();  或 handle.unmount();

// app/web/screen.html 独立窗口挂载：
mountScreen(containerEl, api, { standalone: true });
```

### 2.0 入口模式：新窗口（主）/ `#/screen`（兼容）

- **主入口**：`app/web/screen.html` 独立页面（无导航壳），由 `app.js` 顶栏「3D 大屏」按钮与品牌点击
  通过 `window.open('./screen.html', '_blank', 'width=1600,height=900')` 打开；当前页面的 `?mock=1` /
  `?mockoff=...` 演示参数会透传给新窗口；弹窗被拦截时退回旧 `#/screen` 内嵌路由。
- `screen.html` 复用 `theme.css` + `screen.css` + importmap，登录态由 Cookie 自动携带；未登录时显示
  「请先登录」并给出返回 `index.html` 入口（不依赖 app.js 外壳全局变量）。
- **独立模式**（`standalone:true`）下 HUD 顶部显示「✕ 返回管理界面」按钮，`Esc` 关闭大屏：
  优先 `window.close()`，被浏览器拦截时回退 `history.back()` / `./index.html`。
- **内嵌模式**（旧 `#/screen`）不注入返回按钮、不抢 `Esc`（由 app.js 负责 Esc 返回），行为与之前一致。
- 两种模式共用同一 `mountScreen/unmountScreen` 与 HUD，WebGL 画布、性能降级逻辑完全一致。

其余 api/数据契约：

- `api.getOverview(): Promise<overview>`（`docs/api.md §2`）
- `api.getTopology(): Promise<{nodes,links}>`（可选；网络拓扑层，`docs/api.md` / task-5 契约）
- `api.subscribe(handler)`：**兼容两种回调签名**
  - `handler(type, payload)` —— ui 的 `api.js` 当前实现（`type` = `'hello' | 'tick' | 'alert'`）
  - `handler(tickData)` —— 任务书最小契约
- 若 `api.subscribe` 缺失 → 自动退化为 **每 2s 轮询 getOverview**；两者都缺失时 HUD 显示等待态；
  本模块**不直接 fetch**。
- 首屏用 overview 补 `alerts / trend / categories / 首帧设备`；subscribe 模式下每 10s 刷新一次 overview 告警；
- 若 `api.getSettings` 存在，会读取系统总开关（30s 刷新）：`enabled === false` 时 HUD 显示
  「系统未启用」空态卡片（KPI 0、图例 0、Top5 空），**不当作错误**；启用后自动恢复。
  说明：ui 的 app.js 现在会在进入 `#/screen` 前先检查总开关，`enabled=false` 时直接走 2D 占位、
  不再调用本模块；这里保留的开关检测是**二次防御**（运行中切换总开关 / 其它调用方直连）。
- 实时 `alert` 事件与 overview.alerts 会按 id + ts 合并，不会因 10s 的 overview 刷新丢失刚推送的告警。
- **Esc**：内嵌模式由页面（ui 的 app.js）处理，本模块不抢占；独立窗口模式下由本模块负责关闭（见 §2.0）。
- 重复 `mountScreen` 会先 `unmountScreen`；容器 `el` 从 DOM 移除时 1s 内自动清理；
- WebGL 初始化失败时不会抛崩页面：HUD 保留，显示降级提示。

### 2.1 SSE 增量语义（与 backend-dev 对齐）

后端 `/api/stream` 的 tick 帧为**增量语义**，本模块已完整支持：

| 字段 | 处理 |
|---|---|
| `full: true` | `devices` 为全量列表 → 3D 与 HUD 设备字典整体替换 |
| `full: false` | `devices` 只含本帧变化设备 → 按 `ip` 合并更新（其余设备保留） |
| `full` 缺省 | 视为全量（兼容旧契约 / ui 的 mock tick），整体替换 |
| `deviceCount` | 当前可见设备总数（HUD「共 N 台」优先使用；`kpi.devices` 兜底） |
| `removed: ["ip"]`（可选） | **仅 `full=false` 帧**出现：先合并 `devices`，再从 3D/HUD 设备字典删除这些 ip（被 forget/隐藏的设备，≤2s 内消失；`online:false` 不在此列） |
| `kpi / sys / categories / trendPoint / wan` | 每帧全量，直接覆盖 |

3D 内部维护 `knownDevices`（ip → 设备）字典，再按流量挑选 Top24 渲染；HUD 维护自己的
`deviceMap` 用于 Top5 与总数统计。overview 的 `topDevices` 是部分快照：非空时按增量合并，
空列表时整体清空（配合系统未启用/无设备场景）。

已用 backend 抓取的真实 SSE 帧做过回放回归：
- 常规增量（hello + 1 帧 full 14 台 + 5 帧增量 + alert）：3D 与 HUD 均 **14 台**，增量不丢设备；
- forget 单台场景（tick#3 `full=false, deviceCount=13, removed:["192.168.1.43"]`）：3D 与 HUD 均在
  该帧后变 **13 台**，被隐藏设备不再出现，`kpi.devices` 同步为 13；
- forget 批量场景（同帧 `devices` 里另有正常变化设备 + `removed:["192.168.1.41","192.168.1.42","192.168.1.43"]`，
  升序、`deviceCount=11`）：3D 与 HUD 均变 **11 台**，「合并 + 删除」在同一帧正确处理；
- 全程 0 console error；截图见 `docs/shots-3d/screen-sse-replay-1920.png`、`screen-sse-forget-1920.png`、
  `screen-sse-forget-batch-1920.png`。

`/api/system` 新增的 `rssMb / cpuPct` 本模块不消费（属于顶栏系统状态，由 ui 处理）。

### 2.2 网络拓扑层（GET /api/topology）

3D 大屏在地面层新增网络节点与流向链路（不遮挡设备环/托盘）：

- **数据来源**：`api.getTopology()`（task-5 契约：`{nodes:[{id,type,name,cidr,up,rxBps,txBps}], links:[{from,to,kind,upBps,downBps}]}`）。
  `screen.js` 每 **3s** 拉取并调用 `scene.setTopology(topo)`（后端 buildTopology 5s 缓存，实际约 3~5s 刷新）；
  后端 `GET /api/topology` 已挂载（`app/api.go handleTopology`，含 LAN/ZeroTier/VPN/Docker/互联网/代理与
  direct/proxy/zt 链路），已用 `-demo` 后端 + Playwright 真实登录验证；mock 模式返回 `makeTopology` 合成拓扑，
  旧后端 404 时返回最小兜底（LAN↔互联网），确保大屏始终可渲染。
- **节点**：LAN 交换、ZeroTier、VPN 网关、互联网、代理（以及后端返回的任意虚拟接口 zt*/tun*/wg* 等），
  以地面半环布局（左→上→右，r=22）排布，避开 HUD 底部/角落面板；节点色按 type（lan 蓝 / zerotier 绿 /
  vpn 紫 / internet 青 / proxy 紫）；`up=false` 节点灰显但保留标签。
- **节点标签**：复用 CanvasTexture LRU，显示 `名称 + ↓rx + ↑tx`（bit/s 自动单位）；有流量的节点标签放大 18%，保证速率可读。
- **链路**：从中心核心到各节点的二次贝塞尔弧线，按 `kind` 着色（direct 青 / proxy 紫 / zt 绿 / vpn 紫罗兰 / lan 蓝）；
  **有流量 = 实线加粗弧管（宽度随 bps，0.022→0.08）+ 弧线中点速率标签（`↓下行 ↑上行`，1s 节流/LRU 重绘）+
  源端发光圆点（中心核心侧）+ 终点方向箭头锥体（指向节点）+ 流动粒子**，**无流量 = 虚线（无数值标签）**；
  粒子流向按 up/down 主导方向。方向标识按链路 kind 提亮，避免与同色弧管混在一起。
- **HUD 流向图例**：左上「流向图例」四色（直接出网青 / 经代理紫 / 经 ZeroTier 绿 / 经 VPN 紫罗兰）+
  「实线=有流量、虚线=无流量」，让用户一眼对应链路样式。
- **交互**：raycaster 支持节点拾取；hover 放大/发光并回调 `onHoverNode(id)`；点击节点高亮 + 相机聚焦
  （`focusNode`）并回调 `onSelectNode(id)`；点击空白同时清空设备/节点选中。`createTrayScene` 新增
  `onSelectNode/onHoverNode` 选项与 `scene.setTopology(topo)`、`scene.focusNode(id)` 方法（均为向后兼容的增量 API）。
- 节点数量与类型由后端决定；前端不硬编码虚拟接口，`up=true` 的 zt/tun/wg 自动上拓扑。

HUD（HTML 浮层，容器 `pointer-events:none`、面板 `auto`，样式内联注入 `<style>`，前缀 `.gl-screen`）：

- 左上：品牌「观澜 NetScope / 用户上网行为态势感知」+ 实时时钟（每秒）；
- 左上（品牌下）：流向图例（direct 青 / proxy 紫 / zt 绿 / vpn 紫罗兰 + 实线=有流量、虚线=无流量）；
- 右上：4 个 KPI（在线设备 / 活跃连接 / 总下行速率 / 告警数，tabular-nums）；
- 右侧：告警流（最多 4 条，severity 色条：critical/warn/info）；
- 左下：分类图例（8 色块 + 名称 + 占比 + 迷你占比条）；
- 底部中央：Top 5 设备横向条形榜；
- 右下：`拖拽旋转 · 滚轮缩放 · Esc 退出` 提示；
- 1600×900 / 1366×768 有响应式收缩规则。**HUD 内没有任何调试/预览按钮。**

## 3. 性能与资源策略

| 项 | 实现 |
|---|---|
| 帧率自适应 | rAF 按目标间隔跳帧：常态 **30fps**；`document.hidden` 暂停；`update()` 后 3s 无新数据 → **12fps** 巡航；指针交互（拖拽/hover/滚轮）后 1.2s 内临时 **60fps** |
| 几何复用 | 设备芯片/光柱/柱底光晕各 1 份共享 geometry；分类扇柱 2 份合并 geometry（顶面/侧面各 8 group，共用 8 套分类材质，顶点色压暗侧面）；刻度环 1 个 InstancedMesh；粒子单个 Points |
| 材质收敛 | 分类 8 套 + 设备状态 4 套 `MeshStandardMaterial` + 托盘/核心光塔 2 套结构件材质（固定 14 套，不随设备数增长）；辉光线/粒子/刻度用共享 basic/shader 材质 |
| 光源 | 固定 4 个：Hemisphere + 2 Point + 1 Directional；`shadowMap` 关闭（托盘下方径向渐变假阴影） |
| 标签纹理 | LRU `CanvasTexture` 缓存（上限 64，refcount 保护在用纹理），仅文本变化重绘，节流 1s |
| 内存 | 标签纹理 ≤24×512×160×4B ≈ 8MB；几何/顶点总计约 2.5 万三角；不启用后处理 render target；`dispose()` 释放 geometry/material/texture/renderer 并移除全部事件监听 |
| 设备上限 | >24 台只渲染 Top 24（按 `downBps+upBps`，对在场设备给 1.35 粘性系数避免频繁换人） |
| 粒子上限 | 24 × 6 = 144（≤200），单 Points + position/color/size 属性缓冲 |
| 验收实测（headless SwiftShader，真实 GPU 更快） | 8 台：drawCalls ≈ 104、三角 ≈ 22.3k、JS 堆 ≈ 12MB；24 台：drawCalls ≈ 195、三角 ≈ 24.1k、JS 堆 ≈ 10MB；CanvasTexture 8/24 张 |

## 4. 自测页 `_preview.html`

在 `app/web` 目录起静态服务（如 `python -m http.server 8811`）后打开：

```
/js/3d/_preview.html                     # 默认 8 台设备，合成 tick，每 2s 一帧
/js/3d/_preview.html?devices=24          # 24 台设备
/js/3d/_preview.html?q=medium            # 降级画质
/js/3d/_preview.html?hud=1               # 用 screen.js 渲染完整 HUD（内置假 api）
/js/3d/_preview.html?hud=1&inc=1         # SSE 增量语义：full / 增量帧交替，验证设备字典合并
/js/3d/_preview.html?hud=1&disabled=1    # 系统未启用空态：KPI 0 + 「系统未启用」卡片
/js/3d/_preview.html?hud=1&cycle=6       # 额外做 6 次 mount/unmount 循环自检（验证 dispose）
/js/3d/_preview.html?hud=1&frames=./_sse_fixture.jsonl            # 回放真实 SSE JSONL 帧（开发联调，自备文件）
/js/3d/_preview.html?hud=1&frames=./_sse_fixture.jsonl&removed=1  # 末尾追加一帧合成 removed 增量
```

- 页面左上按钮：8 台 / 24 台 / 暂停 / high / medium / 聚焦首个设备 / 复位视角 —— **仅自测页有**；
- 左下角状态栏：帧率模式、drawCalls、三角数、标签纹理数、相机距离、`U+FFFD` 错误数等；
- `window.onerror` / `unhandledrejection` / `console.error` 会显示在右下角红色面板；
- 无头截图时页面用 `warmup()` 直接推进到稳定构图，真实浏览器会自然播放入场动画。

## 5. 调参入口（`tray.js` 顶部 `CFG`）

| 键 | 默认 | 说明 |
|---|---|---|
| `trayRadius` | 13 | 数据托盘半径 |
| `sectorMinHeight / sectorMaxHeight` | 0.8 / 4.2 | 分类扇柱高度范围（`0.8 + share×3.4`；降低上限避免单类超大时遮挡其它顶面） |
| `deviceInner / deviceOuter` | 15.5 / 17 | 设备芯片交错双环半径 |
| `pillarMinHeight / pillarMaxHeight` | 0.8 / 7 | 速率光柱高度 clamp 范围 |
| `trendRadius` | 11.1 | 60 段趋势刻度环半径 |
| `cameraHome` | (0, 30, 40) | 默认全景机位（distance≈48.3；托盘/设备环/标签完整入画，四周 ≥6% 边距） |
| `minDistance / maxDistance` | 24 / 70 | 缩放范围（与相机拉远配套上调） |
| `autoRotateRadPerSec` | 0.25/60 | 自动巡航角速度 |
| `labelHeight` | 1.45 | 标签 Sprite 世界高度（数量多时自动再缩 0.74/0.84） |
| `topoRadius` | 22 | 网络拓扑节点地面环半径（半环「左→上→右」布局，避开 HUD 面板） |
| `topoLabelHeight` | 1.55 | 拓扑节点标签 Sprite 世界高度 |
| `topoLinkMaxWidth` | 0.085 | 有流量链路弧管最大半径（线宽随 bps 线性增强） |
| `topoFlowLabelHeight` | 1.25 | 有流量链路中点速率标签 Sprite 高度（`↓下行 ↑上行`） |
| `topoParticlesPerLink` | 5 | 每条有流量链路的流动粒子数（`quality='medium'` 时不渲染粒子） |
| `entryDuration / focusDuration` | 1.2 / 1.1 | 入场 / 聚焦相机动画时长 |
| `labelCacheMax` | 64 | 标签纹理 LRU 上限 |

`quality: 'medium'`：关闭 MSAA 与粒子、DPR ≤ 1.5，其余一致。

## 6. 已知限制 / 说明

1. **⚠️ 有意偏离 `docs/design.md §6.2` 的场景尺寸与相机（lead 视觉验收后定稿，请勿"照规范改回去"）**：
   - **场景半径有意保留放大值**：托盘 11→**13**、设备环 13.2/14.6→**15.5/17**、刻度环 10.9→**11.1**。
     原因：design §6.2 的原始尺寸按更保守的构图推导；产品已明确「可读性优先于占比」，缩回原尺寸会让
     设备环掉到 50% 以下、设备芯片与标签挤在一起。保留现状后设备环占画面约 55–58% 宽。
   - **相机相应拉远**：`(0,26,34)` → **`(0,30,40)`**（distance≈48.3，elev 34°，fov 保持 45），
     `minDistance/maxDistance` 18/60 → **24/70**；经投影核算 + 截图核对，托盘、设备双环、芯片与标签
     完整入画且四周留白 ≥6%，解决"镜头怼在托盘上/边缘被裁"的问题。
   - **扇柱高度上限 4.0/6.0 → 4.2**：`0.8 + share × 3.4`（clamp 0.8–4.2），贴近 design §6.2 的 4.0，
     避免单一分类占比 97% 时形成"高墙"遮挡相邻扇柱顶面（已用 backend 真实 SSE 帧验证）。
   - **中心光晕收敛**：glow sprite 4.2/0.09（运行时呼吸 0.08±0.02）、spark 1.6/0.14、尖点 1.4/0.38、
     点光 120→**15**。过曝根因是中心 PointLight 在扇柱顶面的镜面高光，不是 glow sprite；核心仍靠
     六棱柱 + 光塔 + 3 光环 + 脉冲保持视觉焦点，中心过曝像素占比已降到 ~0.2%。
   - 其余构图要素不变：极角 0.25π–0.48π、阻尼 .06、自动巡航 0.25 rad/min。
   - **修改前须知**：以上数值是经过 lead/deploy-verify 像素级验收的定稿；如确需改回 §6.2 原始值，
     必须重新做 1600×900/1920×1080 的构图与可读性验收（托盘完整入画、≥6% 边距、8 个扇柱顶面可辨）。
2. **Bloom / 后处理默认关闭且当前未启用**：为省 GPU 与显存，辉光用少量加法 Sprite/材质实现；
   `opts.fx='bloom'` 目前不会启用 EffectComposer（未打包相关 addon），以免出现「开关无效」的误解。
   若后续必须上真 Bloom，需要额外打包 `EffectComposer/RenderPass/UnrealBloomPass` 等文件。
3. 标签在密集（如 24 台）时采用屏幕空间重叠规避，会隐藏低优先级标签（悬停/选中/高流量优先），
   以保证「不重叠 + 可读」；悬停设备可让该标签强制显示。
4. 设备数量 >24 时只渲染 Top24；被挤出画面的设备不再有 3D 芯片与轨道（HUD 的 Top5 仍按全量设备算）。
5. 初始入场动画为墙钟+帧时间双参考；极低帧率下入场会直接落在稳定构图而不是长时间悬在远处。
6. `dispose()` 后对象不可再用；页面重复进入大屏请调用 `unmountScreen()`（内部已 `dispose`）。
   已用 `_preview.html?hud=1&cycle=6` 验证连续 6 次 mount/unmount 无异常、无 WebGL 上下文泄漏告警。
7. `screen.js` 的 HUD 是独立注入的 scoped 样式，不依赖 `css/screen.css`；与 ui 的玻璃拟态令牌视觉一致。
8. 设备标签速率按 `downBps / upBps` 展示；上行/下行统一 bit/s，单位自动 Kb/s、Mb/s、Gb/s。
9. 仅测试过 Chrome/Edge（Chromium 内核）；Safari 未验证（ES module + importmap 需较新版本）。
10. **网络拓扑层数据来源与后端状态**：`api.getTopology()` 请求 `GET /api/topology`；
    backend 已实现并挂载该路由（`app/topology.go buildTopology` + `app/api.go handleTopology`，
    返回 LAN/ZeroTier/VPN/Docker/互联网/代理节点与 direct/proxy/zt 链路），已用 `-demo` 后端 +
    Playwright 真实登录验证联调通过。前端 mock 模式（`?mock=1`）返回 `makeTopology` 合成拓扑；
    仅当旧后端 404 / 离线时返回最小兜底（LAN↔互联网），保证大屏仍可渲染。
    拓扑节点采用半环布局（r=22）避开 HUD 底部面板；拓扑标签与设备标签未做统一重叠规避，
    密集场景可能局部相邻，可后续按需纳入 declutter。

## 7. 验收截图

见 `docs/shots-3d/`：

- `3d-tray-1920.png` / `3d-tray-1600.png`：3D 托盘自测页（合成数据，8 台设备）
- `3d-tray-24devices-1920.png`：24 台设备上限
- `screen-1920.png` / `screen-1600.png`：真实 `#/screen` 页面（`?mock=1`，含 HUD）
- `screen-window-1920.png` / `screen-window-1600.png`：独立窗口 `screen.html?mock=1`（含「返回管理界面」按钮、拓扑层流向标签/箭头/图例）
- `screen-topology-1920.png` / `screen-topology-1600.png`：`?mock=1` 拓扑流向特写（链路速率标签 `↓下行 ↑上行`、源端光点/终点箭头、四色流向图例）
- `screen-real-backend-1600.png`：真实 Go 后端（`-demo`）联调截图：登录 → `screen.html` 独立大屏 + 真实 `/api/topology` 节点与链路流量
- `screen-disabled-1920.png`：系统未启用空态（`?hud=1&disabled=1`）
- `screen-sse-replay-1920.png`：回放 backend 抓取的真实 SSE JSONL（hello + full + 5 帧增量 + alert）
- `screen-sse-forget-1920.png`：真实 forget 场景回放（增量帧带 `removed:["192.168.1.43"]`，3D/HUD 13 台）
- `screen-sse-forget-batch-1920.png`：批量 forget 边界帧回放（同帧 3 个 removed + 正常设备更新，3D/HUD 11 台）

复现命令（在 `app/web` 下）：

```powershell
python -m http.server 8811
& "C:\Program Files\Google\Chrome\Application\chrome.exe" --headless=new `
  --enable-unsafe-swiftshader --disable-gpu-sandbox --window-size=1920,1080 `
  --virtual-time-budget=12000 --screenshot=shot.png `
  "http://127.0.0.1:8811/js/3d/_preview.html"
```
