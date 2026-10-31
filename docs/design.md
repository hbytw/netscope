# 观澜 NetScope · 视觉与交互设计规范 v1

> 风格关键词：**深空科技 / 玻璃拟态 / 极简霓虹 / 数据可读性优先**
> 目标屏幕：1920×1080 大屏为主，兼容 1366×768；触控/鼠标均可操作。

---

## 1. 色彩令牌（CSS Variables）

```css
:root{
  --bg-0:#05070d;         /* 页面底色，近黑蓝 */
  --bg-1:#0a0f1a;         /* 面板底色 */
  --bg-2:#101827;         /* 卡片/悬浮 */
  --line:rgba(148,163,184,.14);
  --text-0:#e8eefc;       /* 主文字 */
  --text-1:#9fb0cc;       /* 次文字 */
  --text-2:#5d6f8c;       /* 弱文字 */
  --brand:#22d3ee;        /* 主色 青 */
  --brand-2:#7c5cff;      /* 辅色 紫 */
  --ok:#34d399; --warn:#fbbf24; --crit:#fb7185; --info:#38bdf8;
  --glow:0 0 24px rgba(34,211,238,.35);
  --radius:14px;
  /* 分类色见 api.md §8，保持一致 */
}
```

- 深色底 + 细边框 + 轻微内阴影；禁止大面积纯黑/纯白。
- 玻璃面板：`background:linear-gradient(180deg,rgba(16,24,39,.82),rgba(10,15,26,.92)); backdrop-filter:blur(14px); border:1px solid var(--line)`。
- 光晕仅用于强调数据（KPI、设备风险、告警），不做无意义装饰。
- 状态色语义固定：绿=正常、黄=注意、红=严重、青=品牌/主指标。

## 2. 字体与排版

- 字体栈：`-apple-system,"Segoe UI","PingFang SC","Microsoft YaHei",system-ui,sans-serif`；数字用 `font-variant-numeric: tabular-nums`。
- 字号：KPI 数字 34–44px/700；面板标题 15px/600；正文 13px；辅助 12px；单位 11px 淡色。
- 间距基准 4px；面板内边距 16–20px；卡片圆角 14px，小组件 10px。

## 3. 布局骨架

```
┌──────────────────────────────────────────────────────────────┐
│ 顶栏 56px：品牌 LOGO + 名称 | 导航 Tab | 系统状态 | 时间 | 用户 │
├──────────────────────────────────────────────────────────────┤
│ 内容区（padding 18px，可滚动）                                 │
└──────────────────────────────────────────────────────────────┘
```
- 导航项：总览大屏 / 设备 / 流量 / 行为 / 安全 / 设置。当前项：底部 2px 青色渐变条 + 文字提亮。
- 大屏页（`#/screen`）隐藏导航，全屏画布 + HUD 浮层；按 `Esc` 返回。
- 内容区网格：12 列，间距 16px；卡片 `min-height` 依内容，禁止整页横向滚动。

## 4. 通用组件

| 组件 | 规范 |
|---|---|
| 卡片 `.card` | 玻璃面板 + 标题行（标题 + 右侧操作）+ 内容；`overflow:hidden` |
| KPI 块 | 标签(12px 弱) + 数值(36px 700) + 单位 + 环比小箭头（绿升/红降按语义取色） |
| 按钮 | 主按钮青底深字；次按钮透明+边框；危险按钮红描边；高度 32/36px，圆角 8px |
| 表格 | 表头 12px 弱色、行高 44px、hover 提亮、斑马纹禁用；IP/MAC 用等宽字体 |
| 标签 Chip | 圆角 999px，12px，透明底+同色描边；分类标签用分类色 |
| 开关 | 36×20px 轨道，开启青底、滑块白 |
| 输入/选择 | 深底、1px 边框、聚焦青色描边 + 光晕 |
| 抽屉 Drawer | 右侧 420px 滑出，遮罩 `rgba(0,0,0,.5)`，用于设备详情 |
| 弹窗 Modal | 居中 520px，遮罩 + 模糊 |
| Toast | 右上角，3 s 自动消失，成功/失败/信息三态 |
| 空态 | 居中图标 + 一句话说明 + 主操作按钮 |
| 骨架屏 | 面板加载时用 3 条微光条动画，避免白屏 |

## 5. 图表规范（自研 Canvas 2D，`web/js/ui/chart.js`）

- 面积图：上下行双色渐变填充（上行紫 `#7c5cff`，下行青 `#22d3ee`），0 基线细线，hover 显示十字线与数值气泡。
- 堆叠面积：分类色，透明度 0.85，图例可点击隐藏。
- 环图：中心显示总量（自动单位 B/KB/MB/GB），切片间距 2px，hover 高亮外扩 3px。
- 横向条形榜：左侧名称 120px 截断，右侧数值，条用渐变。
- 迷你趋势线（sparkline）：高 36px，无坐标轴。
- 所有图表：`devicePixelRatio` 自适应、`ResizeObserver` 重绘、无第三方依赖、支持空数据占位。

## 6. 3D 托盘大屏（Three.js，`web/js/3d/tray.js`）

### 6.1 模块契约（前端内部接口，冻结）
```js
import { createTrayScene } from './3d/tray.js';
const scene = createTrayScene(containerEl, {
  onSelectDevice: (ip) => {},     // 点击设备芯片
  onHoverDevice: (ip|null) => {},
  quality: 'high' | 'medium'      // 低端设备自动降级
});
scene.update(state);   // state = SSE tick 数据（api.md §8），内部自行 lerp
scene.setHighlight(ip|null);
scene.focusDevice(ip);           // 相机聚焦某设备
scene.resize();
scene.dispose();
```
- 不得依赖外部网络资源；Three.js 以本地 ESM 文件形式内置（`web/js/vendor/three.module.js` + `OrbitControls.js`）。
- 除 `tick` 数据外不访问 API；所有交互通过回调交给页面。

### 6.2 场景构图
- 相机：`PerspectiveCamera(45)`，初始 `(0,26,34)` 看向 `(0,3,0)`；`OrbitControls` 阻尼 0.06、自动巡航 0.25 rad/min、极角 0.25π–0.48π、距离 18–60。
- 地面：半径 26 的深色圆盘 + 极坐标网格（8 环 × 24 条辐，`LineSegments`，透明度 0.10–0.18）+ 中心径向渐变光斑。
- 路由核心（原点）：六棱柱 `CylinderGeometry(2.2,2.2,0.9,6)`，青色自发光 + 内部线框；外层 3 个倾角不同的 `TorusGeometry` 光环反向旋转；底部脉冲扩散环（`RingGeometry` 缩放+透明度循环）；上方 `Sprite` 光晕。
- 数据托盘：`CylinderGeometry(11,11,0.7,96)` 深色金属盘 + 顶面 0.06 透明玻璃层 + 外缘发光细环；整体以 0.02 rad/s 自转。
- 分类扇区：8 个环形扇柱（`Shape.absarc` + `ExtrudeGeometry`，内径 3.4、外径 10.4），顺序按 api.md §8，**角度=实时占比，高度=实时占比（0.4–4.0，lerp 平滑）**；分类色 + 轻微自发光；占比为 0 时保留 0.05 细条。
- 设备芯片：外环半径 13.2–14.6（按设备索引错位），离盘高 0.9；六边形薄片（`CylinderGeometry(0.85,0.85,0.22,6)`）+ 顶部小光点；颜色：正常青、限速黄、断网红、风险高紫红；下方垂直光柱 `CylinderGeometry(0.05,0.05,h)`，`h = clamp(speed/200kbps,0.3,6)`，加法混合自发光。
- 轨道与粒子：每设备一条 `QuadraticBezierCurve3`（设备→上方控制点→核心），`Line` 虚线动画朝核心流动；每设备最多 6 个 `Points` 粒子沿曲线循环，速度∝速率。
- 刻度环：半径 10.9，60 个细柱（`InstancedMesh`），高度=最近 60 点下行速率归一化。
- 标签：`CanvasTexture` Sprite（设备名+速率），字号 26px，常驻但不重叠；仅在文本变化时重绘纹理。

### 6.3 性能与降级
- `renderer.setPixelRatio(Math.min(devicePixelRatio,2))`，`antialias` 开启；`toneMapping = ACESFilmic`，`outputColorSpace = SRGB`。
- 设备 > 40 时只显示 Top 24；粒子总数 ≤ 200；`document.hidden` 时暂停渲染。
- 移动端/低端 GPU：`quality:'medium'` 关闭抗锯齿与粒子，DPR 上限 1.5。
- 统一在 `dispose()` 中释放 geometry/material/texture 与 `requestAnimationFrame`。

### 6.4 HUD 浮层（HTML，覆盖在 canvas 上，`pointer-events:none`，子元素可交互）
- 左上：品牌「观澜 NetScope」+ 副标题「用户上网行为态势感知」+ 实时时钟。
- 右上：4 个 KPI（在线设备 / 活跃连接 / 总下行 / 告警）。
- 右侧：告警流（最多 4 条，按级别色条）。
- 左下：分类图例（8 色块 + 名称 + 当前占比）。
- 底部中央：Top 5 设备横向条形榜。
- 交互：HUD 面板 `pointer-events:auto`；拖拽画布不被 HUD 阻断（HUD 仅占据边角）。

## 7. 页面要点

### 7.1 总览（`#/overview`，非 3D 轻量版）
KPI 行（4 项）+ 双栏：左「实时上下行曲线（60 点）」+ 右「分类占比环图」；下排：Top 设备榜 / 最近告警 / 系统状态。

### 7.2 设备（`#/devices`）
顶部：搜索框 + 分组筛选 + 「仅在线」开关 + 统计条（在线/离线/总数）。
表格列：设备（图标+别名/主机名+IP+MAC）、状态、实时上下行（带迷你趋势）、累计流量、风险、操作（断网/限速/详情）。
点击行 → 右侧抽屉：设备信息、实时曲线、Top 域名、Top 目标、连接列表、快捷操作。

### 7.3 流量（`#/traffic`）
时间范围 Tab（1h/6h/24h/7d）+ 刷新；主图上下行面积图（可切换堆叠分类）；下方三栏：分类环图 / Top 设备 / Top 域名；底部实时连接表（搜索 + 封禁操作）。

### 7.4 行为（`#/behavior`）
左：策略列表（开关、命中的设备数、时间窗摘要）；右：策略编辑器（名称、目标设备多选、生效日/时段、动作、分类多选、域名列表、限速值）。
上方快捷区：「一键断网」设备芯片墙 + 「全部恢复」；底部：DNS 拦截域名列表与还原按钮。

### 7.5 安全（`#/security`）
顶部：风险等级横幅（low/guard/high 三态色）+ 事件统计；左侧事件流（按级别过滤、确认、查看证据）；右侧设备风险排行 + 规则命中趋势。

### 7.6 设置（`#/settings`）
采集与留存、DNS 旁挂开关（带风险提示）、告警阈值、修改密码、系统信息、卸载与回滚指引。

## 8. 交互与可访问性
- 所有异步操作有 loading 态；失败 Toast + 面板内错误提示，不阻塞整页。
- 键盘：`Tab` 可达主要控件；`Esc` 关闭抽屉/弹窗/退出大屏。
- 对比度：正文与底色对比 ≥ 4.5:1；不只靠颜色表达状态（配图标/文字）。
- 动画：CSS 过渡 150–250ms `cubic-bezier(.4,0,.2,1)`；3D 数值用指数平滑，禁止突变。
