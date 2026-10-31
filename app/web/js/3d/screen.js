/*!
 * 观澜 NetScope · 大屏页面（canvas + HUD 浮层）
 * ------------------------------------------------------------------
 * 用法（ui 的 #/screen 路由）：
 *   import { mountScreen, unmountScreen } from './3d/screen.js';
 *   const handle = mountScreen(containerEl, api);
 *   // ... 路由离开时：unmountScreen();
 *
 * api 契约（容忍缺失）：
 *   api.getOverview(): Promise<overview>          // 见 docs/api.md §2
 *   api.subscribe(handler): () => void            // handler 收到 SSE tick（§8）
 *   —— 若 api.subscribe 缺失，则退化为每 2s 轮询 getOverview。
 * 本模块不直接 fetch；所有数据来自传入的 api。
 * HUD 样式在本文件内注入（scoped 到 .gl-screen），不修改 css/ 目录。
 */

import { createTrayScene, CATEGORY_META } from './tray.js';

const TAU = Math.PI * 2;

/* ---------- 格式化工具 ---------- */

function formatRate(bps) {
  // 统一按字节速率显示（bit/s ÷ 8 = byte/s，MB/s），与管理页 formatBps 一致
  const v = Math.max(0, Number(bps) || 0) / 8;
  if (v >= 1024 * 1024 * 1024) return { v: (v / (1024 * 1024 * 1024)).toFixed(2), u: 'GB/s' };
  if (v >= 1024 * 1024) return { v: (v / (1024 * 1024)).toFixed(1), u: 'MB/s' };
  if (v >= 1024) return { v: (v / 1024).toFixed(0), u: 'KB/s' };
  return { v: v.toFixed(0), u: 'B/s' };
}

function rateText(bps) {
  const r = formatRate(bps);
  return r.v + ' ' + r.u;
}

function formatCount(n) {
  const v = Math.max(0, Number(n) || 0);
  return v >= 10000 ? (v / 1000).toFixed(1) + 'k' : String(Math.round(v));
}

function formatPct(share) {
  const p = Math.max(0, Number(share) || 0) * 100;
  return (p >= 10 ? p.toFixed(0) : p.toFixed(1)) + '%';
}

function timeHM(ts) {
  const d = new Date((Number(ts) || 0) * 1000);
  if (Number.isNaN(d.getTime())) return '--:--';
  return String(d.getHours()).padStart(2, '0') + ':' + String(d.getMinutes()).padStart(2, '0');
}

const WEEK = ['周日', '周一', '周二', '周三', '周四', '周五', '周六'];

const SEVERITY = {
  critical: { label: '严重', color: '#fb7185' },
  warn: { label: '警告', color: '#fbbf24' },
  info: { label: '提示', color: '#38bdf8' },
};

/* ---------- 样式（注入一次，scoped .gl-screen） ---------- */

const STYLE_ID = 'gl-screen-style';

const SCREEN_CSS = `
.gl-screen{position:absolute;inset:0;overflow:hidden;background:#05070d;color:#e8eefc;
  font-family:-apple-system,"Segoe UI","PingFang SC","Microsoft YaHei",system-ui,sans-serif;
  -webkit-font-smoothing:antialiased;user-select:none;}
.gl-screen *{box-sizing:border-box;}
.gl-screen .gl-canvas{position:absolute;inset:0;z-index:0;}
.gl-screen .gl-canvas canvas{display:block;width:100%;height:100%;}
.gl-screen .gl-hud{position:absolute;inset:0;z-index:2;pointer-events:none;}
.gl-screen .gl-hud::before{content:"";position:absolute;inset:0;pointer-events:none;
  background:radial-gradient(ellipse at 50% 46%,transparent 46%,rgba(2,4,9,.55) 100%);}
.gl-screen .gl-panel{position:absolute;pointer-events:auto;
  background:linear-gradient(180deg,rgba(16,24,39,.8),rgba(9,14,24,.92));
  border:1px solid rgba(148,163,184,.16);border-radius:14px;
  box-shadow:0 20px 54px rgba(0,0,0,.48),inset 0 1px 0 rgba(255,255,255,.04);
  backdrop-filter:blur(14px);-webkit-backdrop-filter:blur(14px);}
.gl-screen .gl-panel::after{content:"";position:absolute;inset:0;border-radius:inherit;pointer-events:none;
  background:linear-gradient(120deg,rgba(34,211,238,.10),transparent 32%,transparent 70%,rgba(124,92,255,.08));}
.gl-screen .gl-panel>*{position:relative;z-index:1;}
.gl-screen .gl-eyebrow{font-size:11px;letter-spacing:.22em;color:#5d6f8c;text-transform:uppercase;}

/* 品牌 / 时钟 */
.gl-screen .gl-brand{left:26px;top:20px;display:flex;align-items:center;gap:14px;padding:13px 18px;}
.gl-screen .gl-mark{width:36px;height:36px;border-radius:10px;position:relative;flex:none;
  background:conic-gradient(from 210deg,#22d3ee,#7c5cff,#22d3ee);
  box-shadow:0 0 22px rgba(34,211,238,.45),inset 0 0 12px rgba(5,10,20,.55);}
.gl-screen .gl-mark::before{content:"";position:absolute;inset:7px;border-radius:4px;
  background:#060b14;clip-path:polygon(50% 0,100% 25%,100% 75%,50% 100%,0 75%,0 25%);}
.gl-screen .gl-mark::after{content:"";position:absolute;inset:12px;border-radius:2px;
  background:linear-gradient(180deg,#22d3ee,#7c5cff);clip-path:polygon(50% 0,100% 25%,100% 75%,50% 100%,0 75%,0 25%);
  box-shadow:0 0 12px rgba(34,211,238,.8);}
.gl-screen .gl-brand-copy{display:flex;flex-direction:column;gap:3px;}
.gl-screen .gl-brand-name{font-size:20px;font-weight:700;letter-spacing:.06em;color:#eef7ff;line-height:1;
  text-shadow:0 0 22px rgba(34,211,238,.35);}
.gl-screen .gl-brand-name em{font-style:normal;font-weight:500;color:#22d3ee;letter-spacing:.12em;}
.gl-screen .gl-brand-sub{font-size:11px;letter-spacing:.2em;color:#6c809c;}
.gl-screen .gl-clock{margin-left:10px;padding-left:16px;border-left:1px solid rgba(148,163,184,.16);
  display:flex;flex-direction:column;gap:2px;min-width:118px;}
.gl-screen .gl-clock-time{font-size:25px;font-weight:700;letter-spacing:.04em;color:#dff6ff;
  font-variant-numeric:tabular-nums;line-height:1.1;}
.gl-screen .gl-clock-date{font-size:11px;color:#5d6f8c;letter-spacing:.08em;font-variant-numeric:tabular-nums;}

/* KPI */
.gl-screen .gl-kpis{position:absolute;right:26px;top:20px;display:flex;gap:10px;z-index:1;}
.gl-screen .gl-kpi{position:relative;pointer-events:auto;min-width:136px;padding:11px 15px 12px;border-radius:13px;
  background:linear-gradient(180deg,rgba(16,24,39,.84),rgba(9,14,24,.92));
  border:1px solid rgba(148,163,184,.16);backdrop-filter:blur(14px);
  box-shadow:0 16px 44px rgba(0,0,0,.42),inset 0 1px 0 rgba(255,255,255,.04);}
.gl-screen .gl-kpi-label{font-size:11.5px;color:#93a6c2;letter-spacing:.1em;display:flex;align-items:center;gap:6px;}
.gl-screen .gl-kpi-label i{width:5px;height:5px;border-radius:50%;background:#22d3ee;box-shadow:0 0 8px #22d3ee;flex:none;}
.gl-screen .gl-kpi-value{margin-top:6px;font-size:32px;font-weight:700;line-height:1;color:#f2f8ff;
  font-variant-numeric:tabular-nums;letter-spacing:.01em;text-shadow:0 0 22px rgba(34,211,238,.18);}
.gl-screen .gl-kpi-unit{font-size:11px;font-weight:500;color:#5d6f8c;margin-left:4px;letter-spacing:.06em;}
.gl-screen .gl-kpi-sub{margin-top:5px;font-size:10.5px;color:#5d6f8c;letter-spacing:.06em;font-variant-numeric:tabular-nums;}
.gl-screen .gl-kpi.is-alert .gl-kpi-value{color:#fbbf24;text-shadow:0 0 22px rgba(251,191,36,.3);}
.gl-screen .gl-kpi.is-alert.is-crit .gl-kpi-value{color:#fb7185;text-shadow:0 0 22px rgba(251,113,133,.35);}
.gl-screen .gl-kpi.is-alert .gl-kpi-label i{background:#fbbf24;box-shadow:0 0 8px #fbbf24;}
.gl-screen .gl-kpi.is-alert.is-crit .gl-kpi-label i{background:#fb7185;box-shadow:0 0 8px #fb7185;}

/* 告警流 */
.gl-screen .gl-alerts{right:26px;top:124px;width:326px;padding:13px 15px 11px;}
.gl-screen .gl-alerts-head{display:flex;align-items:center;gap:8px;margin-bottom:9px;}
.gl-screen .gl-alerts-head .dot{width:7px;height:7px;border-radius:50%;background:#fb7185;
  box-shadow:0 0 10px rgba(251,113,133,.9);animation:gl-pulse 1.8s ease-in-out infinite;}
.gl-screen .gl-alerts-title{font-size:12.5px;font-weight:600;letter-spacing:.12em;color:#cfe0f4;}
.gl-screen .gl-alerts-count{margin-left:auto;font-size:10.5px;color:#8fa6c4;font-variant-numeric:tabular-nums;}
.gl-screen .gl-alert{display:flex;align-items:flex-start;gap:9px;padding:8px 0;border-top:1px solid rgba(148,163,184,.1);}
.gl-screen .gl-alert:first-child{border-top:0;padding-top:2px;}
.gl-screen .gl-alert-bar{width:3px;height:30px;border-radius:2px;flex:none;margin-top:2px;
  box-shadow:0 0 10px currentColor;background:currentColor;}
.gl-screen .gl-alert-body{min-width:0;flex:1;}
.gl-screen .gl-alert-title{font-size:12px;color:#dbe6f4;line-height:1.35;display:-webkit-box;
  -webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden;}
.gl-screen .gl-alert-meta{margin-top:3px;display:flex;gap:8px;font-size:10px;color:#5d6f8c;font-variant-numeric:tabular-nums;}
.gl-screen .gl-alert-meta b{font-weight:600;color:#8fa6c4;}
.gl-screen .gl-alert-empty{padding:10px 0 8px;font-size:11.5px;color:#5d6f8c;text-align:center;}

/* 流向图例（拓扑链路 kind 颜色 + 实线/虚线语义） */
.gl-screen .gl-flow-legend{left:26px;top:108px;width:246px;padding:12px 14px 10px;}
.gl-screen .gl-flow-head{display:flex;align-items:center;gap:8px;margin-bottom:8px;}
.gl-screen .gl-flow-title{font-size:12.5px;font-weight:600;letter-spacing:.12em;color:#cfe0f4;}
.gl-screen .gl-flow-kinds{display:grid;grid-template-columns:1fr 1fr;gap:6px 10px;}
.gl-screen .gl-flow-item{display:flex;align-items:center;gap:7px;font-size:11.5px;color:#b7c7dd;white-space:nowrap;}
.gl-screen .gl-flow-item i{width:8px;height:8px;border-radius:50%;background:var(--c,#22d3ee);
  box-shadow:0 0 8px var(--c,#22d3ee);flex:none;}
.gl-screen .gl-flow-lines{display:flex;align-items:center;gap:14px;margin-top:9px;padding-top:8px;
  border-top:1px solid rgba(148,163,184,.12);font-size:11px;color:#8ea3bf;}
.gl-screen .gl-flow-line{display:flex;align-items:center;gap:7px;}
.gl-screen .gl-flow-line i{width:22px;height:0;border-top:2px solid #22d3ee;flex:none;
  box-shadow:0 0 6px rgba(34,211,238,.5);}
.gl-screen .gl-flow-line.dashed i{border-top-style:dashed;opacity:.75;}

/* 分类图例 */
.gl-screen .gl-legend{left:26px;bottom:26px;width:280px;padding:13px 15px 9px;}
.gl-screen .gl-legend-head{display:flex;align-items:center;gap:8px;margin-bottom:8px;}
.gl-screen .gl-legend-title{font-size:12.5px;font-weight:600;letter-spacing:.12em;color:#cfe0f4;}
.gl-screen .gl-legend-total{margin-left:auto;font-size:10.5px;color:#5d6f8c;font-variant-numeric:tabular-nums;}
.gl-screen .gl-legend-row{display:grid;grid-template-columns:10px 1fr auto;align-items:center;gap:8px;
  padding:4.5px 0;font-size:12px;color:#b7c7dd;position:relative;}
.gl-screen .gl-legend-swatch{width:9px;height:9px;border-radius:2.5px;box-shadow:0 0 8px currentColor;background:currentColor;}
.gl-screen .gl-legend-name{white-space:nowrap;overflow:hidden;text-overflow:ellipsis;letter-spacing:.02em;}
.gl-screen .gl-legend-pct{font-size:11.5px;color:#93a6c2;font-variant-numeric:tabular-nums;}
.gl-screen .gl-legend-track{display:block;position:absolute;left:0;right:0;bottom:1px;height:2px;border-radius:1px;
  background:rgba(148,163,184,.09);overflow:hidden;}
.gl-screen .gl-legend-fill{display:block;height:100%;border-radius:1px;background:currentColor;opacity:.75;
  transition:width .5s cubic-bezier(.4,0,.2,1);}

/* Top5 */
.gl-screen .gl-top5{left:50%;transform:translateX(-50%);bottom:26px;width:560px;padding:13px 17px 11px;}
.gl-screen .gl-top5-head{display:flex;align-items:center;gap:8px;margin-bottom:8px;}
.gl-screen .gl-top5-title{font-size:12.5px;font-weight:600;letter-spacing:.12em;color:#cfe0f4;}
.gl-screen .gl-top5-sub{margin-left:auto;font-size:10.5px;color:#5d6f8c;}
.gl-screen .gl-top5-row{display:grid;grid-template-columns:20px 132px 1fr 92px;align-items:center;gap:10px;
  padding:5px 0;font-size:12px;}
.gl-screen .gl-top5-rank{font-size:10.5px;color:#5d6f8c;font-variant-numeric:tabular-nums;text-align:center;
  border:1px solid rgba(148,163,184,.16);border-radius:5px;line-height:16px;height:16px;}
.gl-screen .gl-top5-row:first-of-type .gl-top5-rank{color:#0b1220;background:#22d3ee;border-color:#22d3ee;font-weight:700;}
.gl-screen .gl-top5-name{color:#c5d5ea;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;letter-spacing:.02em;}
.gl-screen .gl-top5-track{display:block;height:7px;border-radius:4px;background:rgba(148,163,184,.1);overflow:hidden;}
.gl-screen .gl-top5-bar{display:block;height:100%;border-radius:4px;
  background:linear-gradient(90deg,rgba(34,211,238,.55),#22d3ee);
  box-shadow:0 0 14px rgba(34,211,238,.45);transition:width .55s cubic-bezier(.4,0,.2,1);}
.gl-screen .gl-top5-val{text-align:right;color:#8fa6c4;font-size:11.5px;font-variant-numeric:tabular-nums;letter-spacing:.02em;}

/* 提示 */
.gl-screen .gl-hint{position:absolute;right:26px;bottom:30px;font-size:11.5px;color:#5d6f8c;letter-spacing:.06em;
  display:flex;align-items:center;gap:10px;pointer-events:none;}
.gl-screen .gl-hint kbd{font-family:inherit;font-size:10.5px;color:#9fb0cc;padding:2px 7px;border-radius:5px;
  border:1px solid rgba(148,163,184,.22);background:rgba(16,24,39,.6);letter-spacing:.08em;}
.gl-screen .gl-hint i{width:3px;height:3px;border-radius:50%;background:#334155;}

/* 独立窗口（screen.html）的返回/关闭按钮 */
.gl-screen .gl-close{position:absolute;left:50%;top:20px;transform:translateX(-50%);z-index:5;pointer-events:auto;
  display:inline-flex;align-items:center;gap:8px;padding:9px 17px;border-radius:999px;cursor:pointer;
  font-family:inherit;font-size:12.5px;font-weight:500;letter-spacing:.05em;color:#cfe0f4;
  background:linear-gradient(180deg,rgba(16,24,39,.86),rgba(9,14,24,.94));
  border:1px solid rgba(148,163,184,.22);backdrop-filter:blur(12px);-webkit-backdrop-filter:blur(12px);
  box-shadow:0 14px 40px rgba(0,0,0,.4);transition:border-color .2s,background .2s,color .2s;}
.gl-screen .gl-close:hover{border-color:rgba(34,211,238,.55);background:rgba(34,211,238,.14);color:#eafcff;}
.gl-screen .gl-close:active{transform:translateX(-50%) scale(.98);}
.gl-screen .gl-close span:first-child{font-size:14px;line-height:1;color:#7fe9fb;}

/* 加载 / 错误 */
.gl-screen .gl-loading{position:absolute;left:50%;top:50%;transform:translate(-50%,-50%);z-index:3;
  display:flex;align-items:center;gap:12px;padding:12px 20px;border-radius:12px;pointer-events:none;
  background:rgba(8,13,23,.82);border:1px solid rgba(34,211,238,.2);font-size:12.5px;color:#9fb0cc;
  transition:opacity .4s ease,visibility .4s ease;}
.gl-screen .gl-loading.hide{opacity:0;visibility:hidden;}
.gl-screen .gl-spinner{width:16px;height:16px;border-radius:50%;flex:none;
  border:2px solid rgba(34,211,238,.2);border-top-color:#22d3ee;animation:gl-spin .9s linear infinite;}

/* 空态 / 未启用 */
.gl-screen .gl-notice{position:absolute;left:50%;top:47%;transform:translate(-50%,-50%);z-index:3;
  display:none;flex-direction:column;align-items:center;gap:9px;padding:24px 34px;border-radius:16px;text-align:center;
  pointer-events:auto;background:linear-gradient(180deg,rgba(16,24,39,.9),rgba(8,13,22,.94));
  border:1px solid rgba(148,163,184,.2);box-shadow:0 26px 80px rgba(0,0,0,.55);
  backdrop-filter:blur(16px);-webkit-backdrop-filter:blur(16px);}
.gl-screen .gl-notice.show{display:flex;}
.gl-screen .gl-notice-icon{width:54px;height:54px;border-radius:50%;position:relative;
  border:1px solid rgba(34,211,238,.3);box-shadow:inset 0 0 26px rgba(34,211,238,.12),0 0 24px rgba(34,211,238,.14);}
.gl-screen .gl-notice-icon::before{content:"";position:absolute;inset:11px;border-radius:50%;
  border:1.5px dashed rgba(34,211,238,.5);animation:gl-spin 9s linear infinite;}
.gl-screen .gl-notice-icon::after{content:"";position:absolute;left:50%;top:50%;width:9px;height:9px;margin:-4.5px 0 0 -4.5px;
  border-radius:50%;background:#22d3ee;box-shadow:0 0 14px #22d3ee;}
.gl-screen .gl-notice-tag{font-size:10px;letter-spacing:.26em;color:#4f6482;text-transform:uppercase;}
.gl-screen .gl-notice-title{font-size:18px;font-weight:600;letter-spacing:.08em;color:#eaf5ff;}
.gl-screen .gl-notice-sub{max-width:380px;font-size:12px;line-height:1.75;color:#7d90ab;}
.gl-screen .gl-error{position:absolute;left:50%;bottom:96px;transform:translateX(-50%);z-index:3;
  padding:8px 16px;border-radius:9px;font-size:12px;color:#ffc8d2;background:rgba(60,12,20,.9);
  border:1px solid rgba(251,113,133,.45);display:none;}
.gl-screen .gl-error.show{display:block;}

@keyframes gl-spin{to{transform:rotate(360deg);}}
@keyframes gl-pulse{0%,100%{opacity:1;transform:scale(1);}50%{opacity:.45;transform:scale(.8);}}

@media (max-width:1720px){
  .gl-screen .gl-kpi{min-width:118px;padding:9px 12px 10px;}
  .gl-screen .gl-kpi-value{font-size:27px;}
  .gl-screen .gl-top5{width:500px;}
  .gl-screen .gl-top5-row{grid-template-columns:20px 116px 1fr 84px;}
  .gl-screen .gl-alerts{width:300px;}
  .gl-screen .gl-legend{width:256px;}
  .gl-screen .gl-brand{padding:11px 15px;}
  .gl-screen .gl-brand-name{font-size:18px;}
  .gl-screen .gl-clock-time{font-size:22px;}
}
@media (max-width:1366px){
  .gl-screen .gl-kpi{min-width:104px;}
  .gl-screen .gl-kpi-value{font-size:24px;}
  .gl-screen .gl-top5{width:440px;}
  .gl-screen .gl-alerts{width:272px;}
  .gl-screen .gl-legend{width:234px;}
  .gl-screen .gl-hint{display:none;}
}
`;

function ensureStyle() {
  let style = document.getElementById(STYLE_ID);
  if (!style) {
    style = document.createElement('style');
    style.id = STYLE_ID;
    style.textContent = SCREEN_CSS;
    document.head.appendChild(style);
  }
  return style;
}

/* ---------- DOM 构建 ---------- */

const KPI_DEFS = [
  { key: 'online', label: '在线设备' },
  { key: 'conns', label: '活跃连接' },
  { key: 'down', label: '总下行速率' },
  { key: 'alerts', label: '告警数' },
];

function buildHud(root) {
  const hud = document.createElement('div');
  hud.className = 'gl-hud';
  hud.innerHTML = `
    <div class="gl-panel gl-brand">
      <div class="gl-mark"></div>
      <div class="gl-brand-copy">
        <div class="gl-brand-name">观澜 <em>NetScope</em></div>
        <div class="gl-brand-sub">用户上网行为态势感知</div>
      </div>
      <div class="gl-clock">
        <div class="gl-clock-time" data-ref="clock-time">--:--:--</div>
        <div class="gl-clock-date" data-ref="clock-date">----</div>
      </div>
    </div>

    <div class="gl-kpis">
      ${KPI_DEFS.map(
        (k) => `
        <div class="gl-kpi" data-kpi="${k.key}">
          <div class="gl-kpi-label"><i></i>${k.label}</div>
          <div class="gl-kpi-value" data-ref="kpi-${k.key}">--</div>
          <div class="gl-kpi-sub" data-ref="kpi-${k.key}-sub">&nbsp;</div>
        </div>`,
      ).join('')}
    </div>

    <div class="gl-panel gl-alerts">
      <div class="gl-alerts-head">
        <span class="dot"></span>
        <span class="gl-alerts-title">实时告警</span>
        <span class="gl-alerts-count" data-ref="alerts-count">0 条</span>
      </div>
      <div data-ref="alerts-list"></div>
    </div>

    <div class="gl-panel gl-flow-legend" data-ref="flow-legend">
      <div class="gl-flow-head">
        <span class="gl-flow-title">流向图例</span>
      </div>
      <div class="gl-flow-kinds">
        <span class="gl-flow-item"><i style="--c:#22d3ee"></i>直接出网</span>
        <span class="gl-flow-item"><i style="--c:#a78bfa"></i>经代理</span>
        <span class="gl-flow-item"><i style="--c:#34d399"></i>经 ZeroTier</span>
        <span class="gl-flow-item"><i style="--c:#8b5cf6"></i>经 VPN</span>
      </div>
      <div class="gl-flow-lines">
        <span class="gl-flow-line solid"><i></i>有流量</span>
        <span class="gl-flow-line dashed"><i></i>无流量</span>
      </div>
    </div>

    <div class="gl-panel gl-legend">
      <div class="gl-legend-head">
        <span class="gl-legend-title">流量分类</span>
        <span class="gl-legend-total" data-ref="legend-total">合计 --</span>
      </div>
      <div data-ref="legend-list"></div>
    </div>

    <div class="gl-panel gl-top5">
      <div class="gl-top5-head">
        <span class="gl-top5-title">设备流量 Top 5</span>
        <span class="gl-top5-sub" data-ref="top5-sub">实时下行 + 上行</span>
      </div>
      <div data-ref="top5-list"></div>
    </div>

    <div class="gl-hint">
      <span>拖拽旋转</span><i></i><span>滚轮缩放</span><i></i><kbd>Esc</kbd><span>退出</span>
    </div>

    <div class="gl-notice" data-ref="notice">
      <div class="gl-notice-icon"></div>
      <div class="gl-notice-tag">NETSCOPE · STANDBY</div>
      <div class="gl-notice-title" data-ref="notice-title">系统未启用</div>
      <div class="gl-notice-sub" data-ref="notice-sub">请在「设置」中启用总开关与流量采集，实时态势将在启用后自动接入。</div>
    </div>

    <div class="gl-loading" data-ref="loading"><span class="gl-spinner"></span><span data-ref="loading-text">数据接入中…</span></div>
    <div class="gl-error" data-ref="error"></div>
  `;
  root.appendChild(hud);
  return hud;
}

/* ---------- 模块状态 ---------- */

let current = null; // { root, el, scene, handle, timers, unsub, observer, refs, ... }

function mountScreen(el, api, opts = {}) {
  if (!el) throw new Error('[screen] mountScreen: 容器不能为空');
  unmountScreen();

  ensureStyle();

  const root = document.createElement('div');
  root.className = 'gl-screen';
  const canvasHost = document.createElement('div');
  canvasHost.className = 'gl-canvas';
  root.appendChild(canvasHost);
  const hud = buildHud(root);
  el.appendChild(root);

  const refs = {};
  root.querySelectorAll('[data-ref]').forEach((node) => {
    refs[node.getAttribute('data-ref')] = node;
  });

  /* ---------- 独立窗口（screen.html）：返回/关闭 ---------- */
  const standalone = opts.standalone === true;
  let onEscClose = null;

  function closeScreen() {
    // 由 window.open 打开的窗口可直接 close；直接访问的标签页被浏览器拦截时回退
    try {
      window.close();
    } catch (_) {
      /* ignore */
    }
    setTimeout(() => {
      if (window.closed) return;
      if (history.length > 1) history.back();
      else location.replace('./index.html');
    }, 120);
  }

  if (standalone) {
    const closeBtn = document.createElement('button');
    closeBtn.type = 'button';
    closeBtn.className = 'gl-close';
    closeBtn.title = '关闭大屏（Esc）';
    closeBtn.innerHTML = '<span aria-hidden="true">✕</span><span>返回管理界面</span>';
    closeBtn.addEventListener('click', closeScreen);
    hud.appendChild(closeBtn);

    const hint = hud.querySelector('.gl-hint');
    if (hint) {
      hint.innerHTML =
        '<span>拖拽旋转</span><i></i><span>滚轮缩放</span><i></i><kbd>Esc</kbd><span>关闭大屏</span>';
    }

    onEscClose = (ev) => {
      if (ev.key === 'Escape') {
        ev.preventDefault();
        ev.stopPropagation();
        closeScreen();
      }
    };
    document.addEventListener('keydown', onEscClose, true);
  }

  const quality =
    opts.quality ||
    (window.matchMedia && window.matchMedia('(pointer: coarse)').matches ? 'medium' : 'high');

  let scene = null;
  let sceneError = null;
  try {
    scene = createTrayScene(canvasHost, {
      quality,
      fx: opts.fx,
      onSelectDevice: (ip) => {
        // 交给页面处理（ui 可在 #/screen 打开设备抽屉）；HUD 不阻塞
        if (typeof opts.onSelectDevice === 'function') opts.onSelectDevice(ip);
      },
      onHoverDevice: (ip) => {
        if (typeof opts.onHoverDevice === 'function') opts.onHoverDevice(ip);
      },
      onSelectNode: (id) => {
        // 网络拓扑节点点击（LAN / ZeroTier / VPN / 互联网 / 代理）
        if (typeof opts.onSelectNode === 'function') opts.onSelectNode(id);
      },
      onHoverNode: (id) => {
        if (typeof opts.onHoverNode === 'function') opts.onHoverNode(id);
      },
    });
  } catch (err) {
    sceneError = err;
    console.error('[screen] 3D 场景初始化失败：', err);
    hud.querySelector('[data-ref="loading-text"]').textContent = '3D 渲染不可用（WebGL 初始化失败）';
  }

  const state = {
    root,
    el,
    hud,
    refs,
    scene,
    api: api || {},
    destroyed: false,
    receivedData: false,
    unsub: null,
    timers: [],
    standalone,
    onEscClose,
    kpi: { online: 0, devices: 0, conns: 0, down: 0, alerts: 0 },
    categories: CATEGORY_META.map((c) => ({ key: c.key, label: c.label, color: c.color, share: 0, downBps: 0, upBps: 0 })),
    /** ip -> 设备（HUD Top5 需要全量；SSE 增量帧按 full 语义合并） */
    deviceMap: new Map(),
    deviceTotal: 0,
    /** null=未知，true=已启用，false=后端总开关关闭 */
    systemEnabled: null,
    noticeKind: null,
    alerts: [],
  };
  current = state;

  /* ---------- HUD 更新 ---------- */

  function tickClock() {
    if (state.destroyed) return;
    const now = new Date();
    if (refs['clock-time']) {
      refs['clock-time'].textContent =
        String(now.getHours()).padStart(2, '0') +
        ':' +
        String(now.getMinutes()).padStart(2, '0') +
        ':' +
        String(now.getSeconds()).padStart(2, '0');
    }
    if (refs['clock-date']) {
      refs['clock-date'].textContent =
        now.getFullYear() +
        '-' +
        String(now.getMonth() + 1).padStart(2, '0') +
        '-' +
        String(now.getDate()).padStart(2, '0') +
        ' ' +
        WEEK[now.getDay()];
    }
  }

  function setKpi(key, valueNode, subText, opts_) {
    const card = root.querySelector('[data-kpi="' + key + '"]');
    if (!card) return;
    const valueEl = refs['kpi-' + key];
    const subEl = refs['kpi-' + key + '-sub'];
    if (valueEl) valueEl.innerHTML = valueNode;
    if (subEl && subText != null) subEl.innerHTML = subText;
    if (opts_ && opts_.alertClass != null) {
      card.classList.toggle('is-alert', !!opts_.alertClass);
      card.classList.toggle('is-crit', !!opts_.crit);
    }
  }

  function updateKpi(kpi) {
    if (!kpi) return;
    const s = state.kpi;
    s.online = Number(kpi.online) || 0;
    const totalFromKpi = Number(kpi.devices);
    s.devices = Number.isFinite(totalFromKpi) ? totalFromKpi : state.deviceTotal || s.online;
    s.conns = Number(kpi.conns) || 0;
    s.down = Number(kpi.downBps) || 0;
    s.alerts = Number(kpi.alerts) || 0;

    setKpi('online', `${s.online}`, `共 ${s.devices} 台设备`);
    setKpi('conns', formatCount(s.conns), '会话连接数');
    const dr = formatRate(s.down);
    setKpi('down', `${dr.v}<span class="gl-kpi-unit">${dr.u}</span>`, `↑ ${rateText(kpi.upBps)}`);
    const alertLevel = s.alerts >= 3 ? 'crit' : 'warn';
    setKpi(
      'alerts',
      `${s.alerts}`,
      s.alerts > 0 ? '需关注' : '运行平稳',
      { alertClass: s.alerts > 0, crit: alertLevel === 'crit' },
    );
  }

  function rebuildLegend() {
    if (!refs['legend-list']) return;
    let totalBps = 0;
    state.categories.forEach((c) => (totalBps += (c.downBps || 0) + (c.upBps || 0)));
    refs['legend-list'].innerHTML = state.categories
      .map((c) => {
        const pct = Math.max(0, Math.min(1, Number(c.share) || 0));
        return `
        <div class="gl-legend-row" style="color:${c.color}">
          <span class="gl-legend-swatch"></span>
          <span class="gl-legend-name" style="color:#b7c7dd">${c.label}</span>
          <span class="gl-legend-pct" data-legend-pct="${c.key}">${formatPct(pct)}</span>
          <span class="gl-legend-track"><span class="gl-legend-fill" data-legend-bar="${c.key}" style="width:${(
            pct * 100
          ).toFixed(1)}%"></span></span>
        </div>`;
      })
      .join('');
    if (refs['legend-total']) refs['legend-total'].textContent = '合计 ' + rateText(totalBps);
  }

  function updateCategories(categories) {
    if (!Array.isArray(categories) || !categories.length) return;
    const byKey = new Map();
    for (const c of categories) {
      if (c && c.key) byKey.set(c.key, c);
    }
    let changed = false;
    for (const cat of state.categories) {
      const src = byKey.get(cat.key);
      if (!src) continue;
      const share = Number(src.share);
      if (Number.isFinite(share)) cat.share = Math.max(0, Math.min(1, share));
      cat.downBps = Number(src.downBps) || cat.downBps;
      cat.upBps = Number(src.upBps) || cat.upBps;
      changed = true;
    }
    if (changed) rebuildLegend();
  }

  function rebuildTop5() {
    if (!refs['top5-list']) return;
    const list = [...state.deviceMap.values()]
      .sort(
        (a, b) =>
          (Number(b.downBps) || 0) + (Number(b.upBps) || 0) - ((Number(a.downBps) || 0) + (Number(a.upBps) || 0)),
      )
      .slice(0, 5);
    if (!list.length) {
      refs['top5-list'].innerHTML = '<div class="gl-alert-empty">暂无设备流量数据</div>';
      if (refs['top5-sub']) refs['top5-sub'].textContent = '实时下行 + 上行';
      return;
    }
    const max = Math.max(...list.map((d) => (Number(d.downBps) || 0) + (Number(d.upBps) || 0)), 1);
    refs['top5-list'].innerHTML = list
      .map((d, i) => {
        const rate = (Number(d.downBps) || 0) + (Number(d.upBps) || 0);
        const name = d.alias || d.name || d.hostname || d.ip || '未知设备';
        const width = Math.max(3, (rate / max) * 100);
        return `
        <div class="gl-top5-row">
          <span class="gl-top5-rank">${i + 1}</span>
          <span class="gl-top5-name" title="${escapeHtml(name)}">${escapeHtml(name)}</span>
          <span class="gl-top5-track"><span class="gl-top5-bar" style="width:${width.toFixed(1)}%"></span></span>
          <span class="gl-top5-val">${rateText(rate)}</span>
        </div>`;
      })
      .join('');
    const total = state.deviceTotal || state.deviceMap.size;
    if (refs['top5-sub']) refs['top5-sub'].textContent = '实时下行 + 上行 · 共 ' + total + ' 台';
  }

  /** @param {Array} list @param {boolean} full true=整体替换；false=按 ip 合并（后端增量语义） */
  function mergeHudDevices(list, full) {
    if (!Array.isArray(list)) return;
    if (full) state.deviceMap.clear();
    for (const d of list) {
      if (!d || !d.ip) continue;
      state.deviceMap.set(String(d.ip), d);
    }
  }

  function renderAlerts() {
    if (!refs['alerts-list']) return;
    const alerts = state.alerts.slice(0, 4);
    refs['alerts-count'].textContent = state.alerts.length + ' 条';
    if (!alerts.length) {
      refs['alerts-list'].innerHTML = '<div class="gl-alert-empty">暂无告警，网络运行平稳</div>';
      return;
    }
    refs['alerts-list'].innerHTML = alerts
      .map((a) => {
        const sev = SEVERITY[a.severity] || SEVERITY.info;
        const title = a.title || a.detail || a.type || '安全事件';
        const device = a.deviceName ? ' · ' + a.deviceName : a.deviceIp ? ' · ' + a.deviceIp : '';
        return `
        <div class="gl-alert" style="color:${sev.color}">
          <span class="gl-alert-bar"></span>
          <div class="gl-alert-body">
            <div class="gl-alert-title" style="color:#dbe6f4" title="${escapeHtml(title)}">${escapeHtml(title)}</div>
            <div class="gl-alert-meta"><b>${sev.label}</b><span>${timeHM(a.ts)}</span><span>${escapeHtml(device)}</span></div>
          </div>
        </div>`;
      })
      .join('');
  }

  function updateAlerts(alerts) {
    if (!Array.isArray(alerts)) return;
    state.alerts = alerts
      .slice()
      .sort((a, b) => (Number(b.ts) || 0) - (Number(a.ts) || 0));
    renderAlerts();
  }

  /** overview 的 alerts 与 live alert 事件合并（避免 10s overview 刷新把刚推送的告警冲掉） */
  function mergeAlerts(list) {
    if (!Array.isArray(list)) return;
    const byId = new Map();
    const push = (a) => {
      if (!a || typeof a !== 'object') return;
      const id = a.id || String(a.ts) + ':' + String(a.title || a.type || '');
      if (!byId.has(id)) byId.set(id, a);
    };
    list.forEach(push);
    state.alerts.forEach(push);
    updateAlerts([...byId.values()]);
  }

  function setLoadingDone() {
    if (state.receivedData) return;
    state.receivedData = true;
    if (refs.loading) refs.loading.classList.add('hide');
  }

  function showError(msg) {
    if (!refs.error) return;
    refs.error.textContent = msg;
    refs.error.classList.add('show');
    clearTimeout(state.errorTimer);
    state.errorTimer = setTimeout(() => {
      if (refs.error) refs.error.classList.remove('show');
    }, 6000);
  }

  /* ---------- 系统开关 / 空态 / 告警 ---------- */

  function showNotice(kind, title, sub) {
    state.noticeKind = kind;
    if (refs['notice-title'] && title) refs['notice-title'].textContent = title;
    if (refs['notice-sub'] && sub) refs['notice-sub'].textContent = sub;
    if (refs.notice) refs.notice.classList.add('show');
  }

  function hideNotice() {
    state.noticeKind = null;
    if (refs.notice) refs.notice.classList.remove('show');
  }

  /** GET /api/settings：enabled=false 时按空态渲染，不当作错误 */
  function applySettings(settings) {
    if (!settings || state.destroyed) return;
    state.settings = settings;
    state.systemEnabled = settings.enabled !== false;
    if (!state.systemEnabled) {
      showNotice(
        'disabled',
        '系统未启用',
        '观澜 NetScope 总开关已关闭。请在「设置」中启用系统与流量采集，实时态势将自动恢复。',
      );
    } else {
      if (state.noticeKind === 'disabled') hideNotice();
      syncNoticeFromData();
    }
  }

  /** 依据数据维护空态提示（未启用 / 等待设备），不把空数据当错误 */
  function syncNoticeFromData() {
    if (state.destroyed) return;
    if (state.systemEnabled === false) return; // 保持「系统未启用」
    const hasDeviceData = state.deviceMap.size > 0;
    const total = Number(state.deviceTotal) || 0;
    if (hasDeviceData || total > 0) {
      if (state.noticeKind === 'standby' || state.noticeKind === 'disabled') hideNotice();
      return;
    }
    if (state.systemEnabled === true) {
      // 已启用但暂无可显示设备：不弹大卡片，交给列表空态 + KPI 0
      if (state.noticeKind === 'standby') hideNotice();
      return;
    }
    showNotice('standby', '暂无实时数据', '系统可能尚未启用或暂无设备接入。请在「设置」中检查总开关与流量采集。');
  }

  function handleAlertEvent(ev) {
    if (!ev || typeof ev !== 'object') return;
    const list = [ev, ...state.alerts];
    const seen = new Set();
    const deduped = [];
    for (const a of list) {
      if (!a) continue;
      const id = a.id || String(a.ts) + ':' + String(a.title || a.type || '');
      if (seen.has(id)) continue;
      seen.add(id);
      deduped.push(a);
    }
    updateAlerts(deduped.slice(0, 20));
  }

  function applyTick(tick) {
    if (!tick || state.destroyed || typeof tick !== 'object') return;
    setLoadingDone();
    // 设备增量语义：full=false 时 devices 只含变化设备 → 按 ip 合并；否则整体替换（旧契约）
    const full = tick.full !== false;
    // 先确定总数，再合并/删除并渲染 Top5（否则「共 N 台」会晚一帧）
    if (Number.isFinite(Number(tick.deviceCount))) state.deviceTotal = Number(tick.deviceCount);
    else if (tick.kpi && Number.isFinite(Number(tick.kpi.devices))) state.deviceTotal = Number(tick.kpi.devices);
    if (Array.isArray(tick.devices)) {
      mergeHudDevices(tick.devices, full);
      // removed：仅增量帧出现的被 forget/隐藏设备，合并后再删除
      if (!full && Array.isArray(tick.removed)) {
        for (const ip of tick.removed) state.deviceMap.delete(String(ip));
      }
      if (!Number.isFinite(Number(tick.deviceCount)) && full) state.deviceTotal = state.deviceMap.size;
      rebuildTop5();
    } else if (!full && Array.isArray(tick.removed)) {
      for (const ip of tick.removed) state.deviceMap.delete(String(ip));
      rebuildTop5();
    }

    if (state.scene) state.scene.update(tick);
    if (tick.kpi) updateKpi(tick.kpi);
    if (Array.isArray(tick.categories)) updateCategories(tick.categories);
    if (tick.event || tick.alert) handleAlertEvent(tick.event || tick.alert);
    syncNoticeFromData();
  }

  function normalizeOverview(ov) {
    if (!ov) return null;
    const topDevices = Array.isArray(ov.topDevices) ? ov.topDevices : [];
    const tick = {
      ts: ov.ts,
      kpi: ov.kpi,
      sys: ov.sys,
      categories: Array.isArray(ov.categories) ? ov.categories : undefined,
      // overview.topDevices 只是部分快照：非空时按增量合并；空时视为整体清空（系统未启用/无设备）
      full: topDevices.length === 0,
      deviceCount: ov.kpi && Number.isFinite(Number(ov.kpi.devices)) ? Number(ov.kpi.devices) : undefined,
      devices: topDevices.map((d) => ({
        ip: d.ip,
        name: d.name,
        alias: d.alias,
        online: d.online !== false,
        upBps: d.upBps,
        downBps: d.downBps,
        conns: d.conns,
        risk: d.risk,
        blocked: !!d.blocked,
        topCat: d.topCat,
      })),
      trend: Array.isArray(ov.trend) ? ov.trend : undefined,
    };
    if (Array.isArray(ov.trend) && ov.trend.length) {
      const last = ov.trend[ov.trend.length - 1];
      tick.trendPoint = { t: last.t, up: last.up, down: last.down };
    }
    return { tick, overview: ov };
  }

  function applyOverview(ov) {
    if (!ov || state.destroyed) return;
    setLoadingDone();
    const norm = normalizeOverview(ov);
    if (norm) {
      const tick = norm.tick;
      const full = tick.full !== false;
      if (Number.isFinite(Number(tick.deviceCount))) state.deviceTotal = Number(tick.deviceCount);
      mergeHudDevices(tick.devices, full);
      if (!Number.isFinite(Number(tick.deviceCount)) && full) state.deviceTotal = state.deviceMap.size;
      rebuildTop5();
      if (state.scene) state.scene.update(tick);
      if (ov.kpi) updateKpi(ov.kpi);
      if (Array.isArray(ov.categories)) updateCategories(ov.categories);
    }
    if (Array.isArray(ov.alerts)) mergeAlerts(ov.alerts);
    syncNoticeFromData();
  }

  /* ---------- 数据接入 ---------- */

  const apiObj = state.api || {};
  try {
    if (typeof apiObj.subscribe === 'function') {
      // 兼容两种 SSE 回调签名：
      //   handler(type, payload)   —— ui/api.js 当前实现（'hello'|'tick'|'alert'）
      //   handler(tickData)        —— 任务书最小契约
      const onEvent = (first, second) => {
        if (state.destroyed) return;
        if (typeof first === 'string') {
          const type = first;
          const payload = second;
          if (type === 'tick') applyTick(payload);
          else if (type === 'alert') handleAlertEvent(payload);
          else if (type === 'hello') {
            /* 握手帧：含 version/intervalMs，无需处理 */
          }
          return;
        }
        const data = first;
        if (!data || typeof data !== 'object') return;
        if (data.type === 'alert' || data.kind === 'alert' || data.event) {
          handleAlertEvent(data.event || data.alert || data);
          return;
        }
        applyTick(data);
      };
      const unsub = apiObj.subscribe(onEvent);
      state.unsub = typeof unsub === 'function' ? unsub : null;
    } else if (typeof apiObj.getOverview === 'function') {
      // 无 SSE：每 2s 轮询兜底
      const poll = () => {
        if (state.destroyed) return;
        Promise.resolve(apiObj.getOverview())
          .then((ov) => {
            if (state.destroyed) return;
            applyOverview(ov);
          })
          .catch((err) => showError('数据刷新失败：' + (err && err.message ? err.message : err)));
      };
      poll();
      state.timers.push({ id: setInterval(poll, 2000), kind: 'poll' });
    }
  } catch (err) {
    showError('数据订阅失败：' + (err && err.message ? err.message : err));
  }

  // 系统总开关：enabled=false 时按空态渲染「系统未启用」而非报错
  if (typeof apiObj.getSettings === 'function') {
    const loadSettings = () => {
      if (state.destroyed) return;
      Promise.resolve(apiObj.getSettings())
        .then((s) => {
          if (!state.destroyed) applySettings(s);
        })
        .catch(() => {});
    };
    loadSettings();
    state.timers.push({ id: setInterval(loadSettings, 30000), kind: 'settings' });
  }

  // 网络拓扑（GET /api/topology）：10s 拉取一次，喂给 3D 场景的拓扑层
  if (typeof apiObj.getTopology === 'function' && scene) {
    const loadTopology = () => {
      if (state.destroyed || !state.scene) return;
      Promise.resolve(apiObj.getTopology())
        .then((topo) => {
          if (!state.destroyed && state.scene && topo && Array.isArray(topo.nodes)) {
            state.scene.setTopology(topo);
          }
        })
        .catch((err) => {
          console.warn('[screen] topology 加载失败：', err && err.message ? err.message : err);
        });
    };
    loadTopology();
    // 链路速率标签需"近实时"：3s 轮询（后端 buildTopology 5s 缓存，实际约 3~5s 刷新）；
    // 标签重绘仍走 1s 节流 + LRU，避免抖动/纹理churn。
    state.timers.push({ id: setInterval(loadTopology, 3000), kind: 'topology' });
  }

  // 首屏 overview（补 alerts / trend / 分类标签 / 首帧设备）；subscribe 模式下每 10s 刷新一次
  if (typeof apiObj.getOverview === 'function') {
    Promise.resolve(apiObj.getOverview())
      .then((ov) => {
        if (!state.destroyed) applyOverview(ov);
      })
      .catch((err) => {
        if (apiObj.subscribe) showError('数据读取失败：' + (err && err.message ? err.message : err));
      });
    if (apiObj.subscribe) {
      state.timers.push({
        id: setInterval(() => {
          if (state.destroyed) return;
          Promise.resolve(apiObj.getOverview())
            .then((ov) => {
              if (!state.destroyed && ov) {
                // 只补告警：KPI/设备/趋势以 SSE tick 为准，避免 overview 慢一拍覆盖实时值
                if (Array.isArray(ov.alerts)) mergeAlerts(ov.alerts);
              }
            })
            .catch(() => {});
        }, 10000),
        kind: 'overview',
      });
    }
  } else if (!apiObj.subscribe) {
    refs['loading-text'].textContent = '等待数据源接入…';
  }

  // 时钟
  tickClock();
  state.timers.push({ id: setInterval(tickClock, 1000), kind: 'clock' });

  // el 被移除时自动清理
  state.timers.push({
    id: setInterval(() => {
      if (state.destroyed) return;
      if (!el.isConnected) unmountScreen();
    }, 1000),
    kind: 'watch',
  });

  // 初始占位
  rebuildLegend();
  renderAlerts();

  const handle = {
    root,
    hud,
    scene,
    unmount: unmountScreen,
  };
  state.handle = handle;
  return handle;
}

function unmountScreen() {
  const state = current;
  if (!state) return;
  current = null;
  state.destroyed = true;

  for (const t of state.timers) clearInterval(t.id);
  state.timers.length = 0;
  if (state.errorTimer) clearTimeout(state.errorTimer);

  try {
    if (typeof state.unsub === 'function') state.unsub();
  } catch (e) {
    /* ignore */
  }
  state.unsub = null;

  try {
    if (state.scene) state.scene.dispose();
  } catch (err) {
    console.error('[screen] 3D 场景释放失败：', err);
  }
  state.scene = null;

  if (state.root && state.root.parentNode) state.root.parentNode.removeChild(state.root);
  if (state.onEscClose) {
    document.removeEventListener('keydown', state.onEscClose, true);
    state.onEscClose = null;
  }
}

function escapeHtml(str) {
  return String(str == null ? '' : str).replace(/[&<>"']/g, (c) => {
    switch (c) {
      case '&':
        return '&amp;';
      case '<':
        return '&lt;';
      case '>':
        return '&gt;';
      case '"':
        return '&quot;';
      default:
        return '&#39;';
    }
  });
}

export { mountScreen, unmountScreen };
