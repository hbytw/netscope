/* ==========================================================================
   观澜 NetScope · 自研 Canvas 2D 图表
   依据 docs/design.md §5：devicePixelRatio 自适应、ResizeObserver 重绘、
   十字线 hover、环图 hover 外扩、横向条形榜、sparkline、空数据占位。
   —— 渲染策略：数据变更仅置 dirty，rAF 合批，同一帧只画一次。
   ========================================================================== */

const FONT = '-apple-system, "Segoe UI", "PingFang SC", "Microsoft YaHei", system-ui, sans-serif';
const MONO = 'ui-monospace, SFMono-Regular, Menlo, Consolas, monospace';

/* ---------- 通用基础设施 ---------- */

/**
 * 创建一个受管图表实例。
 * @param {HTMLCanvasElement} canvas
 * @param {(ctx: CanvasRenderingContext2D, w: number, h: number, instance: object) => void} draw
 */
function createChart(canvas, draw) {
  const inst = {
    canvas,
    ctx: canvas.getContext('2d'),
    w: 0, h: 0,
    dirty: true,
    rafId: 0,
    ro: null,
    disposed: false,
    hover: null,
    _cleanup: [],
    onHover: null
  };

  const applySize = () => {
    const rect = canvas.getBoundingClientRect();
    const cssW = Math.max(1, Math.round(rect.width || canvas.clientWidth || 300));
    const cssH = Math.max(1, Math.round(rect.height || canvas.clientHeight || 150));
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    inst.w = cssW; inst.h = cssH;
    canvas.width = Math.round(cssW * dpr);
    canvas.height = Math.round(cssH * dpr);
    inst.ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    inst.dirty = true;
    schedule(inst);
  };

  const schedule = (i) => {
    if (i.disposed || i.rafId) return;
    i.rafId = requestAnimationFrame(() => {
      i.rafId = 0;
      if (i.disposed || !i.dirty) return;
      i.dirty = false;
      try {
        i.ctx.clearRect(0, 0, i.w, i.h);
        draw(i.ctx, i.w, i.h, i);
      } catch (err) {
        console.error('[chart] draw error', err);
      }
    });
  };

  inst.invalidate = () => { inst.dirty = true; schedule(inst); };
  inst.resize = applySize;

  // 监听容器尺寸
  if (typeof ResizeObserver !== 'undefined') {
    inst.ro = new ResizeObserver(() => applySize());
    inst.ro.observe(canvas.parentElement || canvas);
  }
  // 窗口缩放兜底
  const onWinResize = () => applySize();
  window.addEventListener('resize', onWinResize);
  inst._cleanup.push(() => window.removeEventListener('resize', onWinResize));

  applySize();
  return inst;
}

function disposeChart(inst) {
  if (!inst || inst.disposed) return;
  inst.disposed = true;
  if (inst.rafId) cancelAnimationFrame(inst.rafId);
  inst.rafId = 0;
  if (inst.ro) { try { inst.ro.disconnect(); } catch (_) {} inst.ro = null; }
  inst._cleanup.forEach((fn) => { try { fn(); } catch (_) {} });
  inst._cleanup = [];
}

function emptyPlaceholder(ctx, w, h, text = '暂无数据') {
  ctx.save();
  ctx.fillStyle = 'rgba(93,111,140,.62)';
  ctx.font = `12px ${FONT}`;
  ctx.textAlign = 'center';
  ctx.textBaseline = 'middle';
  ctx.fillText(text, w / 2, h / 2);
  ctx.strokeStyle = 'rgba(148,163,184,.10)';
  ctx.setLineDash([4, 5]);
  ctx.lineWidth = 1;
  ctx.strokeRect(10.5, 10.5, w - 21, h - 21);
  ctx.restore();
}

function roundRect(ctx, x, y, w, h, r) {
  const rr = Math.min(r, Math.abs(w) / 2, Math.abs(h) / 2);
  ctx.beginPath();
  ctx.moveTo(x + rr, y);
  ctx.arcTo(x + w, y, x + w, y + h, rr);
  ctx.arcTo(x + w, y + h, x, y + h, rr);
  ctx.arcTo(x, y + h, x, y, rr);
  ctx.arcTo(x, y, x + w, y, rr);
  ctx.closePath();
}

function niceMax(v) {
  if (!Number.isFinite(v) || v <= 0) return 1;
  const exp = Math.floor(Math.log10(v));
  const base = Math.pow(10, exp);
  const f = v / base;
  let m;
  if (f <= 1) m = 1;
  else if (f <= 1.25) m = 1.25;
  else if (f <= 1.5) m = 1.5;
  else if (f <= 2) m = 2;
  else if (f <= 2.5) m = 2.5;
  else if (f <= 3) m = 3;
  else if (f <= 4) m = 4;
  else if (f <= 5) m = 5;
  else if (f <= 6) m = 6;
  else if (f <= 8) m = 8;
  else m = 10;
  return m * base;
}

function fmtAxisBps(v) {
  if (!Number.isFinite(v)) return '';
  if (v === 0) return '0';
  const units = ['', 'K', 'M', 'G', 'T'];
  let x = Math.abs(v); let i = 0;
  while (x >= 1000 && i < units.length - 1) { x /= 1000; i++; }
  if (x >= 100) return `${Math.round(x)}${units[i]}`;
  if (x >= 10) return `${Math.round(x)}${units[i]}`;
  return `${x.toFixed(1)}${units[i]}`;
}

function fmtAxisBytes(v) {
  if (!Number.isFinite(v)) return '';
  if (v === 0) return '0';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let x = Math.abs(v); let i = 0;
  while (x >= 1024 && i < units.length - 1) { x /= 1024; i++; }
  return `${x < 10 ? x.toFixed(1) : Math.round(x)}${units[i]}`;
}

/* ---------- 时间轴映射（绘制与 hover 共用，保证命中索引一致） ---------- */

/**
 * 解析模型的横轴：优先用真实时间戳 stamps + 窗口 timeWindow，
 * 没有 stamps 时退化为等距索引。
 */
function axisOf(model, len) {
  const stamps = Array.isArray(model.stamps) && model.stamps.length === len && len > 0 ? model.stamps : null;
  const win = Array.isArray(model.timeWindow) && model.timeWindow.length === 2 ? model.timeWindow : null;
  const tMin = win ? Number(win[0]) : (stamps ? Number(stamps[0]) : 0);
  const tMax = win ? Number(win[1]) : (stamps ? Number(stamps[len - 1]) : 1);
  const tSpan = (tMax - tMin) || 1;
  return { stamps, win, tMin, tMax, tSpan };
}

/** 索引 → 像素 X（与 areaChart 绘制使用同一套映射） */
function xAtIndex(ax, len, padL, plotW, idx) {
  if (ax.stamps) {
    const t = Number(ax.stamps[idx]) || ax.tMin;
    return padL + ((t - ax.tMin) / ax.tSpan) * plotW;
  }
  return padL + (len <= 1 ? plotW / 2 : (idx / (len - 1)) * plotW);
}

/** 像素 X → 索引（真实时间轴按 stamps 反查最近点，等距轴按比例取整） */
function indexAtX(ax, len, padL, plotW, mx) {
  let idx;
  if (ax.stamps) {
    const t = ax.tMin + ((mx - padL) / plotW) * ax.tSpan;
    idx = 0;
    let bd = Infinity;
    for (let i = 0; i < len; i++) {
      const d = Math.abs(Number(ax.stamps[i]) - t);
      if (d < bd) { bd = d; idx = i; }
    }
  } else {
    idx = Math.round(((mx - padL) / plotW) * (len - 1));
  }
  return Math.max(0, Math.min(len - 1, idx));
}

/* ---------- 面积图（支持堆叠 / 非堆叠、双色渐变、十字线） ---------- */

/**
 * @param {HTMLCanvasElement} canvas
 * @param {object} opts
 *   series: Array<{labels?:string[], keys:string[], values:number[][], colors:string[], names:string[], stacked?:boolean, unit?:'bps'|'bytes'}>
 *   或简化形式：{labels, series:[{name,color,values:number[]}]}
 */
export function areaChart(canvas, opts = {}) {
  const inst = createChart(canvas, (ctx, w, h, i) => {
    const model = i.model;
    const series = model.series || [];
    const labels = model.labels || [];
    const stacked = !!model.stacked;
    const unit = model.unit || 'bps';

    // 归一化为 {name, color, values[]}
    let rows = [];
    if (model.series && model.series.length && Array.isArray(model.series[0])) {
      rows = series.map((values, idx) => ({
        name: (model.names && model.names[idx]) || `S${idx + 1}`,
        color: (model.colors && model.colors[idx]) || '#22d3ee',
        values: values || []
      }));
    } else if (model.series && model.series.length && model.series[0] && typeof model.series[0] === 'object') {
      rows = model.series.map((s) => ({ name: s.name || '', color: s.color || '#22d3ee', values: s.values || [] }));
    }

    const padL = model.padLeft ?? 52;
    const padR = 14;
    const padT = 12;
    const padB = 26;
    const plotW = Math.max(10, w - padL - padR);
    const plotH = Math.max(10, h - padT - padB);

    const total = rows.reduce((a, r) => a + (r.values?.length || 0), 0);
    if (!rows.length || total === 0) { emptyPlaceholder(ctx, w, h, model.emptyText || '暂无数据'); return; }

    const len = Math.max(...rows.map((r) => r.values.length));
    // 计算上限
    let maxV = 0;
    if (stacked) {
      for (let x = 0; x < len; x++) {
        let s = 0;
        for (const r of rows) s += (r.values[x] || 0);
        if (s > maxV) maxV = s;
      }
    } else {
      for (const r of rows) for (const v of r.values) if (v > maxV) maxV = v;
    }
    const top = niceMax(maxV * 1.12) || 1;

    // 真实时间轴（可选）：model.stamps 为与数据点一一对应的秒级时间戳，
    // model.timeWindow 为 [起始秒, 结束秒]。提供后按真实时间定位 X 轴，
    // 混合粒度（历史桶 + 实时细粒度）也能正确排布，窗口右移即整条曲线滚动。
    const ax = axisOf(model, len);
    const stamps = ax.stamps;
    const tMin = ax.tMin;
    const tSpan = ax.tSpan;

    const xAt = (idx) => xAtIndex(ax, len, padL, plotW, idx);
    const yAt = (v) => padT + plotH - (v / top) * plotH;

    // 网格 + Y 轴（在面积之下绘制，作为底纹）
    ctx.save();
    ctx.font = `10.5px ${MONO}`;
    ctx.textBaseline = 'middle';
    ctx.textAlign = 'right';
    const gridSteps = 4;
    const gridYs = [];
    for (let g = 0; g <= gridSteps; g++) {
      const v = (top / gridSteps) * g;
      const y = yAt(v);
      gridYs.push({ v, y });
      ctx.strokeStyle = 'rgba(148,163,184,.09)';
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.moveTo(padL, Math.round(y) + .5);
      ctx.lineTo(padL + plotW, Math.round(y) + .5);
      ctx.stroke();
    }
    ctx.restore();

    // 面积绘制
    const base = new Array(len).fill(0);
    rows.forEach((r) => {
      const vals = r.values;
      if (!vals || vals.length === 0) return;
      const c = r.color;
      const grad = ctx.createLinearGradient(0, padT, 0, padT + plotH);
      grad.addColorStop(0, hexA(c, stacked ? 0.85 : 0.55));
      grad.addColorStop(0.55, hexA(c, stacked ? 0.42 : 0.22));
      grad.addColorStop(1, hexA(c, 0.02));
      ctx.save();
      ctx.beginPath();
      const upper = new Array(len);
      for (let x = 0; x < len; x++) {
        const v = Number(vals[x]) || 0;
        upper[x] = stacked ? base[x] + v : v;
        const px = xAt(x);
        const py = yAt(upper[x]);
        if (x === 0) ctx.moveTo(px, py); else ctx.lineTo(px, py);
      }
      for (let x = len - 1; x >= 0; x--) {
        const py = yAt(stacked ? base[x] : 0);
        ctx.lineTo(xAt(x), py);
      }
      ctx.closePath();
      ctx.fillStyle = grad;
      ctx.fill();

      // 顶部描边
      ctx.beginPath();
      for (let x = 0; x < len; x++) {
        const px = xAt(x); const py = yAt(upper[x]);
        if (x === 0) ctx.moveTo(px, py); else ctx.lineTo(px, py);
      }
      ctx.strokeStyle = hexA(c, 0.95);
      ctx.lineWidth = 1.6;
      ctx.lineJoin = 'round';
      // 点数较多时关闭描边阴影（阴影绘制代价随点数线性放大）
      if (len <= 400) {
        ctx.shadowColor = hexA(c, 0.5);
        ctx.shadowBlur = 7;
      }
      ctx.stroke();
      ctx.restore();

      if (stacked) for (let x = 0; x < len; x++) base[x] += (Number(vals[x]) || 0);
    });

    // Y 轴刻度文字（绘制在面积之上，保证始终可见）
    ctx.save();
    ctx.font = `10.5px ${MONO}`;
    ctx.textBaseline = 'middle';
    ctx.textAlign = 'right';
    gridYs.forEach((g, gi) => {
      const lbl = unit === 'bytes' ? fmtAxisBytes(g.v) : fmtAxisBps(g.v);
      ctx.fillStyle = 'rgba(93,111,140,.92)';
      ctx.fillText(lbl, padL - 8, g.y);
    });
    // 0 基线细线
    ctx.strokeStyle = 'rgba(148,163,184,.22)';
    ctx.lineWidth = 1;
    ctx.beginPath();
    ctx.moveTo(padL, Math.round(yAt(0)) + .5);
    ctx.lineTo(padL + plotW, Math.round(yAt(0)) + .5);
    ctx.stroke();
    ctx.restore();

    // X 轴标签（最多 6 个）
    ctx.save();
    ctx.font = `10.5px ${MONO}`;
    ctx.fillStyle = 'rgba(93,111,140,.9)';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'top';
    const tickCount = Math.min(6, len);
    for (let k = 0; k < tickCount; k++) {
      let idx;
      if (stamps) {
        // 真实时间轴：按时间等分取刻度，标签落在最接近该时刻的数据点上
        const t = tMin + tSpan * (tickCount === 1 ? 0.5 : k / (tickCount - 1));
        idx = 0;
        let bd = Infinity;
        for (let i = 0; i < len; i++) {
          const d = Math.abs(stamps[i] - t);
          if (d < bd) { bd = d; idx = i; }
        }
      } else {
        idx = tickCount === 1 ? 0 : Math.round((k / (tickCount - 1)) * (len - 1));
      }
      const lbl = labels[idx] ?? '';
      if (!lbl) continue;
      let x = xAt(idx);
      if (x > padL + plotW - 16) x = padL + plotW - 16;
      if (x < padL + 16) x = padL + 16;
      ctx.fillText(String(lbl).slice(-5), x, padT + plotH + 8);
    }
    ctx.restore();

    // 十字线 + 气泡
    const hov = i.hover;
    if (hov && hov.index >= 0 && hov.index < len) {
      const px = xAt(hov.index);
      ctx.save();
      ctx.strokeStyle = 'rgba(232,238,252,.30)';
      ctx.lineWidth = 1;
      ctx.setLineDash([3, 3]);
      ctx.beginPath();
      ctx.moveTo(Math.round(px) + .5, padT);
      ctx.lineTo(Math.round(px) + .5, padT + plotH);
      ctx.stroke();
      ctx.setLineDash([]);

      // 数据点
      rows.forEach((r) => {
        const v = Number(r.values[hov.index]) || 0;
        const y = stacked ? yAt(baseStackAt(rows, hov.index, r)) : yAt(v);
        ctx.beginPath();
        ctx.arc(px, y, 3, 0, Math.PI * 2);
        ctx.fillStyle = r.color;
        ctx.shadowColor = hexA(r.color, 0.9);
        ctx.shadowBlur = 8;
        ctx.fill();
        ctx.shadowBlur = 0;
      });

      // 数值气泡
      const lines = rows.map((r) => ({
        text: `${r.name || ''} ${unit === 'bytes' ? fmtAxisBytes(Number(r.values[hov.index]) || 0) : fmtAxisBps(Number(r.values[hov.index]) || 0)}`,
        color: r.color
      }));
      const bubbleW = 130;
      const bubbleH = 18 + lines.length * 16;
      let bx = px + 12;
      if (bx + bubbleW > w - 4) bx = px - bubbleW - 12;
      if (bx < 4) bx = 4;
      const by = Math.max(4, Math.min(padT, h - bubbleH - 4));
      ctx.fillStyle = 'rgba(8,12,21,.94)';
      ctx.strokeStyle = 'rgba(148,163,184,.28)';
      ctx.lineWidth = 1;
      roundRect(ctx, bx, by, bubbleW, bubbleH, 8);
      ctx.fill(); ctx.stroke();
      ctx.font = `11px ${FONT}`;
      ctx.textAlign = 'left';
      ctx.textBaseline = 'middle';
      lines.forEach((ln, k) => {
        const ly = by + 13 + k * 16;
        ctx.fillStyle = ln.color;
        ctx.fillRect(bx + 9, ly - 3.5, 7, 7);
        ctx.fillStyle = '#e8eefc';
        ctx.fillText(ln.text, bx + 22, ly);
      });
      ctx.restore();
    }
  });

  inst.model = normalizeAreaModel(opts);

  // hover 交互
  const onMove = (ev) => {
    const rect = canvas.getBoundingClientRect();
    const mx = ev.clientX - rect.left;
    const my = ev.clientY - rect.top;
    const m = inst.model;
    const rows = m.rows || [];
    const len = m.len || 0;
    if (!len || my < 0 || my > rect.height) { return; }
    const padL = m.padLeft ?? 52;
    const plotW = Math.max(10, rect.width - padL - 14);
    // 真实时间轴：按 stamps 反查最近时间点，避免等距公式反算导致落错点
    const ax = axisOf(m, len);
    const idx = indexAtX(ax, len, padL, plotW, mx);
    const x = xAtIndex(ax, len, padL, plotW, idx);
    if (Math.abs(mx - x) > Math.max(18, plotW / len)) { setHover(null); return; }
    setHover({ index: idx });
  };
  const onLeave = () => setHover(null);
  const setHover = (hv) => {
    const a = inst.hover, b = hv;
    if (a === b) return;
    if ((!a && !b) || (a && b && a.index === b.index)) return;
    inst.hover = hv;
    inst.invalidate();
    if (inst.onHover) inst.onHover(hv);
  };
  canvas.addEventListener('mousemove', onMove);
  canvas.addEventListener('mouseleave', onLeave);
  canvas.addEventListener('touchstart', (e) => { if (e.touches[0]) onMove(e.touches[0]); }, { passive: true });
  canvas.addEventListener('touchmove', (e) => { if (e.touches[0]) onMove(e.touches[0]); }, { passive: true });
  inst._cleanup.push(() => {
    canvas.removeEventListener('mousemove', onMove);
    canvas.removeEventListener('mouseleave', onLeave);
  });

  inst.update = (next) => {
    const m = normalizeAreaModel({ ...inst.model, ...next });
    inst.model = m;
    inst.invalidate();
  };
  inst.setHover = setHover;
  inst.dispose = () => disposeChart(inst);
  return inst;
}

function baseStackAt(rows, idx, target) {
  let s = 0;
  for (const r of rows) {
    if (r === target) break;
    s += (Number(r.values[idx]) || 0);
  }
  return s;
}

function normalizeAreaModel(opts) {
  const m = { ...opts };
  let rows = [];
  if (m.series && m.series.length && Array.isArray(m.series[0])) {
    rows = m.series.map((values, idx) => ({
      name: (m.names && m.names[idx]) || `S${idx + 1}`,
      color: (m.colors && m.colors[idx]) || '#22d3ee',
      values: values || []
    }));
  } else if (m.series && m.series.length && m.series[0] && typeof m.series[0] === 'object') {
    rows = m.series.map((s) => ({ name: s.name || '', color: s.color || '#22d3ee', values: s.values || [] }));
  }
  m.rows = rows;
  m.len = rows.reduce((mx, r) => Math.max(mx, (r.values?.length || 0)), 0);
  return m;
}

/* ---------- 环图 ---------- */

/**
 * @param {HTMLCanvasElement} canvas
 * @param {object} opts { data:[{key,label,value,color}], height, centerLabel, unit }
 */
export function donutChart(canvas, opts = {}) {
  const inst = createChart(canvas, (ctx, w, h, i) => {
    const data = (i.model.data || []).filter((d) => (Number(d.value) || 0) > 0);
    const total = data.reduce((a, d) => a + (Number(d.value) || 0), 0);
    const cx = w / 2;
    const cy = h / 2;
    const rOut = Math.max(10, Math.min(w, h) / 2 - 10);
    const rIn = rOut * (i.model.ratio ?? 0.62);

    if (!data.length || total <= 0) { emptyPlaceholder(ctx, w, h, i.model.emptyText || '暂无数据'); return; }

    const gapPx = 2;
    let start = -Math.PI / 2;

    data.forEach((d) => {
      const v = Number(d.value) || 0;
      const frac = v / total;
      let a0 = start;
      let a1 = start + frac * Math.PI * 2;
      start = a1;
      const hovered = i.hover && i.hover.key === d.key;
      const grow = hovered ? 3 : 0;
      const rO = rOut + grow;
      const rI = rIn + grow;

      let a0g = a0 + gapPx / 2 / rOut;
      let a1g = a1 - gapPx / 2 / rOut;
      if (a1g <= a0g) a1g = a0g + 0.001;

      ctx.save();
      ctx.beginPath();
      ctx.arc(cx, cy, rO, a0g, a1g);
      ctx.arc(cx, cy, rI, a1g, a0g, true);
      ctx.closePath();
      const base = d.color || '#22d3ee';
      if (hovered) {
        ctx.fillStyle = base;
        ctx.shadowColor = hexA(base, 0.85);
        ctx.shadowBlur = 14;
      } else {
        ctx.fillStyle = hexA(base, 0.88);
      }
      ctx.fill();
      ctx.restore();
    });

    // 中心总量
    ctx.save();
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillStyle = '#e8eefc';
    ctx.font = `700 ${Math.max(14, Math.round(rIn * 0.5))}px ${FONT}`;
    const centerText = i.model.centerText ?? fmtAxisBytes(total);
    ctx.fillText(centerText, cx, cy - 6);
    ctx.fillStyle = 'rgba(93,111,140,.95)';
    ctx.font = `11px ${FONT}`;
    ctx.fillText(i.model.centerLabel || '总量', cx, cy + 13);
    ctx.restore();

    // hover 标签
    if (i.hover) {
      const d = data.find((x) => x.key === i.hover.key);
      if (d) {
        const txt = `${d.label} ${((Number(d.value) / total) * 100).toFixed(1)}%`;
        ctx.save();
        ctx.font = `11px ${FONT}`;
        const tw = ctx.measureText(txt).width + 16;
        let bx = cx + rOut + 12;
        if (bx + tw > w) bx = cx - rOut - tw - 12;
        if (bx < 2) bx = 2;
        const by = Math.max(2, Math.min(cy - 12, h - 26));
        ctx.fillStyle = 'rgba(8,12,21,.94)';
        ctx.strokeStyle = 'rgba(148,163,184,.28)';
        ctx.lineWidth = 1;
        roundRect(ctx, bx, by, tw, 24, 7);
        ctx.fill(); ctx.stroke();
        ctx.fillStyle = d.color || '#22d3ee';
        ctx.fillRect(bx + 7, by + 9, 7, 7);
        ctx.fillStyle = '#e8eefc';
        ctx.textAlign = 'left';
        ctx.textBaseline = 'middle';
        ctx.fillText(txt, bx + 20, by + 12.5);
        ctx.restore();
      }
    }
  });

  inst.model = { ...opts, data: opts.data || [] };

  const onMove = (ev) => {
    const rect = canvas.getBoundingClientRect();
    const mx = ev.clientX - rect.left;
    const my = ev.clientY - rect.top;
    const cx = rect.width / 2, cy = rect.height / 2;
    const rOut = Math.max(10, Math.min(rect.width, rect.height) / 2 - 10);
    const d = Math.hypot(mx - cx, my - cy);
    if (d > rOut + 4 || d < rOut * 0.45) { setHover(null); return; }
    let ang = Math.atan2(my - cy, mx - cx) + Math.PI / 2;
    if (ang < 0) ang += Math.PI * 2;
    const data = (inst.model.data || []).filter((x) => (Number(x.value) || 0) > 0);
    const total = data.reduce((a, x) => a + (Number(x.value) || 0), 0);
    if (!total) { setHover(null); return; }
    let acc = 0;
    for (const item of data) {
      const frac = (Number(item.value) || 0) / total;
      const a0 = acc * Math.PI * 2;
      const a1 = (acc + frac) * Math.PI * 2;
      acc += frac;
      if (ang >= a0 && ang <= a1) { setHover({ key: item.key, item }); return; }
    }
    setHover(null);
  };
  const setHover = (hv) => {
    const a = inst.hover, b = hv;
    if ((a === null && b === null) || (a && b && a.key === b.key)) return;
    inst.hover = hv;
    inst.invalidate();
    if (inst.onHover) inst.onHover(hv);
  };
  canvas.addEventListener('mousemove', onMove);
  canvas.addEventListener('mouseleave', () => setHover(null));
  inst._cleanup.push(() => canvas.removeEventListener('mousemove', onMove));

  inst.update = (next) => { inst.model = { ...inst.model, ...next }; inst.invalidate(); };
  inst.dispose = () => disposeChart(inst);
  return inst;
}

/* ---------- 横向条形榜 ---------- */

/**
 * @param {HTMLCanvasElement} canvas
 * @param {object} opts { items:[{name,value,color,sub}], height, valueFormat }
 */
export function barRank(canvas, opts = {}) {
  const inst = createChart(canvas, (ctx, w, h, i) => {
    const items = i.model.items || [];
    if (!items.length) { emptyPlaceholder(ctx, w, h, i.model.emptyText || '暂无数据'); return; }

    const padL = i.model.nameWidth ?? 116;
    const padR = i.model.valueWidth ?? 78;
    const padT = 4;
    const padB = 4;
    const rowH = Math.max(18, (h - padT - padB) / items.length);
    const barH = Math.min(9, Math.max(5, rowH * 0.4));
    const trackX = padL;
    const trackW = Math.max(20, w - padL - padR);
    const max = Math.max(...items.map((it) => Number(it.value) || 0)) || 1;

    ctx.save();
    ctx.textBaseline = 'middle';
    items.forEach((it, k) => {
      const cy = padT + rowH * k + rowH / 2;
      const c = it.color || '#22d3ee';

      // 名称
      ctx.font = `11.5px ${FONT}`;
      ctx.textAlign = 'left';
      ctx.fillStyle = 'rgba(159,176,204,.96)';
      let nm = String(it.name || '');
      const maxChars = Math.max(4, Math.floor((padL - 10) / 6.6));
      if (nm.length > maxChars) nm = nm.slice(0, maxChars - 1) + '…';
      ctx.fillText(nm, 0, cy);

      // 轨道
      ctx.fillStyle = 'rgba(148,163,184,.10)';
      roundRect(ctx, trackX, cy - barH / 2, trackW, barH, barH / 2);
      ctx.fill();

      // 条
      const bw = Math.max(2, (Math.max(0, Number(it.value) || 0) / max) * trackW);
      const g = ctx.createLinearGradient(trackX, 0, trackX + trackW, 0);
      g.addColorStop(0, hexA(c, 0.95));
      g.addColorStop(1, hexA(c, 0.42));
      ctx.fillStyle = g;
      ctx.shadowColor = hexA(c, 0.42);
      ctx.shadowBlur = 7;
      roundRect(ctx, trackX, cy - barH / 2, bw, barH, barH / 2);
      ctx.fill();
      ctx.shadowBlur = 0;

      // 数值
      ctx.font = `11.5px ${MONO}`;
      ctx.textAlign = 'right';
      ctx.fillStyle = '#e8eefc';
      const val = i.model.valueFormat ? i.model.valueFormat(it.value) : fmtAxisBytes(it.value);
      ctx.fillText(val, w, cy);
    });
    ctx.restore();
  });

  inst.model = { ...opts, items: opts.items || [] };
  inst.update = (next) => { inst.model = { ...inst.model, ...next }; inst.invalidate(); };
  inst.dispose = () => disposeChart(inst);
  return inst;
}

/* ---------- Sparkline ---------- */

/**
 * @param {HTMLCanvasElement} canvas
 * @param {object} opts { values:number[], color, fill }
 */
export function sparkline(canvas, opts = {}) {
  const inst = createChart(canvas, (ctx, w, h, i) => {
    const vals = (i.model.values || []).map((v) => Number(v) || 0);
    if (vals.length < 2) { emptyPlaceholder(ctx, w, h, ''); return; }
    const c = i.model.color || '#22d3ee';
    const max = Math.max(...vals);
    const min = Math.min(...vals);
    const range = (max - min) || 1;
    const pad = 2;
    const plotH = h - pad * 2;
    const xAt = (idx) => (idx / (vals.length - 1)) * w;
    const yAt = (v) => pad + plotH - ((v - min) / range) * plotH;

    ctx.save();
    if (i.model.fill !== false) {
      const g = ctx.createLinearGradient(0, 0, 0, h);
      g.addColorStop(0, hexA(c, 0.40));
      g.addColorStop(1, hexA(c, 0.01));
      ctx.beginPath();
      ctx.moveTo(0, h);
      for (let k = 0; k < vals.length; k++) ctx.lineTo(xAt(k), yAt(vals[k]));
      ctx.lineTo(w, h);
      ctx.closePath();
      ctx.fillStyle = g;
      ctx.fill();
    }
    ctx.beginPath();
    for (let k = 0; k < vals.length; k++) {
      const px = xAt(k), py = yAt(vals[k]);
      if (k === 0) ctx.moveTo(px, py); else ctx.lineTo(px, py);
    }
    ctx.strokeStyle = c;
    ctx.lineWidth = 1.3;
    ctx.lineJoin = 'round';
    ctx.shadowColor = hexA(c, 0.55);
    ctx.shadowBlur = 5;
    ctx.stroke();
    ctx.shadowBlur = 0;
    // 末端点
    const lx = xAt(vals.length - 1), ly = yAt(vals[vals.length - 1]);
    ctx.beginPath();
    ctx.arc(lx - 1, ly, 1.9, 0, Math.PI * 2);
    ctx.fillStyle = c;
    ctx.fill();
    ctx.restore();
  });

  inst.model = { ...opts, values: opts.values || [] };
  inst.update = (next) => { inst.model = { ...inst.model, ...next }; inst.invalidate(); };
  inst.dispose = () => disposeChart(inst);
  return inst;
}

/* ---------- 工具：颜色透明度 ---------- */
export function hexA(hex, alpha) {
  const h = String(hex || '#22d3ee').replace('#', '');
  const full = h.length === 3 ? h.split('').map((x) => x + x).join('') : h.padEnd(6, '0').slice(0, 6);
  const num = parseInt(full, 16);
  const r = (num >> 16) & 255;
  const g = (num >> 8) & 255;
  const b = num & 255;
  return `rgba(${r},${g},${b},${alpha})`;
}

/** 生成系列色阶（分类色） */
export function catColors(keys) {
  const palette = { video: '#22d3ee', game: '#a78bfa', social: '#f472b6', web: '#38bdf8', download: '#fbbf24', mail: '#34d399', cloud: '#2dd4bf', other: '#94a3b8' };
  return (keys || []).map((k) => palette[k] || '#94a3b8');
}

export { disposeChart };
