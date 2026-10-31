/* ==========================================================================
   观澜 NetScope · 通用组件
   依据 docs/design.md §4：KPI / 卡片 / 表格 / Chip / Switch / 按钮 /
   Modal / Drawer / Toast / ConfirmDialog / 风险徽标 / 设备图标
   ========================================================================== */

import { formatBps, formatBytes, formatPercent, riskLevel, RISK_LABEL, RISK_SEM } from './format.js';

/* ---------- DOM 助手 ---------- */

export function h(tag, attrs = {}, children = []) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k === 'class') el.className = v;
    else if (k === 'html') el.innerHTML = v;
    else if (k === 'text') el.textContent = v;
    else if (k === 'style' && typeof v === 'object') Object.assign(el.style, v);
    else if (k.startsWith('on') && typeof v === 'function') el.addEventListener(k.slice(2).toLowerCase(), v);
    else if (k === 'dataset') for (const [dk, dv] of Object.entries(v)) el.dataset[dk] = dv;
    else el.setAttribute(k, v === true ? '' : String(v));
  }
  const list = Array.isArray(children) ? children : [children];
  for (const c of list) {
    if (c === null || c === undefined || c === false) continue;
    el.appendChild(typeof c === 'string' || typeof c === 'number' ? document.createTextNode(String(c)) : c);
  }
  return el;
}

export function svgIcon(path, size = 14, opts = {}) {
  const ns = 'http://www.w3.org/2000/svg';
  const svg = document.createElementNS(ns, 'svg');
  svg.setAttribute('viewBox', opts.viewBox || '0 0 24 24');
  svg.setAttribute('width', size);
  svg.setAttribute('height', size);
  svg.setAttribute('fill', opts.fill || 'none');
  svg.setAttribute('stroke', opts.stroke || 'currentColor');
  svg.setAttribute('stroke-width', opts.width || 1.8);
  svg.setAttribute('stroke-linecap', 'round');
  svg.setAttribute('stroke-linejoin', 'round');
  svg.setAttribute('aria-hidden', 'true');
  const p = document.createElementNS(ns, 'path');
  p.setAttribute('d', path);
  svg.appendChild(p);
  return svg;
}

export const ICONS = {
  search: 'M11 4a7 7 0 1 0 0 14 7 7 0 0 0 0-14ZM20 20l-4-4',
  close: 'M6 6l12 12M18 6L6 18',
  chevronDown: 'M6 9l6 6 6-6',
  chevronRight: 'M9 6l6 6-6 6',
  chevronLeft: 'M15 6l-6 6 6 6',
  refresh: 'M20 11A8 8 0 1 0 18 16M20 6v5h-5',
  power: 'M12 3v9M6.5 6.8a8 8 0 1 0 11 0',
  logout: 'M15 12H4m0 0 4-4M4 12l4 4M10 4h8a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2h-8',
  shield: 'M12 3l7 3v5c0 4.5-3 8-7 10-4-2-7-5.5-7-10V6l7-3Z',
  device: 'M4 5h16a1 1 0 0 1 1 1v9a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1V6a1 1 0 0 1 1-1Zm4 14h8',
  server: 'M4 4h16v6H4zM4 14h16v6H4zM7 7h.01M7 17h.01',
  globe: 'M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18Zm0 0c-2.5 2.2-3.8 5.2-3.8 9S9.5 18.8 12 21c2.5-2.2 3.8-5.2 3.8-9S14.5 5.2 12 3ZM3.5 9h17M3.5 15h17',
  list: 'M8 6h13M8 12h13M8 18h13M3.5 6h.01M3.5 12h.01M3.5 18h.01',
  settings: 'M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6Zm8.4-3a8.4 8.4 0 0 0-.13-1.4l2-1.55-2-3.46-2.37.96a8.3 8.3 0 0 0-2.4-1.4L15.2 2H8.8l-.3 2.15a8.3 8.3 0 0 0-2.4 1.4l-2.37-.96-2 3.46 2 1.55a8.5 8.5 0 0 0 0 2.8l-2 1.55 2 3.46 2.37-.96a8.3 8.3 0 0 0 2.4 1.4l.3 2.15h6.4l.3-2.15a8.3 8.3 0 0 0 2.4-1.4l2.37.96 2-3.46-2-1.55c.08-.46.13-.93.13-1.4Z',
  activity: 'M3 12h4l3-8 4 16 3-8h4',
  alert: 'M12 9v4m0 4h.01M10.3 4.2 2.4 18a2 2 0 0 0 1.7 3h15.8a2 2 0 0 0 1.7-3L13.7 4.2a2 2 0 0 0-3.4 0Z',
  info: 'M12 16v-4m0-4h.01M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18Z',
  check: 'M4 12.5 9 17.5 20 6.5',
  plus: 'M12 5v14M5 12h14',
  trash: 'M4 7h16M9 7V5h6v2m-8 0 1 13h8l1-13',
  edit: 'M4 20h4L19 9a2.1 2.1 0 0 0-3-3L5 17v3Z',
  ban: 'M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18ZM5.6 5.6l12.8 12.8',
  gauge: 'M12 14a2 2 0 1 0 0-4 2 2 0 0 0 0 4Zm1.4-3.4L18 6M4 19h16',
  clock: 'M12 7v5l3 2M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18Z',
  eye: 'M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7-10-7-10-7Zm10 3a3 3 0 1 0 0-6 3 3 0 0 0 0 6Z',
  key: 'M14 7a4 4 0 1 1-3.5 5.9L4 19.5V16h3v-3h3l.5-.5A4 4 0 0 1 14 7Z',
  undo: 'M4 9h9a5 5 0 0 1 0 10H8M4 9l4-4M4 9l4 4',
  download: 'M12 3v12m0 0 4-4m-4 4-4-4M4 19h16',
  filter: 'M3 5h18l-7 8v6l-4 2v-8L3 5Z',
  layers: 'M12 3 3 8l9 5 9-5-9-5ZM3 13l9 5 9-5',
  arrowUp: 'M12 19V5m0 0-5 5m5-5 5 5',
  arrowDown: 'M12 5v14m0 0 5-5m-5 5-5-5',
  lock: 'M6 11h12v9H6zM9 11V8a3 3 0 0 1 6 0v3',
  cpu: 'M8 8h8v8H8zM5 10h3m-3 4h3m8-4h3m-3 4h3M10 5v3m4-3v3m-4 8v3m4-3v3',
  monitor: 'M3 5h18v11H3zM8 20h8M12 16v4',
  wifi: 'M2 8.5a16 16 0 0 1 20 0M5.5 12a11 11 0 0 1 13 0M9 15.5a6 6 0 0 1 6 0M12 19h.01',
  mobile: 'M7 3h10v18H7zM11 18h2',
  tv: 'M3 6h18v11H3zM8 21h8M12 17v4',
  laptop: 'M4 5h16v11H4zM2 19h20',
  printer: 'M7 8V3h10v5M6 18H4v-7h16v7h-2M7 14h10v7H7z',
  router: 'M4 14h16v5H4zM7 10a4 4 0 0 1 8 0M9.5 6.5a7 7 0 0 1 5 0M12 14h.01',
  camera: 'M4 8h3l2-3h6l2 3h3v11H4zM12 17a4 4 0 1 0 0-8 4 4 0 0 0 0 8Z',
  speaker: 'M5 9h4l5-4v14l-5-4H5zM17 9a4 4 0 0 1 0 6',
  gamepad: 'M7 8h10a4 4 0 0 1 3.9 4.9l-1 4a2.5 2.5 0 0 1-4.3.7L14 16h-4l-1.6 1.6a2.5 2.5 0 0 1-4.3-.7l-1-4A4 4 0 0 1 7 8Zm1 3v3M8 9.5h2M16 11h.01M18 13h.01',
  bulb: 'M9 18h6M10 21h4M12 3a6 6 0 0 0-3.5 10.9V16h7v-2.1A6 6 0 0 0 12 3Z'
};

/* ---------- KPI 块 ---------- */

export function kpi({ label, value, unit, delta, deltaLabel, sem = 'brand', icon, sparkCanvas, hint }) {
  const el = h('div', { class: `kpi s-${sem}` }, [
    h('div', { class: 'kpi-label' }, [
      icon ? svgIcon(icon, 13) : null,
      h('span', { text: label })
    ]),
    h('div', { class: 'kpi-value' }, [
      h('span', { text: value }),
      unit ? h('span', { class: 'u', text: unit }) : null
    ]),
    (delta !== undefined && delta !== null) || hint || deltaLabel ? h('div', { class: 'kpi-meta' }, [
      delta !== undefined && delta !== null ? h('span', {
        class: `kpi-delta ${delta > 0 ? 'up' : delta < 0 ? 'down' : 'flat'}`
      }, [
        svgIcon(delta >= 0 ? ICONS.arrowUp : ICONS.arrowDown, 11),
        h('span', { text: `${delta > 0 ? '+' : ''}${delta}` })
      ]) : null,
      deltaLabel ? h('span', { text: deltaLabel }) : null,
      hint ? h('span', { text: hint }) : null
    ]) : null
  ]);
  if (sparkCanvas) {
    const box = h('div', { class: 'kpi-spark' });
    box.appendChild(sparkCanvas);
    el.appendChild(box);
  }
  return el;
}

/* ---------- 卡片 ---------- */

export function card({ title, sub, actions, bodyClass = '', body = [], foot = [], cls = '', style }) {
  const c = h('section', { class: `card ${cls}`, style });
  if (title || actions) {
    c.appendChild(h('div', { class: 'card-head' }, [
      h('div', {}, [
        h('div', { class: 'card-title', text: title || '' }),
        sub ? h('div', { class: 'card-sub', text: sub }) : null
      ]),
      actions ? h('div', { class: 'card-actions' }, actions) : null
    ]));
  }
  const b = h('div', { class: `card-body ${bodyClass}` });
  const list = Array.isArray(body) ? body : [body];
  list.forEach((x) => { if (x) b.appendChild(x); });
  c.appendChild(b);
  if (foot && foot.length) c.appendChild(h('div', { class: 'card-foot' }, foot));
  return c;
}

/* ---------- 按钮 ---------- */

export function button(label, opts = {}) {
  const b = h('button', {
    class: `btn ${opts.variant || 'ghost'} ${opts.size || ''} ${opts.block ? 'block' : ''}`.trim(),
    type: 'button',
    title: opts.title || '',
    onclick: opts.onClick,
    disabled: opts.disabled
  }, [
    opts.icon ? svgIcon(opts.icon, opts.size === 'sm' ? 12 : 13) : null,
    label ? h('span', { text: label }) : null
  ]);
  if (opts.loading) b.classList.add('is-loading');
  b.setLoading = (on) => b.classList.toggle('is-loading', !!on);
  return b;
}

/* ---------- Chip ---------- */

export function chip(text, opts = {}) {
  const c = h('span', { class: `chip ${opts.sem ? `s-${opts.sem}` : ''} ${opts.plain ? 'plain' : ''} ${opts.square ? 'sq' : ''}`.trim() }, [
    opts.dot ? h('i', { class: 'dot' }) : null,
    opts.icon ? svgIcon(opts.icon, 11) : null,
    h('span', { text })
  ]);
  if (opts.onClick) {
    c.classList.add('chip-btn');
    if (opts.active) c.classList.add('on');
    c.addEventListener('click', opts.onClick);
  }
  return c;
}

/* ---------- Switch ---------- */

export function switchControl({ checked = false, label = '', onChange, disabled = false }) {
  const input = h('input', { type: 'checkbox', disabled, ...(checked ? { checked: true } : {}) });
  const track = h('span', { class: 'switch-track' });
  const lab = h('label', { class: 'switch' }, [input, track, label ? h('span', { class: 'switch-label', text: label }) : null]);
  input.addEventListener('change', () => { if (onChange) onChange(input.checked); });
  lab.setChecked = (v) => { input.checked = !!v; };
  lab.getEl = () => input;
  return lab;
}

/* ---------- 表格 ---------- */

/**
 * 可排序 / 可搜索 / 空态 / 骨架屏的表格。
 * @returns {HTMLElement & {setRows, setLoading, setQuery, setSort}}
 */
export function table({ columns, rows = [], empty = '暂无数据', emptyIcon = ICONS.list, searchable = false, onRowClick, sortKey, sortDir = 'desc', pageSize = 0, rowClass }) {
  const wrap = h('div', { class: 'table-wrap' });
  const tbl = h('table', { class: 'tbl' });
  const thead = h('thead');
  const tbody = h('tbody');
  tbl.appendChild(thead);
  tbl.appendChild(tbody);
  wrap.appendChild(tbl);

  let state = { rows: [], query: '', sortKey, sortDir, loading: false, page: 1 };

  function renderHead() {
    thead.innerHTML = '';
    const tr = h('tr');
    columns.forEach((c) => {
      const sorted = state.sortKey === c.key;
      const th = h('th', {
        class: `${c.sortable === false ? '' : 'sortable'} ${sorted ? 'sorted' : ''} ${c.align === 'right' ? 'td-right' : ''}`.trim(),
        style: c.width ? { width: c.width } : null
      }, [
        h('span', { text: c.title }),
        c.sortable === false ? null : h('span', { class: 'sort-ind', text: sorted ? (state.sortDir === 'asc' ? '▲' : '▼') : '⇅' })
      ]);
      if (c.sortable !== false) {
        th.addEventListener('click', () => {
          if (state.sortKey === c.key) state.sortDir = state.sortDir === 'asc' ? 'desc' : 'asc';
          else { state.sortKey = c.key; state.sortDir = c.sortableDir || 'desc'; }
          render();
        });
      }
      tr.appendChild(th);
    });
    thead.appendChild(tr);
  }

  function sortRows(list) {
    if (!state.sortKey) return list;
    const col = columns.find((c) => c.key === state.sortKey);
    const get = col?.sortValue || ((r) => r[state.sortKey]);
    return list.slice().sort((a, b) => {
      const va = get(a), vb = get(b);
      if (typeof va === 'number' && typeof vb === 'number') return state.sortDir === 'asc' ? va - vb : vb - va;
      const sa = String(va ?? ''), sb = String(vb ?? '');
      return state.sortDir === 'asc' ? sa.localeCompare(sb, 'zh-CN') : sb.localeCompare(sa, 'zh-CN');
    });
  }

  function render() {
    tbody.innerHTML = '';
    if (state.loading) {
      for (let i = 0; i < 5; i++) {
        const tr = h('tr');
        columns.forEach(() => tr.appendChild(h('td', {}, [h('div', { class: 'skel-line w2', style: { margin: '13px 0' } })])));
        tbody.appendChild(tr);
      }
      return;
    }
    let list = state.rows;
    if (state.query) {
      const q = state.query.toLowerCase();
      list = list.filter((r) => (r.__search || '').toLowerCase().includes(q));
    }
    list = sortRows(list);

    const total = list.length;
    let pageItems = list;
    if (pageSize > 0) {
      const pages = Math.max(1, Math.ceil(total / pageSize));
      state.page = Math.min(state.page, pages);
      const start = (state.page - 1) * pageSize;
      pageItems = list.slice(start, start + pageSize);
    }

    if (!pageItems.length) {
      const tr = h('tr');
      const td = h('td', { colspan: columns.length, style: { height: 'auto', padding: '0' } });
      td.appendChild(emptyState(empty, 'list' in ICONS ? emptyIcon : ICONS.list));
      tr.appendChild(td);
      tbody.appendChild(tr);
      if (api.__onPage) api.__onPage(1, 1);
      return;
    }
    pageItems.forEach((r) => {
      const tr = h('tr');
      const extra = rowClass ? rowClass(r) : '';
      if (extra) tr.className = extra;
      columns.forEach((c) => {
        const td = h('td', { class: `${c.align === 'right' ? 'td-right' : ''} ${c.cellClass || ''}`.trim() });
        const v = c.render ? c.render(r) : r[c.key];
        if (v instanceof Node) td.appendChild(v);
        else td.textContent = v === undefined || v === null ? '—' : String(v);
        tr.appendChild(td);
      });
      if (onRowClick) {
        tr.style.cursor = 'pointer';
        tr.addEventListener('click', (ev) => {
          if (ev.target.closest('button, a, input, select, .switch, .op-btn')) return;
          onRowClick(r, ev);
        });
      }
      tbody.appendChild(tr);
    });
    if (api.__onPage) api.__onPage(state.page, pageSize > 0 ? Math.max(1, Math.ceil(total / pageSize)) : 1);
  }

  const api = {
    el: wrap,
    setRows(next) { state.rows = next || []; render(); },
    setLoading(on) { state.loading = !!on; render(); },
    setQuery(q) { state.query = q || ''; state.page = 1; render(); },
    setSort(key, dir = 'desc') { state.sortKey = key; state.sortDir = dir; render(); },
    getRows() { return state.rows; },
    refresh: render,
    __onPage: null
  };
  renderHead();
  render();
  return api;
}

/* ---------- 空态 / 骨架 / 错误 ---------- */

export function emptyState(text, icon = ICONS.list, hint = '', action = null) {
  return h('div', { class: 'empty' }, [
    h('div', { class: 'empty-icon' }, [svgIcon(icon, 20)]),
    h('div', { class: 'empty-text', text }),
    hint ? h('div', { class: 'empty-hint', text: hint }) : null,
    action || null
  ]);
}

export function skeleton(lines = 3) {
  const s = h('div', { class: 'skel' });
  for (let i = 0; i < lines; i++) s.appendChild(h('div', { class: `skel-line w${(i % 3) + 1}` }));
  return s;
}

export function errorBox(message, onRetry) {
  return h('div', { class: 'err-box' }, [
    h('span', { class: 'e-icon' }, [svgIcon(ICONS.alert, 14)]),
    h('span', { class: 'spacer', text: message || '加载失败' }),
    onRetry ? button('重试', { size: 'sm', variant: 'ghost', onClick: onRetry }) : null
  ]);
}

/**
 * 系统未启用 / 功能开关关闭时的空态提示（docs/api.md §7.3）。
 * 不报错，仅说明原因并给出指引。
 */
export function disabledState({ title, desc, hint, icon = ICONS.power, action = null }) {
  return h('div', { class: 'disabled-state' }, [
    h('div', { class: 'disabled-state-ico' }, [svgIcon(icon, 24)]),
    h('div', { class: 'disabled-state-title', text: title || '该功能未启用' }),
    desc ? h('div', { class: 'disabled-state-desc', text: desc }) : null,
    hint ? h('div', { class: 'disabled-state-hint', text: hint }) : null,
    action
  ]);
}

/* ---------- Toast ---------- */

export function toast(message, type = 'info', opts = {}) {
  const host = document.getElementById('toast-host');
  if (!host) return;
  const sem = type === 'success' ? 'ok' : type === 'error' ? 'crit' : 'info';
  const icon = type === 'success' ? ICONS.check : type === 'error' ? ICONS.alert : ICONS.info;
  const el = h('div', { class: `toast s-${sem}` }, [
    h('span', { class: 'toast-ico' }, [svgIcon(icon, 14)]),
    h('div', { class: 'toast-msg' }, [
      opts.title ? h('div', { class: 'toast-title', text: opts.title }) : null,
      h('div', { text: message })
    ]),
    h('button', { class: 'toast-close', type: 'button', onclick: () => remove() }, [svgIcon(ICONS.close, 12)])
  ]);
  let timer = null;
  const remove = () => {
    if (timer) clearTimeout(timer);
    el.classList.add('out');
    setTimeout(() => el.remove(), 220);
  };
  host.appendChild(el);
  timer = setTimeout(remove, opts.duration || 3000);
  return { close: remove, el };
}

/* ---------- Modal ---------- */

export function modal({ title, body = [], foot = [], width, onClose, closable = true }) {
  const host = document.getElementById('overlay-host');
  const mask = h('div', { class: 'mask' });
  const box = h('div', { class: 'modal', style: width ? { width: `min(${width}px, calc(100vw - 40px))` } : null });
  const head = h('div', { class: 'modal-head' }, [
    h('div', { class: 'modal-title', text: title || '' }),
    h('div', { class: 'spacer', style: { flex: '1' } }),
    closable ? h('button', { class: 'icon-btn', type: 'button', onclick: () => api.close() }, [svgIcon(ICONS.close, 13)]) : null
  ]);
  const bodyEl = h('div', { class: 'modal-body' });
  (Array.isArray(body) ? body : [body]).forEach((b) => { if (b) bodyEl.appendChild(b); });
  const footEl = h('div', { class: 'modal-foot' });
  (Array.isArray(foot) ? foot : [foot]).forEach((b) => { if (b) footEl.appendChild(b); });
  box.appendChild(head); box.appendChild(bodyEl);
  if (footEl.children.length) box.appendChild(footEl);
  host.appendChild(mask);
  host.appendChild(box);

  const onKey = (ev) => { if (ev.key === 'Escape') api.close(); };
  document.addEventListener('keydown', onKey);
  if (closable) mask.addEventListener('click', () => api.close());

  const api = {
    el: box,
    body: bodyEl,
    close() {
      document.removeEventListener('keydown', onKey);
      mask.remove(); box.remove();
      if (onClose) onClose();
    },
    setLoading(on) { box.querySelectorAll('button').forEach((b) => { b.disabled = !!on; }); }
  };
  return api;
}

/* ---------- Drawer ---------- */

export function drawer({ title, sub, body = [], foot = [], width, onClose }) {
  const host = document.getElementById('overlay-host');
  const mask = h('div', { class: 'mask' });
  const box = h('div', { class: 'drawer', style: width ? { width: `min(${width}px, 94vw)` } : null });
  const head = h('div', { class: 'drawer-head' }, [
    h('div', { style: { minWidth: '0' } }, [
      h('div', { class: 'drawer-title', text: title || '' }),
      sub ? h('div', { class: 'drawer-sub', text: sub }) : null
    ]),
    h('div', { class: 'spacer', style: { flex: '1' } }),
    h('button', { class: 'icon-btn', type: 'button', onclick: () => api.close() }, [svgIcon(ICONS.close, 13)])
  ]);
  const bodyEl = h('div', { class: 'drawer-body' });
  (Array.isArray(body) ? body : [body]).forEach((b) => { if (b) bodyEl.appendChild(b); });
  const footEl = h('div', { class: 'drawer-foot' });
  (Array.isArray(foot) ? foot : [foot]).forEach((b) => { if (b) footEl.appendChild(b); });
  box.appendChild(head); box.appendChild(bodyEl);
  if (footEl.children.length) box.appendChild(footEl);
  host.appendChild(mask);
  host.appendChild(box);
  mask.addEventListener('click', () => api.close());
  const onKey = (ev) => { if (ev.key === 'Escape') api.close(); };
  document.addEventListener('keydown', onKey);

  const api = {
    el: box,
    body: bodyEl,
    foot: footEl,
    close() {
      document.removeEventListener('keydown', onKey);
      mask.remove(); box.remove();
      if (onClose) onClose();
    },
    setBody(nodes) {
      bodyEl.innerHTML = '';
      (Array.isArray(nodes) ? nodes : [nodes]).forEach((n) => { if (n) bodyEl.appendChild(n); });
    },
    setFoot(nodes) {
      footEl.innerHTML = '';
      (Array.isArray(nodes) ? nodes : [nodes]).forEach((n) => { if (n) footEl.appendChild(n); });
    }
  };
  return api;
}

/* ---------- ConfirmDialog ---------- */

export function confirmDialog({ title = '确认操作', message, confirmText = '确认', cancelText = '取消', danger = false, onConfirm }) {
  const m = modal({
    title,
    width: 420,
    body: [h('div', { class: 'fs-13', style: { lineHeight: '1.6', color: 'var(--text-1)' }, text: message })],
    foot: [
      button(cancelText, { variant: 'ghost', onClick: () => m.close() }),
      button(confirmText, { variant: danger ? 'danger' : 'primary', onClick: async () => {
        const btn = m.el.querySelector('.btn:last-child');
        btn.classList.add('is-loading');
        try { await onConfirm(); m.close(); } catch (e) { btn.classList.remove('is-loading'); toast(e.message || '操作失败', 'error'); }
      } })
    ]
  });
  return m;
}

/* ---------- 风险徽标 ---------- */

export function riskBadge(risk, opts = {}) {
  const lv = riskLevel(risk);
  const sem = RISK_SEM[lv];
  const pct = Math.round(Math.min(1, Math.max(0, Number(risk) || 0)) * 100);
  const el = h('span', { class: `chip s-${sem} ${opts.square ? 'sq' : ''}`.trim(), title: `风险评分 ${pct}` }, [
    h('i', { class: 'dot' }),
    h('span', { text: opts.compact ? `${pct}` : `${RISK_LABEL[lv]} ${pct}` })
  ]);
  return el;
}

/* ---------- 设备图标（按厂商/类型生成 SVG） ---------- */

const VENDOR_ICONS = {
  魅族: ICONS.mobile, 华为: ICONS.mobile, 小米: ICONS.mobile, 红米: ICONS.mobile,
  OPPO: ICONS.mobile, vivo: ICONS.mobile, 荣耀: ICONS.mobile, 苹果: ICONS.mobile,
  iPhone: ICONS.mobile, 三星: ICONS.mobile, realme: ICONS.mobile, 一加: ICONS.mobile,
  联想: ICONS.laptop, 华硕: ICONS.router, 惠普: ICONS.printer, 任天堂: ICONS.gamepad
};

const TYPE_ICONS = {
  手机: ICONS.mobile, 电脑: ICONS.laptop, 电视: ICONS.tv, 打印机: ICONS.printer,
  路由: ICONS.router, 摄像头: ICONS.camera, 音箱: ICONS.speaker,
  游戏机: ICONS.gamepad, 其他: ICONS.device
};

export function deviceIcon(device, size = 30) {
  const ns = 'http://www.w3.org/2000/svg';
  const svg = document.createElementNS(ns, 'svg');
  svg.setAttribute('viewBox', '0 0 32 32');
  svg.setAttribute('width', size);
  svg.setAttribute('height', size);
  svg.setAttribute('fill', 'none');
  svg.setAttribute('aria-hidden', 'true');

  const vendor = (device?.vendor || '').trim();
  const host = (device?.hostname || '').trim();
  const type = (device?.deviceType || device?.type || '').trim();
  const sem = device?.online === false ? 'muted' : (device?.blocked ? 'crit' : 'brand');

  const colorMap = { brand: '#22d3ee', muted: '#5d6f8c', crit: '#fb7185', warn: '#fbbf24', ok: '#34d399' };
  const c = colorMap[sem] || '#22d3ee';

  // 背景圆角方块
  const bg = document.createElementNS(ns, 'rect');
  bg.setAttribute('x', '1'); bg.setAttribute('y', '1');
  bg.setAttribute('width', '30'); bg.setAttribute('height', '30');
  bg.setAttribute('rx', '9');
  bg.setAttribute('fill', 'rgba(148,163,184,.07)');
  bg.setAttribute('stroke', 'rgba(148,163,184,.16)');
  svg.appendChild(bg);

  // 图标路径：设备类型优先，其次厂商，最后按主机名特征推断
  let d = TYPE_ICONS[type];
  if (!d) d = VENDOR_ICONS[vendor];
  if (!d) {
    const hay = `${host} ${vendor} ${type}`.toLowerCase();
    if (/tv|box|电视|机顶盒|airc|mibox/.test(hay)) d = ICONS.tv;
    else if (/iphone|phone|手机|android|meizu|redmi|note|al00|huawei|xiaomi|oppo|vivo/.test(hay)) d = ICONS.mobile;
    else if (/pc|laptop|desktop|电脑|mac|win/.test(hay)) d = ICONS.laptop;
    else if (/camera|摄像/.test(hay)) d = ICONS.camera;
    else if (/speaker|音箱|audio|sonos/.test(hay)) d = ICONS.speaker;
    else if (/game|switch|游戏/.test(hay)) d = ICONS.gamepad;
    else if (/printer|打印|laser|m233/.test(hay)) d = ICONS.printer;
    else if (/router|路由|gateway|ax6000|openwrt/.test(hay)) d = ICONS.router;
    else d = ICONS.device;
  }
  // 把 24 视口路径缩放到 32 视口居中
  const g = document.createElementNS(ns, 'g');
  g.setAttribute('transform', 'translate(5.4 5.4) scale(0.88)');
  const p = document.createElementNS(ns, 'path');
  p.setAttribute('d', d);
  p.setAttribute('stroke', c);
  p.setAttribute('stroke-width', '1.9');
  p.setAttribute('stroke-linecap', 'round');
  p.setAttribute('stroke-linejoin', 'round');
  g.appendChild(p);
  svg.appendChild(g);
  return svg;
}

/* ---------- 分页器 ---------- */

export function pager({ onChange }) {
  const el = h('div', { class: 'row-gap-2', style: { justifyContent: 'flex-end', width: '100%' } });
  const info = h('span', { class: 'fs-11 dim' });
  const prev = button('', { size: 'sm', variant: 'ghost', icon: ICONS.chevronLeft, onClick: () => api.prev() });
  const next = button('', { size: 'sm', variant: 'ghost', icon: ICONS.chevronRight, onClick: () => api.next() });
  const st = { page: 1, pages: 1, total: 0 };
  const render = () => {
    info.textContent = `第 ${st.page} / ${st.pages} 页 · 共 ${st.total} 条`;
    prev.disabled = st.page <= 1;
    next.disabled = st.page >= st.pages;
  };
  el.appendChild(info);
  el.appendChild(prev);
  el.appendChild(next);
  const api = {
    el,
    set(page, pages, total) {
      st.page = page; st.pages = Math.max(1, pages); st.total = total;
      render();
    },
    prev() { if (st.page > 1) { st.page--; render(); if (onChange) onChange(st.page); } },
    next() { if (st.page < st.pages) { st.page++; render(); if (onChange) onChange(st.page); } }
  };
  render();
  return api;
}

/* ---------- 键值表 ---------- */

export function kvList(pairs) {
  const g = h('div', { class: 'kv-grid' });
  pairs.filter(Boolean).forEach(([k, v]) => {
    g.appendChild(h('div', { class: 'kv' }, [
      h('span', { class: 'k', text: k }),
      h('span', { class: 'v', text: v ?? '—' })
    ]));
  });
  return g;
}

/* ---------- 速率显示 ---------- */

export function rateCell(upBps, downBps, sparkCanvas) {
  const el = h('div', { class: 'rate' }, [
    h('div', { class: 'rate-line' }, [
      h('span', { class: 'ar txt-brand', text: '↑' }),
      h('span', { class: 'up', text: formatBps(upBps) })
    ]),
    h('div', { class: 'rate-line' }, [
      h('span', { class: 'ar txt-brand', text: '↓' }),
      h('span', { class: 'dn', text: formatBps(downBps) })
    ])
  ]);
  if (sparkCanvas) {
    const sp = h('div', { class: 'rate-spark' });
    sp.appendChild(sparkCanvas);
    el.appendChild(sp);
  }
  return el;
}

export { formatBps, formatBytes, formatPercent };
