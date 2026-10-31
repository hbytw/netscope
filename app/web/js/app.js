/* ==========================================================================
   观澜 NetScope · 应用外壳与路由
   - hash 路由：#/overview #/devices #/traffic #/behavior #/security #/settings #/screen
   - 顶栏 56px：品牌 / 导航 / 系统状态（来自 SSE tick.sys）/ 时钟 / 退出
   - 生命周期：切页时调用上一页 unmount()，释放图表、监听器、SSE 订阅
   ========================================================================== */

import { api, MOCK_MODE, subscribeSettings, isEnabled, refreshSettings, setSwitch } from './api.js';
import { h, svgIcon, toast, modal, drawer, button, ICONS, confirmDialog } from './ui/components.js';
import { formatBps, formatNumber, formatDuration } from './ui/format.js';

import * as OverviewPage from './ui/overview.js';
import * as DevicesPage from './ui/devices.js';
import * as TrafficPage from './ui/traffic.js';
import * as BehaviorPage from './ui/behavior.js';
import * as SecurityPage from './ui/security.js';
import * as SettingsPage from './ui/settings.js';
import { renderLogin } from './ui/login.js';

const ROUTES = [
  { path: 'overview', label: '总览大屏', icon: ICONS.monitor, mod: OverviewPage },
  { path: 'devices', label: '设备', icon: ICONS.device, mod: DevicesPage },
  { path: 'traffic', label: '流量', icon: ICONS.activity, mod: TrafficPage },
  { path: 'behavior', label: '行为', icon: ICONS.list, mod: BehaviorPage },
  { path: 'security', label: '安全', icon: ICONS.shield, mod: SecurityPage },
  { path: 'settings', label: '设置', icon: ICONS.settings, mod: SettingsPage }
];

const appEl = document.getElementById('app');
const overlayHost = document.getElementById('overlay-host');

/* ---------- 全局错误收集（mock 模式下显示角标自查） ---------- */
const consoleErrors = [];
window.addEventListener('error', (ev) => {
  const msg = ev.message || String(ev.error || 'unknown error');
  consoleErrors.push(msg);
  console.error('[window.onerror]', msg, ev.filename, ev.lineno);
  showErrorBadge();
});
window.addEventListener('unhandledrejection', (ev) => {
  const msg = (ev.reason && ev.reason.message) || String(ev.reason || 'unhandled rejection');
  consoleErrors.push(msg);
  console.error('[unhandledrejection]', msg);
  showErrorBadge();
});
const origError = console.error.bind(console);
console.error = (...args) => {
  const first = args.map((a) => (a && a.message) ? a.message : String(a)).join(' ');
  consoleErrors.push(first);
  origError(...args);
  showErrorBadge();
};

let errBadgeEl = null;
function showErrorBadge() {
  if (!MOCK_MODE) return;
  if (!errBadgeEl) {
    errBadgeEl = h('div', { class: 'err-badge' });
    document.body.appendChild(errBadgeEl);
  }
  errBadgeEl.textContent = `⚠ 控制台错误 ${consoleErrors.length} 处\n${consoleErrors.slice(-3).join('\n')}`;
}

/* ---------- 全局工具（供页面模块使用） ---------- */
window.__glToast = (msg, type = 'info', opts) => toast(msg, type, opts);
window.__glModal = (opts) => modal(opts);
window.__glDrawer = (opts) => drawer(opts);
window.__glConfirm = (opts) => confirmDialog(opts);
window.__glErrors = consoleErrors;

/* ---------- 状态 ---------- */
const state = {
  route: 'overview',
  authed: false,
  username: '',
  sys: null,
  kpi: null,
  currentUnmount: null,
  clockTimer: null,
  screenMount: null
};

/* ---------- 顶栏 ---------- */
let els = {};

function buildShell() {
  appEl.innerHTML = '';

  // 3D 大屏入口：新窗口/新标签页打开独立页面 screen.html（不再走 SPA 内嵌）；
  // 弹窗被浏览器拦截时退回旧的 #/screen 内嵌路由（保持兼容）。
  // 若当前页面带 ?mock=1 / ?mockoff=... 演示参数，则透传给新窗口，离线演示也能正常渲染。
  const openScreenWindow = () => {
    let win = null;
    try {
      const params = new URLSearchParams(location.search);
      const carry = params.has('mock') || params.has('mockoff') ? '?' + params.toString() : '';
      win = window.open('./screen.html' + carry, '_blank', 'width=1600,height=900');
    } catch (_) {
      win = null;
    }
    if (!win) location.hash = '#/screen';
  };

  const brand = h('div', { class: 'brand', title: '在新窗口打开 3D 托盘态势大屏' }, [
    h('div', { class: 'brand-logo' }),
    h('div', { class: 'brand-text' }, [
      h('div', { class: 'brand-name', html: '观澜<em>NetScope</em>' }),
      h('div', { class: 'brand-sub', text: '用户上网行为态势感知' })
    ])
  ]);
  brand.addEventListener('click', openScreenWindow);

  const nav = h('nav', { class: 'nav', role: 'tablist' });
  ROUTES.forEach((r) => {
    const b = h('button', { class: 'nav-tab', type: 'button', role: 'tab', dataset: { path: r.path } }, [
      h('span', { text: r.label })
    ]);
    b.addEventListener('click', () => { location.hash = `#/${r.path}`; });
    nav.appendChild(b);
  });

  // 3D 大屏入口：新窗口打开独立大屏页 screen.html；旧 #/screen 路由仍保留兼容。
  const screenBtn = h('button', {
    class: 'nav-tab nav-tab-screen',
    type: 'button',
    title: '在新窗口打开 3D 托盘态势大屏',
    'aria-label': '在新窗口打开 3D 托盘态势大屏',
  }, [
    svgIcon(ICONS.monitor, 13),
    h('span', { text: '3D 大屏' })
  ]);
  screenBtn.addEventListener('click', openScreenWindow);

  const sysbar = h('div', { class: 'sysbar' }, [
    sysBadge(),
    h('div', { class: 'sys-sep' }),
    sysItem('cpuPct', 'CPU'),
    sysItem('memPct', '内存'),
    h('div', { class: 'sys-sep' }),
    sysItem('connCount', '连接', 'opt'),
    sysItem('online', '在线', 'opt')
  ]);

  const clock = h('div', { class: 'clock' }, [
    h('div', { class: 't num', text: '--:--:--' }),
    h('div', { class: 'd', text: '' })
  ]);

  const logoutBtn = h('button', { class: 'icon-btn', type: 'button', title: '退出登录' }, [svgIcon(ICONS.logout, 15)]);
  logoutBtn.addEventListener('click', doLogout);

  const topbar = h('header', { class: 'topbar' }, [
    brand,
    screenBtn,
    nav,
    h('div', { class: 'topbar-right' }, [
      sysbar,
      h('div', { class: 'sys-sep' }),
      clock,
      logoutBtn
    ])
  ]);

  const content = h('main', { class: 'content', id: 'content' });

  appEl.appendChild(topbar);
  appEl.appendChild(content);

  els = { topbar, nav, content, clock, sysbar };
  startClock();
}

function sysItem(key, label, extraCls = '') {
  const v = h('span', { class: `v ${extraCls}`, text: '—' });
  const el = h('div', { class: `sys-item ${extraCls}`, dataset: { key } }, [
    h('span', { class: 'k', text: label }),
    v
  ]);
  sysValues[key] = v;
  return el;
}

const sysValues = {};

/** 顶栏系统状态标识：运行中 / 未启用 */
function sysBadge() {
  const el = h('span', {
    class: 'chip s-mute plain', title: '系统总开关状态',
    style: { cursor: 'pointer' }
  }, [
    h('i', { class: 'dot' }),
    h('span', { text: '未启用' })
  ]);
  el.addEventListener('click', () => { location.hash = '#/settings'; });
  sysValues.badge = el;
  return el;
}

function updateSysBadge() {
  const el = sysValues.badge;
  if (!el) return;
  const on = isEnabled();
  el.className = `chip ${on ? 's-ok' : 's-mute plain'}`;
  el.querySelector('span').textContent = on ? '运行中' : '未启用';
  el.title = on ? '系统已启用，正在采集与管控' : '系统未启用（点击前往设置页开启）';
}

function updateSys(sys, kpi) {
  if (!sys) return;
  state.sys = sys;
  const set = (k, val, warnAt, critAt) => {
    const el = sysValues[k];
    if (!el) return;
    el.textContent = val;
    el.classList.remove('warn', 'crit');
    if (critAt !== undefined && val !== '—' && typeof val === 'number') {
      if (val >= critAt) el.classList.add('crit');
      else if (warnAt !== undefined && val >= warnAt) el.classList.add('warn');
    }
  };
  set('cpuPct', `${Number(sys.cpuPct || 0).toFixed(0)}%`, 70, 88);
  set('memPct', `${Number(sys.memPct || 0).toFixed(0)}%`, 78, 90);
  set('connCount', formatNumber(sys.connCount || 0));
  if (kpi) set('online', `${kpi.online ?? 0}/${kpi.devices ?? 0}`);
}

function startClock() {
  const tick = () => {
    const d = new Date();
    const p = (x) => String(x).padStart(2, '0');
    els.clock.querySelector('.t').textContent = `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
    const week = ['日', '一', '二', '三', '四', '五', '六'][d.getDay()];
    els.clock.querySelector('.d').textContent = `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} 周${week}`;
  };
  tick();
  if (state.clockTimer) clearInterval(state.clockTimer);
  state.clockTimer = setInterval(tick, 1000);
}

/* ---------- 路由 ---------- */

function parseRoute() {
  const raw = (location.hash || '').replace(/^#\/?/, '').split('?')[0];
  const p = raw || 'overview';
  if (p === 'screen') return 'screen';
  return ROUTES.some((r) => r.path === p) ? p : 'overview';
}

function setActiveNav(path) {
  els.nav.querySelectorAll('.nav-tab').forEach((b) => {
    b.classList.toggle('active', b.dataset.path === path);
  });
}

let renderToken = 0;

async function renderRoute() {
  const route = parseRoute();
  const token = ++renderToken;

  // 释放上一页
  if (state.currentUnmount) {
    try { state.currentUnmount(); } catch (e) { console.error('[unmount]', e); }
    state.currentUnmount = null;
  }
  state.screenMount = null;
  overlayHost.innerHTML = '';

  if (route === 'screen') {
    els.topbar.style.display = 'none';
    els.content.style.padding = '0';
    els.content.style.overflow = 'hidden';
    await renderScreen();
    return;
  }

  els.topbar.style.display = '';
  els.content.style.padding = '';
  els.content.style.overflow = '';
  setActiveNav(route);

  const def = ROUTES.find((r) => r.path === route);
  const host = h('div', { class: 'page' });
  els.content.innerHTML = '';
  els.content.appendChild(host);

  const ctx = {
    api,
    isMock: MOCK_MODE,
    showToast: window.__glToast,
    modal: window.__glModal,
    drawer: window.__glDrawer,
    confirm: window.__glConfirm,
    onSys: (sys, kpi) => updateSys(sys, kpi)
  };

  try {
    const res = await def.mod.mount(host, ctx);
    if (token !== renderToken) { try { res?.unmount?.(); } catch (_) {} return; }
    state.currentUnmount = res?.unmount || null;
  } catch (e) {
    console.error('[route error]', e);
    host.appendChild(h('div', { class: 'err-box' }, [
      h('span', { class: 'e-icon' }, [svgIcon(ICONS.alert, 14)]),
      h('span', { text: `页面加载失败：${e.message || e}` })
    ]));
  }
}

/* ---------- 大屏页（3D 优先，失败降级 2D） ---------- */
async function renderScreen() {
  const root = h('div', { class: 'screen-root' });
  const canvasHost = h('div', { class: 'screen-canvas-host' });
  root.appendChild(canvasHost);
  els.content.innerHTML = '';
  els.content.appendChild(root);

  const onKey = (ev) => {
    if (ev.key === 'Escape') { location.hash = '#/overview'; }
  };
  document.addEventListener('keydown', onKey);

  // 系统未启用（api.md §7.3）：大屏仍可进入，但显示占位且不发起 SSE 订阅
  if (!isEnabled()) {
    document.removeEventListener('keydown', onKey);
    const note = h('div', { class: 'screen-fallback-note' }, [
      svgIcon(ICONS.info, 12),
      h('span', { text: '系统未启用，大屏暂无实时数据（按 Esc 返回管理界面）' })
    ]);
    root.appendChild(note);
    const host = h('div', { class: 'page', style: { padding: '76px 24px 24px', height: '100%', overflow: 'auto' } });
    root.appendChild(host);
    const ctx = {
      api, isMock: MOCK_MODE,
      showToast: window.__glToast, modal: window.__glModal,
      drawer: window.__glDrawer, confirm: window.__glConfirm,
      onSys: (sys, kpi) => updateSys(sys, kpi)
    };
    const res = await OverviewPage.mount(host, ctx);
    state.currentUnmount = () => {
      document.removeEventListener('keydown', onKey);
      try { res?.unmount?.(); } catch (_) {}
    };
    return;
  }

  let mounted = false;
  try {
    const mod = await import('./3d/screen.js');
    if (typeof mod.mountScreen === 'function') {
      const res = await mod.mountScreen(canvasHost, api);
      mounted = true;
      state.screenMount = res || null;
      // 3D 模块自行处理 HUD；本模块仅负责 Esc 与销毁
      state.currentUnmount = () => {
        document.removeEventListener('keydown', onKey);
        try {
          if (res && typeof res.dispose === 'function') res.dispose();
          else if (res && typeof res.unmount === 'function') res.unmount();
        } catch (e) { console.error('[screen dispose]', e); }
        canvasHost.innerHTML = '';
      };
      return;
    }
    throw new Error('3D 模块未导出 mountScreen');
  } catch (e) {
    console.warn('[screen] 3D 模块不可用，降级为 2D 总览：', e?.message || e);
  }

  // 降级：2D 总览
  document.removeEventListener('keydown', onKey);
  const note = h('div', { class: 'screen-fallback-note' }, [
    svgIcon(ICONS.info, 12),
    h('span', { text: '3D 场景模块不可用，已降级为 2D 总览（按 Esc 返回管理界面）' })
  ]);
  root.appendChild(note);

  const host = h('div', { class: 'page', style: { padding: '76px 24px 24px', height: '100%', overflow: 'auto' } });
  root.appendChild(host);
  const ctx = {
    api, isMock: MOCK_MODE,
    showToast: window.__glToast, modal: window.__glModal,
    drawer: window.__glDrawer, confirm: window.__glConfirm,
    onSys: (sys, kpi) => updateSys(sys, kpi)
  };
  try {
    const res = await OverviewPage.mount(host, ctx);
    state.currentUnmount = () => {
      document.removeEventListener('keydown', onKey);
      try { res?.unmount?.(); } catch (_) {}
    };
  } catch (e) {
    console.error('[screen fallback]', e);
    host.appendChild(h('div', { class: 'err-box' }, [h('span', { text: `总览加载失败：${e.message || e}` })]));
  }
}

/* ---------- 登录 ---------- */

function showLogin() {
  teardownPage();
  els.content.innerHTML = '';
  els.nav.style.display = 'none';
  document.querySelector('.topbar-right').style.display = 'none';
  const wrap = h('div', { class: 'login-wrap' });
  els.content.appendChild(wrap);
  els.content.style.padding = '0';
  els.content.style.overflow = 'hidden';
  renderLogin(wrap, {
    api,
    onSuccess: async () => {
      els.nav.style.display = '';
      document.querySelector('.topbar-right').style.display = '';
      els.content.style.padding = '';
      els.content.style.overflow = '';
      await afterLogin();
    }
  });
}

function teardownPage() {
  if (state.currentUnmount) {
    try { state.currentUnmount(); } catch (e) { console.error(e); }
    state.currentUnmount = null;
  }
}

async function afterLogin() {
  // 关键：表单登录成功后必须置 authed = true，
  // 否则 hashchange 监听器会因 !state.authed 直接 return，导致导航与路由切换全部失效。
  state.authed = true;

  // 加载开关状态（顶栏徽标 + 各页未启用降级）
  try { await refreshSettings(); } catch (e) { console.warn('[settings]', e.message); }
  updateSysBadge();
  state.unsubSettings = subscribeSettings(() => {
    updateSysBadge();
  });

  // 登录后立即拉一次系统状态并订阅 SSE（顶栏系统状态复用 tick.sys）
  try {
    const ov = await api.getOverview();
    updateSys(ov.sys, ov.kpi);
  } catch (e) {
    console.warn('[overview bootstrap]', e.message);
  }
  const unsub = api.subscribe((type, payload) => {
    if (type === 'tick') {
      updateSys(payload.sys, payload.kpi);
      state.lastTick = payload;
      window.__glTick = payload;
      document.dispatchEvent(new CustomEvent('gl:tick', { detail: payload }));
    } else if (type === 'alert') {
      document.dispatchEvent(new CustomEvent('gl:alert', { detail: payload }));
    }
  });
  state.shellUnsub = unsub;
  await renderRoute();
}

async function doLogout() {
  try { await api.logout(); } catch (e) { /* 忽略 */ }
  teardownPage();
  if (state.shellUnsub) { state.shellUnsub(); state.shellUnsub = null; }
  api.closeAllSubscriptions();
  state.authed = false;
  showLogin();
}

/* ---------- 启动 ---------- */

async function boot() {
  buildShell();
  api.onUnauthorized(() => {
    teardownPage();
    state.authed = false;
    toast('登录已失效，请重新登录', 'error');
    showLogin();
  });

  let session = null;
  try {
    session = await api.session();
  } catch (e) {
    console.warn('[session]', e.message);
    session = { authed: false };
  }
  state.authed = !!(session && session.authed);
  state.username = (session && session.username) || '';

  if (!state.authed) {
    showLogin();
  } else {
    await afterLogin();
  }
}

window.addEventListener('hashchange', () => {
  if (!state.authed) return;
  renderRoute();
});

// 首次进入若 hash 为空则规范化为 #/overview
if (!location.hash) location.hash = '#/overview';

boot().catch((e) => {
  console.error('[boot]', e);
  appEl.innerHTML = '';
  appEl.appendChild(h('div', { class: 'login-wrap' }, [
    h('div', { class: 'err-box' }, [h('span', { text: `启动失败：${e.message || e}` })])
  ]));
});
