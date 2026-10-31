/* ==========================================================================
   观澜 NetScope · 总览页（#/overview）
   依据 docs/design.md §7.1：KPI 行 + 双栏（实时曲线 / 分类环图）
   + 下排（Top 设备榜 / 最近告警 / 系统状态）
   ========================================================================== */

import {
  h, card, kpi, chip, button, svgIcon, ICONS, skeleton, emptyState, errorBox, deviceIcon, toast
} from './components.js';
import { areaChart, donutChart, barRank } from './chart.js';
import {
  formatBps, formatNumber, formatPercent, formatDuration,
  formatRelative, riskLevel, RISK_LABEL, RISK_SEM, SEVERITY_SEM, SEVERITY_LABEL, CATEGORY_COLOR
} from './format.js';
import { subscribeSettings, isEnabled, setSwitch, refreshSettings } from '../api.js';

export async function mount(host, ctx) {
  const { api } = ctx;
  const charts = {};
  const cleanups = [];
  let data = null;
  let destroyed = false;

  /* ---------- 系统未启用提示条（api.md §7.3） ---------- */
  const noticeBar = h('div', { class: 'notice-bar hidden' }, [
    h('div', { class: 'notice-bar-ico' }, [svgIcon(ICONS.alert, 17)]),
    h('div', { class: 'notice-bar-main' }, [
      h('div', { class: 'notice-bar-title', text: '系统未启用' }),
      h('div', { class: 'notice-bar-desc', text: '系统未启用，当前仅显示配置状态，不采集、不管控、不影响路由器现有功能。' })
    ]),
    button('启用系统', {
      variant: 'primary', icon: ICONS.power,
      onClick: async (e) => {
        const b = e.currentTarget;
        b.classList.add('is-loading');
        try {
          const r = await setSwitch('enabled', true);
          const parts = [];
          if (r.revoked && r.revoked.length) parts.push(`已撤销：${r.revoked.join('；')}`);
          if (r.applied && r.applied.length) parts.push(`已执行：${r.applied.join('；')}`);
          toast(parts.length ? parts.join('｜') : '系统已启用', 'success', { title: '系统已启用' });
          await reloadAll();
        } catch (err) {
          b.classList.remove('is-loading');
          toast(err.message || '启用失败', 'error');
        }
      }
    })
  ]);

  /* ---------- 骨架屏 ---------- */
  const kpiRow = h('div', { class: 'kpi-row' });
  for (let i = 0; i < 4; i++) {
    kpiRow.appendChild(h('div', { class: 'kpi s-brand' }, [skeleton(3)]));
  }
  const trendCanvas = h('canvas');
  const donutCanvas = h('canvas');
  const rankCanvas = h('canvas');

  const trendCard = card({
    title: '实时上下行曲线',
    sub: '最近 2 分钟 · 60 个采样点',
    actions: [chip('2 s 刷新', { sem: 'info', plain: true })],
    body: [h('div', { class: 'chart-box', style: { height: '252px' } }, [trendCanvas]), legendHost()]
  });

  const donutCard = card({
    title: '分类占比',
    sub: '按下行带宽',
    body: [h('div', { class: 'chart-box', style: { height: '216px' } }, [donutCanvas])]
  });

  const rankCard = card({
    title: 'Top 设备',
    sub: '按实时下行速率',
    body: [h('div', { class: 'chart-box', style: { height: '320px' } }, [rankCanvas])]
  });

  const alertCard = card({
    title: '最近告警',
    sub: '',
    body: [h('div', { id: 'ov-alerts' })],
    bodyClass: 'flush'
  });

  const sysCard = card({
    title: '系统状态',
    sub: '路由器本机',
    body: [h('div', { id: 'ov-sys' })]
  });

  host.appendChild(noticeBar);
  host.appendChild(kpiRow);
  host.appendChild(h('div', { class: 'grid' }, [
    h('div', { class: 'g8' }, [trendCard]),
    h('div', { class: 'g4' }, [donutCard]),
    h('div', { class: 'g4' }, [rankCard]),
    h('div', { class: 'g4' }, [alertCard]),
    h('div', { class: 'g4' }, [sysCard])
  ]));

  const legendEl = trendCard.querySelector('.chart-legend');

  function legendHost() {
    const box = h('div', { class: 'chart-legend' });
    return box;
  }

  /* ---------- 渲染 ---------- */
  function renderKpis(d) {
    kpiRow.innerHTML = '';
    const k = d.kpi;
    const sys = d.sys || {};
    const items = [
      {
        label: '在线设备', value: String(k.online ?? 0), unit: `/ ${k.devices ?? 0}`,
        sem: 'brand', icon: ICONS.device,
        deltaLabel: `活跃连接 ${formatNumber(k.conns || 0)}`,
        delta: null
      },
      {
        label: '实时下行', value: formatBps(k.downBps || 0).split(' ')[0], unit: formatBps(k.downBps || 0).split(' ')[1],
        sem: 'ok', icon: ICONS.download,
        deltaLabel: `上行 ${formatBps(k.upBps || 0)}`, delta: null
      },
      {
        label: 'DNS 查询', value: (k.dnsQps ?? 0).toFixed(1), unit: 'qps',
        sem: 'info', icon: ICONS.globe,
        deltaLabel: `新建连接 ${k.newConns ?? 0} / 2s`, delta: null
      },
      {
        label: '未确认告警', value: String(k.alerts ?? 0), unit: '条',
        sem: (k.alerts || 0) > 0 ? 'crit' : 'ok', icon: ICONS.alert,
        deltaLabel: `风险 ${RISK_LABEL[k.riskLevel] || '低风险'}`, delta: null
      }
    ];
    items.forEach((it) => {
      const el = kpi({
        label: it.label, value: it.value, unit: it.unit, sem: it.sem,
        icon: it.icon, deltaLabel: it.deltaLabel
      });
      kpiRow.appendChild(el);
    });
    ctx.onSys?.(sys, k);
  }

  function renderTrend(d) {
    const labels = (d.trend || []).map((p) => {
      const dt = new Date(p.t * 1000);
      return `${String(dt.getHours()).padStart(2, '0')}:${String(dt.getMinutes()).padStart(2, '0')}:${String(dt.getSeconds()).padStart(2, '0')}`;
    });
    // 后端 trend 的 up/down 为 bit/s → ÷8 得到字节/秒，与图例/气泡（formatBps）口径一致
    const series = [
      { name: '下行', color: '#22d3ee', values: (d.trend || []).map((p) => (p.down || 0) / 8) },
      { name: '上行', color: '#7c5cff', values: (d.trend || []).map((p) => (p.up || 0) / 8) }
    ];
    if (!charts.trend) {
      charts.trend = areaChart(trendCanvas, { labels, series, stacked: false, unit: 'bytes' });
    } else {
      charts.trend.update({ labels, series });
    }
    renderLegend();
  }

  function renderLegend() {
    legendEl.innerHTML = '';
    const d = data;
    if (!d) return;
    const pts = d.trend || [];
    const n = pts.length || 1;
    const avgUp = pts.reduce((a, p) => a + (p.up || 0), 0) / n;
    const avgDown = pts.reduce((a, p) => a + (p.down || 0), 0) / n;
    [
      { name: '下行均值', color: '#22d3ee', val: formatBps(avgDown) },
      { name: '上行均值', color: '#7c5cff', val: formatBps(avgUp) }
    ].forEach((it) => {
      legendEl.appendChild(h('div', { class: 'legend-item' }, [
        h('span', { class: 'legend-swatch', style: { '--c': it.color } }),
        h('span', { text: it.name }),
        h('span', { class: 'legend-val', text: it.val })
      ]));
    });
  }

  function renderDonut(d) {
    const items = (d.categories || []).map((c) => ({
      key: c.key, label: c.label, value: c.downBps || 0, color: c.color || CATEGORY_COLOR[c.key] || '#94a3b8'
    }));
    const total = items.reduce((a, x) => a + x.value, 0);
    const model = {
      data: items,
      centerText: formatBps(total),
      centerLabel: '当前下行'
    };
    if (!charts.donut) charts.donut = donutChart(donutCanvas, model);
    else charts.donut.update(model);

    // 图例列表
    const list = donutCard.querySelector('.chart-legend') || (() => {
      const box = h('div', { class: 'chart-legend grid2' });
      donutCard.querySelector('.card-body').appendChild(box);
      return box;
    })();
    list.innerHTML = '';
    const cats = (d.categories || []);
    const anyValue = cats.some((c) => (c.downBps || 0) > 0);
    cats.forEach((c) => {
      list.appendChild(h('div', { class: 'legend-item', title: `${c.label} ${formatPercent(c.share)}` }, [
        h('span', { class: 'legend-swatch', style: { '--c': c.color || CATEGORY_COLOR[c.key], opacity: anyValue ? '1' : '.4' } }),
        h('span', { text: c.label }),
        h('span', { class: 'legend-val', text: anyValue ? formatPercent(c.share, 0) : '—' })
      ]));
    });
  }

  function renderRank(d) {
    const items = (d.topDevices || []).slice(0, 10).map((t, i) => ({
      name: t.alias || t.name || t.ip,
      value: t.downBps || 0,
      color: ['#22d3ee', '#7c5cff', '#38bdf8', '#2dd4bf', '#34d399', '#f472b6', '#fbbf24', '#a78bfa', '#fb7185', '#38bdf8'][i % 10]
    }));
    const model = { items, valueFormat: (v) => formatBps(v) };
    if (!charts.rank) charts.rank = barRank(rankCanvas, model);
    else charts.rank.update(model);
  }

  function renderAlerts(d) {
    const box = alertCard.querySelector('#ov-alerts');
    box.innerHTML = '';
    const list = d.alerts || [];
    if (!list.length) {
      box.appendChild(emptyState('暂无告警', ICONS.check, '网络运行平稳'));
      return;
    }
    const wrap = h('div', { class: 'event-list' });
    list.slice(0, 6).forEach((e) => {
      const sem = SEVERITY_SEM[e.severity] || 'info';
      wrap.appendChild(h('div', { class: 'event-item' }, [
        h('div', { class: 'event-bar', style: { '--sem': `var(--${sem})` } }),
        h('div', { class: 'event-main' }, [
          h('div', { class: 'event-title', text: e.title || e.type }),
          h('div', { class: 'event-detail', text: e.detail || '' }),
          h('div', { class: 'event-meta' }, [
            chip(SEVERITY_LABEL[e.severity] || '提示', { sem, plain: true }),
            h('span', { text: formatRelative(e.ts) }),
            e.deviceIp ? h('span', { class: 'mono', text: e.deviceIp }) : null
          ])
        ])
      ]));
    });
    box.appendChild(wrap);
  }

  function renderSys(d) {
    const box = sysCard.querySelector('#ov-sys');
    box.innerHTML = '';
    const s = d.sys || {};
    const rows = [
      ['CPU 占用', `${Number(s.cpuPct || 0).toFixed(1)}%`],
      ['内存占用', `${Number(s.memPct || 0).toFixed(1)}% · ${s.memUsedMb || 0} MB`],
      ['系统负载', String(s.load1 ?? '—')],
      ['CPU 温度', `${Number(s.tempC || 0).toFixed(1)} °C`],
      ['运行时长', formatDuration(s.uptimeSec || 0)],
      ['WAN 接收', formatBps(s.wanRxBps || 0)],
      ['WAN 发送', formatBps(s.wanTxBps || 0)],
      ['当前连接数', formatNumber(s.connCount || 0)]
    ];
    const g = h('div', { class: 'kv-grid' });
    rows.forEach(([k, v]) => {
      g.appendChild(h('div', { class: 'kv' }, [
        h('span', { class: 'k', text: k }),
        h('span', { class: 'v', text: v })
      ]));
    });
    box.appendChild(g);
  }

  function renderAll(d) {
    data = d;
    renderKpis(d);
    renderTrend(d);
    renderDonut(d);
    renderRank(d);
    renderAlerts(d);
    renderSys(d);
  }

  /** 系统未启用时展示提示条（api.md §7.3） */
  function renderNotice() {
    const off = !isEnabled();
    noticeBar.classList.toggle('hidden', !off);
  }

  async function reloadAll() {
    try {
      const d = await api.getOverview();
      if (destroyed) return;
      renderAll(d);
      renderNotice();
    } catch (e) {
      console.error('[overview]', e);
    }
  }

  /* ---------- 加载 ---------- */
  // 先拉取开关状态（决定是否展示「系统未启用」提示条）
  try {
    await refreshSettings();
  } catch (e) {
    console.warn('[overview settings]', e.message);
  }
  renderNotice();

  try {
    const d = await api.getOverview();
    if (destroyed) return { unmount() {} };
    renderAll(d);
  } catch (e) {
    if (destroyed) return { unmount() {} };
    console.error('[overview]', e);
    kpiRow.innerHTML = '';
    kpiRow.appendChild(h('div', { class: 'g12' }, [
      errorBox(`总览数据加载失败：${e.message || e}`, async () => {
        try { renderAll(await api.getOverview()); } catch (e2) { ctx.showToast(e2.message, 'error'); }
      })
    ]));
  }

  /* ---------- 开关变化 → 更新提示条 ---------- */
  const unsubSettings = subscribeSettings(() => {
    if (destroyed) return;
    renderNotice();
  });
  cleanups.push(unsubSettings);

  /* ---------- SSE 增量更新（仅更新受影响组件） ---------- */
  // app.js 已把 /api/stream 的 tick/alert 以 CustomEvent 派发到 document，
  // 本页只监听 document 事件，避免重复订阅同一流导致数据翻倍。
  const onTick = (ev) => {
    const t = ev.detail;
    if (!t || destroyed || !data) return;
    // KPI / 系统状态
    data.kpi = { ...data.kpi, ...t.kpi };
    data.sys = { ...data.sys, ...t.sys };
    // 趋势：追加一个点
    if (t.trendPoint) {
      data.trend = [...(data.trend || []).slice(-59), { t: t.trendPoint.t, up: t.trendPoint.up, down: t.trendPoint.down }];
    }
    // 分类
    if (t.categories && t.categories.length) {
      data.categories = (data.categories || []).map((c) => {
        const n = t.categories.find((x) => x.key === c.key);
        return n ? { ...c, upBps: n.upBps, downBps: n.downBps, share: n.share } : c;
      });
    }
    // Top 设备
    if (t.devices && t.devices.length) {
      const map = new Map(t.devices.map((d2) => [d2.ip, d2]));
      data.topDevices = (data.topDevices || []).map((d2) => {
        const n = map.get(d2.ip);
        return n ? { ...d2, upBps: n.upBps, downBps: n.downBps } : d2;
      });
    }
    renderKpis(data);
    renderTrend(data);
    renderDonut(data);
    renderRank(data);
  };

  const onAlert = (ev) => {
    if (destroyed || !data) return;
    const e = ev.detail;
    data.alerts = [e, ...(data.alerts || [])].slice(0, 8);
    renderAlerts(data);
    ctx.showToast?.(`${e.title || '新告警'}`, e.severity === 'critical' ? 'error' : 'info');
  };

  document.addEventListener('gl:tick', onTick);
  document.addEventListener('gl:alert', onAlert);
  cleanups.push(() => {
    document.removeEventListener('gl:tick', onTick);
    document.removeEventListener('gl:alert', onAlert);
  });

  return {
    unmount() {
      destroyed = true;
      cleanups.forEach((fn) => { try { fn(); } catch (_) {} });
      Object.values(charts).forEach((c) => { try { c?.dispose?.(); } catch (_) {} });
    }
  };
}
