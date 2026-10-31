/* ==========================================================================
   观澜 NetScope · 流量分析页（#/traffic）
   依据 docs/design.md §7.3：时间范围 Tab + 堆叠切换；主图上下行/分类堆叠面积图；
   三栏（分类环图 / Top 设备 / Top 域名）；底部实时连接表（搜索 + 封禁）
   ========================================================================== */

import {
  h, card, chip, button, table, pager, switchControl, svgIcon, ICONS,
  skeleton, emptyState, errorBox, toast, disabledState, modal
} from './components.js';
import { areaChart, donutChart, barRank } from './chart.js';
import {
  formatBps, formatBytes, formatNumber, formatPercent, formatTime, formatRelative,
  CATEGORY_COLOR, CATEGORY_LABEL, CATEGORY_ORDER
} from './format.js';
import { refreshSettings, isEnabled, isFeatureOn, subscribeSettings } from '../api.js';

const RANGES = [
  { key: '1h', label: '1 小时' },
  { key: '6h', label: '6 小时' },
  { key: '24h', label: '24 小时' },
  { key: '7d', label: '7 天' }
];

export async function mount(host, ctx) {
  const { api } = ctx;
  const charts = [];
  const cleanups = [];
  let range = '1h';
  let stacked = false;
  let data = null;
  let domains = [];
  let conns = [];
  let destroyed = false;
  let unsub = null;
  let connQuery = '';
  let connPage = 1;
  let dstBlocked = new Set();   // 已封禁的目标 IP（用于就地解封）
  let devBlocked = new Set();   // 已断网的设备 IP（用于就地解封）
  let urlQuery = '';
  let urlPage = 1;

  /* ---------- 头部 ---------- */
  const rangeSeg = h('div', { class: 'segment' });
  RANGES.forEach((r) => {
    const b = h('button', { type: 'button', text: r.label });
    if (r.key === range) b.classList.add('active');
    b.addEventListener('click', () => {
      range = r.key;
      rangeSeg.querySelectorAll('button').forEach((x) => x.classList.remove('active'));
      b.classList.add('active');
      loadTraffic();
    });
    rangeSeg.appendChild(b);
  });

  const stackSwitch = switchControl({
    label: '按分类堆叠',
    onChange: (v) => { stacked = v; renderMain(); }
  });

  const refreshBtn = button('刷新', { variant: 'ghost', icon: ICONS.refresh, onClick: () => loadTraffic() });

  const rateNow = h('span', { class: 'fs-12', text: '—' });
  const headCard = h('div', { class: 'card', style: { padding: '11px 16px' } }, [
    h('div', { class: 'row-gap-3', style: { flexWrap: 'wrap' } }, [
      h('span', { class: 'fs-12 dim', text: '时间范围' }),
      rangeSeg,
      h('div', { class: 'sys-sep' }),
      stackSwitch,
      h('div', { class: 'spacer', style: { flex: '1' } }),
      h('div', { class: 'row-gap-2', style: { gap: '6px' } }, [
        h('span', { class: 'fs-11 dim', text: '实时' }),
        rateNow
      ]),
      refreshBtn
    ])
  ]);

  /* ---------- 主图 ---------- */
  const mainCanvas = h('canvas');
  const mainLegend = h('div', { class: 'chart-legend' });
  const mainCard = card({
    title: '流量趋势',
    sub: '上下行流量与分类构成',
    body: [h('div', { class: 'chart-box', style: { height: '248px' } }, [mainCanvas]), mainLegend]
  });

  /* ---------- 三栏 ---------- */
  const catCanvas = h('canvas');
  const catCard = card({
    title: '分类占比', sub: '',
    body: [h('div', { class: 'chart-box', style: { height: '186px' } }, [catCanvas]), h('div', { class: 'chart-legend grid2' })]
  });

  const devCanvas = h('canvas');
  const devCard = card({
    title: 'Top 设备', sub: '按下行流量',
    body: [h('div', { class: 'chart-box', style: { height: '186px' } }, [devCanvas])]
  });

  const domList = h('div', { class: 'rank-list' });
  const domCard = card({
    title: 'Top 域名', sub: '按流量',
    body: [domList]
  });

  /* ---------- 访问 URL 明细（WAF 风格） ---------- */
  const urlSearch = h('input', { class: 'input', type: 'search', placeholder: '搜索 URL / 域名' });
  const urlSearchWrap = h('div', { class: 'search-wrap', style: { minWidth: '220px', flex: '0 1 280px' } }, [
    svgIcon(ICONS.search, 13), urlSearch
  ]);
  const urlPager = pager({ onChange: (p) => { urlPage = p; renderUrlList(); } });
  const urlCount = h('span', { class: 'card-sub' });
  const urlCols = [
    {
      key: 'domain', title: 'URL / 域名', width: '31%',
      render: (d) => h('div', { class: 'col', style: { lineHeight: '1.3', minWidth: '0' } }, [
        h('span', { class: 'td-strong truncate', text: d.domain }),
        h('span', { class: 'dim fs-11 truncate', text: d.label || d.category || '' })
      ]),
      sortValue: (d) => d.domain
    },
    {
      key: 'category', title: '类别', width: '12%',
      render: (d) => chip(CATEGORY_LABEL[d.category] || '其他', { sem: 'brand' })
    },
    {
      key: 'hits', title: '访问', width: '8%', align: 'right',
      render: (d) => h('span', { class: 'num', text: formatNumber(d.hits || 0) }),
      sortValue: (d) => d.hits
    },
    {
      key: 'devices', title: '源主机', width: '16%',
      render: (d) => {
        const list = d.deviceList || [];
        if (!list.length) return h('span', { class: 'dim fs-11', text: `${formatNumber(d.devices || 0)} 台` });
        const names = list.slice(0, 2).map((x) => x.alias || x.name || x.ip).join('、');
        const more = list.length > 2 ? ` +${list.length - 2}` : '';
        return h('div', { class: 'col', style: { minWidth: '0', lineHeight: '1.3' } }, [
          h('span', { class: 'truncate fs-11', text: names + more }),
          h('span', { class: 'dim fs-11', text: list.length > 1 ? `${list.length} 台设备` : (list[0].ip || '') })
        ]);
      },
      sortValue: (d) => (d.deviceList || []).length || d.devices || 0
    },
    {
      key: 'bytes', title: '流量', width: '14%', align: 'right',
      render: (d) => h('span', { class: 'num', text: formatBytes(d.bytes || 0) }),
      sortValue: (d) => d.bytes
    },
    {
      key: 'lastSeen', title: '最近', width: '19%', align: 'right',
      render: (d) => h('span', { class: 'dim fs-11', text: d.lastSeen ? formatRelative(d.lastSeen) : '-' }),
      sortValue: (d) => d.lastSeen
    }
  ];
  const urlTbl = table({ columns: urlCols, rows: [], pageSize: 12, sortKey: 'bytes', sortDir: 'desc', onRowClick: (d) => showUrlDetail(d) });
  const urlCard = card({
    title: '最近访问 URL', sub: 'WAF 式访问记录 · 按流量',
    actions: [urlCount],
    bodyClass: 'flush',
    body: [urlTbl.el],
    foot: [urlPager.el]
  });
  const urlToolbar = h('div', { class: 'card', style: { padding: '11px 16px' } }, [
    h('div', { class: 'row-gap-3' }, [urlSearchWrap, h('span', { class: 'fs-11 dim', text: '来自 dnsmasq 查询日志 · 点击行看设备' })])
  ]);

  /* ---------- 连接表 ---------- */
  const connSearch = h('input', { class: 'input', type: 'search', placeholder: '搜索 域名 / 目标 IP / 设备' });
  const connSearchWrap = h('div', { class: 'search-wrap', style: { minWidth: '240px', flex: '0 1 300px' } }, [
    svgIcon(ICONS.search, 13), connSearch
  ]);
  const connPager = pager({ onChange: (p) => { connPage = p; renderConns(); } });
  const connCount = h('span', { class: 'card-sub' });

  const connCols = [
    {
      key: 'domain', title: '目标', width: '30%',
      render: (c) => h('div', { class: 'col', style: { lineHeight: '1.3', minWidth: '0' } }, [
        h('span', { class: 'td-strong truncate', text: c.domain || c.dstIp }),
        h('span', { class: 'dim fs-11 mono truncate', text: `${c.dstIp}:${c.dstPort} · ${c.app || '-'}` })
      ]),
      sortValue: (c) => c.domain || c.dstIp
    },
    {
      key: 'srcIp', title: '设备', width: '20%',
      render: (c) => h('div', { class: 'col', style: { lineHeight: '1.3' } }, [
        h('span', { class: 'truncate', text: c.deviceName || c.srcIp }),
        h('span', { class: 'dim fs-11 mono', text: c.srcIp })
      ]),
      sortValue: (c) => c.srcIp
    },
    {
      key: 'path', title: '流向', width: '13%',
      render: (c) => chip(PATH_LABEL[c.path] || (c.iface || '直接出网'), { sem: PATH_SEM[c.path] || 'brand' }),
      sortValue: (c) => c.path || ''
    },
    {
      key: 'category', title: '分类', width: '11%',
      render: (c) => chip(CATEGORY_LABEL[c.category] || '其他', { sem: 'brand' })
    },
    {
      key: 'downBytes', title: '下行', width: '12%', align: 'right',
      render: (c) => h('span', { class: 'num', text: formatBytes(c.downBytes || 0) }),
      sortValue: (c) => c.downBytes
    },
    {
      key: 'upBytes', title: '上行', width: '11%', align: 'right',
      render: (c) => h('span', { class: 'num dim', text: formatBytes(c.upBytes || 0) }),
      sortValue: (c) => c.upBytes
    },
    {
      key: 'state', title: '状态', width: '9%',
      render: (c) => chip(c.state, { plain: true, sem: c.state === 'ESTABLISHED' ? 'ok' : 'mute' })
    },
    {
      key: 'ops', title: '操作', width: '10%', align: 'right', sortable: false,
      render: (c) => {
        const box = h('div', { class: 'ops' });
        const dstBlockedNow = dstBlocked.has(c.dstIp);
        const devBlockedNow = devBlocked.has(c.srcIp);

        // 封禁目标 IP（已封则解封）
        const b1 = h('button', {
          class: `op-btn ${dstBlockedNow ? 'ok' : 'danger'}`, type: 'button',
          title: dstBlockedNow ? `解除封禁 ${c.dstIp}` : '封禁目标 IP'
        }, [svgIcon(dstBlockedNow ? ICONS.undo : ICONS.ban, 12)]);
        b1.addEventListener('click', async (ev) => {
          ev.stopPropagation();
          b1.classList.add('is-loading');
          try {
            if (dstBlockedNow) {
              await api.unblock(c.dstIp, 'dst');
              toast(`已解除封禁 ${c.dstIp}`, 'success');
              dstBlocked.delete(c.dstIp);
            } else {
              await api.blockConn(c.id, 'dst');
              toast(`已封禁目标 ${c.dstIp}`, 'success');
              dstBlocked.add(c.dstIp);
            }
            b1.classList.remove('is-loading');
            renderConns();
          } catch (e) {
            b1.classList.remove('is-loading');
            toast(e.message || (dstBlockedNow ? '解封失败' : '封禁失败'), 'error');
          }
        });

        // 断网该设备（已断则解封）
        const b2 = h('button', {
          class: `op-btn ${devBlockedNow ? 'ok' : 'warn'}`, type: 'button',
          title: devBlockedNow ? `恢复 ${c.srcIp} 联网` : '断网该设备'
        }, [svgIcon(devBlockedNow ? ICONS.undo : ICONS.device, 12)]);
        b2.addEventListener('click', async (ev) => {
          ev.stopPropagation();
          b2.classList.add('is-loading');
          try {
            if (devBlockedNow) {
              await api.unblock(c.srcIp, 'device');
              toast(`已恢复 ${c.srcIp} 联网`, 'success');
              devBlocked.delete(c.srcIp);
            } else {
              await api.blockConn(c.id, 'device');
              toast(`已断开 ${c.srcIp}`, 'success');
              devBlocked.add(c.srcIp);
            }
            b2.classList.remove('is-loading');
            renderConns();
          } catch (e) {
            b2.classList.remove('is-loading');
            toast(e.message || (devBlockedNow ? '恢复失败' : '操作失败'), 'error');
          }
        });
        box.appendChild(b1); box.appendChild(b2);
        return box;
      }
    }
  ];

  const connTbl = table({
    columns: connCols,
    rows: [],
    pageSize: 50,
    onRowClick: (c) => showConnDetail(c)
  });
  connTbl.__onPage = (p, pages) => connPager.set(p, pages, filteredConns.length);

  const connCard = card({
    title: '实时连接',
    sub: '',
    actions: [connCount],
    bodyClass: 'flush',
    body: [connTbl.el],
    foot: [connPager.el]
  });

  const connToolbar = h('div', { class: 'card', style: { padding: '11px 16px' } }, [
    h('div', { class: 'row-gap-3' }, [connSearchWrap, h('span', { class: 'fs-11 dim', text: '每页 50 条 · 可按目标封禁' })])
  ]);

  host.appendChild(headCard);
  host.appendChild(mainCard);
  host.appendChild(h('div', { class: 'grid' }, [
    h('div', { class: 'g4' }, [catCard]),
    h('div', { class: 'g4' }, [devCard]),
    h('div', { class: 'g4' }, [domCard])
  ]));
  host.appendChild(urlToolbar);
  host.appendChild(urlCard);
  host.appendChild(connToolbar);
  host.appendChild(connCard);

  /* ---------- 事件 ---------- */
  connSearch.addEventListener('input', () => { connQuery = connSearch.value.trim(); connPage = 1; renderConns(); });
  cleanups.push(() => connSearch.removeEventListener('input', () => {}));
  urlSearch.addEventListener('input', () => { urlQuery = urlSearch.value.trim(); urlPage = 1; renderUrlList(); });
  cleanups.push(() => urlSearch.removeEventListener('input', () => {}));

  /* ---------- 渲染 ---------- */
  function seriesLabels() {
    if (!data) return [];
    return (data.series || []).map((p) => {
      const dt = new Date(p.t * 1000);
      if (range === '7d') return `${dt.getMonth() + 1}/${dt.getDate()}`;
      return `${String(dt.getHours()).padStart(2, '0')}:${String(dt.getMinutes()).padStart(2, '0')}`;
    });
  }

  function renderMain() {
    if (!data) return;
    const labels = seriesLabels();
    const bucketSec = Number(data.bucketSec) || 30;
    let series;
    if (stacked) {
      // 后端 series.byCat 是「字节/桶」→ 换算成「字节/秒」，与全站字节单位一致
      const cats = (data.byCategory || []).filter((c) => Number(c.down || 0) > 0);
      series = cats.map((c) => ({
        name: c.label,
        color: c.color || CATEGORY_COLOR[c.key] || '#94a3b8',
        values: (data.series || []).map((p) => Math.round(((p.byCat && p.byCat[c.key]) || 0) / bucketSec))
      }));
    } else {
      // 后端 series.up/down 是 bit/s → ÷8 得到字节/秒
      series = [
        { name: '下行', color: '#22d3ee', values: (data.series || []).map((p) => Math.round((p.down || 0) / 8)) },
        { name: '上行', color: '#7c5cff', values: (data.series || []).map((p) => Math.round((p.up || 0) / 8)) }
      ];
    }
    const model = { labels, series, stacked, unit: 'bytes' };
    if (!charts.main) charts.main = areaChart(mainCanvas, model);
    else charts.main.update(model);
    renderMainLegend();
  }

  function renderMainLegend() {
    mainLegend.innerHTML = '';
    if (!data) return;
    if (stacked) {
      (data.byCategory || []).forEach((c) => {
        mainLegend.appendChild(h('div', { class: 'legend-item' }, [
          h('span', { class: 'legend-swatch', style: { '--c': c.color || CATEGORY_COLOR[c.key] } }),
          h('span', { text: c.label }),
          h('span', { class: 'legend-val', text: formatPercent(c.share, 0) })
        ]));
      });
    } else {
      // series.up/down 是 bit/s 速率：展示区间均值（累加速率无物理意义）
      const n = (data.series || []).length || 1;
      const avgUp = (data.series || []).reduce((a, p) => a + (p.up || 0), 0) / n;
      const avgDown = (data.series || []).reduce((a, p) => a + (p.down || 0), 0) / n;
      [
        { name: '下行均值', color: '#22d3ee', val: formatBps(avgDown) },
        { name: '上行均值', color: '#7c5cff', val: formatBps(avgUp) }
      ].forEach((it) => {
        mainLegend.appendChild(h('div', { class: 'legend-item' }, [
          h('span', { class: 'legend-swatch', style: { '--c': it.color } }),
          h('span', { text: it.name }),
          h('span', { class: 'legend-val', text: it.val })
        ]));
      });
    }
  }

  function renderCat() {
    const items = (data.byCategory || []).map((c) => ({
      key: c.key, label: c.label, value: c.down || 0, color: c.color || CATEGORY_COLOR[c.key] || '#94a3b8'
    }));
    const total = items.reduce((a, x) => a + x.value, 0);
    const model = { data: items, centerText: formatBytes(total), centerLabel: '总下行' };
    if (!charts.cat) charts.cat = donutChart(catCanvas, model);
    else charts.cat.update(model);
    const leg = catCard.querySelector('.chart-legend');
    if (leg) {
      leg.innerHTML = '';
      (data.byCategory || []).forEach((c) => {
        leg.appendChild(h('div', { class: 'legend-item', title: `${c.label} ${formatPercent(c.share)}` }, [
          h('span', { class: 'legend-swatch', style: { '--c': c.color || CATEGORY_COLOR[c.key] } }),
          h('span', { text: c.label }),
          h('span', { class: 'legend-val', text: formatPercent(c.share, 0) })
        ]));
      });
    }
  }

  function renderDev() {
    const items = (data.byDevice || []).slice(0, 8).map((t, i) => ({
      name: t.alias || t.name || t.ip,
      value: t.down || 0,
      color: ['#22d3ee', '#7c5cff', '#38bdf8', '#2dd4bf', '#34d399', '#f472b6', '#fbbf24', '#a78bfa'][i % 8]
    }));
    const model = { items, valueFormat: (v) => formatBytes(v) };
    if (!charts.dev) charts.dev = barRank(devCanvas, model);
    else charts.dev.update(model);
  }

  function renderDomains() {
    domList.innerHTML = '';
    if (!domains.length) {
      domList.appendChild(emptyState('暂无域名记录', ICONS.globe));
      return;
    }
    const max = Math.max(...domains.map((d) => d.bytes || 0)) || 1;
    domains.slice(0, 10).forEach((d) => {
      domList.appendChild(h('div', { class: 'rank-row' }, [
        h('div', { class: 'rank-name', title: `${d.label ? d.label + ' · ' : ''}${d.domain}`, text: d.domain }),
        h('div', { class: 'rank-bar' }, [
          h('i', { style: { width: `${Math.max(3, ((d.bytes || 0) / max) * 100)}%`, '--c': CATEGORY_COLOR[d.category] || '#94a3b8' } })
        ]),
        h('div', { class: 'rank-val', text: formatBytes(d.bytes || 0) })
      ]));
    });
  }

  // 访问 URL 明细（WAF 风格）：可搜索 + 分页
  function renderUrlList() {
    const q = urlQuery.toLowerCase();
    let list = domains;
    if (q) list = domains.filter((d) => `${d.domain} ${d.label || ''} ${d.category || ''}`.toLowerCase().includes(q));
    urlTbl.__page = urlPage;
    urlTbl.setRows(list);
    urlCount.textContent = `${list.length} 条`;
  }

  let filteredConns = [];
  function renderConns() {
    const q = connQuery.toLowerCase();
    filteredConns = q
      ? conns.filter((c) => `${c.domain || ''} ${c.dstIp} ${c.app || ''} ${c.srcIp} ${c.deviceName || ''}`.toLowerCase().includes(q))
      : conns.slice();
    connTbl.__page = connPage;
    connTbl.setRows(filteredConns);
    connCount.textContent = `${formatNumber(conns.length)} 条连接`;
  }

  // 连接详情弹窗：点击连接行展示完整字段
  const PATH_LABEL = { direct: '直接出网', proxy: '经代理', zerotier: '经 ZeroTier', vpn: '经 VPN', lan: '内网' };
  const PATH_SEM = { direct: 'brand', proxy: 'warn', zerotier: 'ok', vpn: 'info', lan: 'mute' };
  function showConnDetail(c) {
    if (!c) return;
    const kv = (k, v) => h('div', { class: 'kv' }, [
      h('span', { class: 'k dim', text: k }),
      h('span', { class: 'v mono', text: String(v ?? '-') })
    ]);
    const pathLabel = PATH_LABEL[c.path] || (c.iface ? c.iface : '直接出网');
    const body = h('div', { class: 'kv-grid', style: { padding: '4px 2px' } }, [
      kv('设备', c.deviceName || c.srcIp),
      kv('源地址', `${c.srcIp}:${c.srcPort}`),
      kv('目标', c.domain || c.dstIp),
      kv('目标地址', `${c.dstIp}:${c.dstPort}`),
      kv('协议', c.proto),
      kv('流向', c.iface ? `${pathLabel} · ${c.iface}` : pathLabel),
      kv('分类', CATEGORY_LABEL[c.category] || '其他'),
      kv('应用', c.app || '-'),
      kv('状态', c.state || '-'),
      kv('持续', `${Math.round((c.durationSec || 0) / 60)} 分 ${(c.durationSec || 0) % 60} 秒`),
      kv('下行', formatBytes(c.downBytes || 0)),
      kv('上行', formatBytes(c.upBytes || 0)),
      kv('开始时间', c.startedAt ? formatTime(c.startedAt) : '-'),
      kv('最后活跃', c.lastSeenAt ? formatRelative(c.lastSeenAt) : '-')
    ]);
    modal({
      title: `连接详情 · ${c.domain || c.dstIp}`,
      width: 560,
      body: [h('div', { class: 'row-gap-2', style: { marginBottom: '4px' } }, [
        chip(pathLabel, { sem: PATH_SEM[c.path] || 'brand' }),
        chip(c.proto, { plain: true, sem: 'mute' })
      ]), body]
    });
  }

  /* URL / 域名访问详情（源主机、次数、流量、时间） */
  function showUrlDetail(d) {
    if (!d) return;
    const kv = (k, v) => h('div', { class: 'kv' }, [
      h('span', { class: 'k dim', text: k }),
      h('span', { class: 'v mono', text: String(v ?? '-') })
    ]);
    const devList = d.deviceList || [];
    const devRows = devList.length
      ? devList.map((x) => h('div', { class: 'row-gap-2 fs-12', style: { justifyContent: 'space-between', padding: '6px 0', borderBottom: '1px solid var(--line-soft)' } }, [
          h('div', { class: 'col', style: { minWidth: '0', flex: '1' } }, [
            h('span', { class: 'td-strong truncate', text: x.alias || x.name || x.ip }),
            h('span', { class: 'dim fs-11 mono', text: x.ip || '' })
          ]),
          h('div', { class: 'col', style: { textAlign: 'right' } }, [
            h('span', { class: 'num fs-12', text: `${formatNumber(x.hits || 0)} 次` }),
            h('span', { class: 'dim fs-11', text: formatBytes(x.bytes || 0) }),
            h('span', { class: 'dim fs-11', text: x.lastSeen ? formatRelative(x.lastSeen) : '' })
          ])
        ]))
      : [h('div', { class: 'dim fs-12', text: '暂无设备明细' })];

    const body = h('div', { class: 'col gap-3' }, [
      h('div', { class: 'kv-grid' }, [
        kv('域名', d.domain),
        kv('类别', CATEGORY_LABEL[d.category] || '其他'),
        kv('分类标签', d.label || '-'),
        kv('访问次数', formatNumber(d.hits || 0)),
        kv('流量', formatBytes(d.bytes || 0)),
        kv('源主机数', `${d.devices || devList.length || 0} 台`),
        kv('最近访问', d.lastSeen ? formatRelative(d.lastSeen) : '-'),
        kv('首次访问', d.firstSeen ? formatRelative(d.firstSeen) : '-')
      ]),
      h('div', {}, [
        h('div', { class: 'fs-12 dim', style: { marginBottom: '4px' }, text: `访问设备（${devList.length || d.devices || 0}）` }),
        h('div', { class: 'col' }, devRows)
      ])
    ]);
    modal({
      title: `URL 详情 · ${d.domain}`,
      width: 560,
      body: [body]
    });
  }

  /* ---------- 加载 ---------- */
  async function loadTraffic() {
    try {
      const d = await api.getTraffic(range);
      if (destroyed) return;
      data = d;
      renderMain();
      renderCat();
      renderDev();
    } catch (e) {
      console.error('[traffic]', e);
      toast(e.message || '流量数据加载失败', 'error');
    }
    try {
      const dom = await api.getDomains(range, 50);
      if (destroyed) return;
      domains = dom && Array.isArray(dom.domains) ? dom.domains : [];
      renderDomains();
      renderUrlList();
    } catch (e) {
      console.warn('[traffic domains]', e.message);
    }
  }

  async function loadConns() {
    try {
      const r = await api.getConns({ limit: 200 });
      if (destroyed) return;
      conns = (r && r.conns) || [];
      renderConns();
    } catch (e) {
      console.warn('[traffic conns]', e.message);
    }
  }

  // 拉取封禁列表，填充就地解封集合（封目标 dst / 断网设备 device）
  async function loadBlocks() {
    try {
      const r = await api.getBlocks();
      if (destroyed) return;
      const ds = new Set(), dv = new Set();
      ((r && r.blocks) || []).forEach((b) => {
        if (b.type === 'dst') ds.add(b.ip);
        else if (b.type === 'device') dv.add(b.ip);
      });
      dstBlocked = ds;
      devBlocked = dv;
      renderConns();
    } catch (e) {
      console.warn('[traffic blocks]', e.message);
    }
  }

  try { await refreshSettings(); } catch (e) { console.warn('[traffic settings]', e.message); }
  await loadTraffic();
  await Promise.all([loadConns(), loadBlocks()]);

  /* ---------- 未启用 / 未采集时的降级展示（api.md §7.3） ---------- */
  function applyDisabledState() {
    const sysOff = !isEnabled();
    const noCollect = sysOff || !isFeatureOn('collect');
    let panel = host.querySelector('.disabled-panel');
    if (!noCollect) {
      if (panel) panel.remove();
      mainCard.classList.remove('hidden');
      host.querySelector('.grid')?.classList.remove('hidden');
      connToolbar.classList.remove('hidden');
      connCard.classList.remove('hidden');
      headCard.classList.remove('hidden');
      return;
    }
    if (!panel) {
      panel = h('div', { class: 'disabled-panel card' });
      host.insertBefore(panel, host.firstChild);
    }
    panel.innerHTML = '';
    panel.appendChild(h('div', { class: 'card-body' }, [disabledState({
      icon: ICONS.activity,
      title: sysOff ? '系统未启用' : '流量采集未开启',
      desc: sysOff
        ? '系统未启用，当前仅显示配置状态，不采集、不管控、不影响路由器现有功能。'
        : '「流量采集」开关未开启，未读取 conntrack / DNS 日志 / DHCP 租约，因此没有流量数据。',
      hint: sysOff ? '前往「设置 → 系统开关」开启总开关' : '前往「设置 → 系统开关」开启「流量采集」',
      action: button('前往设置', { variant: 'primary', size: 'sm', onClick: () => { location.hash = '#/settings'; } })
    })]));
    mainCard.classList.add('hidden');
    headCard.classList.add('hidden');
    host.querySelector('.grid')?.classList.add('hidden');
    connToolbar.classList.add('hidden');
    connCard.classList.add('hidden');
  }

  applyDisabledState();
  const unsubSettings = subscribeSettings(() => {
    if (destroyed) return;
    applyDisabledState();
    loadTraffic();
    loadConns();
    loadBlocks();
  });
  cleanups.push(unsubSettings);

  /* ---------- SSE 增量更新（2 秒实时） ---------- */
  // tick.trendPoint 是 2 秒粒度的实时速率（bit/s），与 series 的 up/down 单位一致。
  // 策略：同一 30 秒桶内「更新最后一点」，跨桶时才追加新点 —— 既 2 秒实时，又不会像
  // 之前那样每 2 秒 push 一个点导致尾部拉平、时间轴重复刻度。
  const onTick = (ev) => {
    const t = ev.detail;
    if (destroyed || !t || !data || !Array.isArray(data.series) || !data.series.length) return;
    const tp = t.trendPoint || null;
    if (!tp) return;
    const bucketSec = Number(data.bucketSec) || 30;
    const now = Number(tp.t || t.ts || 0) || Math.floor(Date.now() / 1000);
    const bucketStart = Math.floor(now / bucketSec) * bucketSec;
    const last = data.series[data.series.length - 1];

    if (bucketStart > last.t) {
      // 跨入新桶：追加一个实时点（byCat 先留空，堆叠模式用 tick.categories 补齐）
      data.series.push({ t: bucketStart, up: tp.up || 0, down: tp.down || 0, byCat: {} });
      if (data.series.length > 240) data.series.shift();
    } else {
      // 同桶：直接更新最后一点的实时速率
      last.up = tp.up || 0;
      last.down = tp.down || 0;
    }

    // 堆叠模式：用 tick.categories（各分类当前 bit/s）换算成字节/桶，更新最后一点
    if (stacked && Array.isArray(t.categories) && t.categories.length) {
      const tail = data.series[data.series.length - 1];
      const bc = {};
      t.categories.forEach((c) => {
        const k = c.key;
        if (!k) return;
        bc[k] = Math.round(((c.downBps || 0) * bucketSec) / 8);
      });
      tail.byCat = bc;
    }
    renderMain();
  };
  document.addEventListener('gl:tick', onTick);
  cleanups.push(() => document.removeEventListener('gl:tick', onTick));
  const refreshTimer = setInterval(() => {
    if (destroyed || document.visibilityState === 'hidden') return;
    loadTraffic();
    loadConns();
  }, 30000);
  cleanups.push(() => clearInterval(refreshTimer));

  unsub = api.subscribe((type, payload) => {
    if (destroyed) return;
    if (type === 'tick' && payload && payload.kpi) {
      // 只更新头部实时速率，不掺入 30 秒桶序列
      rateNow.textContent = `↓ ${formatBps(payload.kpi.downBps || 0)}  ↑ ${formatBps(payload.kpi.upBps || 0)}`;
    }
  });
  cleanups.push(() => unsub && unsub());

  return {
    unmount() {
      destroyed = true;
      cleanups.forEach((fn) => { try { fn(); } catch (_) {} });
      charts.forEach((c) => { try { c.dispose?.(); } catch (_) {} });
    }
  };
}
