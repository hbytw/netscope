/* ==========================================================================
   观澜 NetScope · 安全态势页（#/security）
   依据 docs/design.md §7.5：
   顶部风险等级横幅（low/guard/high 三态）+ 事件统计；
   左侧事件流（级别过滤、确认、查看证据）；右侧设备风险排行 + 规则命中趋势
   ========================================================================== */

import {
  h, card, chip, button, table, pager, svgIcon, ICONS,
  skeleton, emptyState, errorBox, toast, modal, deviceIcon, disabledState
} from './components.js';
import { areaChart, barRank } from './chart.js';
import {
  formatNumber, formatRelative, formatTime, formatPercent,
  riskLevel, RISK_LABEL, RISK_SEM, SEVERITY_SEM, SEVERITY_LABEL
} from './format.js';
import { refreshSettings, isEnabled, isFeatureOn, subscribeSettings } from '../api.js';

const SEVERITIES = [
  { key: '', label: '全部', sem: 'info' },
  { key: 'critical', label: '严重', sem: 'crit' },
  { key: 'warn', label: '警告', sem: 'warn' },
  { key: 'info', label: '提示', sem: 'info' }
];

const EVENT_TYPES = {
  new_device: '新设备入网', device_online: '设备上线', device_offline: '设备离线',
  port_scan: '端口扫描', bad_port: '高危端口', blacklist_domain: '黑名单域名',
  dns_tunnel: 'DNS 隧道', traffic_anomaly: '流量异常', policy_hit: '策略命中'
};

export async function mount(host, ctx) {
  const { api } = ctx;
  const charts = {};
  const cleanups = [];
  let events = [];
  let summary = { critical: 0, warn: 0, info: 0, total: 0 };
  let risk = { level: 'low', devices: [] };
  let blocks = [];
  let whitelist = [];
  let severity = '';
  let ackFilter = 'all';
  let destroyed = false;

  /* ---------- 风险横幅 ---------- */
  const bannerIcon = h('div', { class: 'risk-icon' }, [svgIcon(ICONS.shield, 22)]);
  const bannerTitle = h('div', { class: 'risk-title', text: '风险等级' });
  const bannerDesc = h('div', { class: 'risk-desc', text: '正在分析近 1 小时安全事件…' });
  const bannerStats = h('div', { class: 'risk-stats' });
  const banner = h('div', { class: 'risk-banner s-ok' }, [
    bannerIcon,
    h('div', {}, [bannerTitle, bannerDesc]),
    bannerStats
  ]);

  /* ---------- 过滤器 ---------- */
  const sevBar = h('div', { class: 'row-gap-2', style: { flexWrap: 'wrap' } });
  SEVERITIES.forEach((s) => {
    const b = h('span', { class: `chip chip-btn ${s.key === severity ? 'on' : ''}`, style: { '--sem': `var(--${s.sem})` } }, [
      h('span', { text: s.label })
    ]);
    b.addEventListener('click', () => {
      severity = s.key;
      sevBar.querySelectorAll('.chip').forEach((x) => x.classList.remove('on'));
      b.classList.add('on');
      loadEvents();
    });
    sevBar.appendChild(b);
  });

  const ackSel = h('select', { class: 'select', style: { width: '128px' } }, [
    h('option', { value: 'all', text: '全部事件' }),
    h('option', { value: 'unacked', text: '仅未确认' }),
    h('option', { value: 'acked', text: '仅已确认' })
  ]);
  ackSel.addEventListener('change', () => { ackFilter = ackSel.value; loadEvents(); });
  cleanups.push(() => ackSel.removeEventListener('change', () => {}));

  const clearBtn = button('清空事件', { variant: 'danger', size: 'sm', icon: ICONS.trash, onClick: onClear });
  const filterCard = h('div', { class: 'card', style: { padding: '10px 16px' } }, [
    h('div', { class: 'row-gap-3', style: { flexWrap: 'wrap' } }, [
      h('span', { class: 'fs-12 dim', text: '级别' }),
      sevBar,
      h('div', { class: 'sys-sep' }),
      ackSel,
      h('div', { class: 'spacer', style: { flex: '1' } }),
      clearBtn
    ])
  ]);

  /* ---------- 事件流 ---------- */
  const eventList = h('div', { class: 'event-list' });
  const eventPager = pager({ onChange: () => renderEvents() });
  const eventCount = h('span', { class: 'card-sub' });
  const eventCard = card({
    title: '安全事件流',
    sub: '',
    actions: [eventCount],
    bodyClass: 'flush',
    body: [eventList],
    foot: [eventPager.el]
  });

  /* ---------- 风险排行 ---------- */
  const riskCanvas = h('canvas');
  const riskList = h('div', { class: 'risk-list' });
  const riskCard = card({
    title: '设备风险排行',
    sub: '近 1 小时行为异常加权 · 点击设备看依据',
    actions: [h('span', { class: 'card-sub fs-11 dim', text: '≠ 病毒检测' })],
    body: [riskList]
  });

  /* ---------- 规则命中趋势 ---------- */
  const trendCanvas = h('canvas');
  const trendCard = card({
    title: '规则命中趋势',
    sub: '最近 10 分钟',
    body: [h('div', { class: 'chart-box', style: { height: '190px' } }, [trendCanvas])]
  });

  host.appendChild(banner);
  host.appendChild(filterCard);

  /* ---------- 封禁列表（误操作解封入口；始终可见，不受降级影响） ---------- */
  const blockList = h('div', { class: 'block-list' });
  const blockCount = h('span', { class: 'card-sub', text: '加载中…' });
  const blockCard = card({
    title: '封禁 / 限速列表',
    sub: '误操作可在此解封',
    actions: [blockCount],
    bodyClass: 'flush',
    body: [blockList],
    style: { marginBottom: '0', height: '100%' }
  });

  /* ---------- 告警白名单列表（查看 / 取消加白） ---------- */
  const wlList = h('div', { class: 'block-list' });
  const wlCount = h('span', { class: 'card-sub', text: '加载中…' });
  const wlCard = card({
    title: '告警白名单',
    sub: '加白后同类不再告警',
    actions: [wlCount],
    bodyClass: 'flush',
    body: [wlList],
    style: { marginBottom: '0', height: '100%' }
  });

  /* ---------- 威胁情报查询（命中才告警；此处仅查询窗口） ---------- */
  const tqInput = h('input', { class: 'input', type: 'search', placeholder: '查询域名或 IP 是否命中威胁情报库（如 pool.minexmr.com / 1.2.3.4）' });
  const tqList = h('div', { class: 'block-list', style: { maxHeight: '336px', overflowY: 'auto' } });
  const tqCount = h('span', { class: 'card-sub', text: '' });
  const tqUpd = h('span', { class: 'card-sub dim fs-11' });
  const tqBtn = button('立即更新', { variant: 'ghost', size: 'sm', icon: ICONS.refresh });
  const tqCard = card({
    title: '威胁情报查询',
    sub: '后台自动检测 · 命中即告警 · 开源情报库',
    actions: [tqCount, tqUpd],
    bodyClass: 'flush',
    body: [h('div', { class: 'search-wrap', style: { margin: '12px 16px 6px' } }, [svgIcon(ICONS.search, 13), tqInput]), tqList],
    foot: [tqBtn],
    style: { marginBottom: '0', height: '100%' }
  });

  host.appendChild(h('div', { class: 'grid', style: { alignItems: 'start' } }, [
    h('div', { class: 'g7' }, [eventCard]),
    h('div', { class: 'g5' }, [
      h('div', { class: 'grid', style: { gap: '13px' } }, [
        h('div', { class: 'g12' }, [riskCard]),
        h('div', { class: 'g12' }, [trendCard])
      ])
    ])
  ]));

  /* 第二排：封禁 / 白名单 / 情报查询（三列等高） */
  host.appendChild(h('div', { class: 'grid', style: { alignItems: 'stretch' } }, [
    h('div', { class: 'g4' }, [blockCard]),
    h('div', { class: 'g4' }, [wlCard]),
    h('div', { class: 'g4' }, [tqCard])
  ]));

  /* ---------- 渲染 ---------- */
  /* ---------- 封禁列表渲染 ---------- */
  const BLOCK_TYPE_LABEL = { device: '断网', dst: '封目标', limit: '限速' };
  const BLOCK_TYPE_SEM = { device: 'crit', dst: 'warn', limit: 'warn' };

  function renderBlocks() {
    blockCount.textContent = blocks.length ? `${blocks.length} 条` : '';
    blockList.innerHTML = '';
    if (!blocks.length) {
      blockList.appendChild(h('div', { class: 'tq-hint dim fs-12' }, [
        svgIcon(ICONS.shield, 14), h('span', { text: '当前无封禁 / 限速记录' })
      ]));
      return;
    }
    blocks.forEach((b) => {
      const typeLabel = BLOCK_TYPE_LABEL[b.type] || b.type || '—';
      const row = h('div', { class: 'block-row' }, [
        h('div', { class: 'col', style: { minWidth: '0', flex: '1' } }, [
          h('div', { class: 'row-gap-2', style: { flexWrap: 'wrap', gap: '6px' } }, [
            h('span', { class: 'mono td-strong truncate', text: b.ip }),
            chip(typeLabel, { sem: BLOCK_TYPE_SEM[b.type] || 'mute' }),
            b.type === 'limit'
              ? chip(`↓${b.downKbps || 0} ↑${b.upKbps || 0} Kbps`, { plain: true, sem: 'mute' })
              : null
          ]),
          h('div', { class: 'dim fs-11', text: `${b.reason || (b.type === 'device' ? '手动断网' : '手动封禁')}${b.at ? ' · ' + formatRelative(b.at) : ''}` })
        ]),
        button('解封', {
          variant: 'primary', size: 'sm', icon: ICONS.undo,
          onClick: async (ev) => {
            const btn = ev.currentTarget;
            btn.classList.add('is-loading');
            try {
              await api.unblock(b.ip, b.type);
              toast(`已解封 ${b.ip}`, 'success');
              await loadBlocks();
            } catch (e) {
              btn.classList.remove('is-loading');
              toast(e.message || '解封失败', 'error');
            }
          }
        })
      ]);
      blockList.appendChild(row);
    });
  }

  async function loadBlocks() {
    try {
      const r = await api.getBlocks();
      if (destroyed) return;
      blocks = (r && Array.isArray(r.blocks)) ? r.blocks : [];
    } catch (e) {
      if (destroyed) return;
      blocks = [];
      blockCount.textContent = '';
    }
    renderBlocks();
  }

  /* ---------- 白名单列表渲染 ---------- */
  function renderWhitelist() {
    wlCount.textContent = whitelist.length ? `${whitelist.length} 项` : '';
    wlList.innerHTML = '';
    if (!whitelist.length) {
      wlList.appendChild(h('div', { class: 'tq-hint dim fs-12' }, [
        svgIcon(ICONS.plus, 14), h('span', { text: '当前无加白项' })
      ]));
      return;
    }
    whitelist.forEach((w) => {
      const row = h('div', { class: 'block-row' }, [
        h('div', { class: 'col', style: { minWidth: '0', flex: '1' } }, [
          h('div', { class: 'row-gap-2', style: { flexWrap: 'wrap', gap: '6px' } }, [
            chip(EVENT_TYPES[w.type] || w.type || '事件', { sem: 'ok', plain: true }),
            h('span', { class: 'mono td-strong truncate', text: w.target })
          ]),
          h('div', { class: 'dim fs-11', text: `${w.note || '—'}${w.at ? ' · ' + formatRelative(w.at) : ''}` })
        ]),
        button('取消加白', {
          variant: 'warn', size: 'sm', icon: ICONS.undo,
          onClick: async (ev) => {
            const btn = ev.currentTarget;
            btn.classList.add('is-loading');
            try {
              await api.removeWhitelist(w.id);
              toast(`已取消加白 ${w.target}`, 'success');
              await loadWhitelist();
            } catch (e) {
              btn.classList.remove('is-loading');
              toast(e.message || '取消失败', 'error');
            }
          }
        })
      ]);
      wlList.appendChild(row);
    });
  }

  async function loadWhitelist() {
    try {
      const r = await api.getWhitelist();
      if (destroyed) return;
      whitelist = (r && Array.isArray(r.items)) ? r.items : [];
    } catch (e) {
      if (destroyed) return;
      whitelist = [];
      wlCount.textContent = '';
    }
    renderWhitelist();
  }

  /* ---------- 威胁情报查询（命中才告警；此处仅查询窗口） ---------- */
  const THREAT_KIND_LABEL = { c2: '远控C2', phishing: '钓鱼', mining: '矿池', botnet: '僵尸网络', malware: '恶意软件', scam: '诈骗/博彩' };
  const THREAT_KIND_SEM = { c2: 'crit', phishing: 'warn', mining: 'crit', botnet: 'warn', malware: 'warn', scam: 'warn' };
  let tqSearched = false;

  function tqHint(text, icon) {
    tqList.innerHTML = '';
    tqList.appendChild(h('div', { class: 'tq-hint dim fs-12' }, [
      svgIcon(icon || ICONS.search, 14),
      h('span', { text })
    ]));
  }

  function renderThreatQuery(data) {
    const doms = (data && data.domains) || [];
    const ips = (data && data.ips) || [];
    const rows = [
      ...doms.map((t) => ({ ...t, type: '域名' })),
      ...ips.map((t) => ({ ...t, type: 'IP' }))
    ];
    tqList.innerHTML = '';
    if (!rows.length) {
      tqHint('未命中（该地址不在情报库，不会告警）', ICONS.check);
      return;
    }
    const shown = rows.slice(0, 50);
    shown.forEach((t) => {
      const kind = t.kind || 'malware';
      tqList.appendChild(h('div', { class: 'tq-row' }, [
        h('div', { class: 'tq-main' }, [
          h('div', { class: 'tq-line' }, [
            h('span', { class: 'mono tq-target truncate', text: t.target }),
            chip(THREAT_KIND_LABEL[kind] || kind, { sem: THREAT_KIND_SEM[kind] || 'warn', plain: true }),
            chip('命中', { sem: 'crit', plain: true })
          ]),
          h('div', { class: 'dim fs-11 truncate', text: `${t.type} · ${t.source || '开源情报'}` })
        ]),
        h('div', { class: 'tq-side dim fs-11' }, [t.confidence ? `置信度 ${t.confidence}` : ''])
      ]));
    });
    if (rows.length > shown.length) {
      tqList.appendChild(h('div', { class: 'tq-hint dim fs-11' }, [h('span', { text: `另有 ${rows.length - shown.length} 条命中未显示` })]));
    }
  }

  async function loadThreats() {
    const q = tqInput.value.trim();
    try {
      if (!q) {
        // 空查询：只取库计数/更新时间，不展示任何明细
        tqSearched = false;
        const r = await api.getThreats({ limit: 1 });
        if (destroyed) return;
        const c = (r && r.counts) || {};
        tqCount.textContent = c.domains != null ? `库：域名 ${c.domains} · IP ${c.ips}` : '';
        renderThreatUpdated(r);
        tqHint('输入域名 / IP 查询是否命中情报库；后台命中会自动告警');
        return;
      }
      tqSearched = true;
      const r = await api.getThreats({ search: q });
      if (destroyed) return;
      const c = (r && r.counts) || {};
      tqCount.textContent = c.domains != null ? `库：域名 ${c.domains} · IP ${c.ips}` : '';
      renderThreatUpdated(r);
      renderThreatQuery(r);
    } catch (e) {
      if (destroyed) return;
      tqCount.textContent = '';
      tqHint('威胁情报库查询不可用');
    }
  }

  // 更新时间显示
  function renderThreatUpdated(data) {
    if (data && data.updatedAt) {
      tqUpd.textContent = `上次更新 ${formatRelative(data.updatedAt)}`;
    } else {
      tqUpd.textContent = '';
    }
  }

  function renderBanner() {
    const lv = risk.level || 'low';
    const sem = RISK_SEM[lv];
    banner.className = `risk-banner s-${sem}`;
    bannerIcon.innerHTML = '';
    bannerIcon.appendChild(svgIcon(lv === 'high' ? ICONS.alert : lv === 'guard' ? ICONS.gauge : ICONS.shield, 22));
    bannerTitle.textContent = `整体风险：${RISK_LABEL[lv]}`;
    const desc = {
      low: '近 1 小时未发现明显异常行为，设备行为符合预期。',
      guard: '存在需要关注的行为异常，建议查看右侧设备风险排行并及时处置。',
      high: '检测到高危行为特征（端口扫描 / 高危端口外联等），请立即核查并断网处置。'
    };
    bannerDesc.textContent = desc[lv] || '';
    bannerStats.innerHTML = '';
    [
      ['严重', summary.critical || 0, 'var(--crit)'],
      ['警告', summary.warn || 0, 'var(--warn)'],
      ['提示', summary.info || 0, 'var(--info)'],
      ['事件总数', summary.total || 0, 'var(--text-0)']
    ].forEach(([k, v, c]) => {
      bannerStats.appendChild(h('div', { class: 'risk-stat' }, [
        h('div', { class: 'v num', style: { color: c }, text: String(v) }),
        h('div', { class: 'k', text: k })
      ]));
    });
  }

  function renderEvents() {
    eventList.innerHTML = '';
    if (!events.length) {
      eventList.appendChild(emptyState('暂无匹配的安全事件', ICONS.shield, '调整级别筛选或清空筛选条件'));
      eventPager.set(1, 1, 0);
      return;
    }
    const pageSize = 50;
    const pages = Math.max(1, Math.ceil(events.length / pageSize));
    // 当前页码从 pager 读取（pager 内部状态，外部不可见）
    const page = Math.min(Math.max(1, eventPager.getPage()), pages);
    const slice = events.slice((page - 1) * pageSize, page * pageSize);
    eventPager.set(page, pages, events.length);
    eventCount.textContent = `${events.length} 条事件`;

    slice.forEach((e) => {
      const sem = SEVERITY_SEM[e.severity] || 'info';
      const item = h('div', { class: `event-item ${e.acked ? 'event-acked' : ''}` }, [
        h('div', { class: 'event-bar', style: { '--sem': `var(--${sem})` } }),
        h('div', { class: 'event-main' }, [
          h('div', { class: 'event-title', text: e.title || EVENT_TYPES[e.type] || e.type }),
          h('div', { class: 'event-detail', text: e.detail || '' }),
          h('div', { class: 'event-meta' }, [
            chip(SEVERITY_LABEL[e.severity] || '提示', { sem, plain: true }),
            chip(EVENT_TYPES[e.type] || e.type, { plain: true }),
            h('span', { text: formatRelative(e.ts) }),
            e.deviceIp ? h('span', { class: 'mono', text: e.deviceIp }) : null
          ])
        ]),
        h('div', { class: 'ops' }, [
          h('button', { class: 'op-btn', type: 'button', title: '查看证据' }, [svgIcon(ICONS.eye, 12)]),
          h('button', { class: 'op-btn', type: 'button', title: e.acked ? '取消确认' : '确认' }, [svgIcon(ICONS.check, 12)])
        ])
      ]);
      const btns = item.querySelectorAll('.op-btn');
      btns[0].addEventListener('click', () => showEvidence(e));
      btns[1].addEventListener('click', async () => {
        try {
          await api.ackEvent(e.id, !e.acked);
          e.acked = !e.acked;
          toast(e.acked ? '事件已确认' : '已取消确认', 'success');
          renderEvents();
          renderBanner();
        } catch (err) { toast(err.message || '操作失败', 'error'); }
      });
      eventList.appendChild(item);
    });
  }

  function showEvidence(e) {
    const ev = e.evidence || {};
    const rows = Object.entries(ev).map(([k, v]) => {
      const val = Array.isArray(v) ? v.join('、') : (v && typeof v === 'object' ? JSON.stringify(v) : String(v));
      return h('div', { class: 'kv' }, [
        h('span', { class: 'k', text: k }),
        h('span', { class: 'v', text: val })
      ]);
    });
    const body = h('div', { class: 'col gap-3' }, [
      h('div', { class: 'bg-panel' }, [
        h('div', { class: 'kv' }, [h('span', { class: 'k', text: '事件 ID' }), h('span', { class: 'v mono', text: e.id })]),
        h('div', { class: 'kv' }, [h('span', { class: 'k', text: '时间' }), h('span', { class: 'v', text: formatTime(e.ts, true) })]),
        h('div', { class: 'kv' }, [h('span', { class: 'k', text: '设备' }), h('span', { class: 'v', text: `${e.deviceName || '—'} · ${e.deviceIp || '—'}` })]),
        h('div', { class: 'kv' }, [h('span', { class: 'k', text: '级别' }), h('span', { class: 'v', text: SEVERITY_LABEL[e.severity] || e.severity })])
      ]),
      // 威胁研判（判断是否为真实威胁）
      h('div', { class: 'bg-panel', style: { borderColor: `var(--${semCss(e.severity)})` } }, [
        h('div', { class: 'row-gap-2', style: { marginBottom: '6px' } }, [
          svgIcon(ICONS.shield, 14),
          h('span', { class: 'fs-12 td-strong', text: '威胁研判' })
        ]),
        h('div', { class: 'fs-12', style: { lineHeight: '1.7' } }, [
          h('p', { style: { margin: '0 0 4px' }, text: threatInterpret(e) }),
          h('p', { class: 'dim', style: { margin: '0' }, text: threatAction(e) })
        ])
      ]),
      rows.length ? h('div', { class: 'col gap-1' }, rows) : h('div', { class: 'dim fs-12', text: '该事件无结构化证据字段。' }),
      h('div', { class: 'fs-12 muted', style: { lineHeight: '1.6' }, text: e.detail || '' })
    ]);
    const wlTarget = whitelistTarget(e);
    const wlBtn = button('加入白名单', {
      variant: 'primary', size: 'sm', icon: ICONS.plus,
      onClick: async () => {
        try {
          await api.addWhitelist(e.type || 'other', wlTarget, e.title || '');
          toast(`已加白：${EVENT_TYPES[e.type] || e.type} · ${wlTarget}，后续同类不再告警`, 'success');
          m.close();
          await loadWhitelist();
        } catch (err) { toast(err.message || '加白失败', 'error'); }
      }
    });
    const m = modal({ title: `事件证据 · ${e.title || EVENT_TYPES[e.type] || e.type}`, width: 560, body: [body], foot: [wlBtn] });
  }

  // 白名单目标：设备事件用 deviceIp；域名类用 evidence.domain；其余 deviceIp
  function whitelistTarget(e) {
    const ev = e.evidence || {};
    if (e.type === 'blacklist_domain' || e.type === 'dns_tunnel') {
      return ev.domain || ev.name || e.detail || e.deviceIp || 'unknown';
    }
    return e.deviceIp || ev.srcIp || ev.ip || 'unknown';
  }

  // 严重度 → 语义色（供威胁研判边框）
  function semCss(sev) {
    return sev === 'critical' ? 'crit' : sev === 'warn' ? 'warn' : 'info';
  }

  // 威胁解读：按类型 + 级别给出判断
  const THREAT_HINT = {
    port_scan: { w: '疑似端口扫描：攻击者枚举开放端口，可能探测服务漏洞。建议封禁该源 IP 并核查是否被爆破。', c: '端口扫描特征明显：可能正在进行漏洞探测/横向渗透，建议立即断网该设备并全盘查杀。', i: '少量端口探测，可能为正常工具/误报，可关注。' },
    bad_port: { w: '连接到高危端口：目标端口常用于恶意远控/挖矿/代理跳板。建议封禁该目标 IP。', c: '高危端口外联确认：疑似 C2 回连或挖矿，建议立即断网并隔离。', i: '高危端口连接，确认应用是否必要，必要时封禁目标。' },
    blacklist_domain: { w: '访问黑名单域名：命中已知赌博/色情/恶意域名库。建议拦截该域名。', c: '多次访问黑名单域名，建议断网设备并拦截域名。', i: '命中黑名单域名，建议加入域名拦截。' },
    dns_tunnel: { w: 'DNS 隧道嫌疑：TXT 查询异常，可能用于隐蔽外联。建议封禁该设备。', c: 'DNS 隧道特征明显：数据疑似经 DNS 外传，建议立即断网并排查。', i: '少量 TXT 查询，可能为正常，可关注。' },
    traffic_anomaly: { w: '流量异常：流量远超基线，可能为下载/攻击/挖矿。建议核查。', c: '严重流量异常，疑似攻击/挖矿，建议断网处置。', i: '流量小幅波动，可能为正常下载，可关注。' },
    new_device: { i: '新设备入网：首次发现，建议确认是否为合法设备，必要时限制。' },
    policy_hit: { w: '策略命中：设备触发了您配置的行为策略，按策略处置。', i: '策略命中（如限速），属预期行为。' }
  };
  function threatInterpret(e) {
    const t = e.type || '';
    const sev = e.severity || 'info';
    const hint = THREAT_HINT[t];
    if (!hint) return `类型「${EVENT_TYPES[t] || t}」，级别 ${SEVERITY_LABEL[sev] || sev}。请结合证据字段判断。`;
    if (sev === 'critical') return hint.c || hint.w || hint.i;
    if (sev === 'warn') return hint.w || hint.i;
    return hint.i || hint.w;
  }
  function threatAction(e) {
    const sev = e.severity || 'info';
    if (sev === 'critical') return '建议：立即断网该设备 + 封禁目标，必要时联系运维排查。';
    if (sev === 'warn') return '建议：核查该行为，封禁目标或限速，持续观察。';
    return '建议：暂不处置，观察后续是否升级。';
  }

  // 各事件类型判定依据（风险/告警详情用）
  const REASON_HINT = {
    port_scan: '60 秒内新连接 ≥20 个不同公网端口（已排除内网/ZeroTier/VPN）',
    bad_port: '连接到高危端口（常用于远控/挖矿/代理跳板）',
    blacklist_domain: '访问命中高危域名库（赌博/色情/矿池/恶意/钓鱼）',
    bad_ip: '连接命中威胁情报库恶意 IP（C2/僵尸网络/矿池）',
    dns_tunnel: '60 秒内 TXT 查询异常，疑似 DNS 隧道外传',
    traffic_anomaly: '1 小时内上传流量超基线，且境外目的占比较高',
    policy_hit: '触发了您配置的行为策略',
    new_device: '新设备入网（首次发现）'
  };

  function renderRisk() {
    riskList.innerHTML = '';
    const devs = (risk.devices || []).slice(0, 10);
    if (!devs.length) {
      riskList.appendChild(emptyState('暂无风险设备', ICONS.shield));
      return;
    }
    devs.forEach((d) => {
      // 风险分上限 1.0，超出时钳制，避免进度条溢出轨道
      const pct = Math.min(100, Math.max(0, Math.round((d.risk || 0) * 100)));
      const sem = pct >= 60 ? 'crit' : pct >= 30 ? 'warn' : 'info';
      const reasons = (d.reasons || []).map((r) => `${EVENT_TYPES[r.type] || r.type} ×${r.count}`).join(' · ') || '—';
      const row = h('div', { class: 'risk-row', style: { cursor: 'pointer' } }, [
        h('div', { class: 'col', style: { minWidth: '0', flex: '1' } }, [
          h('div', { class: 'row-gap-2', style: { gap: '6px' } }, [
            h('span', { class: 'td-strong truncate', text: d.name || d.ip }),
            chip(`${pct}%`, { sem, plain: true })
          ]),
          h('div', { class: 'dim fs-11 truncate', text: reasons })
        ]),
        h('div', { class: 'risk-track' }, [
          h('i', { style: { width: `${pct}%`, '--c': `var(--${sem})` } })
        ])
      ]);
      row.addEventListener('click', () => showRiskDetail(d));
      riskList.appendChild(row);
    });
  }

  function showRiskDetail(d) {
    const reasons = d.reasons || [];
    const rows = reasons.length
      ? reasons.map((r) => h('div', { class: 'kv' }, [
          h('span', { class: 'k', text: EVENT_TYPES[r.type] || r.type }),
          h('span', { class: 'v', text: `${r.count} 次${r.lastTs ? ' · 最近 ' + formatRelative(r.lastTs) : ''}${REASON_HINT[r.type] ? ' — ' + REASON_HINT[r.type] : ''}` })
        ]))
      : [h('div', { class: 'dim fs-12', text: '暂无事件依据（风险可能来自累计/低阈值）。' })];
    const body = h('div', { class: 'col gap-3' }, [
      h('div', { class: 'bg-panel' }, [
        h('div', { class: 'kv' }, [h('span', { class: 'k', text: '设备' }), h('span', { class: 'v', text: `${d.name || '—'} · ${d.ip || '—'}` })]),
        h('div', { class: 'kv' }, [h('span', { class: 'k', text: '风险分' }), h('span', { class: 'v', text: `${Math.round((d.risk || 0) * 100)}%` })])
      ]),
      h('div', { class: 'fs-12 muted', style: { lineHeight: '1.7' }, text: '风险分 = 近 1 小时行为异常事件加权（critical 0.4 / warn 0.2 / info 0.05，封顶 1.0）。它是"可疑行为信号"，不等于病毒/木马检测。' }),
      h('div', { class: 'col gap-1', style: { marginTop: '2px' } }, rows)
    ]);
    modal({ title: `风险详情 · ${d.name || d.ip}`, width: 560, body: [body] });
  }

  function renderTrend() {
    // 规则命中趋势：以事件时间轴聚合（近 12 桶）
    const now = Math.floor(Date.now() / 1000);
    const buckets = 12;
    const span = 600;
    const counts = new Array(buckets).fill(0);
    events.forEach((e) => {
      const age = now - (e.ts || now);
      if (age < 0 || age > span) return;
      const i = Math.min(buckets - 1, Math.floor((age / span) * buckets));
      counts[buckets - 1 - i] += 1;
    });
    const labels = counts.map((_, i) => {
      const t = now - span + (i + 1) * (span / buckets);
      const dt = new Date(t * 1000);
      return `${String(dt.getHours()).padStart(2, '0')}:${String(dt.getMinutes()).padStart(2, '0')}`;
    });
    const model = {
      labels,
      series: [
        { name: '命中', color: '#fb7185', values: counts },
        { name: '基线', color: '#7c5cff', values: counts.map((c) => Math.max(0, Math.round(c * 0.35))) }
      ],
      unit: 'count'
    };
    if (!charts.trend) charts.trend = areaChart(trendCanvas, model);
    else charts.trend.update(model);
  }

  /* ---------- 加载 ---------- */
  async function loadEvents() {
    try {
      const params = { limit: 100 };
      if (severity) params.severity = severity;
      if (ackFilter !== 'all') params.ack = ackFilter;
      const r = await api.getEvents(params);
      if (destroyed) return;
      events = (r && r.events) || [];
      summary = (r && r.summary) || summary;
      renderEvents();
      renderBanner();
      renderTrend();
    } catch (e) {
      console.error('[security events]', e);
      toast(e.message || '事件加载失败', 'error');
    }
  }

  async function loadRisk() {
    try {
      const r = await api.getRisk();
      if (destroyed) return;
      risk = r || { level: 'low', devices: [] };
      renderBanner();
      renderRisk();
    } catch (e) { console.warn('[security risk]', e.message); }
  }

  async function onClear() {
    ctx.confirm({
      title: '清空安全事件', danger: true, confirmText: '清空',
      message: '将删除全部安全事件记录（不可恢复）。确认继续？',
      onConfirm: async () => {
        try {
          await api.clearEvents();
          toast('事件已清空', 'success');
          await loadEvents();
          await loadRisk();
        } catch (e) { throw e; }
      }
    });
  }

  try { await refreshSettings(); } catch (e) { console.warn('[security settings]', e.message); }
  await Promise.all([loadEvents(), loadRisk()]);
  await Promise.all([loadBlocks(), loadWhitelist(), loadThreats()]);

  /* ---------- 未启用 / 未开启告警时的降级展示（api.md §7.3） ---------- */
  function applyDisabledState() {
    const sysOff = !isEnabled();
    const noAlerts = sysOff || !isFeatureOn('alerts');
    let panel = host.querySelector('.disabled-panel');
    if (!noAlerts) {
      if (panel) panel.remove();
      banner.classList.remove('hidden');
      filterCard.classList.remove('hidden');
      host.querySelector('.grid')?.classList.remove('hidden');
      return;
    }
    if (!panel) {
      panel = h('div', { class: 'disabled-panel card' });
      host.insertBefore(panel, host.firstChild);
    }
    panel.innerHTML = '';
    panel.appendChild(h('div', { class: 'card-body' }, [disabledState({
      icon: ICONS.shield,
      title: sysOff ? '系统未启用' : '安全告警未开启',
      desc: sysOff
        ? '系统未启用，当前仅显示配置状态，不采集、不管控、不影响路由器现有功能。'
        : '「安全告警」开关未开启，不做规则研判、不产生新事件（历史事件仍保留可查）。',
      hint: sysOff ? '前往「设置 → 系统开关」开启总开关' : '前往「设置 → 系统开关」开启「安全告警」',
      action: button('前往设置', { variant: 'primary', size: 'sm', onClick: () => { location.hash = '#/settings'; } })
    })]));
    banner.classList.add('hidden');
    filterCard.classList.add('hidden');
    host.querySelector('.grid')?.classList.add('hidden');
  }

  /* ---------- 威胁情报查询事件（搜索 + 立即更新） ---------- */
  let tqTimer = null;
  tqInput.addEventListener('input', () => {
    clearTimeout(tqTimer);
    tqTimer = setTimeout(loadThreats, 350);
  });
  tqInput.addEventListener('keydown', (ev) => { if (ev.key === 'Enter') { clearTimeout(tqTimer); loadThreats(); } });
  tqBtn.addEventListener('click', async () => {
    tqBtn.disabled = true;
    tqBtn.textContent = '更新中…';
    try {
      const r = await api.updateThreats();
      if (destroyed) return;
      if (r && r.ok) {
        toast(`威胁情报库已更新：域名 ${r.domains} · IP ${r.ips}`, 'success');
      } else {
        toast(`更新失败：${(r && r.errors) ? r.errors.join('；') : '源不可达'}`.slice(0, 120), 'error');
      }
      loadThreats();
    } catch (e) {
      if (destroyed) return;
      toast('威胁情报库更新请求失败', 'error');
    } finally {
      if (!destroyed) { tqBtn.disabled = false; tqBtn.textContent = '立即更新'; }
    }
  });

  applyDisabledState();
  const unsubSettings = subscribeSettings(() => {
    if (destroyed) return;
    applyDisabledState();
    loadEvents();
    loadRisk();
    loadBlocks();
    loadWhitelist();
    loadThreats();
  });
  cleanups.push(unsubSettings);

  /* ---------- SSE 增量 ---------- */
  // app.js 已把 /api/stream 的 alert 以 CustomEvent 派发到 document，
  // 本页只监听 document 事件，避免重复订阅导致告警与统计翻倍。
  const onAlert = (ev) => {
    const e = ev.detail;
    if (destroyed || !e) return;
    events = [e, ...events];
    summary.total = (summary.total || 0) + 1;
    if (e.severity === 'critical') summary.critical = (summary.critical || 0) + 1;
    else if (e.severity === 'warn') summary.warn = (summary.warn || 0) + 1;
    else summary.info = (summary.info || 0) + 1;
    renderEvents();
    renderBanner();
    renderTrend();
  };

  document.addEventListener('gl:alert', onAlert);
  cleanups.push(() => document.removeEventListener('gl:alert', onAlert));

  return {
    unmount() {
      destroyed = true;
      cleanups.forEach((fn) => { try { fn(); } catch (_) {} });
      Object.values(charts).forEach((c) => { try { c?.dispose?.(); } catch (_) {} });
    }
  };
}
