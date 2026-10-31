/* ==========================================================================
   观澜 NetScope · 设备页（#/devices）
   依据 docs/design.md §7.2：搜索 + 分组筛选 + 仅在线开关 + 统计条；
   表格（设备/状态/实时速率+迷你趋势/累计流量/风险/操作）；点击行 → 右侧抽屉
   ========================================================================== */

import {
  h, card, chip, button, switchControl, table, pager, drawer, modal, svgIcon, ICONS,
  skeleton, emptyState, errorBox, deviceIcon, rateCell, riskBadge, toast, disabledState
} from './components.js';
import { areaChart, sparkline, barRank } from './chart.js';
import {
  formatBps, formatBytes, formatNumber, formatDuration, formatRelative,
  formatTime, riskLevel, RISK_LABEL, RISK_SEM, CATEGORY_COLOR, CATEGORY_LABEL
} from './format.js';
import { refreshSettings, isEnabled, isFeatureOn, subscribeSettings } from '../api.js';

export async function mount(host, ctx) {
  const { api } = ctx;
  const charts = [];
  const cleanups = [];
  let devices = [];
  let filtered = [];
  let query = '';
  let groupFilter = '';
  let onlyOnline = false;
  let destroyed = false;
  let drawerInst = null;
  let unsub = null;

  /* ---------- 头部工具栏 ---------- */
  const searchInput = h('input', { class: 'input', type: 'search', placeholder: '搜索 别名 / 主机名 / IP / MAC / 厂商' });
  const searchWrap = h('div', { class: 'search-wrap', style: { minWidth: '260px', flex: '0 1 320px' } }, [
    svgIcon(ICONS.search, 13), searchInput
  ]);

  const groupSelect = h('select', { class: 'select', style: { width: '140px' } }, [
    h('option', { value: '', text: '全部分组' })
  ]);

  const onlineSwitch = switchControl({
    label: '仅在线',
    onChange: (v) => { onlyOnline = v; applyFilter(); }
  });

  const statBar = h('div', { class: 'stat-bar' });

  const toolbar = h('div', { class: 'card', style: { padding: '11px 16px' } }, [
    h('div', { class: 'row-gap-3', style: { flexWrap: 'wrap' } }, [
      searchWrap,
      groupSelect,
      onlineSwitch,
      h('div', { class: 'spacer', style: { flex: '1' } }),
      statBar
    ])
  ]);

  /* ---------- 表格 ---------- */
  const cols = [
    {
      key: 'name', title: '设备', width: '260px',
      render: (d) => {
        const wrap = h('div', { class: 'dev-cell' }, [
          deviceIcon(d, 30),
          h('div', { class: 'dev-meta' }, [
            h('div', { class: 'dev-alias truncate', text: d.alias || d.hostname || d.ip }),
            h('div', { class: 'dev-name truncate', text: d.alias ? `${d.hostname} · ${d.vendor}` : `${d.vendor || '未知设备'}` }),
            h('div', { class: 'dev-sub', text: `${d.ip} · ${d.mac}` })
          ])
        ]);
        return wrap;
      }
    },
    {
      key: 'online', title: '状态', width: '96px',
      render: (d) => {
        if (d.blocked) return chip('已断网', { sem: 'crit' });
        if (!d.online) return chip('离线', { sem: 'mute', plain: true });
        if (d.limitKbps && (d.limitKbps.down || d.limitKbps.up)) return chip('限速中', { sem: 'warn' });
        return h('span', { class: 'status s-ok' }, [
          h('i', { class: 'status-dot pulse', style: { '--sem': 'var(--ok)' } }),
          h('span', { text: '在线' })
        ]);
      }
    },
    {
      key: 'downBps', title: '实时速率', width: '128px',
      render: (d) => rateCell(d.upBps, d.downBps),
      sortValue: (d) => d.downBps
    },
    {
      key: 'totalDown', title: '累计流量', width: '130px', align: 'right',
      render: (d) => h('div', { class: 'col', style: { alignItems: 'flex-end', lineHeight: '1.35' } }, [
        h('span', { class: 'td-strong num', text: `↓ ${formatBytes(d.totalDown)}` }),
        h('span', { class: 'dim fs-11 num', text: `↑ ${formatBytes(d.totalUp)}` })
      ]),
      sortValue: (d) => d.totalDown
    },
    {
      key: 'risk', title: '风险', width: '112px',
      render: (d) => riskBadge(d.risk),
      sortValue: (d) => d.risk
    },
    {
      key: 'ops', title: '操作', width: '160px', align: 'right', sortable: false,
      render: (d) => {
        const box = h('div', { class: 'ops' });
        const blk = h('button', {
          class: `op-btn ${d.blocked ? 'on' : 'danger'}`, type: 'button',
          title: d.blocked ? '恢复联网' : '断网'
        }, [svgIcon(d.blocked ? ICONS.undo : ICONS.ban, 12)]);
        blk.addEventListener('click', (ev) => { ev.stopPropagation(); toggleBlock(d, blk); });
        const lim = h('button', { class: 'op-btn warn', type: 'button', title: '限速' }, [svgIcon(ICONS.gauge, 12)]);
        lim.addEventListener('click', (ev) => { ev.stopPropagation(); openLimitModal(d); });
        const det = h('button', { class: 'op-btn', type: 'button', title: '详情' }, [svgIcon(ICONS.eye, 12)]);
        det.addEventListener('click', (ev) => { ev.stopPropagation(); openDeviceDrawer(d); });
        box.appendChild(blk); box.appendChild(lim); box.appendChild(det);
        return box;
      }
    }
  ];

  const tbl = table({
    columns: cols,
    rows: [],
    onRowClick: (d) => openDeviceDrawer(d),
    rowClass: (d) => (d.blocked ? 'row-danger' : (d.risk >= 0.6 ? 'row-warn' : ''))
  });

  const pagerEl = pager({ onChange: (p) => { tbl.__page = p; renderTable(); } });
  tbl.__onPage = (page, pages) => pagerEl.set(page, pages, filtered.length);

  const tableCard = card({
    title: '设备列表',
    sub: '',
    actions: [h('span', { class: 'card-sub', id: 'dev-count' })],
    bodyClass: 'flush',
    body: [tbl.el],
    foot: [pagerEl.el]
  });

  host.appendChild(toolbar);
  host.appendChild(tableCard);

  /* ---------- 事件 ---------- */
  const onSearch = () => { query = searchInput.value.trim(); applyFilter(); };
  searchInput.addEventListener('input', onSearch);
  groupSelect.addEventListener('change', () => { groupFilter = groupSelect.value; applyFilter(); });
  cleanups.push(() => {
    searchInput.removeEventListener('input', onSearch);
    groupSelect.removeEventListener('change', () => {});
  });

  /* ---------- 过滤与渲染 ---------- */
  function applyFilter() {
    const q = query.toLowerCase();
    filtered = devices.filter((d) => {
      if (onlyOnline && !d.online) return false;
      if (groupFilter && d.group !== groupFilter) return false;
      if (!q) return true;
      const hay = `${d.alias || ''} ${d.hostname || ''} ${d.ip || ''} ${d.mac || ''} ${d.vendor || ''} ${d.group || ''}`.toLowerCase();
      return hay.includes(q);
    });
    filtered.forEach((d) => { d.__search = `${d.alias || ''} ${d.hostname || ''} ${d.ip || ''} ${d.mac || ''} ${d.vendor || ''} ${d.group || ''}`; });
    renderTable();
    renderStats();
  }

  function renderStats() {
    const online = devices.filter((d) => d.online).length;
    const blocked = devices.filter((d) => d.blocked).length;
    const limited = devices.filter((d) => d.limitKbps && (d.limitKbps.down || d.limitKbps.up)).length;
    const risky = devices.filter((d) => (d.risk || 0) >= 0.6).length;
    statBar.innerHTML = '';
    const items = [
      ['在线', online, 'var(--ok)'], ['离线', devices.length - online, 'var(--text-2)'],
      ['总数', devices.length, 'var(--text-0)'], ['已断网', blocked, 'var(--crit)'],
      ['限速中', limited, 'var(--warn)'], ['高风险', risky, 'var(--crit)']
    ];
    items.forEach(([k, v, c], i) => {
      if (i > 0) statBar.appendChild(h('div', { class: 'stat-div' }));
      statBar.appendChild(h('div', { class: 'stat-item' }, [
        h('span', { class: 'v num', style: { color: c }, text: String(v) }),
        h('span', { class: 'k', text: k })
      ]));
    });
    const cnt = tableCard.querySelector('#dev-count');
    if (cnt) cnt.textContent = `显示 ${filtered.length} / ${devices.length} 台`;
  }

  function renderTable() {
    tbl.setRows(filtered);
  }

  function refreshGroups() {
    const groups = [...new Set(devices.map((d) => d.group).filter(Boolean))].sort();
    const cur = groupSelect.value;
    groupSelect.innerHTML = '';
    groupSelect.appendChild(h('option', { value: '', text: '全部分组' }));
    groups.forEach((g) => groupSelect.appendChild(h('option', { value: g, text: g })));
    groupSelect.value = groups.includes(cur) ? cur : '';
  }

  /* ---------- 写操作 ---------- */
  async function toggleBlock(d, btn) {
    btn.classList.add('is-loading');
    try {
      const r = await api.setBlock(d.ip, !d.blocked);
      const applied = (r && r.applied) || [];
      toast(d.blocked ? `已恢复 ${d.ip} 联网` : `已断开 ${d.ip} 网络`, 'success', {
        title: d.blocked ? '恢复联网' : '断网操作完成',
        duration: 2600
      });
      if (applied.length) console.info('[applied]', applied);
      await reload();
    } catch (e) {
      toast(e.message || '操作失败', 'error');
      btn.classList.remove('is-loading');
    }
  }

  function openLimitModal(d) {
    const down = h('input', { class: 'input num', type: 'number', min: '0', step: '100', value: String(d.limitKbps?.down || 0) });
    const up = h('input', { class: 'input num', type: 'number', min: '0', step: '100', value: String(d.limitKbps?.up || 0) });
    const presets = h('div', { class: 'row-gap-2', style: { flexWrap: 'wrap' } });
    [[256, 128], [512, 256], [1024, 512], [2048, 512]].forEach(([dk, uk]) => {
      presets.appendChild(button(`${dk / 1024}M/${uk / 1024}M`, {
        size: 'sm', onClick: () => { down.value = dk; up.value = uk; }
      }));
    });
    const m = modal({
      title: `限速设置 · ${d.alias || d.hostname}`,
      width: 440,
      body: [
        h('div', { class: 'col gap-3' }, [
          h('div', { class: 'field' }, [
            h('label', { class: 'field-label' }, [h('span', { text: '下行限速 (Kbps)' })]),
            down
          ]),
          h('div', { class: 'field' }, [
            h('label', { class: 'field-label' }, [h('span', { text: '上行限速 (Kbps)' })]),
            up
          ]),
          h('div', { class: 'field' }, [
            h('label', { class: 'field-label' }, [h('span', { text: '常用预设' })]),
            presets
          ]),
          h('div', { class: 'fs-11 dim', text: '填写 0 表示取消该项限速。限速通过 tc 队列实现，最大粒度 100 Kbps。' })
        ])
      ],
      foot: [
        button('取消', { variant: 'ghost', onClick: () => m.close() }),
        button('应用限速', { variant: 'primary', onClick: async () => {
          const b = m.el.querySelector('.btn:last-child');
          b.classList.add('is-loading');
          try {
            const r = await api.setLimit(d.ip, Number(down.value) || 0, Number(up.value) || 0);
            toast('限速已生效', 'success');
            if (r && r.applied) console.info('[applied]', r.applied);
            m.close();
            await reload();
          } catch (e) {
            b.classList.remove('is-loading');
            toast(e.message || '限速失败', 'error');
          }
        } })
      ]
    });
  }

  /* ---------- 设备详情抽屉 ---------- */
  async function openDeviceDrawer(d) {
    if (drawerInst) { try { drawerInst.close(); } catch (_) {} }
    const bodyEl = h('div', { class: 'col gap-3' }, [skeleton(6)]);
    drawerInst = drawer({
      title: d.alias || d.hostname || d.ip,
      sub: `${d.vendor || '未知设备'} · ${d.ip} · ${d.mac}`,
      body: [bodyEl],
      foot: []
    });

    try {
      const info = await api.getDevice(d.ip);
      if (destroyed || !drawerInst) return;
      renderDrawerBody(bodyEl, info);
    } catch (e) {
      bodyEl.innerHTML = '';
      bodyEl.appendChild(errorBox(`设备详情加载失败：${e.message || e}`, () => openDeviceDrawer(d)));
    }
  }

  function renderDrawerBody(box, info) {
    const d = info.device || {};
    box.innerHTML = '';

    // 概要
    const ov = h('div', { class: 'bg-panel' });
    const kv = h('div', { class: 'kv-grid' });
    [
      ['状态', d.online ? '在线' : '离线'],
      ['厂商 / 型号', `${d.vendor || '—'}${d.deviceType ? ' · ' + d.deviceType : ''}`],
      ['分组', d.group || '未分组'],
      ['MAC', d.mac || '—'],
      ['首次出现', formatTime(d.firstSeen, true)],
      ['最后活跃', formatRelative(d.lastSeen)],
      ['连接数', formatNumber(d.conns || 0)],
      ['累计流量', `↓ ${formatBytes(d.totalDown)} · ↑ ${formatBytes(d.totalUp)}`]
    ].forEach(([k, v]) => {
      kv.appendChild(h('div', { class: 'kv' }, [
        h('span', { class: 'k', text: k }),
        h('span', { class: 'v', text: v })
      ]));
    });
    ov.appendChild(kv);
    box.appendChild(ov);

    // 实时速率
    const rateBox = h('div', { class: 'row-gap-3' }, [
      h('div', { class: 'stat-item' }, [
        h('span', { class: 'v num txt-brand', text: formatBps(d.downBps || 0) }),
        h('span', { class: 'k', text: '下行' })
      ]),
      h('div', { class: 'stat-item' }, [
        h('span', { class: 'v num', style: { color: 'var(--brand-2)' }, text: formatBps(d.upBps || 0) }),
        h('span', { class: 'k', text: '上行' })
      ]),
      h('div', { class: 'spacer', style: { flex: '1' } }),
      riskBadge(d.risk)
    ]);
    box.appendChild(rateBox);

    // 实时曲线
    const trendCanvas = h('canvas');
    const trendBox = h('div', { class: 'chart-box', style: { height: '120px' } }, [trendCanvas]);
    box.appendChild(card({
      title: '实时曲线', sub: '最近 2 分钟',
      bodyClass: 'tight',
      body: [trendBox]
    }));
    const labels = (info.trend || []).map((p) => {
      const dt = new Date(p.t * 1000);
      return `${String(dt.getHours()).padStart(2, '0')}:${String(dt.getMinutes()).padStart(2, '0')}:${String(dt.getSeconds()).padStart(2, '0')}`;
    });
    const chart = areaChart(trendCanvas, {
      labels,
      series: [
        { name: '下行', color: '#22d3ee', values: (info.trend || []).map((p) => p.down || 0) },
        { name: '上行', color: '#7c5cff', values: (info.trend || []).map((p) => p.up || 0) }
      ],
      unit: 'bps'
    });
    charts.push(chart);

    // Top 域名
    const domBox = h('div', { class: 'col gap-2' });
    const doms = (info.topDomains || []).slice(0, 5);
    if (!doms.length) domBox.appendChild(emptyState('暂无域名记录', ICONS.globe));
    doms.forEach((t) => {
      domBox.appendChild(h('div', { class: 'row-gap-2' }, [
        chip(t.label || t.domain, { sem: 'brand' }),
        h('span', { class: 'truncate fs-12 muted', style: { flex: '1' }, text: t.domain }),
        h('span', { class: 'fs-11 dim num', text: `${t.hits} 次` }),
        h('span', { class: 'fs-11 num txt-brand', text: formatBytes(t.bytes || 0) })
      ]));
    });
    box.appendChild(card({ title: 'Top 域名', sub: '按访问次数', bodyClass: 'tight', body: [domBox] }));

    // Top 目标
    const dstBox = h('div', { class: 'col gap-2' });
    const dsts = (info.topDsts || []).slice(0, 5);
    if (!dsts.length) dstBox.appendChild(emptyState('暂无目标地址', ICONS.globe));
    dsts.forEach((t) => {
      dstBox.appendChild(h('div', { class: 'row-gap-2' }, [
        h('span', { class: 'mono fs-12', style: { flex: '1' }, text: t.ip }),
        chip(t.country || '—', { plain: true }),
        h('span', { class: 'fs-11 num txt-brand', text: formatBytes(t.bytes || 0) })
      ]));
    });
    box.appendChild(card({ title: 'Top 目标', sub: '按流量', bodyClass: 'tight', body: [dstBox] }));

    // 连接列表
    const connBox = h('div', { class: 'col gap-2' });
    const conns = (info.conns || []).slice(0, 8);
    if (!conns.length) connBox.appendChild(emptyState('当前无活跃连接', ICONS.list));
    conns.forEach((c) => {
      connBox.appendChild(h('div', { class: 'row-gap-2 fs-12' }, [
        h('span', { class: 'mono dim', style: { width: '38px' }, text: c.proto }),
        h('span', { class: 'truncate', style: { flex: '1' }, text: c.domain || c.dstIp }),
        h('span', { class: 'fs-11 dim num', text: formatBytes(c.downBytes || 0) }),
        chip(c.state, { plain: true, sem: c.state === 'ESTABLISHED' ? 'ok' : 'mute' })
      ]));
    });
    box.appendChild(card({ title: '连接列表', sub: `${conns.length} 条`, bodyClass: 'tight', body: [connBox] }));

    // 快捷操作
    const aliasInput = h('input', { class: 'input', placeholder: '设置设备别名', value: d.alias || '' });
    const groupInput = h('input', { class: 'input', placeholder: '设置分组', value: d.group || '' });
    const ops = h('div', { class: 'col gap-3' }, [
      h('div', { class: 'row-gap-2' }, [
        aliasInput,
        button('保存别名', { size: 'sm', onClick: async () => {
          try {
            await api.setAlias(d.ip, aliasInput.value.trim());
            toast('别名已保存', 'success');
            await reload();
          } catch (e) { toast(e.message || '保存失败', 'error'); }
        } })
      ]),
      h('div', { class: 'row-gap-2' }, [
        groupInput,
        button('保存分组', { size: 'sm', onClick: async () => {
          try {
            await api.setGroup(d.ip, groupInput.value.trim());
            toast('分组已保存', 'success');
            await reload();
          } catch (e) { toast(e.message || '保存失败', 'error'); }
        } })
      ]),
      h('div', { class: 'row-gap-2', style: { flexWrap: 'wrap' } }, [
        button(d.blocked ? '恢复联网' : '断网', {
          variant: d.blocked ? 'primary' : 'danger', icon: d.blocked ? ICONS.undo : ICONS.ban,
          onClick: async (e) => {
            const b = e.currentTarget;
            b.classList.add('is-loading');
            try {
              await api.setBlock(d.ip, !d.blocked);
              toast(d.blocked ? '已恢复联网' : '已断网', 'success');
              await reload();
              if (drawerInst) openDeviceDrawer({ ...d, blocked: !d.blocked });
            } catch (err) { b.classList.remove('is-loading'); toast(err.message || '操作失败', 'error'); }
          }
        }),
        button('限速', { variant: 'ghost', icon: ICONS.gauge, onClick: () => openLimitModal(d) }),
        button('移除设备', { variant: 'ghost', icon: ICONS.trash, onClick: () => {
          ctx.confirm({
            title: '移除设备', danger: true, confirmText: '移除',
            message: `将 ${d.alias || d.hostname || d.ip} 从设备列表移除（历史数据保留）。确认继续？`,
            onConfirm: async () => {
              await api.forget(d.ip);
              toast('设备已移除', 'success');
              await reload();
              if (drawerInst) drawerInst.close();
            }
          });
        } })
      ])
    ]);
    box.appendChild(card({ title: '快捷操作', bodyClass: 'tight', body: [ops] }));
  }

  /* ---------- 数据加载 ---------- */
  async function reload() {
    try {
      const list = await api.getDevices();
      if (destroyed) return;
      devices = list || [];
      refreshGroups();
      applyFilter();
    } catch (e) {
      console.error('[devices]', e);
      toast(e.message || '设备列表加载失败', 'error');
    }
  }

  /* ---------- 未启用 / 未采集时的降级展示（api.md §7.3） ---------- */
  function applyDisabledState() {
    const sysOff = !isEnabled();
    const noCollect = sysOff || !isFeatureOn('collect');
    const card = tableCard;
    let panel = card.querySelector('.disabled-panel');

    if (!noCollect) {
      if (panel) panel.remove();
      toolbar.classList.remove('hidden');
      return;
    }
    if (!panel) {
      panel = h('div', { class: 'disabled-panel' });
      card.querySelector('.card-body').appendChild(panel);
    }
    panel.innerHTML = '';
    panel.appendChild(disabledState({
      icon: ICONS.device,
      title: sysOff ? '系统未启用' : '流量采集未开启',
      desc: sysOff
        ? '系统未启用，当前仅显示配置状态，不采集、不管控、不影响路由器现有功能。'
        : '「流量采集」开关未开启，未读取 conntrack / DNS 日志 / DHCP 租约，因此没有设备数据。',
      hint: sysOff ? '前往「设置 → 系统开关」开启总开关' : '前往「设置 → 系统开关」开启「流量采集」',
      action: button('前往设置', {
        variant: 'primary', size: 'sm',
        onClick: () => { location.hash = '#/settings'; }
      })
    }));
    toolbar.classList.toggle('hidden', sysOff);
  }

  tbl.setLoading(true);
  try { await refreshSettings(); } catch (e) { console.warn('[devices settings]', e.message); }
  await reload();
  tbl.setLoading(false);
  applyDisabledState();

  const unsubSettings = subscribeSettings(() => {
    if (destroyed) return;
    applyDisabledState();
    reload();
  });
  cleanups.push(unsubSettings);

  /* ---------- SSE 增量更新 ---------- */
  // 后端约定（backend-dev / web3d-dev，已对齐）：
  //   full=false → 按 ip 合并；removed[] 中的 ip 为已从可见集合移除的设备
  //   full 缺省或 true → 整体替换本地设备列表（向后兼容旧契约：devices 语义为全量）
  const onTick = (ev) => {
    const t = ev.detail;
    if (destroyed || !t || !t.devices) return;
    if (t.full !== false) {
      // 全量帧：整体替换
      const map = new Map(t.devices.map((d) => [d.ip, d]));
      devices = devices.filter((d) => map.has(d.ip)).map((d) => ({ ...d, ...map.get(d.ip) }));
      // 新增本地没有的设备
      t.devices.forEach((n) => {
        if (!devices.find((d) => d.ip === n.ip)) devices.push({ ...n });
      });
      refreshGroups();
      applyFilter();
      return;
    }
    // 增量帧：按 ip 合并
    const map = new Map(t.devices.map((d) => [d.ip, d]));
    // removed：设备被 forget / 隐藏 → 本地立即删除
    if (Array.isArray(t.removed) && t.removed.length) {
      const rm = new Set(t.removed);
      const before = devices.length;
      devices = devices.filter((d) => !rm.has(d.ip));
      if (devices.length !== before) { refreshGroups(); applyFilter(); return; }
    }
    let changed = false;
    devices.forEach((d) => {
      const n = map.get(d.ip);
      if (!n) return;
      if (d.downBps !== n.downBps || d.upBps !== n.upBps || d.online !== n.online || d.risk !== n.risk || d.blocked !== n.blocked) changed = true;
      d.downBps = n.downBps; d.upBps = n.upBps;
      d.online = n.online; d.risk = n.risk; d.blocked = n.blocked;
      d.conns = n.conns ?? d.conns;
      d.alias = n.alias ?? d.alias;
      d.topCat = n.topCat ?? d.topCat;
    });
    if (changed) { renderTable(); renderStats(); }
  };

  document.addEventListener('gl:tick', onTick);
  cleanups.push(() => document.removeEventListener('gl:tick', onTick));

  unsub = api.subscribe((type, payload) => {
    if (destroyed) return;
    if (type === 'tick') onTick({ detail: payload });
  });
  cleanups.push(() => unsub && unsub());

  return {
    unmount() {
      destroyed = true;
      cleanups.forEach((fn) => { try { fn(); } catch (_) {} });
      charts.forEach((c) => { try { c.dispose?.(); } catch (_) {} });
      if (drawerInst) { try { drawerInst.close(); } catch (_) {} }
    }
  };
}
