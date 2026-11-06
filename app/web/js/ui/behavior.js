/* ==========================================================================
   观澜 NetScope · 行为管控页（#/behavior）
   依据 docs/design.md §7.4：
   - 上方快捷区：「一键断网」设备芯片墙 + 「全部恢复」
   - 左：策略列表（开关、命中的设备数、时间窗摘要）
   - 右：策略编辑器（名称、目标设备多选、生效日/时段、动作、分类多选、域名列表、限速）
   - 底部：DNS 拦截域名列表与还原按钮
   ========================================================================== */

import {
  h, card, chip, button, switchControl, table, svgIcon, ICONS,
  skeleton, emptyState, errorBox, toast, confirmDialog, deviceIcon, disabledState
} from './components.js';
import { formatNumber, formatTime, CATEGORY_COLOR, CATEGORY_LABEL, CATEGORY_ORDER } from './format.js';
import { refreshSettings, isEnabled, isFeatureOn, subscribeSettings, getSettingsCache } from '../api.js';

const DAYS = ['一', '二', '三', '四', '五', '六', '日'];

// 定时策略时区的兜底值（与后端 store.go 的 Settings.Timezone 默认值一致）：
// OpenWrt 系统时区通常是 UTC，后端统一换算到该时区后再判断生效时段，
// 所以编辑器的「生效日 / 时段」不能按 UTC 理解。实际值优先取 /api/settings 的
// timezone 字段（默认 Asia/Shanghai）；GUANLAN_TZ 环境变量覆盖未通过 API 暴露。
const DEFAULT_SCHEDULE_TZ = 'Asia/Shanghai';
const ACTIONS = [
  { key: 'block', label: '禁止（断网/拦截分类）', sem: 'crit' },
  { key: 'limit', label: '限速', sem: 'warn' },
  { key: 'allow', label: '白名单放行', sem: 'ok' }
];

export async function mount(host, ctx) {
  const { api } = ctx;
  const cleanups = [];
  let policies = [];
  let devices = [];
  let enforce = null;
  let dnsDomains = [];
  let selectedId = null;
  let editing = null;
  let destroyed = false;
  let tzHintEl = null;   // 生效时段旁的「时区」提示，设置变化时就地更新

  // 当前生效的定时策略时区：优先取服务端 settings.timezone（与后端 scheduleLocation 同源），
  // 老版本后端/字段缺失时回退默认值。
  function scheduleTzName() {
    const s = getSettingsCache();
    const tz = s && typeof s.timezone === 'string' ? s.timezone.trim() : '';
    return tz || DEFAULT_SCHEDULE_TZ;
  }
  function refreshTzHint() {
    if (tzHintEl) tzHintEl.textContent = `时区：${scheduleTzName()}`;
  }

  /* 紧凑空态（减少占屏，替代大图标空态） */
  function hintLine(text, icon = ICONS.list) {
    return h('div', { class: 'tq-hint dim fs-12' }, [svgIcon(icon, 14), h('span', { text })]);
  }

  /* ---------- 顶部快捷区 ---------- */
  const chipWall = h('div', { class: 'chip-wall' });
  const restoreAllBtn = button('全部恢复', { variant: 'ghost', icon: ICONS.undo, onClick: onRestoreAll });
  const quickCard = card({
    title: '一键断网',
    sub: '点击设备芯片可立即断网 / 恢复',
    actions: [restoreAllBtn],
    body: [chipWall]
  });

  /* ---------- 策略列表 ---------- */
  const policyList = h('div', { class: 'policy-list' });
  const policyCard = card({
    title: '策略列表',
    sub: '',
    actions: [button('新建策略', { size: 'sm', variant: 'primary', icon: ICONS.plus, onClick: () => startCreate() })],
    body: [policyList],
    style: { height: '100%' }
  });

  /* ---------- 策略编辑器 ---------- */
  const editorHost = h('div', { class: 'col gap-3' });
  const editorCard = card({
    title: '策略编辑器',
    sub: '',
    actions: [h('span', { class: 'card-sub', id: 'pol-mode', text: '未选择' })],
    body: [editorHost],
    style: { height: '100%' }
  });

  /* ---------- DNS 拦截 ---------- */
  const dnsBody = h('div', { class: 'col gap-2' });
  const dnsRestoreBtn = button('还原全部拦截', { variant: 'danger', size: 'sm', icon: ICONS.undo, onClick: onRestoreDns });
  // 手工封禁入口：可直接粘贴完整 URL（取其域名生效；HTTPS 路径加密不可见）
  const dnsInput = h('input', {
    class: 'input', type: 'text',
    placeholder: '粘贴要封禁的 URL 或域名，如 http://evil.com/path',
    style: { flex: '1', minWidth: '0' }
  });
  const dnsAddBtn = button('封禁', { variant: 'primary', size: 'sm', icon: ICONS.ban, onClick: onAddDomain });
  dnsInput.addEventListener('keydown', (e) => { if (e.key === 'Enter') onAddDomain(); });
  const dnsForm = h('div', { class: 'row-gap-2', style: { paddingBottom: '2px' } }, [dnsInput, dnsAddBtn]);
  const dnsCard = card({
    title: 'DNS 拦截域名',
    sub: '手工封禁可直接贴 URL，按域名生效',
    actions: [dnsRestoreBtn],
    body: [dnsForm, dnsBody],
    style: { height: '100%' }
  });

  const enforceRow = h('div', { class: 'row-gap-3', style: { flexWrap: 'wrap' } });
  const enforceCard = card({
    title: '管控执行状态',
    sub: 'iptables / tc / dnsmasq',
    body: [enforceRow],
    style: { height: '100%' }
  });

  host.appendChild(quickCard);
  host.appendChild(h('div', { class: 'grid' }, [
    h('div', { class: 'g4' }, [policyCard]),
    h('div', { class: 'g8' }, [editorCard])
  ]));
  host.appendChild(h('div', { class: 'grid' }, [
    h('div', { class: 'g8' }, [dnsCard]),
    h('div', { class: 'g4' }, [enforceCard])
  ]));

  /* ---------- 渲染：设备芯片墙 ---------- */
  function renderChipWall() {
    chipWall.innerHTML = '';
    if (!devices.length) {
      chipWall.appendChild(hintLine('暂无设备', ICONS.device));
      return;
    }
    devices.forEach((d) => {
      const cls = d.blocked ? 'dev-chip blocked' : (d.limitKbps && (d.limitKbps.down || d.limitKbps.up)) ? 'dev-chip limited' : 'dev-chip';
      const el = h('div', { class: cls, title: `${d.ip} · ${d.vendor || ''}` }, [
        deviceIcon(d, 15),
        h('span', { text: d.alias || d.hostname || d.ip })
      ]);
      el.addEventListener('click', () => toggleBlock(d, el));
      chipWall.appendChild(el);
    });
  }

  /* ---------- 渲染：策略列表 ---------- */
  function renderPolicyList() {
    policyList.innerHTML = '';
    if (!policies.length) {
      policyList.appendChild(hintLine('暂无策略，点击右上角「新建策略」创建第一条规则', ICONS.list));
      return;
    }
    policies.forEach((p) => {
      const hitDevs = devices.filter((d) => matchesPolicy(p, d)).length;
      const days = (p.schedule?.days || []).length;
      const timeWin = days === 0 ? '全天' : `${days} 天 · ${p.schedule?.start || '00:00'}–${p.schedule?.end || '23:59'}`;
      const act = ACTIONS.find((a) => a.key === p.action) || ACTIONS[0];
      const item = h('div', { class: `policy-item ${p.id === selectedId ? 'active' : ''} ${p.enabled ? '' : 'off'}` }, [
        h('div', { class: 'row-gap-2' }, [
          h('div', { style: { flex: '1', minWidth: '0' } }, [
            h('div', { class: 'policy-name truncate', text: p.name }),
            h('div', { class: 'policy-meta' }, [
              chip(act.label, { sem: act.sem }),
              h('span', { text: `命中 ${hitDevs} 台` }),
              h('span', { text: timeWin }),
              h('span', { text: `命中 ${formatNumber(p.hits || 0)} 次` })
            ])
          ]),
          switchControl({
            checked: !!p.enabled,
            onChange: async (v) => {
              try {
                await api.togglePolicy(p.id, v);
                p.enabled = v;
                toast(v ? `策略「${p.name}」已启用` : `策略「${p.name}」已停用`, 'success');
                renderPolicyList();
                await loadEnforce();
              } catch (e) { toast(e.message || '操作失败', 'error'); }
            }
          }),
          h('button', { class: 'op-btn danger', type: 'button', title: '删除策略' }, [svgIcon(ICONS.trash, 12)])
        ])
      ]);
      item.querySelector('.op-btn').addEventListener('click', async (ev) => {
        ev.stopPropagation();
        confirmDialog({
          title: '删除策略', danger: true, confirmText: '删除',
          message: `确认删除策略「${p.name}」？该操作不可撤销。`,
          onConfirm: async () => {
            try {
              await api.deletePolicy(p.id);
              toast('策略已删除', 'success');
              if (selectedId === p.id) { selectedId = null; editing = null; renderEditor(); }
              await reloadPolicies();
              await loadEnforce();
            } catch (e) { throw e; }
          }
        });
      });
      item.addEventListener('click', () => { selectedId = p.id; editing = null; renderPolicyList(); renderEditor(); });
      policyList.appendChild(item);
    });
  }

  function matchesPolicy(p, d) {
    const t = p.targets || {};
    if (t.all) return true;
    if ((t.ips || []).includes(d.ip)) return true;
    if ((t.groups || []).length && (t.groups || []).includes(d.group)) return true;
    return false;
  }

  /* ---------- 渲染：策略编辑器 ---------- */
  function renderEditor() {
    editorHost.innerHTML = '';
    tzHintEl = null;
    const modeEl = document.getElementById('pol-mode');
    const p = editing || policies.find((x) => x.id === selectedId);
    if (!p) {
      if (modeEl) modeEl.textContent = '未选择';
      editorHost.appendChild(hintLine('选择左侧策略进行编辑，或点击「新建策略」创建一条规则', ICONS.edit));
      return;
    }
    if (modeEl) modeEl.textContent = editing ? '新建中' : `编辑 · ${p.id}`;

    const draft = editing || JSON.parse(JSON.stringify(p));

    const nameInput = h('input', { class: 'input', value: draft.name || '', placeholder: '策略名称，如：22 点后禁止刷短视频' });

    // 目标设备
    const targetAll = switchControl({
      checked: !!draft.targets?.all,
      label: '全部设备',
      onChange: (v) => { draft.targets.all = v; }
    });
    const ipChips = h('div', { class: 'chip-wall' });
    devices.forEach((d) => {
      const on = (draft.targets?.ips || []).includes(d.ip);
      const c = h('span', { class: `chip chip-pick ${on ? 'on' : ''}`, style: { '--sem': 'var(--brand)' } }, [
        h('span', { text: d.alias || d.hostname || d.ip })
      ]);
      c.addEventListener('click', () => {
        const arr = draft.targets.ips || (draft.targets.ips = []);
        const i = arr.indexOf(d.ip);
        if (i >= 0) arr.splice(i, 1); else arr.push(d.ip);
        c.classList.toggle('on');
      });
      ipChips.appendChild(c);
    });

    const groupChips = h('div', { class: 'chip-wall' });
    const groups = [...new Set(devices.map((d) => d.group).filter(Boolean))];
    groups.forEach((g) => {
      const on = (draft.targets?.groups || []).includes(g);
      const c = h('span', { class: `chip chip-pick ${on ? 'on' : ''}`, style: { '--sem': 'var(--brand-2)' } }, [
        h('span', { text: g })
      ]);
      c.addEventListener('click', () => {
        const arr = draft.targets.groups || (draft.targets.groups = []);
        const i = arr.indexOf(g);
        if (i >= 0) arr.splice(i, 1); else arr.push(g);
        c.classList.toggle('on');
      });
      groupChips.appendChild(c);
    });

    // 生效星期
    const dayPicker = h('div', { class: 'day-picker' });
    const dayState = (draft.schedule?.days || []).slice();
    DAYS.forEach((d, i) => {
      const day = i + 1;
      const b = h('button', { type: 'button', text: d });
      if (dayState.includes(day)) b.classList.add('on');
      b.addEventListener('click', () => {
        const i2 = dayState.indexOf(day);
        if (i2 >= 0) dayState.splice(i2, 1); else dayState.push(day);
        b.classList.toggle('on');
      });
      dayPicker.appendChild(b);
    });
    const allDayBtn = button('全天', {
      size: 'sm', onClick: () => { dayState.length = 0; dayPicker.querySelectorAll('button').forEach((x) => x.classList.remove('on')); }
    });

    const startInput = h('input', { class: 'input num', type: 'time', value: draft.schedule?.start || '00:00' });
    const endInput = h('input', { class: 'input num', type: 'time', value: draft.schedule?.end || '23:59' });

    // 动作
    const actionSeg = h('div', { class: 'segment' });
    let action = draft.action || 'block';
    ACTIONS.forEach((a) => {
      const b = h('button', { type: 'button', text: a.label });
      if (a.key === action) b.classList.add('active');
      b.addEventListener('click', () => {
        action = a.key;
        actionSeg.querySelectorAll('button').forEach((x) => x.classList.remove('active'));
        b.classList.add('active');
        limitField.classList.toggle('hidden', action !== 'limit');
      });
      actionSeg.appendChild(b);
    });

    // 分类
    const catChips = h('div', { class: 'chip-wall' });
    const catState = (draft.categories || []).slice();
    CATEGORY_ORDER.forEach((k) => {
      const on = catState.includes(k);
      const c = h('span', { class: `chip chip-pick ${on ? 'on' : ''}`, style: { '--sem': CATEGORY_COLOR[k] } }, [
        h('span', { text: CATEGORY_LABEL[k] })
      ]);
      c.addEventListener('click', () => {
        const i = catState.indexOf(k);
        if (i >= 0) catState.splice(i, 1); else catState.push(k);
        c.classList.toggle('on');
      });
      catChips.appendChild(c);
    });

    // 域名
    const domainInput = h('textarea', { class: 'textarea', placeholder: '每行一个域名，如 douyin.com' });
    domainInput.value = (draft.domains || []).join('\n');

    // 限速
    const downInput = h('input', { class: 'input num', type: 'number', min: '0', step: '100', value: String(draft.limitKbps?.down || 0) });
    const upInput = h('input', { class: 'input num', type: 'number', min: '0', step: '100', value: String(draft.limitKbps?.up || 0) });
    const limitField = h('div', { class: 'row-gap-3' }, [
      h('div', { class: 'field', style: { flex: '1' } }, [
        h('label', { class: 'field-label' }, [h('span', { text: '下行 (Kbps)' })]), downInput
      ]),
      h('div', { class: 'field', style: { flex: '1' } }, [
        h('label', { class: 'field-label' }, [h('span', { text: '上行 (Kbps)' })]), upInput
      ])
    ]);
    if (action !== 'limit') limitField.classList.add('hidden');

    const saveBtn = button(editing ? '创建策略' : '保存修改', { variant: 'primary', icon: ICONS.check });
    saveBtn.addEventListener('click', async () => {
      const payload = {
        name: nameInput.value.trim() || '未命名策略',
        enabled: draft.enabled !== false,
        targets: { ips: draft.targets?.ips || [], groups: draft.targets?.groups || [], all: !!draft.targets?.all },
        schedule: { days: dayState.slice(), start: startInput.value || '00:00', end: endInput.value || '23:59' },
        action,
        categories: catState.slice(),
        domains: domainInput.value.split('\n').map((s) => s.trim()).filter(Boolean),
        limitKbps: { down: Number(downInput.value) || 0, up: Number(upInput.value) || 0 }
      };
      saveBtn.classList.add('is-loading');
      try {
        if (editing) {
          await api.createPolicy(payload);
          toast('策略已创建', 'success');
        } else {
          await api.updatePolicy(draft.id, payload);
          toast('策略已保存', 'success');
        }
        editing = null;
        selectedId = null;
        await reloadPolicies();
        await loadEnforce();
        renderEditor();
      } catch (e) {
        toast(e.message || '保存失败', 'error');
      } finally {
        saveBtn.classList.remove('is-loading');
      }
    });

    const cancelBtn = button('取消', { variant: 'ghost', onClick: () => { editing = null; renderEditor(); } });
    const deleteBtn = editing ? null : button('删除', {
      variant: 'danger', icon: ICONS.trash,
      onClick: () => confirmDialog({
        title: '删除策略', danger: true, confirmText: '删除',
        message: `确认删除策略「${p.name}」？`,
        onConfirm: async () => {
          await api.deletePolicy(p.id);
          toast('策略已删除', 'success');
          selectedId = null;
          await reloadPolicies();
          await loadEnforce();
          renderEditor();
        }
      })
    });

    const tzHint = h('span', {
      class: 'fs-11 dim',
      text: `时区：${scheduleTzName()}`,
      title: '定时策略按该时区解释「生效日 / 时段」，与路由器系统时区（常见为 UTC）无关；'
        + '服务端若用 GUANLAN_TZ 环境变量覆盖，以服务端配置为准'
    });
    tzHintEl = tzHint;

    editorHost.appendChild(h('div', { class: 'grid', style: { gap: '14px' } }, [
      h('div', { class: 'g6' }, [
        h('div', { class: 'field' }, [
          h('label', { class: 'field-label' }, [h('span', { text: '策略名称' })]), nameInput
        ])
      ]),
      h('div', { class: 'g6' }, [
        h('div', { class: 'field' }, [
          h('label', { class: 'field-label' }, [
            h('span', { text: '生效时段' }),
            tzHint
          ]),
          h('div', { class: 'row-gap-2', style: { flexWrap: 'wrap' } }, [dayPicker, allDayBtn, startInput, h('span', { class: 'dim', text: '至' }), endInput])
        ])
      ]),
      h('div', { class: 'g12' }, [
        h('div', { class: 'field' }, [
          h('label', { class: 'field-label' }, [h('span', { text: '目标设备' }), targetAll]),
          ipChips,
          h('div', { class: 'fs-11 dim', text: '按分组：' }),
          groupChips
        ])
      ]),
      h('div', { class: 'g12' }, [
        h('div', { class: 'field' }, [
          h('label', { class: 'field-label' }, [h('span', { text: '执行动作' })]),
          actionSeg,
          limitField
        ])
      ]),
      h('div', { class: 'g6' }, [
        h('div', { class: 'field' }, [
          h('label', { class: 'field-label' }, [h('span', { text: '命中分类（留空 = 整机断网）' })]),
          catChips
        ])
      ]),
      h('div', { class: 'g6' }, [
        h('div', { class: 'field' }, [
          h('label', { class: 'field-label' }, [h('span', { text: '命中域名（每行一个）' })]),
          domainInput
        ])
      ]),
      h('div', { class: 'g12' }, [
        h('div', { class: 'row-gap-2' }, [
          saveBtn,
          editing ? cancelBtn : null,
          deleteBtn
        ])
      ])
    ]));
  }

  function startCreate() {
    editing = {
      name: '', enabled: true,
      targets: { ips: [], groups: [], all: false },
      schedule: { days: [], start: '00:00', end: '23:59' },
      action: 'block', categories: [], domains: [], limitKbps: { down: 0, up: 0 }
    };
    selectedId = null;
    renderPolicyList();
    renderEditor();
  }

  /* ---------- DNS 拦截列表 ---------- */
  // 契约（docs/api.md §5）：
  //   GET /api/enforce/status → dnsBlockedDomains（计数）+ dnsTap（旁挂状态）
  //   GET /api/enforce/dns    → {domains: string[]}（明细，字典序升序）
  // 卡片形态 = 头部计数摘要 + 明细列表（design.md §7.4 要求的是「列表」）
  function renderDns() {
    dnsBody.innerHTML = '';
    const count = (enforce && enforce.dnsBlockedDomains) || 0;
    const tap = enforce ? enforce.dnsTap !== false : true;

    // 头部摘要
    dnsBody.appendChild(h('div', { class: 'row-gap-3', style: { flexWrap: 'wrap', paddingBottom: '4px' } }, [
      h('div', { class: 'stat-item' }, [
        h('span', { class: 'v num', style: { color: count ? 'var(--crit)' : 'var(--text-2)' }, text: String(count) }),
        h('span', { class: 'k', text: '已封堵域名' })
      ]),
      h('div', { class: 'stat-div' }),
      h('div', { class: 'stat-item' }, [
        h('span', { class: 'v', style: { color: tap ? 'var(--ok)' : 'var(--text-2)' }, text: tap ? '已开启' : '已关闭' }),
        h('span', { class: 'k', text: 'DNS 旁挂' })
      ])
    ]));

    // 明细列表
    const domains = dnsDomains || [];
    if (!domains.length) {
      dnsBody.appendChild(hintLine('暂无封禁域名 —— 上方输入 URL/域名即可封禁恶意站点', ICONS.shield));
      return;
    }
    const list = h('div', { class: 'col gap-2' });
    domains.forEach((d) => {
      list.appendChild(h('div', { class: 'row-gap-2 fs-12 dns-row' }, [
        chip('DNS', { sem: 'warn' }),
        h('span', { class: 'truncate mono', style: { flex: '1', minWidth: '0' }, text: d }),
        button('解封', { variant: 'ghost', size: 'sm', onClick: () => onRemoveDomain(d) })
      ]));
    });
    dnsBody.appendChild(list);
  }

  /* 手工封禁 / 解封域名（POST /api/enforce/domains） */
  async function onAddDomain() {
    const v = (dnsInput.value || '').trim();
    if (!v) { toast('请输入要封禁的 URL 或域名', 'warn'); return; }
    dnsAddBtn.disabled = true;
    try {
      const r = await api.addDomainBlock(v);
      dnsInput.value = '';
      if (r && r.effective === false) {
        toast(`已保存 ${r.domain}；「域名封堵」开关未开启，开启后自动生效`, 'warn');
      } else {
        toast(`已封禁 ${r && r.domain ? r.domain : v}`, 'success');
      }
      await loadEnforce();
    } catch (e) {
      toast(e.message || '封禁失败', 'error');
    } finally {
      dnsAddBtn.disabled = false;
    }
  }

  async function onRemoveDomain(d) {
    try {
      await api.removeDomainBlock(d);
      toast(`已解封 ${d}`, 'success');
      await loadEnforce();
    } catch (e) {
      toast(e.message || '解封失败', 'error');
    }
  }

  /* ---------- 执行状态 ---------- */
  function renderEnforce() {
    enforceRow.innerHTML = '';
    if (!enforce) return;
    const items = [
      ['iptables 规则', enforce.iptablesRules || 0, 'var(--brand)'],
      ['tc 限速设备', enforce.tcDevices || 0, 'var(--warn)'],
      ['DNS 拦截域名', enforce.dnsBlockedDomains || 0, 'var(--crit)'],
      ['生效策略', enforce.activePolicies || 0, 'var(--ok)'],
      ['DNS 旁挂', enforce.dnsTap ? '开启' : '关闭', enforce.dnsTap ? 'var(--ok)' : 'var(--text-2)']
    ];
    items.forEach(([k, v, c], i) => {
      if (i > 0) enforceRow.appendChild(h('div', { class: 'stat-div' }));
      enforceRow.appendChild(h('div', { class: 'stat-item' }, [
        h('span', { class: 'v num', style: { color: c }, text: String(v) }),
        h('span', { class: 'k', text: k })
      ]));
    });
  }

  /* ---------- 操作 ---------- */
  async function toggleBlock(d, el) {
    el.style.opacity = '.5';
    try {
      await api.setBlock(d.ip, !d.blocked);
      toast(d.blocked ? `已恢复 ${d.alias || d.ip}` : `已断开 ${d.alias || d.ip}`, 'success');
      await reloadDevices();
      await loadEnforce();
    } catch (e) {
      toast(e.message || '操作失败', 'error');
      el.style.opacity = '';
    }
  }

  async function onRestoreAll() {
    confirmDialog({
      title: '全部恢复', danger: true, confirmText: '全部恢复',
      message: '将清除所有断网规则与限速配置，并还原全部 DNS 拦截。确认继续？',
      onConfirm: async () => {
        try {
          const r = await api.enforceReset();
          toast(`已清除 ${(r && r.removed ? r.removed.length : 0)} 项管控规则`, 'success');
          await reloadDevices();
          await loadEnforce();
        } catch (e) { throw e; }
      }
    });
  }

  async function onRestoreDns() {
    confirmDialog({
      title: '还原 DNS 拦截', danger: true, confirmText: '还原',
      message: '注意：/api/enforce/reset 会清空全部管控（断网 / 限速 / 目标封禁 / DNS 拦截），'
        + '并停用全部策略。确认继续？',
      onConfirm: async () => {
        try {
          const r = await api.enforceReset();
          toast(`已清空全部管控（${(r && r.removed ? r.removed.length : 0)} 项）并停用全部策略`, 'success');
          // 管控被全局清空：设备断网/限速状态与策略启用状态都会变化，必须一并刷新
          await reloadDevices();
          await reloadPolicies();
          await loadEnforce();
        } catch (e) { throw e; }
      }
    });
  }

  /* ---------- 加载 ---------- */
  async function reloadDevices() {
    try {
      const list = await api.getDevices();
      if (destroyed) return;
      devices = list || [];
      renderChipWall();
      renderPolicyList();
    } catch (e) { console.error('[behavior devices]', e); }
  }

  async function reloadPolicies() {
    try {
      const list = await api.getPolicies();
      if (destroyed) return;
      policies = list || [];
      renderPolicyList();
      if (selectedId && !policies.find((p) => p.id === selectedId)) { selectedId = null; renderEditor(); }
    } catch (e) { console.error('[behavior policies]', e); }
  }

  async function loadEnforce() {
    try {
      const s = await api.getEnforceStatus();
      if (destroyed) return;
      enforce = s;
      renderEnforce();
    } catch (e) { console.warn('[behavior enforce]', e.message); }
    // DNS 明细（docs/api.md §5 GET /api/enforce/dns，只读）
    try {
      const list = await api.getDnsBlocked();
      if (destroyed) return;
      dnsDomains = Array.isArray(list) ? list : [];
    } catch (e) {
      console.warn('[behavior dns]', e.message);
      dnsDomains = [];
    }
    renderDns();
  }

  try { await refreshSettings(); } catch (e) { console.warn('[behavior settings]', e.message); }
  await reloadDevices();
  await reloadPolicies();
  await loadEnforce();
  renderEditor();

  /* ---------- 未启用 / 未管控时的降级展示（api.md §7.3） ---------- */
  function applyDisabledState() {
    const sysOff = !isEnabled();
    const noControl = sysOff || !isFeatureOn('deviceControl');
    let panel = host.querySelector('.disabled-panel');
    if (!noControl) {
      if (panel) panel.remove();
      quickCard.classList.remove('hidden');
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
      title: sysOff ? '系统未启用' : '设备管控未开启',
      desc: sysOff
        ? '系统未启用，当前仅显示配置状态，不采集、不管控、不影响路由器现有功能。'
        : '「设备管控」开关未开启，策略只记录不执行；断网 / 限速操作不会下发任何规则。',
      hint: sysOff ? '前往「设置 → 系统开关」开启总开关' : '前往「设置 → 系统开关」开启「设备管控」',
      action: button('前往设置', { variant: 'primary', size: 'sm', onClick: () => { location.hash = '#/settings'; } })
    })]));
    quickCard.classList.add('hidden');
    host.querySelector('.grid')?.classList.add('hidden');
  }

  applyDisabledState();
  const unsubSettings = subscribeSettings(() => {
    if (destroyed) return;
    applyDisabledState();
    refreshTzHint();   // 时区等设置变化时就地更新提示（不必重建编辑器）
    reloadDevices();
    reloadPolicies();
  });
  cleanups.push(unsubSettings);

  /* ---------- SSE 增量 ---------- */
  // app.js 已把 /api/stream 的 tick 以 CustomEvent 派发到 document，
  // 本页只监听 document 事件，避免重复订阅同一流。
  const onTick = (ev) => {
    const t = ev.detail;
    if (destroyed || !t || !t.devices) return;
    const map = new Map(t.devices.map((d) => [d.ip, d]));
    let changed = false;
    devices.forEach((d) => {
      const n = map.get(d.ip);
      if (!n) return;
      if (d.blocked !== n.blocked) changed = true;
      d.blocked = n.blocked;
    });
    if (changed) { renderChipWall(); renderPolicyList(); }
  };
  document.addEventListener('gl:tick', onTick);
  cleanups.push(() => document.removeEventListener('gl:tick', onTick));

  return {
    unmount() {
      destroyed = true;
      cleanups.forEach((fn) => { try { fn(); } catch (_) {} });
    }
  };
}
