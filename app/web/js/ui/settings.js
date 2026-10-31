/* ==========================================================================
   观澜 NetScope · 设置页（#/settings）
   依据 docs/design.md §7.6 + docs/api.md §7.1–§7.3：
   系统开关（总开关 + 7 个功能开关）、采集与留存、DNS 旁挂风险提示、
   告警阈值、修改密码、系统信息、卸载与回滚指引
   ========================================================================== */

import {
  h, card, chip, button, switchControl, svgIcon, ICONS,
  skeleton, errorBox, toast, kvList, confirmDialog
} from './components.js';
import { formatDuration, formatNumber, formatTime } from './format.js';
import {
  SWITCH_DEFS, REVOKE_SWITCHES, subscribeSettings, refreshSettings, setSwitch
} from '../api.js';

export async function mount(host, ctx) {
  const { api } = ctx;
  const cleanups = [];
  let settings = null;
  let system = null;
  let destroyed = false;

  /* ---------- 系统开关（总开关 + 功能开关） ---------- */
  // 注意：以下变量必须先声明再引用，避免同作用域 TDZ
  const masterStateBadge = h('span', { class: 'chip s-mute plain', text: '未启用' });
  const masterHint = h('div', { class: 'master-hint hidden' }, [
    svgIcon(ICONS.info, 13),
    h('span', { class: 'master-hint-text', text: '' })
  ]);
  const pendingLabel = h('span', { class: 'chip s-warn plain hidden', text: '' });
  let dnsSwitch = null;
  let dnsWarn = null;
  let dnsDesc = null;

  const masterSwitch = switchControl({
    checked: false,
    onChange: (v) => onSwitchChange('enabled', v, masterSwitch)
  });
  const masterRow = h('div', { class: 'master-switch' }, [
    h('div', { class: 'master-switch-ico' }, [svgIcon(ICONS.power, 20)]),
    h('div', { class: 'master-switch-main' }, [
      h('div', { class: 'master-switch-title' }, [
        h('span', { text: '启用系统' }),
        masterStateBadge,
        pendingLabel
      ]),
      h('div', { class: 'master-switch-desc', text: '关闭后系统不采集、不管控，不影响路由器任何现有功能。' }),
      h('div', { class: 'master-switch-desc dim', text: '启用系统后还需开启相应功能开关，各功能才会实际生效。' })
    ]),
    masterSwitch
  ]);

  const featureList = h('div', { class: 'switch-list' });
  const featureSwitches = new Map();
  SWITCH_DEFS.forEach((d) => {
    const sw = switchControl({
      checked: false,
      onChange: (v) => onSwitchChange(d.key, v, sw)
    });
    featureSwitches.set(d.key, sw);
    featureList.appendChild(h('div', { class: 'switch-row' }, [
      h('div', { class: 'switch-row-ico' }, [svgIcon(ICONS[d.icon] || ICONS.layers, 15)]),
      h('div', { class: 'switch-row-main' }, [
        h('div', { class: 'switch-row-name', text: d.name }),
        h('div', { class: 'switch-row-desc', text: d.desc })
      ]),
      sw
    ]));
  });

  const switchCard = card({
    title: '系统开关',
    sub: '两级开关：总开关决定系统是否工作，功能开关逐项控制采集与管控',
    body: [
      h('div', { class: 'col gap-3' }, [
        masterRow,
        masterHint,
        h('div', { class: 'switch-section-label', text: '功能开关' }),
        featureList
      ])
    ]
  });

  /** 开关切换：需要撤销规则的项做二次确认 + loading 态 */
  async function onSwitchChange(key, value, sw) {
    const label = key === 'enabled' ? '系统总开关' : (SWITCH_DEFS.find((d) => d.key === key)?.name || key);
    const doSwitch = async () => {
      sw.getEl().disabled = true;
      try {
        const r = await setSwitch(key, value);
        const parts = [];
        if (r.revoked && r.revoked.length) parts.push(`已撤销：${r.revoked.join('；')}`);
        if (r.applied && r.applied.length) parts.push(`已执行：${r.applied.join('；')}`);
        toast(
          parts.length ? parts.join('｜') : `「${label}」已${value ? '开启' : '关闭'}`,
          value ? 'success' : 'info',
          { title: `「${label}」已${value ? '开启' : '关闭'}`, duration: 4200 }
        );
        applySettings(r.settings, { pending: r.pending, hint: r.hint });
      } catch (e) {
        toast(e.message || '开关变更失败', 'error');
        sw.getEl().checked = !value;
      } finally {
        sw.getEl().disabled = false;
      }
    };

    // 涉及下发规则的开关 → 二次确认
    if (!value && REVOKE_SWITCHES.includes(key)) {
      confirmDialog({
        title: `关闭「${label}」`,
        danger: true,
        confirmText: '确认关闭',
        message: key === 'enabled'
          ? '关闭总开关将级联关闭全部功能开关，并撤销已下发的 iptables / tc / dnsmasq 规则。确认继续？'
          : `关闭「${label}」将撤销该功能已经下发的一切规则（回到从未开启的状态）。确认继续？`,
        onConfirm: doSwitch
      });
      // 取消时把开关拨回去
      sw.getEl().checked = value;
      setTimeout(() => { sw.getEl().checked = !value; }, 0);
      return;
    }
    await doSwitch();
  }

  /** 回填开关状态 */
  function applySettings(s, extra = {}) {
    if (!s) return;
    settings = s;
    const enabled = s.enabled !== false;
    masterSwitch.getEl().checked = enabled;
    masterStateBadge.className = `chip ${enabled ? 's-ok' : 's-mute plain'}`;
    masterStateBadge.textContent = enabled ? '运行中' : '未启用';

    // pending：仍为关闭状态的子开关 key（后端固定顺序返回，数组非 null）
    const pending = Array.isArray(extra.pending) ? extra.pending
      : SWITCH_DEFS.filter((d) => s[d.key] === false).map((d) => d.key);
    const hint = typeof extra.hint === 'string' ? extra.hint : '';

    // 提示文案：优先用后端 hint
    if (hint) {
      masterHint.classList.remove('hidden');
      masterHint.querySelector('.master-hint-text').textContent = hint;
    } else if (!enabled) {
      masterHint.classList.remove('hidden');
      masterHint.querySelector('.master-hint-text').textContent = '系统未启用：当前仅显示配置状态，不采集、不管控、不影响路由器现有功能。';
    } else if (pending.length) {
      masterHint.classList.remove('hidden');
      masterHint.querySelector('.master-hint-text').textContent =
        '系统已启用，但功能开关均未开启，系统当前不会采集任何数据。';
    } else {
      masterHint.classList.add('hidden');
    }

    // 待开启数量徽标
    if (pending.length) {
      pendingLabel.classList.remove('hidden');
      pendingLabel.textContent = `${pending.length} 项待开启`;
      pendingLabel.title = `仍为关闭状态：${pending.map((k) => (SWITCH_DEFS.find((d) => d.key === k)?.name || k)).join('、')}`;
    } else {
      pendingLabel.classList.add('hidden');
    }

    SWITCH_DEFS.forEach((d) => {
      const sw = featureSwitches.get(d.key);
      if (!sw) return;
      const on = enabled && s[d.key] !== false;
      sw.getEl().checked = on;
      sw.getEl().disabled = !enabled;
      const row = sw.closest('.switch-row');
      if (row) row.classList.toggle('pending', !on);
    });

    // DNS 旁挂（历史字段）跟随 dnsTap 开关
    if (dnsSwitch && typeof s.dnsTap === 'boolean') {
      dnsSwitch.getEl().checked = enabled && s.dnsTap;
      dnsWarn.classList.toggle('hidden', !(enabled && s.dnsTap));
      dnsDesc.textContent = (enabled && s.dnsTap)
        ? '已开启：dnsmasq 会在查询日志中记录完整域名，用于域名分类与黑名单拦截。'
        : '已关闭：仅能基于 IP 分类，域名统计与黑名单拦截将不可用。';
    }
  }

  /* ---------- 采集与留存 ---------- */
  const intervalInput = h('input', { class: 'input num', type: 'number', min: '1', max: '60', step: '1' });
  const retentionInput = h('input', { class: 'input num', type: 'number', min: '1', max: '365', step: '1' });
  const dataDirEl = h('span', { class: 'v mono', text: '—' });
  const versionEl = h('span', { class: 'v', text: '—' });

  const collectCard = card({
    title: '采集与留存',
    sub: '数据采样频率与本地留存周期',
    body: [
      h('div', { class: 'grid', style: { gap: '14px' } }, [
        h('div', { class: 'g6' }, [
          h('div', { class: 'field' }, [
            h('label', { class: 'field-label' }, [h('span', { text: '采集间隔（秒）' })]),
            intervalInput,
            h('span', { class: 'field-hint', text: '建议 2 秒；过小会显著增加 CPU 与存储写入。' })
          ])
        ]),
        h('div', { class: 'g6' }, [
          h('div', { class: 'field' }, [
            h('label', { class: 'field-label' }, [h('span', { text: '数据留存（天）' })]),
            retentionInput,
            h('span', { class: 'field-hint', text: '到期数据由后台清理任务自动回收。' })
          ])
        ]),
        h('div', { class: 'g6' }, [
          h('div', { class: 'kv' }, [h('span', { class: 'k', text: '数据目录' }), dataDirEl])
        ]),
        h('div', { class: 'g6' }, [
          h('div', { class: 'kv' }, [h('span', { class: 'k', text: '程序版本' }), versionEl])
        ])
      ])
    ]
  });

  /* ---------- DNS 旁挂 ---------- */
  dnsDesc = h('div', { class: 'fs-12 muted', style: { lineHeight: '1.6' } });
  dnsWarn = h('div', { class: 'err-box', style: { background: 'rgba(251,191,36,.09)', borderColor: 'rgba(251,191,36,.34)', color: '#ffe0a3' } }, [
    h('span', { class: 'e-icon', style: { color: 'var(--warn)' } }, [svgIcon(ICONS.alert, 14)]),
    h('span', {}, [
      h('div', { style: { fontWeight: '600', marginBottom: '2px' }, text: '风险提示：DNS 旁挂会记录所有设备的完整域名查询。' }),
      h('div', { text: '① 可能增大 dnsmasq 日志量与闪存写入；② 用户可感知到极轻微的查询延迟；③ 若日志配置错误可能导致 dnsmasq 无法启动，切换后请确认 DNS 仍可正常解析。' })
    ])
  ]);
  dnsSwitch = switchControl({
    checked: true,
    label: '启用 dnsmasq 旁挂',
    onChange: (v) => {
      dnsWarn.classList.toggle('hidden', !v);
      dnsDesc.textContent = v
        ? '已开启：dnsmasq 会在查询日志中记录完整域名，用于域名分类与黑名单拦截。'
        : '已关闭：仅能基于 IP 分类，域名统计与黑名单拦截将不可用。';
    }
  });
  const dnsCard = card({
    title: 'DNS 旁挂',
    sub: '用于域名级分类与黑名单拦截',
    body: [
      h('div', { class: 'col gap-3' }, [
        h('div', { class: 'row-gap-2' }, [dnsSwitch]),
        dnsDesc,
        dnsWarn
      ])
    ]
  });

  /* ---------- 告警阈值 ---------- */
  const alertEnable = switchControl({ checked: true, label: '启用安全告警' });
  const scanPortsInput = h('input', { class: 'input num', type: 'number', min: '5', max: '200', step: '1' });
  const trafficInput = h('input', { class: 'input num', type: 'number', min: '50', max: '100000', step: '50' });
  const alertCard = card({
    title: '告警阈值',
    sub: '安全事件触发条件',
    body: [
      h('div', { class: 'col gap-3' }, [
        h('div', { class: 'row-gap-2' }, [alertEnable]),
        h('div', { class: 'grid', style: { gap: '14px' } }, [
          h('div', { class: 'g6' }, [
            h('div', { class: 'field' }, [
              h('label', { class: 'field-label' }, [h('span', { text: '端口扫描阈值（端口数）' })]),
              scanPortsInput,
              h('span', { class: 'field-hint', text: '60 秒内访问的不同目的端口数达到该值即触发。' })
            ])
          ]),
          h('div', { class: 'g6' }, [
            h('div', { class: 'field' }, [
              h('label', { class: 'field-label' }, [h('span', { text: '流量异常阈值（MB/小时）' })]),
              trafficInput,
              h('span', { class: 'field-hint', text: '单设备小时下行流量超过该值即触发。' })
            ])
          ])
        ])
      ])
    ]
  });

  /* ---------- 系统信息 ---------- */
  const sysBody = h('div', {}, [skeleton(4)]);
  const sysCard = card({
    title: '系统信息',
    sub: '路由器本机',
    body: [sysBody]
  });

  /* ---------- 卸载与回滚 ---------- */
  const uninstallCard = card({
    title: '卸载与回滚',
    sub: '恢复出厂前的操作指引',
    body: [
      h('div', { class: 'col gap-3' }, [
        h('div', { class: 'fs-12 muted', style: { lineHeight: '1.75' } }, [
          h('div', { text: '1. 停止服务并清理管控规则：' }),
          h('div', { class: 'mono', style: { paddingLeft: '14px', color: 'var(--text-2)' }, text: '/etc/init.d/guanlan stop && /etc/init.d/guanlan remove' }),
          h('div', { text: '2. 移除配置与数据目录（该操作不可恢复）：' }),
          h('div', { class: 'mono', style: { paddingLeft: '14px', color: 'var(--text-2)' }, text: 'rm -rf /etc/config/guanlan /mnt/mmcblk2p4/guanlan' }),
          h('div', { text: '3. 还原 dnsmasq 旁挂配置，恢复原有 DNS 行为。' }),
          h('div', { text: '4. 回滚到旧版本：将固件包替换后执行 sysupgrade -n 保留配置升级。' })
        ]),
        h('div', { class: 'row-gap-2' }, [
          button('一键清除管控规则', {
            variant: 'danger', icon: ICONS.undo,
            onClick: () => ctx.confirm({
              title: '清除管控规则', danger: true, confirmText: '清除',
              message: '将清除所有断网规则、限速与 DNS 拦截。确认继续？',
              onConfirm: async () => {
                const r = await api.enforceReset();
                toast(`已清除 ${(r && r.removed ? r.removed.length : 0)} 项规则`, 'success');
              }
            })
          }),
          button('复制卸载命令', {
            variant: 'ghost', icon: ICONS.download,
            onClick: () => {
              const cmd = '/etc/init.d/guanlan stop && /etc/init.d/guanlan remove && rm -rf /etc/config/guanlan /mnt/mmcblk2p4/guanlan';
              if (navigator.clipboard) {
                navigator.clipboard.writeText(cmd).then(
                  () => toast('卸载命令已复制到剪贴板', 'success'),
                  () => toast('复制失败，请手动选择', 'error')
                );
              } else {
                toast('当前浏览器不支持剪贴板 API', 'error');
              }
            }
          })
        ])
      ])
    ]
  });

  /* ---------- 修改密码 ---------- */
  const oldPwd = h('input', { class: 'input', type: 'password', autocomplete: 'current-password', placeholder: '当前密码' });
  const newPwd = h('input', { class: 'input', type: 'password', autocomplete: 'new-password', placeholder: '新密码（至少 8 位）' });
  const newPwd2 = h('input', { class: 'input', type: 'password', autocomplete: 'new-password', placeholder: '再次输入新密码' });
  const pwdMsg = h('div', { class: 'fs-11 dim' });
  const pwdCard = card({
    title: '修改管理密码',
    sub: '修改后当前会话仍然有效',
    body: [
      h('div', { class: 'col gap-3' }, [
        h('div', { class: 'field' }, [h('label', { class: 'field-label' }, [h('span', { text: '当前密码' })]), oldPwd]),
        h('div', { class: 'field' }, [h('label', { class: 'field-label' }, [h('span', { text: '新密码' })]), newPwd]),
        h('div', { class: 'field' }, [h('label', { class: 'field-label' }, [h('span', { text: '确认新密码' })]), newPwd2]),
        pwdMsg,
        h('div', { class: 'row-gap-2' }, [
          button('修改密码', {
            variant: 'primary', icon: ICONS.key,
            onClick: async (e) => {
              const b = e.currentTarget;
              if (newPwd.value.length < 8) { pwdMsg.textContent = '新密码至少 8 位'; pwdMsg.style.color = 'var(--crit)'; return; }
              if (newPwd.value !== newPwd2.value) { pwdMsg.textContent = '两次输入的新密码不一致'; pwdMsg.style.color = 'var(--crit)'; return; }
              b.classList.add('is-loading');
              try {
                await api.changePassword(oldPwd.value, newPwd.value);
                toast('密码修改成功', 'success');
                pwdMsg.textContent = '密码已更新，请妥善保管。';
                pwdMsg.style.color = 'var(--ok)';
                oldPwd.value = ''; newPwd.value = ''; newPwd2.value = '';
              } catch (err) {
                pwdMsg.textContent = err.message || '修改失败';
                pwdMsg.style.color = 'var(--crit)';
                toast(err.message || '修改失败', 'error');
              } finally {
                b.classList.remove('is-loading');
              }
            }
          })
        ])
      ])
    ]
  });

  /* ---------- 保存 ---------- */
  const saveBtn = button('保存设置', { variant: 'primary', icon: ICONS.check });
  const saveBar = h('div', { class: 'card', style: { padding: '11px 16px' } }, [
    h('div', { class: 'row-gap-3' }, [
      h('span', { class: 'fs-12 dim', text: '修改采集、留存、旁挂与告警配置后统一保存' }),
      h('div', { class: 'spacer', style: { flex: '1' } }),
      saveBtn
    ])
  ]);

  saveBtn.addEventListener('click', async () => {
    saveBtn.classList.add('is-loading');
    try {
      const payload = {
        collectIntervalSec: Number(intervalInput.value) || 2,
        retentionDays: Number(retentionInput.value) || 14,
        alert: {
          enable: alertEnable.getEl().checked,
          scanPorts: Number(scanPortsInput.value) || 20,
          trafficMbPerHour: Number(trafficInput.value) || 500
        }
      };
      const r = await putSettings(payload);
      const parts = [];
      if (r.revoked && r.revoked.length) parts.push(`已撤销：${r.revoked.join('；')}`);
      if (r.applied && r.applied.length) parts.push(`已执行：${r.applied.join('；')}`);
      toast(parts.length ? parts.join('｜') : '设置已保存并生效', 'success', { title: '设置已保存' });
      await loadSettings();
    } catch (e) {
      toast(e.message || '保存失败', 'error');
    } finally {
      saveBtn.classList.remove('is-loading');
    }
  });

  host.appendChild(switchCard);
  host.appendChild(h('div', { class: 'grid' }, [
    h('div', { class: 'g7' }, [
      h('div', { class: 'grid', style: { gap: '13px' } }, [
        h('div', { class: 'g12' }, [collectCard]),
        h('div', { class: 'g12' }, [dnsCard]),
        h('div', { class: 'g12' }, [alertCard])
      ])
    ]),
    h('div', { class: 'g5' }, [
      h('div', { class: 'grid', style: { gap: '13px' } }, [
        h('div', { class: 'g12' }, [sysCard]),
        h('div', { class: 'g12' }, [pwdCard]),
        h('div', { class: 'g12' }, [uninstallCard])
      ])
    ])
  ]));
  host.appendChild(saveBar);

  /* ---------- 加载 ---------- */
  async function loadSettings() {
    try {
      const s = await api.getSettings();
      if (destroyed) return;
      applySettings(s);
      intervalInput.value = s.collectIntervalSec ?? 2;
      retentionInput.value = s.retentionDays ?? 14;
      alertEnable.getEl().checked = s.alert?.enable !== false;
      scanPortsInput.value = s.alert?.scanPorts ?? 20;
      trafficInput.value = s.alert?.trafficMbPerHour ?? 500;
      dataDirEl.textContent = s.dataDir || '—';
      versionEl.textContent = s.version || '—';
    } catch (e) {
      console.error('[settings]', e);
      toast(e.message || '设置加载失败', 'error');
    }
  }

  async function loadSystem() {
    try {
      const s = await api.getSystem();
      if (destroyed) return;
      system = s;
      sysBody.innerHTML = '';
      sysBody.appendChild(kvList([
        ['设备型号', s.model],
        ['主机名', s.hostname],
        ['架构', s.arch],
        ['内核版本', s.kernel],
        ['OpenWrt 版本', s.openwrt],
        ['运行时长', formatDuration(s.uptimeSec || 0)],
        ['内存总量', `${s.memTotalMb || 0} MB`],
        ['内存可用', `${s.memFreeMb || 0} MB`],
        ['存储可用', `${s.diskFreeMb || 0} MB`]
      ]));
    } catch (e) {
      sysBody.innerHTML = '';
      sysBody.appendChild(errorBox(`系统信息加载失败：${e.message || e}`, loadSystem));
    }
  }

  await Promise.all([loadSettings(), loadSystem()]);

  /* ---------- 外部变更开关时同步回填 ---------- */
  const unsubSettings = subscribeSettings((s) => {
    if (destroyed) return;
    applySettings(s);
  });
  cleanups.push(unsubSettings);

  return {
    unmount() {
      destroyed = true;
      cleanups.forEach((fn) => { try { fn(); } catch (_) {} });
    }
  };
}
