/* ==========================================================================
   观澜 NetScope · 登录页
   依据 docs/api.md §1：POST /api/login {"password"}
   连续 5 次失败锁定 60s → 429 {"error":"尝试过于频繁，请稍后再试"}
   ========================================================================== */

import { h, svgIcon, button, ICONS } from './components.js';

export function renderLogin(container, { api, onSuccess }) {
  const errBox = h('div', { class: 'login-err hidden' }, [
    h('span', { class: 'e-icon' }, [svgIcon(ICONS.alert, 13)]),
    h('span', { class: 'msg', text: '' })
  ]);

  const input = h('input', {
    class: 'input', type: 'password', id: 'login-pwd',
    placeholder: '请输入管理密码', autocomplete: 'current-password'
  });
  input.style.height = '38px';

  const submitBtn = button('登 录', { variant: 'primary', size: 'lg', block: true });

  const form = h('form', { class: 'login-form' }, [
    h('div', { class: 'field' }, [
      h('label', { class: 'field-label', for: 'login-pwd' }, [
        svgIcon(ICONS.key, 12),
        h('span', { text: '管理密码' })
      ]),
      input
    ]),
    errBox,
    submitBtn
  ]);

  const panel = h('div', { class: 'login-panel' }, [
    h('div', { class: 'login-logo' }),
    h('div', { class: 'login-title', html: '观澜 <em>NetScope</em>' }),
    h('div', { class: 'login-sub', text: '用户上网行为态势感知' }),
    form,
    h('div', { class: 'login-foot' }, [
      h('div', { text: 'OpenWrt 路由器本地部署 · 会话有效期 24 小时' }),
      h('div', { text: '连续 5 次密码错误将锁定 60 秒' })
    ])
  ]);

  container.appendChild(panel);

  let lockTimer = null;
  let locked = false;
  let attempts = 0;

  const setError = (msg, warn = false) => {
    if (!msg) { errBox.classList.add('hidden'); return; }
    errBox.classList.remove('hidden');
    errBox.classList.toggle('warn', warn);
    errBox.querySelector('.msg').textContent = msg;
  };

  const doLogin = async (ev) => {
    if (ev) ev.preventDefault();
    if (locked) return;
    const pwd = input.value;
    if (!pwd) {
      setError('请输入管理密码');
      input.focus();
      return;
    }
    submitBtn.classList.add('is-loading');
    submitBtn.disabled = true;
    setError('');
    try {
      await api.login(pwd);
      attempts = 0;
      if (lockTimer) { clearInterval(lockTimer); lockTimer = null; }
      input.value = '';
      if (onSuccess) onSuccess();
    } catch (e) {
      attempts += 1;
      const msg = e.message || '登录失败';
      if (e.status === 429 || /锁定|过于频繁/.test(msg)) {
        locked = true;
        startLockCountdown(60);
        setError('尝试过于频繁，请 60 秒后再试', true);
        input.disabled = true;
        submitBtn.disabled = true;
      } else {
        const left = Math.max(0, 5 - attempts);
        const reason = /密码/.test(msg) ? '密码错误' : msg;
        setError(left > 0 ? `${reason}（还可尝试 ${left} 次）` : reason);
        input.select();
      }
    } finally {
      submitBtn.classList.remove('is-loading');
      submitBtn.disabled = locked;
    }
  };

  const startLockCountdown = (sec) => {
    let left = sec;
    const msgEl = errBox.querySelector('.msg');
    const tick = () => {
      msgEl.textContent = `尝试过于频繁，请在 ${left} 秒后重试`;
      left -= 1;
      if (left <= 0) {
        locked = false;
        attempts = 0;
        input.disabled = false;
        submitBtn.disabled = false;
        setError('');
        input.focus();
      }
    };
    if (lockTimer) clearInterval(lockTimer);
    lockTimer = setInterval(tick, 1000);
  };

  form.addEventListener('submit', doLogin);
  submitBtn.addEventListener('click', doLogin);
  setTimeout(() => input.focus(), 60);

  return {
    destroy() {
      if (lockTimer) clearInterval(lockTimer);
    }
  };
}
