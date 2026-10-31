// 开关体系往返测试：切换总开关 → 验证接口返回 applied/revoked/pending/hint → 验证降级路径
const { spawn } = require('child_process');
const http = require('http');
const path = require('path');
const os = require('os');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
function httpGet(url) { return new Promise((res, rej) => { http.get(url, (r) => { let d = ''; r.on('data', (c) => (d += c)); r.on('end', () => res(d)); }).on('error', rej); }); }
class CDP {
  constructor(ws) { this.ws = ws; this.id = 0; this.pending = new Map(); this.listeners = []; }
  static connect(wsUrl) {
    return new Promise((resolve, reject) => {
      const inst = new CDP(); const ws = new WebSocket(wsUrl); inst.ws = ws;
      ws.onopen = () => resolve(inst);
      ws.onerror = () => reject(new Error('ws error'));
      ws.onmessage = (ev) => {
        const self = inst; let msg; try { msg = JSON.parse(ev.data); } catch { return; }
        if (msg.id && self.pending.has(msg.id)) {
          const { resolve: rs, reject: rj } = self.pending.get(msg.id); self.pending.delete(msg.id);
          if (msg.error) rj(new Error(JSON.stringify(msg.error))); else rs(msg.result);
        } else if (msg.method) self.listeners.forEach((fn) => fn(msg));
      };
    });
  }
  on(fn) { this.listeners.push(fn); }
  send(method, params = {}, sessionId) {
    const id = ++this.id;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      const p = { id, method, params }; if (sessionId) p.sessionId = sessionId;
      this.ws.send(JSON.stringify(p));
      setTimeout(() => { if (this.pending.has(id)) { this.pending.delete(id); reject(new Error('timeout ' + method)); } }, 20000);
    });
  }
  close() { try { this.ws.close(); } catch {} }
}

(async () => {
  const chrome = spawn('C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe', [
    '--headless=new', '--enable-unsafe-swiftshader', '--no-sandbox', '--disable-gpu',
    '--window-size=1600,900', '--remote-debugging-port=9336',
    '--user-data-dir=' + path.join(os.tmpdir(), 'glsw-' + Date.now()), 'about:blank'
  ], { stdio: 'ignore' });
  let wsUrl = null;
  for (let i = 0; i < 80; i++) { await sleep(250); try { const j = JSON.parse(await httpGet('http://127.0.0.1:9336/json/version')); if (j.webSocketDebuggerUrl) { wsUrl = j.webSocketDebuggerUrl; break; } } catch {} }
  if (!wsUrl) { console.log('CDP_FAIL'); chrome.kill(); process.exit(2); }
  const cdp = await CDP.connect(wsUrl);
  const errors = [];
  cdp.on((m) => {
    if (m.method === 'Runtime.consoleAPICalled' && m.params.type === 'error') errors.push((m.params.args || []).map((a) => a.value ?? a.description).join(' '));
    if (m.method === 'Runtime.exceptionThrown') errors.push(m.params.exceptionDetails.exception?.description || m.params.exceptionDetails.text);
  });
  const { targetId } = await cdp.send('Target.createTarget', { url: 'about:blank' });
  const { sessionId } = await cdp.send('Target.attachToTarget', { targetId, flatten: true });
  const S = (m, p = {}) => cdp.send(m, p, sessionId).catch(() => ({}));
  const ev = async (expr) => (await S('Runtime.evaluate', { expression: expr, returnByValue: true, awaitPromise: true })).result?.value;

  await S('Runtime.enable'); await S('Page.enable');
  await S('Emulation.setDeviceMetricsOverride', { width: 1600, height: 900, deviceScaleFactor: 1, mobile: false });
  await S('Page.navigate', { url: 'http://127.0.0.1:8812/index.html?mock=1#/settings' });
  await sleep(4000);

  console.log('--- 初始状态 ---');
  console.log(await ev(`JSON.stringify({
    master: !!document.querySelector('.master-switch'),
    masterOn: (document.querySelector('.master-switch input')||{}).checked,
    badge: (document.querySelector('.topbar .chip')||{}).textContent||'',
    featureCount: document.querySelectorAll('.switch-row').length,
    hint: (document.querySelector('.master-hint-text')||{}).textContent||''
  })`));

  console.log('--- 关闭总开关（应触发二次确认弹窗） ---');
  await ev(`(()=>{const i=document.querySelector('.master-switch input');i.click();})()`);
  await sleep(900);
  console.log('confirm modal:', await ev(`JSON.stringify({modal:!!document.querySelector('.modal'),title:(document.querySelector('.modal-title')||{}).textContent||'',msg:(document.querySelector('.modal-body')||{}).textContent||''})`));
  console.log('master still on (cancelled?):', await ev(`(document.querySelector('.master-switch input')||{}).checked`));

  console.log('--- 确认关闭 ---');
  await ev(`(()=>{const b=[...document.querySelectorAll('.modal-foot .btn')].find(x=>x.textContent.includes('确认'));if(b)b.click();})()`);
  await sleep(1600);
  console.log(await ev(`JSON.stringify({
    masterOn: (document.querySelector('.master-switch input')||{}).checked,
    badge: (document.querySelector('.topbar .chip')||{}).textContent||'',
    pendingBadge: (document.querySelector('.master-switch .chip.s-warn')||{}).textContent||'',
    hint: (document.querySelector('.master-hint-text')||{}).textContent||'',
    toast: (document.querySelector('.toast-msg')||{}).textContent||'',
    featureDisabled: [...document.querySelectorAll('.switch-row input')].every(x=>x.disabled)
  })`));

  console.log('--- 切到总览页（应显示未启用提示条） ---');
  await ev(`location.hash='#/overview'`);
  await sleep(2200);
  console.log(await ev(`JSON.stringify({
    notice: !!document.querySelector('.notice-bar'),
    noticeText: (document.querySelector('.notice-bar-title')||{}).textContent||'',
    enableBtn: !!(document.querySelector('.notice-bar .btn')),
    kpi0: (document.querySelector('.kpi-value')||{}).textContent||''
  })`));

  console.log('--- 切到设备页（应显示空态而非报错） ---');
  await ev(`location.hash='#/devices'`);
  await sleep(2200);
  console.log(await ev(`JSON.stringify({
    disabled: !!document.querySelector('.disabled-state'),
    title: (document.querySelector('.disabled-state-title')||{}).textContent||'',
    desc: (document.querySelector('.disabled-state-desc')||{}).textContent||'',
    errBox: !!document.querySelector('.err-box'),
    rows: document.querySelectorAll('table.tbl tbody tr').length
  })`));

  console.log('--- 重新启用系统 ---');
  await ev(`location.hash='#/settings'`);
  await sleep(2200);
  await ev(`(()=>{const i=document.querySelector('.master-switch input');if(!i.checked)i.click();})()`);
  await sleep(700);
  await ev(`(()=>{const b=[...document.querySelectorAll('.modal-foot .btn')].find(x=>x.textContent.includes('确认'));if(b)b.click();})()`);
  await sleep(1600);
  console.log(await ev(`JSON.stringify({
    masterOn: (document.querySelector('.master-switch input')||{}).checked,
    badge: (document.querySelector('.topbar .chip')||{}).textContent||'',
    hint: (document.querySelector('.master-hint-text')||{}).textContent||''
  })`));

  console.log('\nconsole errors:', errors.length);
  errors.slice(0, 6).forEach((e) => console.log('  ' + String(e).slice(0, 200)));
  cdp.close(); chrome.kill();
})().catch((e) => { console.error('FAIL', e); process.exit(1); });
