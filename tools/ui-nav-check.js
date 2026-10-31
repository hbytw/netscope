// 交互自查：登录 → 顶栏导航点击 → hash 切换 → 各页可见性
// 用法: node tools/ui-nav-check.js
const { spawn } = require('child_process');
const http = require('http');
const path = require('path');
const fs = require('fs');
const os = require('os');

const CHROME = 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe';
const BASE = 'http://127.0.0.1:8812/index.html?mock=1';
const OUT_DIR = path.resolve(__dirname, '..', 'temp');

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
function httpGet(url) {
  return new Promise((res, rej) => {
    http.get(url, (r) => { let d = ''; r.on('data', (c) => (d += c)); r.on('end', () => res(d)); }).on('error', rej);
  });
}
class CDP {
  constructor(ws) { this.ws = ws; this.id = 0; this.pending = new Map(); this.listeners = []; }
  static connect(wsUrl) {
    return new Promise((resolve, reject) => {
      const inst = new CDP();
      const ws = new WebSocket(wsUrl);
      inst.ws = ws;
      ws.onopen = () => resolve(inst);
      ws.onerror = () => reject(new Error('ws error'));
      ws.onmessage = (ev) => {
        const self = inst;
        let msg; try { msg = JSON.parse(ev.data); } catch { return; }
        if (msg.id && self.pending.has(msg.id)) {
          const { resolve: rs, reject: rj } = self.pending.get(msg.id);
          self.pending.delete(msg.id);
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
  const chrome = spawn(CHROME, [
    '--headless=new', '--enable-unsafe-swiftshader', '--no-sandbox', '--disable-gpu',
    '--window-size=1600,900', '--remote-debugging-port=9335',
    '--user-data-dir=' + path.join(os.tmpdir(), 'glnav-' + Date.now()), 'about:blank'
  ], { stdio: 'ignore' });

  let wsUrl = null;
  for (let i = 0; i < 80; i++) {
    await sleep(250);
    try { const j = JSON.parse(await httpGet('http://127.0.0.1:9335/json/version')); if (j.webSocketDebuggerUrl) { wsUrl = j.webSocketDebuggerUrl; break; } } catch {}
  }
  if (!wsUrl) { console.log('CDP_FAIL'); chrome.kill(); process.exit(2); }

  const cdp = await CDP.connect(wsUrl);
  const errors = [];
  cdp.on((msg) => {
    if (msg.method === 'Runtime.consoleAPICalled' && msg.params.type === 'error') {
      errors.push('[console.error] ' + (msg.params.args || []).map((a) => a.value ?? a.description).join(' '));
    }
    if (msg.method === 'Runtime.exceptionThrown') {
      errors.push('[exception] ' + (msg.params.exceptionDetails.exception?.description || msg.params.exceptionDetails.text));
    }
  });

  const { targetId } = await cdp.send('Target.createTarget', { url: 'about:blank' });
  const { sessionId } = await cdp.send('Target.attachToTarget', { targetId, flatten: true });
  const S = (m, p = {}) => cdp.send(m, p, sessionId).catch((e) => ({ __err: String(e) }));
  const evalJS = async (expr) => {
    const r = await S('Runtime.evaluate', { expression: expr, returnByValue: true, awaitPromise: true });
    return r.result?.value;
  };

  await S('Runtime.enable'); await S('Page.enable');
  await S('Emulation.setDeviceMetricsOverride', { width: 1600, height: 900, deviceScaleFactor: 1, mobile: false });

  // 1. 打开（mock 模式会自动登录），检查初始页
  await S('Page.navigate', { url: `${BASE}#/overview` });
  await sleep(3500);
  const initial = await evalJS(`JSON.stringify({
    hasLogin: !!document.getElementById('login-pwd'),
    nav: !!document.querySelector('.nav'),
    active: (document.querySelector('.nav-tab.active')||{}).textContent||'',
    page: !!document.querySelector('.page')
  })`);
  console.log('initial:', initial);

  // 2. 点击顶栏导航「设备」
  const clicked = await evalJS(`(()=>{const b=[...document.querySelectorAll('.nav-tab')].find(x=>x.textContent.trim()==='设备');if(!b)return 'NO_BTN';b.click();return 'CLICKED';})()`);
  await sleep(1800);
  const afterNav = await evalJS(`JSON.stringify({
    hash: location.hash,
    active: (document.querySelector('.nav-tab.active')||{}).textContent||'',
    rows: document.querySelectorAll('table.tbl tbody tr').length,
    title: (document.querySelector('.card-title')||{}).textContent||''
  })`);
  console.log('nav click:', clicked, '→', afterNav);

  // 3. 依次点击所有顶栏 Tab
  const tabs = ['总览大屏', '流量', '行为', '安全', '设置'];
  for (const t of tabs) {
    await evalJS(`(()=>{const b=[...document.querySelectorAll('.nav-tab')].find(x=>x.textContent.trim()==='${t}');if(b)b.click();})()`);
    await sleep(1400);
    const st = await evalJS(`JSON.stringify({hash:location.hash,active:(document.querySelector('.nav-tab.active')||{}).textContent||'',cards:document.querySelectorAll('.card').length})`);
    console.log(`tab ${t}:`, st);
  }

  // 4. 直接访问 #/screen
  await evalJS(`location.hash='#/screen'`);
  await sleep(3000);
  const screen = await evalJS(`JSON.stringify({
    hash: location.hash,
    screenRoot: !!document.querySelector('.screen-root'),
    topbarHidden: getComputedStyle(document.querySelector('.topbar')).display==='none',
    canvas: !!document.querySelector('.screen-canvas-host canvas'),
    fallbackNote: (document.querySelector('.screen-fallback-note')||{}).textContent||''
  })`);
  console.log('screen:', screen);

  // 4b. 行为页：点击策略 → 检查编辑器渲染
  await evalJS(`location.hash='#/behavior'`);
  await sleep(2200);
  const pol = await evalJS(`(()=>{const it=document.querySelector('.policy-item');if(!it)return 'NO_POLICY';it.click();return 'CLICKED';})()`);
  await sleep(1200);
  console.log('policy editor:', pol, '→', await evalJS(`JSON.stringify({
    inputs: document.querySelectorAll('.card input, .card textarea, .card select').length,
    dayBtns: document.querySelectorAll('.day-picker button').length,
    chips: document.querySelectorAll('.chip-pick').length,
    actionBtns: document.querySelectorAll('.segment button').length,
    mode: (document.getElementById('pol-mode')||{}).textContent||''
  })`));

  // 4b2. 流量页：切「按分类堆叠」→ 检查堆叠图例与范围 Tab
  await evalJS(`location.hash='#/traffic'`);
  await sleep(2400);
  await evalJS(`(()=>{const s=[...document.querySelectorAll('.switch input')].find(x=>x.parentElement.textContent.includes('堆叠'));if(s){s.click();}})()`);
  await sleep(1400);
  console.log('stacked:', await evalJS(`JSON.stringify({
    legend: document.querySelectorAll('.card .chart-legend .legend-item').length,
    canvases: document.querySelectorAll('canvas').length
  })`));
  // 切时间范围 7d
  await evalJS(`(()=>{const b=[...document.querySelectorAll('.segment button')].find(x=>x.textContent.trim()==='7 天');if(b)b.click();})()`);
  await sleep(2000);
  console.log('range 7d:', await evalJS(`JSON.stringify({active:(document.querySelector('.segment button.active')||{}).textContent||'',hash:location.hash})`));

  // 4b3. 安全页：点「查看证据」→ 弹窗
  await evalJS(`location.hash='#/security'`);
  await sleep(2200);
  await evalJS(`(()=>{const b=document.querySelector('.event-item .op-btn');if(b)b.click();})()`);
  await sleep(1200);
  console.log('evidence modal:', await evalJS(`JSON.stringify({modal:!!document.querySelector('.modal'),title:(document.querySelector('.modal-title')||{}).textContent||''})`));
  await evalJS(`document.dispatchEvent(new KeyboardEvent('keydown',{key:'Escape'}))`);
  await sleep(600);

  // 4c. 设备页：点击行 → 抽屉
  await evalJS(`location.hash='#/devices'`);
  await sleep(2200);
  await evalJS(`(()=>{const tr=document.querySelector('table.tbl tbody tr');if(tr)tr.click();})()`);
  await sleep(2000);
  console.log('device drawer:', await evalJS(`JSON.stringify({
    drawer: !!document.querySelector('.drawer'),
    title: (document.querySelector('.drawer-title')||{}).textContent||'',
    cards: document.querySelectorAll('.drawer .card').length,
    canvas: !!document.querySelector('.drawer canvas')
  })`));
  await evalJS(`document.dispatchEvent(new KeyboardEvent('keydown',{key:'Escape'}))`);
  await sleep(600);

  // 5. Esc 退出大屏
  await evalJS(`location.hash='#/screen'`);
  await sleep(2000);
  await S('Input.dispatchKeyEvent', { type: 'keyDown', key: 'Escape', code: 'Escape', windowsVirtualKeyCode: 27 });
  await S('Input.dispatchKeyEvent', { type: 'keyUp', key: 'Escape', code: 'Escape', windowsVirtualKeyCode: 27 });
  await sleep(1600);
  console.log('after Esc:', await evalJS(`JSON.stringify({hash:location.hash,topbarHidden:getComputedStyle(document.querySelector('.topbar')).display==='none'})`));

  console.log('\nconsole errors:', errors.length);
  errors.slice(0, 8).forEach((e) => console.log('  ' + e.slice(0, 240)));
  cdp.close(); chrome.kill();
})().catch((e) => { console.error('FAIL', e); process.exit(1); });
