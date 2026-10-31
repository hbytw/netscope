// 自查脚本：抓取页面 console 错误 + 检测横向滚动 + 截图
// 用法: node tools/ui-check.js <pages-csv> [width] [height]
const { spawn } = require('child_process');
const http = require('http');
const path = require('path');
const fs = require('fs');
const os = require('os');

const CHROME = 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe';
const PORT = 8812;
const BASE = `http://127.0.0.1:${PORT}/index.html?mock=1`;
const OUT_DIR = path.resolve(__dirname, '..', 'temp');

function httpGet(url) {
  return new Promise((res, rej) => {
    http.get(url, (r) => {
      let d = '';
      r.on('data', (c) => (d += c));
      r.on('end', () => res(d));
    }).on('error', rej);
  });
}

class CDP {
  constructor(ws) {
    this.ws = ws;
    this.id = 0;
    this.pending = new Map();
    this.listeners = [];
  }
  static connect(wsUrl) {
    return new Promise((resolve, reject) => {
      const inst = new CDP();
      const ws = new WebSocket(wsUrl);
      inst.ws = ws;
      ws.onopen = () => resolve(inst);
      ws.onerror = () => reject(new Error('ws error'));
      ws.onmessage = (ev) => {
        const self = inst;
        let msg;
        try { msg = JSON.parse(ev.data); } catch { return; }
        if (msg.id && self.pending.has(msg.id)) {
          const { resolve: rs, reject: rj } = self.pending.get(msg.id);
          self.pending.delete(msg.id);
          if (msg.error) rj(new Error(JSON.stringify(msg.error)));
          else rs(msg.result);
        } else if (msg.method) {
          self.listeners.forEach((fn) => fn(msg));
        }
      };
    });
  }
  on(fn) { this.listeners.push(fn); }
  send(method, params = {}, sessionId) {
    const id = ++this.id;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      const payload = { id, method, params };
      if (sessionId) payload.sessionId = sessionId;
      this.ws.send(JSON.stringify(payload));
      setTimeout(() => {
        if (this.pending.has(id)) { this.pending.delete(id); reject(new Error('timeout ' + method)); }
      }, 30000);
    });
  }
  close() { try { this.ws.close(); } catch {} }
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function main() {
  const pages = process.argv[2] ? process.argv[2].split(',') : ['overview', 'devices', 'traffic', 'behavior', 'security', 'settings', 'screen'];
  const width = Number(process.argv[3] || 1600);
  const height = Number(process.argv[4] || 900);
  const shotTag = process.argv[5] || '';
  const query = process.argv[6] || 'mock=1';

  const chrome = spawn(CHROME, [
    '--headless=new', '--enable-unsafe-swiftshader', '--no-sandbox', '--disable-gpu',
    `--window-size=${width},${height}`,
    '--remote-debugging-port=9333',
    '--user-data-dir=' + path.join(os.tmpdir(), 'gl-check-' + Date.now()),
    'about:blank'
  ], { stdio: 'ignore' });

  let wsUrl = null;
  for (let i = 0; i < 80; i++) {
    await sleep(250);
    try {
      const j = JSON.parse(await httpGet('http://127.0.0.1:9333/json/version'));
      if (j.webSocketDebuggerUrl) { wsUrl = j.webSocketDebuggerUrl; break; }
    } catch {}
  }
  if (!wsUrl) { console.log('CDP_CONNECT_FAIL'); chrome.kill(); process.exit(2); }

  const cdp = await CDP.connect(wsUrl);
  const results = [];

  for (const pg of pages) {
    const errors = [];
    cdp.listeners.length = 0;
    cdp.on((msg) => {
      if (msg.method === 'Runtime.consoleAPICalled' && msg.params.type === 'error') {
        const text = (msg.params.args || []).map((a) => a.value ?? a.description ?? a.type).join(' ');
        errors.push('[console.error] ' + text);
      }
      if (msg.method === 'Runtime.exceptionThrown') {
        const d = msg.params.exceptionDetails;
        errors.push('[exception] ' + (d.exception?.description || d.text));
      }
      if (msg.method === 'Log.entryAdded' && msg.params.entry.level === 'error') {
        errors.push('[log] ' + msg.params.entry.text);
      }
    });

    const { targetId } = await cdp.send('Target.createTarget', { url: 'about:blank' });
    const { sessionId } = await cdp.send('Target.attachToTarget', { targetId, flatten: true });
    const S = (m, p = {}) => cdp.send(m, p, sessionId).catch((e) => ({ __err: String(e) }));

    await S('Runtime.enable');
    await S('Log.enable');
    await S('Page.enable');
    await S('Emulation.setDeviceMetricsOverride', { width, height, deviceScaleFactor: 1, mobile: false });
    await S('Page.navigate', { url: `${BASE.replace('mock=1', query)}#/${pg}` });
    await sleep(4000);
    await S('Runtime.evaluate', { expression: `location.hash='#/${pg}'` });
    await sleep(2600);
    const sc = await S('Runtime.evaluate', {
      expression: `JSON.stringify({
        sw: document.documentElement.scrollWidth, cw: document.documentElement.clientWidth,
        bodySw: document.body.scrollWidth,
        contentSw: (document.getElementById('content')||{}).scrollWidth || 0,
        contentCw: (document.getElementById('content')||{}).clientWidth || 0,
        errBadge: !!document.querySelector('.err-badge'),
        errText: (document.querySelector('.err-badge')||{}).textContent || '',
        title: (document.querySelector('.nav-tab.active')||{}).textContent || ''
      })`, returnByValue: true
    });
    let scroll = {};
    try { scroll = JSON.parse(sc.result?.value || '{}'); } catch {}
    const hOverflow = (scroll.sw > scroll.cw + 1) || (scroll.contentSw > scroll.contentCw + 1);
    results.push({ page: pg, errors, hOverflow, scroll });

    const shot = await S('Page.captureScreenshot', { format: 'png', captureBeyondViewport: false });
    const shotData = shot && (shot.data || (shot.result && shot.result.data));
    if (shotData) {
      fs.writeFileSync(path.join(OUT_DIR, `ui-${shotTag}${pg}.png`), Buffer.from(shotData, 'base64'));
    } else {
      console.log(`[shot-miss] ${pg}: ${JSON.stringify(shot).slice(0, 200)}`);
    }
    await cdp.send('Target.closeTarget', { targetId });
  }

  cdp.close();
  chrome.kill();
  await sleep(300);

  for (const r of results) {
    console.log(`--- ${r.page}: errors=${r.errors.length} hOverflow=${r.hOverflow}`);
    r.errors.slice(0, 6).forEach((e) => console.log('    ' + e.slice(0, 300)));
    if (r.scroll.errBadge) console.log('    ERR_BADGE: ' + r.scroll.errText.slice(0, 400));
    if (r.hOverflow) console.log(`    scroll: doc ${r.scroll.sw}/${r.scroll.cw} content ${r.scroll.contentSw}/${r.scroll.contentCw}`);
  }
  const totalErr = results.reduce((a, r) => a + r.errors.length, 0);
  const of = results.filter((r) => r.hOverflow).map((r) => r.page);
  console.log(`\n=== TOTAL console errors: ${totalErr} ===`);
  console.log(`=== horizontal overflow: ${of.length ? of.join(',') : 'none'} ===`);
}

main().catch((e) => { console.error('CHECK_FAIL', e); process.exit(1); });
