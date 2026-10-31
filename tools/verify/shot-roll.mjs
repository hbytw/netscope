import { chromium } from 'playwright-core';
import { CONFIG, BROWSER_ARGS, resolveBrowserPath } from './config.mjs';
const b = await chromium.launch({ executablePath: resolveBrowserPath(), headless: true, args: BROWSER_ARGS });
try {
  const c = await b.newContext({ viewport: { width: 1600, height: 1000 }, locale: 'zh-CN' });
  const p = await c.newPage();
  const errs = [];
  p.on('pageerror', (e) => errs.push(e.message.slice(0, 200)));
  p.on('console', (m) => { if (m.type() === 'error') errs.push('console: ' + m.text().slice(0, 160)); });
  await p.goto(CONFIG.baseUrl + '/index.html', { waitUntil: 'domcontentloaded' });
  await p.waitForTimeout(1200);
  if (await p.locator('#login-pwd').count()) {
    await p.locator('#login-pwd').first().fill(CONFIG.password);
    await p.locator('.login-form button').first().click();
    await p.waitForTimeout(2500);
  }
  await p.evaluate(() => { location.hash = '#/traffic'; });
  await p.waitForTimeout(5000);
  const probe = () => p.evaluate(() => {
    const cv = document.querySelector('canvas');
    const ctx = cv.getContext('2d');
    const W = cv.width, H = cv.height;
    const img = ctx.getImageData(0, 0, W, H).data;
    let hash = 0, changed = 0;
    const px = new Uint8Array(W * H);
    for (let y = 0; y < H; y++) {
      for (let x = 0; x < W; x++) {
        const i = (y * W + x) * 4;
        const a = img[i + 3] > 30 ? 1 : 0;
        px[y * W + x] = a;
        hash = (hash * 31 + a) % 1000000007;
      }
    }
    const x0 = Math.floor(W * 0.9);
    const rows = [];
    for (let y = 0; y < H; y++) {
      for (let x = x0; x < W; x++) { if (px[y * W + x]) { rows.push(y); break; } }
    }
    const span = rows.length ? rows[rows.length - 1] - rows[0] + 1 : 0;
    return { hash, span, spanPct: +(span / H * 100).toFixed(1), W, H };
  });
  const s0 = await probe();
  await p.waitForTimeout(3000);
  const s1 = await probe();
  await p.waitForTimeout(3000);
  const s2 = await probe();
  console.log('[s0]', JSON.stringify(s0));
  console.log('[s1]', JSON.stringify(s1));
  console.log('[s2]', JSON.stringify(s2));
  console.log('[整图在动]', s0.hash !== s1.hash && s1.hash !== s2.hash);
  console.log('[尾部纵向跨度]', s1.spanPct + '%', s1.spanPct > 12 ? '正常' : '疑似平台');
  console.log('[errors]', errs.length, errs.slice(0, 3).join(' || '));
  await p.screenshot({ path: 'shot-traffic-roll.png', fullPage: false });
} finally { await b.close(); }
