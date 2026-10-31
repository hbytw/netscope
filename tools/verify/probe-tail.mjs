import { chromium } from 'playwright-core';
import { CONFIG, BROWSER_ARGS, resolveBrowserPath } from './config.mjs';
const b = await chromium.launch({ executablePath: resolveBrowserPath(), headless: true, args: BROWSER_ARGS });
try {
  const c = await b.newContext({ viewport: { width: 1600, height: 1000 }, locale: 'zh-CN' });
  const p = await c.newPage();
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
    const cs = [...document.querySelectorAll('canvas')];
    const cv = cs[0];
    if (!cv) return { err: 'no canvas' };
    const ctx = cv.getContext('2d');
    const W = cv.width, H = cv.height;
    const img = ctx.getImageData(0, 0, W, H).data;
    // 统计尾部 8% 区域内的非透明像素行分布
    const x0 = Math.floor(W * 0.92);
    const rows = [];
    for (let y = 0; y < H; y++) {
      let cnt = 0;
      for (let x = x0; x < W; x++) {
        const a = img[(y * W + x) * 4 + 3];
        if (a > 30) cnt++;
      }
      if (cnt > 0) rows.push(y);
    }
    const span = rows.length ? (rows[rows.length - 1] - rows[0] + 1) : 0;
    return { W, H, rows: rows.length, span, spanPct: +(span / H * 100).toFixed(1) };
  });
  const a1 = await probe();
  await p.waitForTimeout(4000);
  const a2 = await probe();
  console.log('[tail-probe-1]', JSON.stringify(a1));
  console.log('[tail-probe-2]', JSON.stringify(a2));
  console.log('[平线判定]', a1.spanPct !== undefined && a1.spanPct < 12 ? '疑似平台(纵向跨度小)' : '正常(纵向有起伏)');
} finally { await b.close(); }
