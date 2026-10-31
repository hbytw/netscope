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
  await p.waitForTimeout(4000);
  const grab = () => p.evaluate(() => {
    const vals = [...document.querySelectorAll('.chart-legend .legend-val')].map((x) => x.textContent);
    const head = document.querySelector('.card .fs-12')?.textContent || '';
    return { vals: vals.slice(0, 2), last: window.__glTick?.trendPoint?.t || 0 };
  });
  const s0 = await grab();
  await p.waitForTimeout(2500);
  const s1 = await grab();
  await p.waitForTimeout(2500);
  const s2 = await grab();
  console.log('[t0]', JSON.stringify(s0));
  console.log('[t1]', JSON.stringify(s1));
  console.log('[t2]', JSON.stringify(s2));
  console.log('[2s-update]', s0.vals[0] !== s1.vals[0] || s1.vals[0] !== s2.vals[0]);
  console.log('[tick-advance]', s0.last, '->', s2.last);
  await p.screenshot({ path: 'shot-traffic-2s.png', fullPage: false });
  console.log('[errors]', errs.length, errs.slice(0, 3).join(' || '));
} finally { await b.close(); }
