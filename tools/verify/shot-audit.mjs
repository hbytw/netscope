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
  const info = await p.evaluate(() => {
    const legend = [...document.querySelectorAll('.chart-legend .legend-item')].slice(0, 6).map((x) => x.innerText.replace(/\n/g, ' '));
    const head = document.querySelector('.card')?.innerText.slice(0, 120).replace(/\n+/g, ' | ');
    return { legend, head };
  });
  console.log('[head]', info.head);
  console.log('[legend]', JSON.stringify(info.legend));
  await p.screenshot({ path: 'shot-traffic-audit.png', fullPage: false });
  // 切换堆叠模式再看
  await p.locator('.switch, [class*=switch]').first().click().catch(() => {});
  await p.waitForTimeout(1200);
  await p.screenshot({ path: 'shot-traffic-stacked.png', fullPage: false });
  console.log('[errors]', errs.length, errs.slice(0, 3).join(' || '));
} finally { await b.close(); }
