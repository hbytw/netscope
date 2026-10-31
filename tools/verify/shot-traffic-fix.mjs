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
  await p.waitForTimeout(3500);
  await p.screenshot({ path: 'shot-traffic-fixed.png', fullPage: false });
  // 读接口再确认后端 series 无异常重复
  const api = await p.evaluate(async () => {
    const r = await fetch('/api/traffic/domains?range=1h&limit=1', { credentials: 'include' });
    return r.status;
  });
  console.log('[api]', api, '[errors]', errs.length, errs.slice(0, 3).join(' || '));
} finally { await b.close(); }
