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
  const heads = await p.evaluate(() => [...document.querySelectorAll('table thead th')].slice(0, 8).map((t) => t.textContent.trim()));
  console.log('[headers]', JSON.stringify(heads));
  // 源主机列内容
  const src = await p.evaluate(() => {
    const tbl = document.querySelector('table');
    if (!tbl) return 'NO TABLE';
    const rows = [...tbl.querySelectorAll('tbody tr')].slice(0, 4);
    return rows.map((r) => [...r.querySelectorAll('td')].slice(0, 5).map((td) => td.innerText.replace(/\n/g, '/')).join(' | '));
  });
  console.log('[rows]', JSON.stringify(src, null, 1));
  await p.locator('table').first().locator('tbody tr').first().click();
  await p.waitForTimeout(800);
  const dlg = await p.evaluate(() => {
    const m = document.querySelector('[class*=modal]');
    return m ? m.innerText.slice(0, 400).replace(/\n+/g, ' | ') : 'NO MODAL';
  });
  console.log('[detail]', dlg);
  await p.screenshot({ path: 'shot-traffic-real.png', fullPage: false });
  console.log('[errors]', errs.length, errs.slice(0, 3).join(' || '));
} finally { await b.close(); }
