import { chromium } from 'playwright-core';
import { CONFIG, BROWSER_ARGS, resolveBrowserPath } from './config.mjs';
const b = await chromium.launch({ executablePath: resolveBrowserPath(), headless: true, args: BROWSER_ARGS });
try {
  const c = await b.newContext({ viewport: { width: 1600, height: 1000 }, locale: 'zh-CN' });
  const p = await c.newPage();
  const errs = [];
  p.on('pageerror', (e) => errs.push(e.message.slice(0, 160)));
  p.on('console', (m) => { if (m.type() === 'error') errs.push('console: ' + m.text().slice(0, 140)); });
  await p.goto(CONFIG.baseUrl + '/index.html', { waitUntil: 'domcontentloaded' });
  await p.waitForTimeout(1200);
  if (await p.locator('#login-pwd').count()) {
    await p.locator('#login-pwd').first().fill(CONFIG.password);
    await p.locator('.login-form button').first().click();
    await p.waitForTimeout(2500);
  }
  // 总览
  await p.evaluate(() => { location.hash = '#/overview'; });
  await p.waitForTimeout(4000);
  const ov = await p.evaluate(() => {
    const sw = [...document.querySelectorAll('.legend-swatch')].map((e) => getComputedStyle(e).backgroundColor);
    const kpi = [...document.querySelectorAll('.kpi-value, .kpi-val')].slice(0, 2).map((e) => e.textContent.trim());
    return { swatches: sw.slice(0, 4), kpi };
  });
  console.log('[overview 分类色]', JSON.stringify(ov.swatches));
  console.log('[overview KPI]', JSON.stringify(ov.kpi));
  // 流量页分页
  await p.evaluate(() => { location.hash = '#/traffic'; });
  await p.waitForTimeout(4000);
  const before = await p.evaluate(() => document.querySelectorAll('table tbody tr').length);
  const pagerInfo = await p.evaluate(() => {
    const btns = [...document.querySelectorAll('.pager button')].map((b) => b.textContent.trim());
    return btns;
  });
  await p.evaluate(() => {
    const b = [...document.querySelectorAll('.pager button')].find((x) => /下一|›|>/.test(x.textContent));
    if (b) b.click();
  });
  await p.waitForTimeout(1200);
  const after = await p.evaluate(() => ({
    rows: document.querySelectorAll('table tbody tr').length,
    txt: document.querySelector('table tbody tr')?.textContent?.trim().slice(0, 40),
    page: [...document.querySelectorAll('.pager .active, .pager button.active')].map((x) => x.textContent.trim())
  }));
  console.log('[分页按钮]', JSON.stringify(pagerInfo));
  console.log('[分页前]', before, '[分页后]', JSON.stringify(after));
  await p.screenshot({ path: 'shot-audit-traffic.png', fullPage: false });
  // 安全页
  await p.evaluate(() => { location.hash = '#/security'; });
  await p.waitForTimeout(3500);
  await p.screenshot({ path: 'shot-audit-security.png', fullPage: false });
  console.log('[errors]', errs.length, errs.slice(0, 4).join(' || '));
} finally { await b.close(); }
