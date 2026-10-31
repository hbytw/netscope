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
  await p.evaluate(() => { location.hash = '#/traffic'; });
  await p.waitForTimeout(4500);
  // 找到 pager 容器（含"第 x / y 页"文本）并读其按钮
  const pager = await p.evaluate(() => {
    const spans = [...document.querySelectorAll('span')].filter((s) => /第\s*\d+\s*\/\s*\d+\s*页/.test(s.textContent));
    return spans.map((s) => ({
      info: s.textContent.trim(),
      btns: s.parentElement ? s.parentElement.querySelectorAll('button').length : 0,
      disabledNext: s.parentElement ? [...s.parentElement.querySelectorAll('button')].map((b) => b.disabled) : []
    }));
  });
  console.log('[分页器]', JSON.stringify(pager));
  // 点下一页：取最后一个 pager 的第二个按钮
  const clicked = await p.evaluate(() => {
    const spans = [...document.querySelectorAll('span')].filter((s) => /第\s*\d+\s*\/\s*\d+\s*页/.test(s.textContent));
    if (!spans.length) return 'no-pager';
    const last = spans[spans.length - 1].parentElement;
    const btns = [...last.querySelectorAll('button')];
    const next = btns[btns.length - 1];
    if (!next || next.disabled) return 'next-disabled';
    next.click();
    return 'clicked';
  });
  await p.waitForTimeout(1200);
  const after = await p.evaluate(() => {
    const spans = [...document.querySelectorAll('span')].filter((s) => /第\s*\d+\s*\/\s*\d+\s*页/.test(s.textContent));
    return spans.map((s) => s.textContent.trim());
  });
  console.log('[分页操作]', clicked, '[分页后]', JSON.stringify(after));
  // 表格内容
  const tables = await p.evaluate(() => [...document.querySelectorAll('table')].map((t) => ({
    rows: t.querySelectorAll('tbody tr').length,
    head: [...t.querySelectorAll('thead th')].map((th) => th.textContent.trim()).slice(0, 4),
    first: t.querySelector('tbody tr')?.textContent?.trim().slice(0, 50)
  })));
  console.log('[表格]', JSON.stringify(tables));
  await p.screenshot({ path: 'shot-final-traffic.png', fullPage: false });
  await p.evaluate(() => { location.hash = '#/overview'; });
  await p.waitForTimeout(4000);
  await p.screenshot({ path: 'shot-final-overview.png', fullPage: false });
  console.log('[errors]', errs.length, errs.slice(0, 3).join(' || '));
} finally { await b.close(); }
