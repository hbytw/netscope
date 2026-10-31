import { chromium } from 'playwright-core';
import { CONFIG, BROWSER_ARGS, resolveBrowserPath } from './config.mjs';
const b = await chromium.launch({ executablePath: resolveBrowserPath(), headless: true, args: BROWSER_ARGS });
try {
  const c = await b.newContext({ viewport: { width: 1600, height: 1000 }, locale: 'zh-CN' });
  const p = await c.newPage();
  const errs = [];
  p.on('pageerror', (e) => errs.push(e.message.slice(0, 150)));
  await p.goto(CONFIG.baseUrl + '/index.html', { waitUntil: 'domcontentloaded' });
  await p.waitForTimeout(1200);
  if (await p.locator('#login-pwd').count()) {
    await p.locator('#login-pwd').first().fill(CONFIG.password);
    await p.locator('.login-form button').first().click();
    await p.waitForTimeout(2500);
  }
  await p.evaluate(() => { location.hash = '#/behavior'; });
  await p.waitForTimeout(3500);
  const info = await p.evaluate(() => {
    const cards = [...document.querySelectorAll('.card')].map((c) => {
      const r = c.getBoundingClientRect();
      return { t: (c.querySelector('.card-title')?.textContent || '').trim(), y: Math.round(r.y), h: Math.round(r.height), w: Math.round(r.width) };
    });
    const page = document.querySelector('.page');
    return { cards: cards.filter((x) => x.t), pageW: page ? Math.round(page.getBoundingClientRect().width) : 0 };
  });
  console.log(JSON.stringify(info));
  await p.screenshot({ path: 'shot-beh.png', fullPage: false });
  console.log('[errors]', errs.length);
} finally { await b.close(); }
