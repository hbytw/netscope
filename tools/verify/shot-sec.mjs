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
  await p.evaluate(() => { location.hash = '#/security'; });
  await p.waitForTimeout(3000);
  const empty = await p.evaluate(() => {
    const card = [...document.querySelectorAll('.card')].find((x) => x.textContent.includes('威胁情报查询'));
    return card ? card.innerText.replace(/\n+/g, ' | ') : 'NO CARD';
  });
  console.log('[empty]', empty.slice(0, 300));
  await p.locator('input[type=search]').first().fill('minexmr');
  await p.waitForTimeout(1500);
  const hit = await p.evaluate(() => {
    const card = [...document.querySelectorAll('.card')].find((x) => x.textContent.includes('威胁情报查询'));
    return card ? card.innerText.replace(/\n+/g, ' | ') : 'NO CARD';
  });
  console.log('[hit]', hit.slice(0, 300));
  await p.screenshot({ path: 'shot-security-threat.png', fullPage: false });
  console.log('[shot] saved');
  console.log('[errors]', errs.length, errs.slice(0, 3).join(' || '));
} finally { await b.close(); }
