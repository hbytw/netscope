// 诊断：真机 traffic 连接表为何 0 行
import { chromium } from 'playwright-core';
import { CONFIG, BROWSER_ARGS, resolveBrowserPath } from './config.mjs';
const browserPath = resolveBrowserPath();
const browser = await chromium.launch({ executablePath: browserPath, headless: true, args: BROWSER_ARGS });
try {
  const ctx = await browser.newContext({ viewport: { width: 1600, height: 900 }, locale: 'zh-CN' });
  const page = await ctx.newPage();
  page.on('console', (m) => { if (m.type() === 'error' || m.type() === 'warning') console.log('CONSOLE[' + m.type() + ']', m.text().slice(0, 160)); });
  page.on('pageerror', (e) => console.log('PAGEERROR', e.message.slice(0, 160)));
  await page.goto(CONFIG.baseUrl + '/index.html', { waitUntil: 'domcontentloaded', timeout: 30000 });
  await page.waitForTimeout(1500);
  if (await page.locator('#login-pwd').count()) {
    await page.locator('#login-pwd').first().fill(CONFIG.password);
    await page.locator('.login-form button').first().click();
    await page.waitForTimeout(3000);
  }
  await page.goto(CONFIG.baseUrl + '/index.html#/traffic', { waitUntil: 'domcontentloaded', timeout: 30000 });
  await page.waitForTimeout(7000);
  const info = await page.evaluate(() => {
    const tbls = document.querySelectorAll('.table');
    const tbodies = document.querySelectorAll('table tbody');
    return {
      tables: tbls.length,
      tbodyRows: [...tbodies].map((t) => t.querySelectorAll('tr').length),
      anyTr: document.querySelectorAll('table tbody tr').length,
      urlCard: !!document.querySelector('.card'),
      bodyText: document.body.innerText.slice(0, 200)
    };
  });
  console.log('INFO', JSON.stringify(info, null, 1));
} finally { await browser.close(); }
