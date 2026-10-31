// 真机 3D 拓扑流向标签验证
import { chromium } from 'playwright-core';
import { CONFIG, BROWSER_ARGS, resolveBrowserPath } from './config.mjs';
const browserPath = resolveBrowserPath();
const browser = await chromium.launch({ executablePath: browserPath, headless: true, args: BROWSER_ARGS });
try {
  const ctx = await browser.newContext({ viewport: { width: 1600, height: 900 }, locale: 'zh-CN' });
  const page = await ctx.newPage();
  const errs = [];
  page.on('console', (m) => { if (m.type() === 'error') errs.push('console: ' + m.text().slice(0, 200)); });
  page.on('pageerror', (e) => errs.push('pageerror: ' + e.message.slice(0, 200)));
  // 登录拿 cookie
  await page.goto(CONFIG.baseUrl + '/index.html', { waitUntil: 'domcontentloaded', timeout: 30000 });
  await page.waitForTimeout(1200);
  if (await page.locator('#login-pwd').count()) {
    await page.locator('#login-pwd').first().fill(CONFIG.password);
    await page.locator('.login-form button').first().click();
    await page.waitForTimeout(3000);
  }
  // 3D 大屏
  await page.goto(CONFIG.baseUrl + '/screen.html', { waitUntil: 'domcontentloaded', timeout: 30000 });
  await page.waitForTimeout(8000);
  const info = await page.evaluate(() => {
    const canvas = document.querySelector('canvas');
    // 图例
    const legend = document.body.innerText.match(/流向图例[^]*?(?=\n\n)/)?.[0] || '';
    return {
      hasCanvas: !!canvas,
      legendHasProxy: /经代理/.test(document.body.innerText),
      legendHasZT: /ZeroTier/.test(document.body.innerText),
      bodyHasProxyBps: /MB\/s|KB\/s|GB\/s|B\/s/.test(document.body.innerText),
      textSample: document.body.innerText.slice(0, 300)
    };
  });
  console.log('[screen] canvas=', info.hasCanvas, '图例proxy=', info.legendHasProxy, '图例zt=', info.legendHasZT);
  console.log('[screen] 流量标签存在=', info.bodyHasProxyBps);
  const txt = await page.evaluate(() => document.body.innerText);
  console.log('[screen] MB/s=', (txt.match(/MB\/s/g) || []).length, 'Mb/s=', (txt.match(/Mb\/s/g) || []).length, 'Kb/s=', (txt.match(/Kb\/s/g) || []).length);
  console.log('[errors]', errs.length); errs.forEach((e) => console.log('  ' + e));
} finally { await browser.close(); }
