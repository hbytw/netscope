// 真机 overview 验证：Top 设备数量 + 单位统一（MB/s）
import { chromium } from 'playwright-core';
import { CONFIG, BROWSER_ARGS, resolveBrowserPath } from './config.mjs';
const browserPath = resolveBrowserPath();
const browser = await chromium.launch({ executablePath: browserPath, headless: true, args: BROWSER_ARGS });
try {
  const ctx = await browser.newContext({ viewport: { width: 1600, height: 900 }, locale: 'zh-CN' });
  const page = await ctx.newPage();
  const errs = [];
  page.on('console', (m) => { if (m.type() === 'error') errs.push('console: ' + m.text().slice(0, 180)); });
  page.on('pageerror', (e) => errs.push('pageerror: ' + e.message.slice(0, 180)));
  await page.goto(CONFIG.baseUrl + '/index.html', { waitUntil: 'domcontentloaded', timeout: 30000 });
  await page.waitForTimeout(1200);
  if (await page.locator('#login-pwd').count()) {
    await page.locator('#login-pwd').first().fill(CONFIG.password);
    await page.locator('.login-form button').first().click();
    await page.waitForTimeout(3000);
  }
  await page.waitForTimeout(4000);
  // 单位检查：页面文本里 Mb/s vs MB/s
  const text = await page.evaluate(() => document.body.innerText);
  const mbPerSec = (text.match(/MB\/s/g) || []).length;
  const mbps = (text.match(/Mb\/s/g) || []).length;
  const mbps2 = (text.match(/Mbps/g) || []).length;
  console.log('[unit] MB/s=', mbPerSec, 'Mb/s=', mbps, 'Mbps=', mbps2);
  // 检查是否有 bps 残留（比特）
  console.log('[unit] 比特残留 bps=', (text.match(/\d+\s*bps\b/g) || []).length, 'Kbps=', (text.match(/Kbps/g) || []).length);
  console.log('[errors]', errs.length); errs.forEach((e) => console.log('  ' + e));
} finally { await browser.close(); }
