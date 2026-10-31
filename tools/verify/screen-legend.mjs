// 3D 图例分类占比检查（真机）
import { chromium } from 'playwright-core';
import { CONFIG, BROWSER_ARGS, resolveBrowserPath } from './config.mjs';
const browserPath = resolveBrowserPath();
const browser = await chromium.launch({ executablePath: browserPath, headless: true, args: BROWSER_ARGS });
try {
  const ctx = await browser.newContext({ viewport: { width: 1600, height: 900 }, locale: 'zh-CN' });
  const page = await ctx.newPage();
  await page.goto(CONFIG.baseUrl + '/index.html', { waitUntil: 'domcontentloaded', timeout: 30000 });
  await page.waitForTimeout(1200);
  if (await page.locator('#login-pwd').count()) {
    await page.locator('#login-pwd').first().fill(CONFIG.password);
    await page.locator('.login-form button').first().click();
    await page.waitForTimeout(3000);
  }
  await page.goto(CONFIG.baseUrl + '/screen.html', { waitUntil: 'domcontentloaded', timeout: 30000 });
  await page.waitForTimeout(8000);
  const legend = await page.evaluate(() => {
    const rows = [...document.querySelectorAll('.gl-legend-row')].map((r) => ({
      name: r.querySelector('.gl-legend-name')?.textContent,
      pct: r.querySelector('.gl-legend-pct')?.textContent
    }));
    return rows;
  });
  console.log('[legend]', JSON.stringify(legend));
} finally { await browser.close(); }
