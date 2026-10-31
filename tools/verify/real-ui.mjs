// 观澜 NetScope · 真机前端功能验收（192.168.1.254:8088）
// 验证：traffic 页 URL 列表/流向列/连接详情弹窗；security 页白名单卡片；screen 拓扑
import path from 'node:path';
import { chromium } from 'playwright-core';
import { CONFIG, BROWSER_ARGS, resolveBrowserPath } from './config.mjs';

const base = CONFIG.baseUrl;
const browserPath = resolveBrowserPath();
if (!browserPath) { console.error('[FATAL] 未找到 Chrome'); process.exit(2); }
const errs = [];
const browser = await chromium.launch({ executablePath: browserPath, headless: true, args: BROWSER_ARGS });
try {
  const ctx = await browser.newContext({ viewport: { width: 1600, height: 900 }, deviceScaleFactor: 1, locale: 'zh-CN' });
  const page = await ctx.newPage();
  page.on('console', (m) => { if (m.type() === 'error') errs.push('console: ' + m.text().slice(0, 220)); });
  page.on('pageerror', (e) => errs.push('pageerror: ' + e.message.slice(0, 220)));

  // 登录
  await page.goto(base + '/index.html', { waitUntil: 'domcontentloaded', timeout: 30000 });
  await page.waitForTimeout(1500);
  if (await page.locator('#login-pwd').count()) {
    await page.locator('#login-pwd').first().fill(CONFIG.password);
    await page.locator('.login-form button').first().click();
    await page.waitForTimeout(3000);
  }

  // 1. traffic 页：URL 列表 + 流向列 + 连接详情
  await page.goto(base + '/index.html#/traffic', { waitUntil: 'domcontentloaded', timeout: 30000 });
  await page.waitForTimeout(6000);
  const urlCard = await page.locator('text=最近访问 URL').count();
  console.log(`[traffic] URL列表卡=${urlCard}`);
  // 连接表行（table 组件 tbody tr，含 URL 表 + 连接表）
  const rows = await page.locator('table tbody tr').count();
  console.log(`[traffic] 表格总行=${rows}`);
  // 连接表是最后一个 table，点其第一行看详情
  const connTbls = await page.locator('table').count();
  console.log(`[traffic] table数=${connTbls}`);
  if (connTbls > 0) {
    const connTbl = page.locator('table').last();
    const firstRow = connTbl.locator('tbody tr').first();
    if (await firstRow.count()) {
      await firstRow.click();
      await page.waitForTimeout(700);
      const detail = await page.locator('text=连接详情').count();
      console.log(`[traffic] 连接详情弹窗=${detail}`);
      await page.keyboard.press('Escape');
      await page.waitForTimeout(300);
    }
  }

  // 2. security 页：白名单卡片 + 封禁列表
  await page.goto(base + '/index.html#/security', { waitUntil: 'domcontentloaded', timeout: 30000 });
  await page.waitForTimeout(3500);
  const wlCard = await page.locator('text=告警白名单').count();
  const blockCard = await page.locator('text=封禁 / 限速列表').count();
  console.log(`[security] 白名单卡=${wlCard} 封禁卡=${blockCard}`);

  // 3. screen 拓扑
  await page.goto(base + '/screen.html', { waitUntil: 'domcontentloaded', timeout: 30000 });
  await page.waitForTimeout(5000);
  const gl = await page.evaluate(() => {
    const c = document.querySelector('#gl-screen-host canvas');
    return { hasCanvas: !!c };
  });
  console.log(`[screen] canvas=${gl.hasCanvas}`);

  console.log(`[errors] ${errs.length}`);
  errs.forEach((e) => console.log('  ' + e));
} finally {
  await browser.close();
}
