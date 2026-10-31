// 观澜 NetScope · 前端 mock 检查（traffic 页：URL 列表 / 连接详情 / 流向列）
import fs from 'node:fs';
import path from 'node:path';
import http from 'node:http';
import { chromium } from 'playwright-core';
import { BROWSER_ARGS, resolveBrowserPath } from './config.mjs';

const webDir = path.resolve(import.meta.dirname, '..', '..', 'app', 'web');
const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.json': 'application/json', '.svg': 'image/svg+xml' };
const server = http.createServer((req, res) => {
  const u = new URL(req.url, 'http://x');
  let p = path.join(webDir, decodeURIComponent(u.pathname));
  if (u.pathname === '/') p = path.join(webDir, 'index.html');
  if (!p.startsWith(webDir) || !fs.existsSync(p) || fs.statSync(p).isDirectory()) { res.writeHead(404); res.end(); return; }
  res.writeHead(200, { 'Content-Type': MIME[path.extname(p)] || 'application/octet-stream' });
  res.end(fs.readFileSync(p));
});
await new Promise((r) => server.listen(0, '127.0.0.1', r));
const port = server.address().port;
const url = `http://127.0.0.1:${port}/index.html?mock=1#/traffic`;

const browserPath = resolveBrowserPath();
if (!browserPath) { console.error('[FATAL] 未找到 Chrome'); process.exit(2); }
const errs = [];
const browser = await chromium.launch({ executablePath: browserPath, headless: true, args: BROWSER_ARGS });
try {
  const ctx = await browser.newContext({ viewport: { width: 1600, height: 900 }, deviceScaleFactor: 1, locale: 'zh-CN' });
  const page = await ctx.newPage();
  page.on('console', (m) => { if (m.type() === 'error') errs.push('console: ' + m.text().slice(0, 260)); });
  page.on('pageerror', (e) => errs.push('pageerror: ' + e.message.slice(0, 260)));

  await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 30000 });
  await page.waitForTimeout(3500);

  // URL 列表卡
  const urlCard = await page.locator('text=最近访问 URL').count();
  const urlTbl = await page.locator('.table').count();
  console.log(`[url-list] 卡片=${urlCard} 表=${urlTbl}`);

  // 连接表存在
  const connTbl = await page.locator('text=实时连接').count();
  console.log(`[conn] 实时连接卡=${connTbl}`);

  // 点击连接行弹详情（若 mock 有连接）
  const row = await page.locator('.table tbody tr').count();
  console.log(`[conn-rows] ${row}`);
  if (row > 0) {
    await page.locator('.table tbody tr').first().click();
    await page.waitForTimeout(600);
    const detail = await page.locator('text=连接详情').count();
    console.log(`[conn-detail] 弹窗=${detail}`);
  }

  console.log(`[errors] ${errs.length}`);
  errs.forEach((e) => console.log('  ' + e));
} finally {
  await browser.close();
  server.close();
}
