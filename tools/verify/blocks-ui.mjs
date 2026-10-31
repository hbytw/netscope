// 观澜 NetScope · 封禁列表 UI 本机 mock 验证（不访问路由器）
// 起静态服务 app/web → 加载 ?mock=1#/security → 检查封禁列表卡片 + 解封按钮
import fs from 'node:fs';
import path from 'node:path';
import http from 'node:http';
import { chromium } from 'playwright-core';
import { BROWSER_ARGS, resolveBrowserPath, ensureDir } from './config.mjs';

const repoRoot = path.resolve(import.meta.dirname, '..', '..');
const webDir = path.join(repoRoot, 'app', 'web');
const outDir = ensureDir(path.join(repoRoot, 'docs'));

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json',
  '.svg': 'image/svg+xml',
};

const server = http.createServer((req, res) => {
  const u = new URL(req.url, 'http://x');
  let p = path.join(webDir, decodeURIComponent(u.pathname));
  if (u.pathname === '/') p = path.join(webDir, 'index.html');
  if (!p.startsWith(webDir)) { res.writeHead(403); res.end(); return; }
  if (!fs.existsSync(p) || fs.statSync(p).isDirectory()) { res.writeHead(404); res.end('nf'); return; }
  res.writeHead(200, { 'Content-Type': MIME[path.extname(p)] || 'application/octet-stream' });
  res.end(fs.readFileSync(p));
});

await new Promise((r) => server.listen(0, '127.0.0.1', r));
const port = server.address().port;
const url = `http://127.0.0.1:${port}/index.html?mock=1#/security`;

const browserPath = resolveBrowserPath();
if (!browserPath) { console.error('[FATAL] 未找到 Chrome'); process.exit(2); }
console.log(`[info] 浏览器: ${browserPath}`);
console.log(`[info] 页面: ${url}`);

const errs = [];
const browser = await chromium.launch({ executablePath: browserPath, headless: true, args: BROWSER_ARGS });
try {
  const ctx = await browser.newContext({ viewport: { width: 1600, height: 900 }, deviceScaleFactor: 1, locale: 'zh-CN' });
  const page = await ctx.newPage();
  page.on('console', (m) => { if (m.type() === 'error') errs.push('console: ' + m.text().slice(0, 300)); });
  page.on('pageerror', (e) => errs.push('pageerror: ' + e.message.slice(0, 300)));

  await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 30000 });
  await page.waitForTimeout(3500);

  // 封禁列表卡片
  const card = await page.locator('.block-list').count();
  const title = await page.locator('text=封禁 / 限速列表').count();
  const rows = await page.locator('.block-row').count();
  const btns = await page.locator('.block-row button').count();
  console.log(`[blocks-card] 卡片=${card} 标题=${title} 行=${rows} 解封按钮=${btns}`);

  // 解封第一个
  if (rows > 0) {
    const before = await page.locator('.block-row').count();
    await page.locator('.block-row button').first().click();
    await page.waitForTimeout(1200);
    const after = await page.locator('.block-row').count();
    console.log(`[unblock] 点击前=${before} 点击后=${after}`);
  }

  // 空态
  const empty = await page.locator('text=当前无封禁').count();
  console.log(`[empty-state] 空态出现=${empty}`);

  console.log(`[errors] ${errs.length}`);
  errs.forEach((e) => console.log('  ' + e));
} finally {
  await browser.close();
  server.close();
}
