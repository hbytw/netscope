import fs from 'node:fs';
import path from 'node:path';
import http from 'node:http';
import { chromium } from 'playwright-core';
import { BROWSER_ARGS, resolveBrowserPath } from './config.mjs';
const webDir = path.resolve(import.meta.dirname, '..', '..', 'app', 'web');
const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8' };
const server = http.createServer((req, res) => {
  const u = new URL(req.url, 'http://x');
  let p = path.join(webDir, decodeURIComponent(u.pathname));
  if (u.pathname === '/') p = path.join(webDir, 'index.html');
  if (!p.startsWith(webDir) || !fs.existsSync(p) || fs.statSync(p).isDirectory()) { res.writeHead(404); res.end(); return; }
  res.writeHead(200, { 'Content-Type': MIME[path.extname(p)] || 'application/octet-stream' });
  res.end(fs.readFileSync(p));
});
await new Promise((r) => server.listen(0, '127.0.0.1', r));
const url = `http://127.0.0.1:${server.address().port}/index.html?mock=1#/security`;
const b = await chromium.launch({ executablePath: resolveBrowserPath(), headless: true, args: BROWSER_ARGS });
try {
  const c = await b.newContext({ viewport: { width: 1600, height: 1000 }, locale: 'zh-CN' });
  const p = await c.newPage();
  const errs = [];
  p.on('pageerror', (e) => errs.push(e.message.slice(0, 200)));
  await p.goto(url, { waitUntil: 'domcontentloaded' });
  await p.waitForTimeout(3500);
  await p.screenshot({ path: 'shot-sec-mock.png', fullPage: false });
  await p.screenshot({ path: 'shot-sec-mock-full.png', fullPage: true });
  // 卡片位置/高度
  const info = await p.evaluate(() => {
    const cards = [...document.querySelectorAll('.card')].map((c) => {
      const r = c.getBoundingClientRect();
      const t = (c.querySelector('.card-title, .card-h, h3')?.textContent || c.textContent.slice(0, 20)).trim().replace(/\s+/g, ' ');
      return { t, x: Math.round(r.x), y: Math.round(r.y), w: Math.round(r.width), h: Math.round(r.height) };
    });
    return { cards, bodyH: document.body.scrollHeight };
  });
  console.log(JSON.stringify(info, null, 1));
  console.log('[errors]', errs.length, errs.join(' || '));
} finally { await b.close(); server.close(); }
