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
const url = `http://127.0.0.1:${server.address().port}/index.html?mock=1#/traffic`;
const b = await chromium.launch({ executablePath: resolveBrowserPath(), headless: true, args: BROWSER_ARGS });
try {
  const c = await b.newContext({ viewport: { width: 1600, height: 1000 }, locale: 'zh-CN' });
  const p = await c.newPage();
  const errs = [];
  p.on('pageerror', (e) => errs.push(e.message.slice(0, 200)));
  p.on('console', (m) => { if (m.type() === 'error') errs.push('console: ' + m.text().slice(0, 160)); });
  await p.goto(url, { waitUntil: 'domcontentloaded' });
  await p.waitForTimeout(3500);
  // 找 URL 表头
  const heads = await p.evaluate(() => [...document.querySelectorAll('table thead th')].map((t) => t.textContent.trim()));
  console.log('[headers]', JSON.stringify(heads));
  // 点击 URL 表第一行
  const urlTable = p.locator('table').first();
  await urlTable.locator('tbody tr').first().click();
  await p.waitForTimeout(700);
  const dlg = await p.evaluate(() => {
    const m = document.querySelector('.modal, [class*=modal]');
    return m ? m.innerText.slice(0, 500).replace(/\n+/g, ' | ') : 'NO MODAL';
  });
  console.log('[detail]', dlg);
  await p.screenshot({ path: 'shot-traffic-url.png', fullPage: false });
  console.log('[errors]', errs.length, errs.slice(0, 3).join(' || '));
} finally { await b.close(); server.close(); }
