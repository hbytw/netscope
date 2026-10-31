// mock 前端检查 security 页（风险详情/威胁情报/白名单）
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
const bp = resolveBrowserPath();
const errs = [];
const b = await chromium.launch({ executablePath: bp, headless: true, args: BROWSER_ARGS });
try {
  const c = await b.newContext({ viewport: { width: 1600, height: 900 }, locale: 'zh-CN' });
  const p = await c.newPage();
  p.on('console', (m) => { if (m.type() === 'error') errs.push('console: ' + m.text().slice(0, 200)); });
  p.on('pageerror', (e) => errs.push('pageerror: ' + e.message.slice(0, 200)));
  await p.goto(url, { waitUntil: 'domcontentloaded', timeout: 30000 });
  await p.waitForTimeout(4000);
  console.log('[risk] 设备风险排行卡=', await p.locator('text=设备风险排行').count());
  console.log('[threat] 威胁情报查询卡=', await p.locator('text=威胁情报查询').count());
  console.log('[wl] 告警白名单卡=', await p.locator('text=告警白名单').count());
  // 威胁情报查询：输入命中
  const tq = await p.locator('input[type=search]').first();
  if (await tq.count()) {
    await tq.fill('minexmr');
    await p.waitForTimeout(700);
    console.log('[tq-hit] 命中项=', await p.locator('text=pool.minexmr.com').count(), '命中徽标=', await p.locator('text=命中').count());
    await tq.fill('zzz-none');
    await p.waitForTimeout(700);
    console.log('[tq-miss] 未命中提示=', await p.locator('text=未命中').count());
  }
  // 点风险行看详情
  const riskRow = await p.locator('.risk-row').count();
  console.log('[risk-row]', riskRow);
  if (riskRow > 0) {
    await p.locator('.risk-row').first().click();
    await p.waitForTimeout(500);
    console.log('[risk-detail] 风险详情弹窗=', await p.locator('text=风险详情').count());
    await p.keyboard.press('Escape');
  }
  console.log('[errors]', errs.length); errs.forEach((e) => console.log('  ' + e));
} finally { await b.close(); server.close(); }
