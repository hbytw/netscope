// 本机冒烟测试：验证 playwright-core + 系统 Chrome + WebGL(SwiftShader) 可用
// 不访问路由器，只打开本机 3D 预览页
import path from 'node:path';
import fs from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { chromium } from 'playwright-core';
import { CONFIG, BROWSER_ARGS, resolveBrowserPath, clip } from './config.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, '..', '..');
const preview = path.join(repoRoot, 'app', 'web', 'js', '3d', '_preview.html');

const browserPath = resolveBrowserPath();
if (!browserPath) {
  console.error('[FATAL] 未找到 Chrome/Edge');
  process.exit(2);
}
console.log(`[info] 浏览器: ${browserPath}`);
console.log(`[info] 预览页: ${preview}`);
if (!fs.existsSync(preview)) {
  console.error('[FATAL] 预览页不存在');
  process.exit(2);
}

const errs = [];
let browser;
try {
  browser = await chromium.launch({ executablePath: browserPath, headless: true, args: BROWSER_ARGS });
  const ctx = await browser.newContext({
    viewport: { width: 1600, height: 900 },
    deviceScaleFactor: 2,
  });
  const page = await ctx.newPage();
  page.on('console', (m) => { if (m.type() === 'error') errs.push({ kind: 'console', text: clip(m.text(), 400) }); });
  page.on('pageerror', (e) => errs.push({ kind: 'pageerror', text: clip(e.message, 400) }));

  const target = process.env.SMOKE_URL || pathToFileURL(preview).href;
  await page.goto(target, { waitUntil: 'domcontentloaded', timeout: 30000 });
  await page.waitForTimeout(6000);

  // WebGL 能力探测
  const gl = await page.evaluate(() => {
    const c = document.createElement('canvas');
    const g = c.getContext('webgl2') || c.getContext('webgl');
    if (!g) return { ok: false };
    const dbg = g.getExtension('WEBGL_debug_renderer_info');
    return {
      ok: true,
      version: g.getParameter(g.VERSION),
      renderer: dbg ? g.getParameter(dbg.UNMASKED_RENDERER_WEBGL) : g.getParameter(g.RENDERER),
      vendor: dbg ? g.getParameter(dbg.UNMASKED_VENDOR_WEBGL) : g.getParameter(g.VENDOR),
    };
  });
  console.log('[WebGL]', JSON.stringify(gl));

  // 页面真实 canvas（非探测用）着色统计
  const render = await page.evaluate(() => {
    const cs = Array.from(document.querySelectorAll('canvas'));
    if (!cs.length) return { count: 0 };
    const c = cs[cs.length - 1];
    const w = c.width, h = c.height;
    try {
      const g = c.getContext('webgl2') || c.getContext('webgl');
      if (g) {
        const px = new Uint8Array(w * h * 4);
        g.readPixels(0, 0, w, h, g.RGBA, g.UNSIGNED_BYTE, px);
        let colored = 0;
        for (let i = 0; i < px.length; i += 4) {
          const r = px[i], gg = px[i + 1], b = px[i + 2];
          if (Math.max(r, gg, b) - Math.min(r, gg, b) > 12) colored++;
        }
        let urlLen = 0;
        try { urlLen = c.toDataURL('image/png').length; } catch { /* ignore */ }
        return { count: cs.length, w, h, colorRatio: colored / (px.length / 4), dataUrlBytes: urlLen };
      }
    } catch (e) { return { count: cs.length, error: String(e) }; }
    return { count: cs.length, w, h };
  });
  console.log('[Canvas]', JSON.stringify(render));

  const out = path.join(repoRoot, 'temp', 'smoke-3d.png');
  fs.mkdirSync(path.dirname(out), { recursive: true });
  await page.screenshot({ path: out });
  const size = fs.existsSync(out) ? fs.statSync(out).size : 0;
  console.log(`[ok] 截图 ${out} (${size} bytes)`);

  console.log(`[summary] console/page 错误数: ${errs.length}`);
  if (errs.length) errs.forEach((e) => console.log(`   - [${e.kind}] ${e.text}`));

  await ctx.close();
} catch (e) {
  console.error('[FATAL]', e.message);
  process.exitCode = 1;
} finally {
  try { if (browser) await browser.close(); } catch { /* ignore */ }
}
