// 观澜 NetScope · 验收截图
// 单次无头 Chrome 会话：登录 → 依次访问 7 个页面 → 截图 → 收集 console error / pageerror / requestfailed
// 用法：
//   node shots.mjs
//   GUANLAN_URL=http://192.168.1.254:8088 GUANLAN_PASS=guanlan2026 node shots.mjs
import fs from 'node:fs';
import path from 'node:path';
import { chromium } from 'playwright-core';
import { CONFIG, DOCS_DIR, BROWSER_ARGS, resolveBrowserPath, ensureDir, clip } from './config.mjs';

const outDir = ensureDir(path.join(DOCS_DIR));
const summaryFile = path.join(outDir, 'shots-summary.json');

const browserPath = resolveBrowserPath();
if (!browserPath) {
  console.error('[FATAL] 未找到 Chrome/Edge 可执行文件，请设置 GUANLAN_CHROME 或 GUANLAN_EDGE 环境变量。');
  process.exit(2);
}
console.log(`[info] 浏览器: ${browserPath}`);
console.log(`[info] 目标地址: ${CONFIG.baseUrl}`);

const issues = [];      // 页面级问题
const consoleErrors = [];
const pageErrors = [];
const requestFailures = [];
const sseNoise = [];
const shots = [];

function record(kind, payload) {
  const item = { kind, ...payload };
  if (kind === 'console') consoleErrors.push(item);
  else if (kind === 'pageerror') pageErrors.push(item);
  else if (kind === 'requestfailed') requestFailures.push(item);
  else if (kind === 'sseNoise') sseNoise.push(item);
  return item;
}

const browser = await chromium.launch({
  executablePath: browserPath,
  headless: true,
  args: BROWSER_ARGS,
});

let context;
let page;

try {
  context = await browser.newContext({
    viewport: CONFIG.viewport,
    deviceScaleFactor: CONFIG.deviceScaleFactor,
    ignoreHTTPSErrors: true,
    locale: 'zh-CN',
    timezoneId: 'Asia/Shanghai',
  });
  page = await context.newPage();
  page.setDefaultTimeout(CONFIG.timeoutMs);

  // ---- 事件收集 -------------------------------------------------------
  page.on('console', (msg) => {
    if (msg.type() !== 'error') return;
    const loc = msg.location() || {};
    record('console', {
      page: currentPageId,
      text: clip(msg.text(), 600),
      url: loc.url || '',
      line: loc.lineNumber ?? null,
    });
  });
  page.on('pageerror', (err) => {
    record('pageerror', {
      page: currentPageId,
      text: clip(err && err.message ? err.message : String(err), 600),
      stack: clip(err && err.stack ? err.stack : '', 1200),
    });
  });
  page.on('requestfailed', (req) => {
    const f = req.failure();
    const reason = f ? f.errorText : 'unknown';
    // 切页时浏览器主动中断上一页面的 SSE 长连接（net::ERR_ABORTED）属预期行为，
    // 不计入 console error，单独统计为导航噪声。
    const isSSENoise = /\/api\/stream/.test(req.url()) && /ABORTED/i.test(reason);
    record(isSSENoise ? 'sseNoise' : 'requestfailed', {
      page: currentPageId,
      method: req.method(),
      url: req.url(),
      reason,
    });
  });
  page.on('response', (res) => {
    if (res.status() >= 400) {
      record('http', {
        page: currentPageId,
        status: res.status(),
        url: res.url(),
        method: res.request().method(),
      });
    }
  });

  // ---- 登录 -----------------------------------------------------------
  let currentPageId = 'login';
  const loginUrl = `${CONFIG.baseUrl}/`;
  console.log(`[step] 打开 ${loginUrl}`);
  await page.goto(loginUrl, { waitUntil: 'domcontentloaded', timeout: CONFIG.timeoutMs });

  const loggedIn = await tryLogin(page);
  if (!loggedIn) {
    issues.push({ page: 'login', severity: 'critical', message: '登录失败，无法继续截图验收' });
    await safeShot('login-failed');
    throw new Error('登录失败');
  }

  // 强制断言：登录必须真正进入应用主体（不是登录页。登录页也能截图并能通过，
  // 所以此处必须断言，否则 7 张截图会全是登录页而不被发现。
  const onLoginPage = await page.locator('input#login-pwd, input[type="password"]').count();
  if (onLoginPage > 0) {
    issues.push({ page: 'login', severity: 'critical', message: '登录后仍停在登录页（SPA 未进入应用主体），截图将全部失效' });
    await safeShot('login-stuck');
    throw new Error('登录后仍停在登录页');
  }
  console.log('[step] 登录成功（已进入应用主体）');

  // ---- 逐页截图 -------------------------------------------------------
  for (const p of CONFIG.pages) {
    currentPageId = p.id;
    const url = `${CONFIG.baseUrl}/${p.route}`;
    console.log(`[step] ${p.id} -> ${url}`);
    let navOk = true;
    try {
      // 用页内 location.hash 切换：SPA 是 hash 路由，必须触发 hashchange 才会重渲染页面。
      // 直接 goto 同一 URL 只改 hash 时不保证重渲染，会回到上一个页面。
      await page.evaluate((route) => { window.location.hash = route; }, p.route);
      await page.waitForFunction(
        (route) => window.location.hash === route,
        p.route,
        { timeout: CONFIG.timeoutMs },
      );
      // 等待页面渲染（3.5s），让 SSE / 图表 / 3D 有时间出内容
      await page.waitForTimeout(CONFIG.pageWaitMs);
    } catch (e) {
      navOk = false;
      issues.push({ page: p.id, severity: 'critical', message: `导航失败: ${clip(e.message, 200)}` });
      await page.waitForTimeout(CONFIG.pageWaitMs);
    }

    const file = path.join(outDir, `shots-${p.id}.png`);
    try {
      await page.screenshot({ path: file, fullPage: false });
      const size = fs.existsSync(file) ? fs.statSync(file).size : 0;
      shots.push({ id: p.id, route: p.route, title: p.title, file: `docs/shots-${p.id}.png`, bytes: size, navOk });
      console.log(`[ok] 截图 ${file} (${size} B)`);
      if (size < 8000) {
        issues.push({ page: p.id, severity: 'warn', message: `截图过小(${size}B)，页面可能空白未渲染` });
      }
    } catch (e) {
      issues.push({ page: p.id, severity: 'warn', message: `截图失败: ${clip(e.message, 200)}` });
    }

    // 3D 大屏渲染深度检查：必须在此处（仍停留在 #/screen、系统已启用时）执行，
    // 否则量到的是别的页面的 canvas，或因总开关关闭而走 2D 占位。
    if (p.id === 'screen') {
      try {
        await page.waitForFunction(() => !!document.querySelector('.gl-canvas canvas'), null, { timeout: CONFIG.timeoutMs });
        const render = await checkCanvasRender(page);
        if (render && !render.nonBlank) {
          issues.push({
            page: 'screen',
            severity: 'critical',
            message: `3D 画布疑似空白（着色像素占比 ${(render.colorRatio * 100).toFixed(3)}%）`,
          });
        }
        if (render) {
          console.log(`[info] 3D 画布着色像素占比 ${(render.colorRatio * 100).toFixed(3)}% (canvas ${render.w}x${render.h}, ${render.kind})`);
          const shot = shots.find((s) => s.id === 'screen');
          if (shot) shot.canvas = render;
        }
      } catch (e) {
        issues.push({ page: 'screen', severity: 'critical', message: `3D 渲染检查异常: ${clip(e.message, 200)}` });
      }
    }

    // 页面健康度检查
    const health = await inspectPage(page, p.id, p.route);
    if (health) issues.push(...health);
  }

  // 第 8 张：「系统未启用」降级路径截图
  currentPageId = 'overview-disabled';
  // 先保存完整开关集，恢复时逐项放回（不能只放 enabled）
  let savedSwitches = null;
  try {
    const sr = await page.request.get(`${CONFIG.baseUrl}/api/settings`);
    if (sr.ok()) {
      const sj = await sr.json();
      savedSwitches = {};
      for (const k of ['enabled', 'collect', 'dnsTap', 'deviceControl', 'domainBlock', 'schedule', 'alerts', 'history']) {
        if (k in sj) savedSwitches[k] = sj[k];
      }
      console.log('[info] 已保存开关集: ' + JSON.stringify(savedSwitches));
    }
  } catch (e) {
    console.warn(`[warn] 读取开关集失败: ${clip(e.message, 200)}`);
  }
  try {
    const t = await page.request.post(`${CONFIG.baseUrl}/api/settings/toggle`, {
      data: { key: 'enabled', value: false },
      headers: { 'Content-Type': 'application/json' },
      timeout: CONFIG.timeoutMs,
    });
    if (!t.ok()) {
      issues.push({ page: 'overview-disabled', severity: 'warn', message: `关闭总开关失败：HTTP ${t.status()}` });
    } else {
      await page.evaluate(() => { window.location.hash = '#/overview'; });
      await page.waitForTimeout(CONFIG.pageWaitMs);
      const f = path.join(outDir, 'shots-overview-disabled.png');
      await page.screenshot({ path: f });
      const size = fs.existsSync(f) ? fs.statSync(f).size : 0;
      shots.push({ id: 'overview-disabled', route: '#/overview (enabled=false)', title: '系统未启用降级页', file: 'docs/shots-overview-disabled.png', bytes: size, navOk: true });
      console.log(`[ok] 截图 ${f} (${size} B)`);

      const st = await page.evaluate(() => {
        const txt = (document.body && document.body.innerText) || '';
        return { bodyLen: txt.length, head: txt.slice(0, 300).replace(/\s+/g, ' ').trim() };
      });
      if (st.bodyLen < 40) {
        issues.push({ page: 'overview-disabled', severity: 'critical', message: `未启用时页面空白（${st.bodyLen} 字符）` });
      }
    }
  } catch (e) {
    issues.push({ page: 'overview-disabled', severity: 'warn', message: `未启用截图异常: ${clip(e.message, 200)}` });
  } finally {
    // 逐项恢复原开关集，不影响真机交付状态
    try {
      if (savedSwitches && Object.keys(savedSwitches).length) {
        const rr = await page.request.put(`${CONFIG.baseUrl}/api/settings`, {
          data: savedSwitches,
          headers: { 'Content-Type': 'application/json' },
          timeout: CONFIG.timeoutMs,
        });
        console.log(`[info] 已恢复开关集 (HTTP ${rr.status()})`);
      } else {
        await page.request.post(`${CONFIG.baseUrl}/api/settings/toggle`, {
          data: { key: 'enabled', value: true },
          headers: { 'Content-Type': 'application/json' },
          timeout: CONFIG.timeoutMs,
        });
        console.log('[info] 已恢复总开关');
      }
    } catch (e) {
      console.warn(`[warn] 恢复开关集失败: ${clip(e.message, 200)}`);
    }
  }

  // 注：3D 大屏渲染深度检查已移到逐页循环内（停留在 #/screen、系统启用时执行），
  // 此处不再重复，避免在"系统未启用"态下量到 2D 占位画布。
} catch (e) {
  issues.push({ page: 'currentPageId', severity: 'critical', message: `流程异常: ${clip(e.message, 400)}` });
  console.error('[error]', e.message);
} finally {
  try { if (page) await page.close(); } catch { /* ignore */ }
  try { if (context) await context.close(); } catch { /* ignore */ }
  try { await browser.close(); } catch { /* ignore */ }
}

// ---- 汇总 -------------------------------------------------------------
const summary = {
  generatedAt: new Date().toISOString(),
  baseUrl: CONFIG.baseUrl,
  browser: browserPath,
  viewport: `${CONFIG.viewport.width}x${CONFIG.viewport.height}@${CONFIG.deviceScaleFactor}x`,
  pageWaitMs: CONFIG.pageWaitMs,
  shots,
  counts: {
    shots: shots.length,
    consoleErrors: consoleErrors.length,
    pageErrors: pageErrors.length,
    requestFailures: requestFailures.length,
    sseNavigationNoise: sseNoise.length,
    http4xx5xx: issues.filter((i) => i.message.startsWith('HTTP')).length,
    issues: issues.length,
  },
  consoleErrors,
  pageErrors,
  requestFailures,
  sseNoise,
  issues,
  // 通过条件：零 console/page 错误、零问题项、且每个配置页面都出了图。
  // 注意：截图总数可能多于 CONFIG.pages.length（例如额外拍的"系统未启用"态截图），
  // 因此只要求"每个配置页面至少各一张"，不能要求总数严格相等。
  passed: consoleErrors.length === 0
    && pageErrors.length === 0
    && issues.length === 0
    && CONFIG.pages.every((p) => shots.some((s) => s.id === p.id)),
};

fs.writeFileSync(summaryFile, JSON.stringify(summary, null, 2), 'utf8');
console.log(`[done] 汇总写入 ${summaryFile}`);
console.log(JSON.stringify(summary.counts, null, 2));
if (!summary.passed) {
  console.log('[warn] 存在 console 错误或页面问题，详见 docs/shots-summary.json');
}
process.exit(summary.passed ? 0 : 1);

// =======================================================================
async function tryLogin(pg) {
  // 前端登录页：app/web/js/ui/login.js 使用 input#login-pwd + 表单提交
  // 先等待登录表单出现（若已自动登录则直接返回）
  const pw = pg.locator('input#login-pwd, input[type="password"]').first();
  let hasForm = false;
  try {
    await pw.waitFor({ state: 'visible', timeout: 8000 });
    hasForm = true;
  } catch {
    // 没有登录表单 → 可能已登录或路由直接进入
    const cookies = await pg.context().cookies();
    if (cookies.some((c) => c.name === 'gl_session')) {
      console.log('[info] 未出现登录表单，但已有 gl_session cookie');
      return true;
    }
    console.warn('[warn] 未找到登录表单，尝试 API 登录');
  }

  if (hasForm) {
    await pw.fill(CONFIG.password);
    // 提交：回车或点击“登 录”按钮（前端按钮文案带空格）
    await pw.press('Enter').catch(() => {});
    try {
      const btn = pg.locator('.login-form button, form button[type="submit"], button').last();
      if (await btn.count()) await btn.click({ timeout: 3000 }).catch(() => {});
    } catch { /* ignore */ }
    await pg.waitForTimeout(2500);

    // 判定登录成功：表单消失且已进入应用主体
    const stillForm = await pg.locator('input#login-pwd, input[type="password"]').count();
    const cookies = await pg.context().cookies();
    const hasCookie = cookies.some((c) => c.name === 'gl_session');
    if (!stillForm) {
      console.log('[info] 表单登录成功');
      return true;
    }
    if (hasCookie) {
      // 有 cookie 但表单仍在 → 重新加载一次（SPA boot 依赖 /api/session）
      console.log('[info] 有会话 cookie 但页面未刷新，重新加载');
      await pg.goto(`${CONFIG.baseUrl}/#/overview`, { waitUntil: 'domcontentloaded' });
      await pg.waitForTimeout(2000);
      if ((await pg.locator('input#login-pwd, input[type="password"]').count()) === 0) {
        console.log('[info] 重新加载后已进入应用');
        return true;
      }
    }
    const err = pg.locator('.login-err .msg, .login-err, .error, [role="alert"]').first();
    if (await err.count()) {
      const txt = (await err.innerText().catch(() => '')).trim();
      console.warn(`[warn] 登录页错误提示: ${txt}`);
      if (/锁定|过于频繁|429/.test(txt)) {
        throw new Error(`登录锁定（${txt}），请 60 秒后重试`);
      }
    }
  }

  // API 兜底
  try {
    const resp = await pg.request.post(`${CONFIG.baseUrl}/api/login`, {
      data: { password: CONFIG.password },
      headers: { 'Content-Type': 'application/json' },
      timeout: CONFIG.timeoutMs,
    });
    if (resp.ok()) {
      const cookies = await pg.context().cookies();
      if (cookies.some((c) => c.name === 'gl_session')) {
        // 必须重新加载页面：SPA 的 boot() 只在首次加载时请求 /api/session，
        // 若不重载，页面会一直停在登录页。
        await pg.goto(`${CONFIG.baseUrl}/#/overview`, { waitUntil: 'domcontentloaded' });
        await pg.waitForTimeout(2000);
        const stillLogin = await pg.locator('input#login-pwd, input[type="password"]').count();
        if (stillLogin === 0) {
          console.log('[info] API 兜底登录成功（已重新加载）');
          return true;
        }
        console.warn('[warn] API 登录后重载仍停在登录页');
      }
    }
    console.warn(`[warn] API 登录失败：HTTP ${resp.status()} ${clip(await resp.text().catch(() => ''), 200)}`);
  } catch (e) {
    console.warn(`[warn] API 登录异常: ${clip(e.message, 200)}`);
  }
  return false;
}

async function safeShot(name) {
  try {
    const f = path.join(outDir, `shots-${name}.png`);
    await page.screenshot({ path: f });
    console.log(`[ok] 截图 ${f}`);
  } catch { /* ignore */ }
}

async function inspectPage(pg, id, route) {
  const out = [];
  const expectedHash = '#/' + String(route || '').replace(/^#\/?/, '');
  try {
    const info = await pg.evaluate(() => {
      const txt = (document.body && document.body.innerText) || '';
      const canvases = Array.from(document.querySelectorAll('canvas')).map((c) => ({
        w: c.width, h: c.height,
        cw: c.clientWidth, ch: c.clientHeight,
      }));
      return {
        title: document.title,
        hash: window.location.hash,
        bodyLen: txt.length,
        head: txt.slice(0, 400).replace(/\s+/g, ' ').trim(),
        canvases,
        // 自绘 SVG 图表数（chart.js 之外的图表实现）
        svgCharts: document.querySelectorAll('svg.chart, svg[data-chart], .chart svg, .chart-box svg').length,
        // 图表容器数（含 canvas 的容器）
        chartContainers: document.querySelectorAll('.chart, .chart-box, [data-chart]').length,
        hasLogin: /登录/.test(txt) && /password/i.test(document.body.innerHTML),
        screenRoot: !!document.querySelector('.screen-root'),
        fallbackNote: !!document.querySelector('.screen-fallback-note'),
      };
    });
    if (info.hasLogin) {
      out.push({ page: id, severity: 'critical', message: '页面仍停留在登录页（未取得会话），截图无效' });
    } else if (info.bodyLen < 40) {
      out.push({ page: id, severity: 'critical', message: `页面内容过少(${info.bodyLen} 字符)，疑似空白渲染` });
    }
    // 图表元素断言：canvas 或自绘 SVG 皆可。
    // 仅对"本应常驻图表"的页面告警；devices / behavior / settings 的图表
    // 在展开详情抽屉时才渲染，列表页本就没有图表，不应误报。
    const CHART_PAGES = new Set(['overview', 'traffic', 'security']);
    if (CHART_PAGES.has(id) && info.canvases.length === 0 && info.svgCharts === 0 && info.chartContainers === 0) {
      out.push({ page: id, severity: 'warn', message: '页面未发现任何图表元素（canvas / svg / 图表容器）' });
    }
    // 路由断言：确认 hash 已切换且页面主体已重渲染
    if (info.hash !== expectedHash) {
      out.push({ page: id, severity: 'critical', message: `路由未切换：hash=${info.hash}（期望 ${expectedHash}）` });
    }
    if (id === 'screen' && !info.screenRoot && !info.fallbackNote) {
      out.push({ page: id, severity: 'critical', message: '进入 #/screen 后未生成 .screen-root（大屏未渲染）' });
    }
    if (id !== 'screen' && info.screenRoot) {
      out.push({ page: id, severity: 'critical', message: '仍停留在大屏页，路由未切换' });
    }
  } catch (e) {
    out.push({ page: id, severity: 'warn', message: `页面检查异常: ${clip(e.message, 200)}` });
  }
  return out;
}

async function checkCanvasRender(pg) {
  return await pg.evaluate(() => {
    const cs = Array.from(document.querySelectorAll('canvas'));
    if (!cs.length) return null;
    const results = [];

    for (const c of cs) {
      const w = c.width, h = c.height;
      const item = { w, h, cw: c.clientWidth, ch: c.clientHeight, colorRatio: 0, nonBlankRatio: 0, nonBlank: false };

      // 2D canvas ：直接读 getImageData
      try {
        const ctx2d = c.getContext('2d', { willReadFrequently: true });
        if (ctx2d) {
          const d = ctx2d.getImageData(0, 0, w, h).data;
          let nonBlank = 0, colored = 0;
          for (let i = 0; i < d.length; i += 4) {
            const r = d[i], g = d[i + 1], b = d[i + 2];
            if (r + g + b > 24) nonBlank++;
            if (Math.max(r, g, b) - Math.min(r, g, b) > 12) colored++;
          }
          const total = d.length / 4;
          item.colorRatio = colored / total;
          item.nonBlankRatio = nonBlank / total;
          item.nonBlank = item.colorRatio > 0.0005;
          item.kind = '2d';
          results.push(item);
          continue;
        }
      } catch { /* 不是 2D 画布 */ }

      // WebGL canvas：无 preserveDrawingBuffer 时 readPixels 可能为空。
      // 此时改用统计 DOM 中的 canvas 尺寸与 WebGL 上下文，
      // 并用 toDataURL 的字节数作为绕校判据。
      try {
        const gl = c.getContext('webgl2') || c.getContext('webgl');
        if (gl) {
          const px = new Uint8Array(w * h * 4);
          gl.readPixels(0, 0, w, h, gl.RGBA, gl.UNSIGNED_BYTE, px);
          let colored = 0, nonBlank = 0;
          for (let i = 0; i < px.length; i += 4) {
            const r = px[i], g = px[i + 1], b = px[i + 2];
            if (r + g + b > 24) nonBlank++;
            if (Math.max(r, g, b) - Math.min(r, g, b) > 12) colored++;
          }
          const total = px.length / 4;
          item.colorRatio = colored / total;
          item.nonBlankRatio = nonBlank / total;
          item.kind = 'webgl';
          item.hasGL = true;
          item.glError = gl.getError();
          // WebGL 无 preserveDrawingBuffer 时 readPixels 可能全零 → 用 toDataURL 长度给估估值
          try {
            const url = c.toDataURL('image/png');
            item.dataUrlBytes = url.length;
            item.nonBlank = item.colorRatio > 0.0005 || url.length > 2000;
          } catch {
            item.nonBlank = item.colorRatio > 0.0005;
          }
          results.push(item);
          continue;
        }
      } catch (e) {
        item.error = String(e);
      }

      // 无上下文：仅报 canvas 尺寸
      results.push(item);
    }

    // 取靠面积最大的画布作为主画布（丽牌 sprite 的 2D canvas 可能更小，
    // 且排在后面，不能取最后一个）
    const main = results.reduce((a, b) => ((b.w * b.h) > (a.w * a.h) ? b : a), results[0]);
    // 找 WebGL 主画布（如果存在），它才是 3D 场景
    const glCanvas = results.find((r) => r.kind === 'webgl' && r.w * r.h >= (main.w * main.h) * 0.5);
    return { ...(glCanvas || main), all: results, mainCanvas: main };
  });
}
