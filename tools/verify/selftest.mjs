// 观澜 NetScope · 接口自检（curl 风格）
// 逐项探测 /healthz、登录、/api/overview、/api/devices、/api/traffic?range=1h、
// /api/policies、/api/events、/api/enforce/status，并把关键 JSON 片段写进报告。
import fs from 'node:fs';
import path from 'node:path';
import { CONFIG, DOCS_DIR, ensureDir, clip } from './config.mjs';

const outDir = ensureDir(DOCS_DIR);
const results = [];
const snippets = {};

function addRow(name, url, expect, actual, ok, note = '') {
  results.push({ name, url, expect, actual, ok, note });
  const mark = ok ? 'PASS' : 'FAIL';
  console.log(`[${mark}] ${name}  ${url}\n       期望: ${expect}\n       实际: ${actual}${note ? `\n       备注: ${note}` : ''}`);
}

/** 用 fetch + cookie jar 模拟 curl 会话 */
const jar = new Map();
function cookieHeader() {
  if (!jar.size) return '';
  return [...jar.entries()].map(([k, v]) => `${k}=${v}`).join('; ');
}
function storeCookies(res) {
  const raw = res.headers.getSetCookie ? res.headers.getSetCookie() : [];
  for (const line of raw) {
    const [pair] = line.split(';');
    const idx = pair.indexOf('=');
    if (idx > 0) jar.set(pair.slice(0, idx).trim(), pair.slice(idx + 1).trim());
  }
}

async function req(method, url, body) {
  const headers = { Accept: 'application/json' };
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  const c = cookieHeader();
  if (c) headers.Cookie = c;
  const t0 = Date.now();
  const res = await fetch(url, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
    redirect: 'manual',
    signal: AbortSignal.timeout(CONFIG.timeoutMs),
  });
  storeCookies(res);
  const text = await res.text();
  let json = null;
  try { json = JSON.parse(text); } catch { /* not json */ }
  return { status: res.status, text, json, ms: Date.now() - t0 };
}

function pick(obj, keys) {
  if (obj === null || typeof obj !== 'object') return obj;
  const out = {};
  for (const k of keys) if (k in obj) out[k] = obj[k];
  return out;
}

const base = CONFIG.baseUrl;

// 1. /healthz（免鉴权）
try {
  const r = await req('GET', `${base}/healthz`);
  const ok = r.status === 200 && r.json && r.json.ok === true;
  addRow('/healthz', '/healthz', 'HTTP 200 且 {"ok":true}', `HTTP ${r.status} ${clip(r.text, 160)}`, ok);
  snippets['/healthz'] = { status: r.status, latencyMs: r.ms, body: r.json ?? clip(r.text, 300) };
} catch (e) {
  addRow('/healthz', '/healthz', 'HTTP 200 且 {"ok":true}', `请求异常 ${e.message}`, false);
}

// 2. 未登录访问受保护接口应为 401
try {
  const r = await req('GET', `${base}/api/overview`);
  const ok = r.status === 401;
  addRow('鉴权拦截（未登录）', '/api/overview', 'HTTP 401', `HTTP ${r.status} ${clip(r.text, 120)}`, ok);
} catch (e) {
  addRow('鉴权拦截（未登录）', '/api/overview', 'HTTP 401', `请求异常 ${e.message}`, false);
}

// 3. 登录
let authed = false;
try {
  const r = await req('POST', `${base}/api/login`, { password: CONFIG.password });
  const hasCookie = jar.has('gl_session');
  const ok = r.status === 200 && r.json && r.json.ok === true && hasCookie;
  authed = ok;
  addRow('POST /api/login', '/api/login', 'HTTP 200 {"ok":true} + gl_session Cookie', `HTTP ${r.status} ${clip(r.text, 160)} cookie=${hasCookie}`, ok);
  snippets['/api/login'] = { status: r.status, body: r.json ?? clip(r.text, 300), cookieSet: hasCookie };
} catch (e) {
  addRow('POST /api/login', '/api/login', 'HTTP 200 {"ok":true} + gl_session Cookie', `请求异常 ${e.message}`, false);
}

// 4. /api/session
try {
  const r = await req('GET', `${base}/api/session`);
  const ok = r.status === 200 && r.json && r.json.authed === true;
  addRow('GET /api/session', '/api/session', 'HTTP 200 {"authed":true}', `HTTP ${r.status} ${clip(r.text, 160)}`, ok);
  snippets['/api/session'] = { status: r.status, body: r.json ?? clip(r.text, 300) };
} catch (e) {
  addRow('GET /api/session', '/api/session', 'HTTP 200 {"authed":true}', `请求异常 ${e.message}`, false);
}

const guarded = [
  {
    name: 'GET /api/overview', url: '/api/overview',
    expect: 'HTTP 200，含 kpi/sys/categories/trend/topDevices',
    validate: (j) => j && j.kpi && j.sys && Array.isArray(j.categories) && Array.isArray(j.trend),
    keys: ['ts'],
    snippet: (j) => ({
      kpi: j.kpi,
      sys: pick(j.sys, ['cpuPct', 'memPct', 'memUsedMb', 'load1', 'uptimeSec', 'tempC', 'connCount']),
      categoriesCount: Array.isArray(j.categories) ? j.categories.length : 0,
      categories: Array.isArray(j.categories) ? j.categories.slice(0, 8).map((c) => pick(c, ['key', 'label', 'share'])) : [],
      trendLen: Array.isArray(j.trend) ? j.trend.length : 0,
      topDevices: Array.isArray(j.topDevices) ? j.topDevices.slice(0, 3).map((d) => pick(d, ['ip', 'name', 'alias', 'upBps', 'downBps'])) : [],
      alerts: Array.isArray(j.alerts) ? j.alerts.length : 0,
    }),
  },
  {
    name: 'GET /api/devices', url: '/api/devices',
    expect: 'HTTP 200，devices 数组且含 ip/mac/online 字段',
    validate: (j) => j && Array.isArray(j.devices),
    snippet: (j) => {
      const d = j.devices || [];
      return {
        count: d.length,
        online: d.filter((x) => x.online).length,
        sample: d.slice(0, 5).map((x) => pick(x, ['ip', 'mac', 'hostname', 'alias', 'online', 'upBps', 'downBps', 'risk'])),
      };
    },
  },
  {
    name: 'GET /api/traffic?range=1h', url: '/api/traffic?range=1h',
    expect: 'HTTP 200，range=1h，含 series/bucketSec/byCategory',
    validate: (j) => j && j.range === '1h' && Array.isArray(j.series) && Array.isArray(j.byCategory),
    snippet: (j) => ({
      range: j.range,
      bucketSec: j.bucketSec,
      seriesLen: Array.isArray(j.series) ? j.series.length : 0,
      seriesTail: Array.isArray(j.series) ? j.series.slice(-3) : [],
      byCategory: Array.isArray(j.byCategory) ? j.byCategory.map((c) => pick(c, ['key', 'label', 'share'])) : [],
      byDeviceTop: Array.isArray(j.byDevice) ? j.byDevice.slice(0, 3).map((d) => pick(d, ['ip', 'name', 'share'])) : [],
      byAppTop: Array.isArray(j.byApp) ? j.byApp.slice(0, 3).map((a) => pick(a, ['key', 'label', 'share'])) : [],
    }),
  },
  {
    name: 'GET /api/policies', url: '/api/policies',
    expect: 'HTTP 200，policies 数组',
    validate: (j) => j && Array.isArray(j.policies),
    snippet: (j) => ({
      count: (j.policies || []).length,
      sample: (j.policies || []).slice(0, 3).map((p) => pick(p, ['id', 'name', 'enabled', 'action', 'schedule'])),
    }),
  },
  {
    name: 'GET /api/events', url: '/api/events?limit=100',
    expect: 'HTTP 200，events 数组 + summary',
    validate: (j) => j && Array.isArray(j.events) && j.summary,
    snippet: (j) => ({
      summary: j.summary,
      count: (j.events || []).length,
      sample: (j.events || []).slice(0, 3).map((e) => pick(e, ['id', 'ts', 'severity', 'type', 'title', 'deviceIp'])),
    }),
  },
  {
    name: 'GET /api/enforce/dns', url: '/api/enforce/dns',
    expect: 'HTTP 200，domains 为字符串数组（已防拤域名明细）',
    validate: (j) => j && Array.isArray(j.domains),
    snippet: (j) => ({ count: (j.domains || []).length, domains: (j.domains || []).slice(0, 20) }),
  },
  {
    name: 'GET /api/enforce/status', url: '/api/enforce/status',
    expect: 'HTTP 200，含 iptablesRules/tcDevices/dnsBlockedDomains/activePolicies/dnsTap',
    validate: (j) => j && typeof j.iptablesRules === 'number' && typeof j.activePolicies === 'number',
    snippet: (j) => j,
  },
];

for (const g of guarded) {
  if (!authed) {
    addRow(g.name, g.url, g.expect, '未登录，跳过', false, '登录失败导致');
    continue;
  }
  try {
    const r = await req('GET', `${base}${g.url}`);
    const ok = r.status === 200 && g.validate(r.json);
    addRow(g.name, g.url, g.expect, `HTTP ${r.status} ${clip(r.text, 200)}`, ok);
    snippets[g.name] = { status: r.status, latencyMs: r.ms, body: g.snippet ? g.snippet(r.json ?? {}) : r.json };
  } catch (e) {
    addRow(g.name, g.url, g.expect, `请求异常 ${e.message}`, false);
  }
}

// 附加：流量其他时间范围（尽力而为）
for (const rg of ['6h', '24h', '7d']) {
  if (!authed) break;
  try {
    const r = await req('GET', `${base}/api/traffic?range=${rg}`);
    const ok = r.status === 200 && r.json && r.json.range === rg && Array.isArray(r.json.series);
    addRow(`GET /api/traffic?range=${rg}`, `/api/traffic?range=${rg}`, 'HTTP 200，range 匹配且 series 为数组',
      `HTTP ${r.status} bucketSec=${r.json?.bucketSec} len=${r.json?.series?.length}`, ok);
  } catch (e) {
    addRow(`GET /api/traffic?range=${rg}`, `/api/traffic?range=${rg}`, 'HTTP 200', `请求异常 ${e.message}`, false);
  }
}

// 附加：settings / system（api.md §7，尽力而为）
for (const [name, url] of [['GET /api/settings', '/api/settings'], ['GET /api/system', '/api/system'], ['GET /api/security/risk', '/api/security/risk']]) {
  if (!authed) break;
  try {
    const r = await req('GET', `${base}${url}`);
    const ok = r.status === 200 && !!r.json;
    addRow(name, url, 'HTTP 200 且返回 JSON', `HTTP ${r.status} ${clip(r.text, 200)}`, ok);
    snippets[name] = { status: r.status, body: r.json ?? clip(r.text, 300) };
  } catch (e) {
    addRow(name, url, 'HTTP 200 且返回 JSON', `请求异常 ${e.message}`, false);
  }
}

// ===========================================================================
// 开关体系用例（docs/api.md §7.1-§7.3）
//
// 要求：
//   * GET /api/settings 返回 enabled + 7 个功能开关字段
//   * POST /api/settings/toggle {"key":"enabled","value":false} 后，
//     GET /api/overview 仍返回 200（不得 5xx），devices 为空数组、kpi 全 0
//   * 恢复 {"key":"enabled","value":true} 后数据应恢复
// 注意：本组用例会改动服务器开关状态，最后必须恢复原状。
// 此处不会触发任何 iptables/tc/dnsmasq 变更（开关抽象由服务端负责）。
// ===========================================================================
const SWITCH_KEYS = ['enabled', 'collect', 'dnsTap', 'deviceControl', 'domainBlock', 'schedule', 'alerts', 'history'];

if (authed) {
  // --- ① 开关字段完整性 ---
  try {
    const r = await req('GET', `${base}/api/settings`);
    const j = r.json || {};
    const missing = SWITCH_KEYS.filter((k) => !(k in j));
    const ok = r.status === 200 && missing.length === 0;
    addRow('GET /api/settings（开关字段）', '/api/settings',
      `含 enabled + 7 个功能开关（${SWITCH_KEYS.join(', ')}）`,
      `HTTP ${r.status} 缺失=${missing.length ? missing.join(',') : '无'} enabled=${j.enabled}`,
      ok, ok ? '' : `缺少字段: ${missing.join(',')}`);
    snippets['GET /api/settings（开关字段）'] = { status: r.status, body: j };
    // 记住原状态（完整开关集），最后要逐项恢复，不能只恢复 enabled
    var originalSwitches = {};
    for (const k of SWITCH_KEYS) if (k in j) originalSwitches[k] = j[k];
    var originalEnabled = j.enabled;
  } catch (e) {
    addRow('GET /api/settings（开关字段）', '/api/settings', '含全部开关字段', `请求异常 ${e.message}`, false);
  }

  // --- ② 关闭总开关（降级路径） ---
  try {
    const t = await req('POST', `${base}/api/settings/toggle`, { key: 'enabled', value: false });
    const okT = t.status === 200 && t.json && (t.json.ok === true || t.json.settings);
    addRow('POST /api/settings/toggle（enabled=false）', '/api/settings/toggle',
      'HTTP 200，返回变更后的 settings',
      `HTTP ${t.status} ${clip(t.text, 200)}`, okT);
    snippets['POST /api/settings/toggle（enabled=false）'] = { status: t.status, body: t.json ?? clip(t.text, 300) };
  } catch (e) {
    addRow('POST /api/settings/toggle（enabled=false）', '/api/settings/toggle', 'HTTP 200', `请求异常 ${e.message}`, false);
  }

  // --- ③ 关闭后 overview 仍 200，且无数据 ---
  try {
    const r = await req('GET', `${base}/api/overview`);
    const j = r.json || {};
    const devCount = Array.isArray(j.devices) ? j.devices.length
      : (Array.isArray(j.topDevices) ? j.topDevices.length : null);
    const kpi = j.kpi || {};
    const kpiAllZero = Object.values(kpi).every((v) => typeof v !== 'number' || v === 0);
    const ok = r.status === 200 && devCount === 0 && kpiAllZero;
    addRow('GET /api/overview（未启用时）', '/api/overview',
      'HTTP 200（不得 5xx），devices 空数组，kpi 全 0',
      `HTTP ${r.status} devices=${devCount} kpiAllZero=${kpiAllZero}`,
      ok, r.status >= 500 ? '出现 5xx，降级路径破坏' : '');
    snippets['GET /api/overview（未启用时）'] = {
      status: r.status, deviceCount: devCount, kpi, latencyMs: r.ms,
    };
  } catch (e) {
    addRow('GET /api/overview（未启用时）', '/api/overview', 'HTTP 200', `请求异常 ${e.message}`, false);
  }

  // --- ④ 关闭后其他页面接口也不得 5xx ---
  for (const [name, url] of [
    ['GET /api/devices（未启用）', '/api/devices'],
    ['GET /api/traffic（未启用）', '/api/traffic?range=1h'],
    ['GET /api/events（未启用）', '/api/events?limit=100'],
    ['GET /api/enforce/status（未启用）', '/api/enforce/status'],
  ]) {
    try {
      const r = await req('GET', `${base}${url}`);
      const ok = r.status === 200;
      addRow(name, url, 'HTTP 200（不得 5xx）', `HTTP ${r.status} ${clip(r.text, 120)}`, ok);
    } catch (e) {
      addRow(name, url, 'HTTP 200', `请求异常 ${e.message}`, false);
    }
  }

  // --- ⑤ 恢复总开关（语义 A：总开关只开总闸，子开关保持各自状态） ---
  try {
    const t = await req('POST', `${base}/api/settings/toggle`, { key: 'enabled', value: true });
    const j = t.json || {};
    const pending = Array.isArray(j.pending) ? j.pending : [];
    const hint = typeof j.hint === 'string' ? j.hint : '';
    const ok = t.status === 200 && j.ok === true && pending.length > 0 && hint.length > 0;
    addRow('POST /api/settings/toggle（enabled=true，语义 A）', '/api/settings/toggle',
      'HTTP 200，返回 pending（仍关闭的子开关）与 hint',
      `HTTP ${t.status} pending=${pending.length}项 hint=${hint ? '有' : '空'}`,
      ok, ok ? '' : '缺 pending/hint 回执能力（合同未实现）');
    snippets['POST /api/settings/toggle（enabled=true）'] = {
      status: t.status, pending, hint, applied: j.applied, revoked: j.revoked, settings: j.settings,
    };
  } catch (e) {
    addRow('POST /api/settings/toggle（enabled=true，语义 A）', '/api/settings/toggle', 'HTTP 200 + pending/hint', `请求异常 ${e.message}`, false);
  }

  // --- ⑥ 通过 PUT 逐个开启子开关后，数据应恢复 ---
  // 注意：这里**不能**开启 dnsTap —— 该开关会改写 /etc/dnsmasq.conf 并重启 dnsmasq
  //（造成 1~2 秒全网 DNS 空窗），与本自检「不改系统状态」的约定冲突。
  try {
    const p = await req('PUT', `${base}/api/settings`, {
      enabled: true, collect: true, alerts: true, history: true,
    });
    const okP = p.status === 200;
    addRow('PUT /api/settings（开启子开关）', '/api/settings',
      'HTTP 200，接受 enabled/collect/alerts/history 子集（不含 dnsTap）',
      `HTTP ${p.status} ${clip(p.text, 160)}`, okP);
    snippets['PUT /api/settings（开启子开关）'] = { status: p.status, body: p.json ?? clip(p.text, 300) };
  } catch (e) {
    addRow('PUT /api/settings（开启子开关）', '/api/settings', 'HTTP 200', `请求异常 ${e.message}`, false);
  }

  // 等待 ≥ 2 个采集周期（demo 2s）后再校验数据恢复
  await new Promise((r) => setTimeout(r, 5000));
  try {
    const r = await req('GET', `${base}/api/overview`);
    const j = r.json || {};
    const devCount = Array.isArray(j.devices) ? j.devices.length
      : (Array.isArray(j.topDevices) ? j.topDevices.length : null);
    const kpi = j.kpi || {};
    const kpiHasData = Object.values(kpi).some((v) => typeof v === 'number' && v !== 0);
    const ok = r.status === 200 && devCount !== 0 && kpiHasData;
    addRow('GET /api/overview（子开关开启后）', '/api/overview',
      'HTTP 200，devices 非空、kpi 有数据',
      `HTTP ${r.status} devices=${devCount} kpiHasData=${kpiHasData}`, ok);
    snippets['GET /api/overview（恢复后）'] = { status: r.status, deviceCount: devCount, kpi };
  } catch (e) {
    addRow('GET /api/overview（子开关开启后）', '/api/overview', 'HTTP 200', `请求异常 ${e.message}`, false);
  }

  // --- ⑦律 完整恢复原开关集（不只是 enabled，还要把每个子开关都放回原值） ---
  try {
    const restore = { ...originalSwitches };
    const p = await req('PUT', `${base}/api/settings`, restore);
    const okR = p.status === 200;
    addRow('PUT /api/settings（恢复原开关集）', '/api/settings',
      'HTTP 200，子开关逐项恢复原值',
      `HTTP ${p.status} ${clip(p.text, 160)}`, okR);
  } catch (e) {
    addRow('PUT /api/settings（恢复原开关集）', '/api/settings', 'HTTP 200', `请求异常 ${e.message}`, false);
  }

  // --- ⑦ 最终确认开关已恢复原状（必须在恢复原开关集之后执行） ---
  try {
    const r = await req('GET', `${base}/api/settings`);
    const j = r.json || {};
    const want = (typeof originalEnabled === 'boolean') ? originalEnabled : true;
    const ok = r.status === 200 && j.enabled === want;
    addRow('开关状态恢复确认', '/api/settings',
      `enabled === ${want}（原状态）`, `HTTP ${r.status} enabled=${j.enabled}`, ok);
  } catch (e) {
    addRow('开关状态恢复确认', '/api/settings', 'enabled 恢复原状', `请求异常 ${e.message}`, false);
  }

  // --- ⑧ /healthz 应带 enabled 字段（免鉴权探活） ---
  try {
    const r = await req('GET', `${base}/healthz`);
    const ok = r.status === 200 && r.json && ('enabled' in r.json);
    addRow('GET /healthz（含 enabled 字段）', '/healthz',
      'HTTP 200 且含 enabled 字段', `HTTP ${r.status} ${clip(r.text, 160)}`, ok);
  } catch (e) {
    addRow('GET /healthz（含 enabled 字段）', '/healthz', 'HTTP 200 + enabled', `请求异常 ${e.message}`, false);
  }
}

// ---- 输出 -------------------------------------------------------------
const pass = results.filter((r) => r.ok).length;
const fail = results.length - pass;
const out = {
  generatedAt: new Date().toISOString(),
  baseUrl: base,
  user: CONFIG.user,
  total: results.length,
  pass,
  fail,
  passed: fail === 0,
  results,
  snippets,
};
const file = path.join(outDir, 'selftest-summary.json');
fs.writeFileSync(file, JSON.stringify(out, null, 2), 'utf8');
console.log(`\n[done] ${pass}/${results.length} 通过，汇总写入 ${file}`);
process.exit(fail === 0 ? 0 : 1);
