// 观澜 NetScope · 验收取证公共配置
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export const REPO_ROOT = path.resolve(__dirname, '..', '..');
export const DOCS_DIR = path.join(REPO_ROOT, 'docs');

export const CONFIG = {
  // 目标地址：默认路由器；可用环境变量覆盖
  baseUrl: (process.env.GUANLAN_URL || 'http://192.168.1.254:8088').replace(/\/+$/, ''),
  user: process.env.GUANLAN_USER || 'admin',
  password: process.env.GUANLAN_PASS || 'guanlan2026',
  chromePath: process.env.GUANLAN_CHROME
    || 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
  // 备用浏览器（Chrome 不存在时）
  edgePath: process.env.GUANLAN_EDGE
    || 'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe',
  viewport: { width: 1600, height: 900 },
  deviceScaleFactor: 2,
  // 每页渲染等待（秒）
  pageWaitMs: Number(process.env.GUANLAN_PAGE_WAIT_MS || 3500),
  timeoutMs: Number(process.env.GUANLAN_TIMEOUT_MS || 45000),
  // 页面清单：与 docs/design.md §7 对应
  pages: [
    { id: 'screen', route: '#/screen', title: '3D 托盘态势大屏' },
    { id: 'overview', route: '#/overview', title: '总览' },
    { id: 'devices', route: '#/devices', title: '设备管理' },
    { id: 'traffic', route: '#/traffic', title: '流量分析' },
    { id: 'behavior', route: '#/behavior', title: '行为管控' },
    { id: 'security', route: '#/security', title: '安全态势' },
    { id: 'settings', route: '#/settings', title: '设置' },
  ],
};

export function resolveBrowserPath() {
  const candidates = [CONFIG.chromePath, CONFIG.edgePath];
  for (const c of candidates) {
    try {
      if (c && fs.existsSync(c)) return c;
    } catch { /* ignore */ }
  }
  return null;
}

export const BROWSER_ARGS = [
  '--enable-unsafe-swiftshader',
  '--disable-gpu-sandbox',
  '--no-sandbox',
  '--disable-dev-shm-usage',
  '--ignore-gpu-blocklist',
  '--use-gl=swiftshader',
  '--no-first-run',
  '--no-default-browser-check',
];

export function ensureDir(p) {
  fs.mkdirSync(p, { recursive: true });
  return p;
}

/** 截断长文本，避免把整个堆栈塞进报告 */
export function clip(text, max = 400) {
  if (typeof text !== 'string') text = String(text ?? '');
  const one = text.replace(/\r/g, '').trim();
  return one.length > max ? one.slice(0, max) + ' …(已截断)' : one;
}
