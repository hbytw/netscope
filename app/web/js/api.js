/* ==========================================================================
   观澜 NetScope · API 客户端
   契约来源 docs/api.md v1（字段名严格一致，不自创字段）
   - REST 封装：统一 JSON、401 → 全局登出、错误抛中文 Error
   - SSE 订阅：/api/stream，断线指数退避重连（上限 10s）
   - mock 模式：location.search 含 mock=1 时不请求后端，返回契约一致的合成数据
   ========================================================================== */

const BASE = '';
const MOCK = (() => {
  try {
    return new URLSearchParams(location.search).get('mock') === '1';
  } catch (_) { return false; }
})();

const isMock = MOCK;
export const MOCK_MODE = isMock;

/* mock 模式下可用 ?mockoff=1 / ?mockoff=collect 预置开关状态，用于验证降级路径 */
if (isMock && typeof location !== 'undefined') {
  try {
    const q = new URLSearchParams(location.search);
    const off = q.get('mockoff');
    if (off) {
      // 由 api.js 模块加载后的 mockState 初始化阶段应用
      window.__GL_MOCK_OFF__ = off === '1' ? 'all' : off;
    }
  } catch (_) {}
}

/* ---------- 订阅注册表（防止泄漏） ---------- */
const _subs = new Set();
let _unauthorizedCbs = [];
let _sessionDead = false;

/** 注册 401 全局回调（app.js 用） */
export function onUnauthorized(cb) {
  if (typeof cb === 'function') _unauthorizedCbs.push(cb);
}
export function offUnauthorized(cb) {
  _unauthorizedCbs = _unauthorizedCbs.filter((c) => c !== cb);
}

/** 关闭所有订阅（登录失效 / 登出时调用） */
export function closeAllSubscriptions() {
  _subs.forEach((s) => { try { s.dispose(); } catch (_) {} });
  _subs.clear();
}

/* ---------- 错误 ---------- */

function makeError(message, code, status) {
  const err = new Error(message || '请求失败');
  err.code = code || 'unknown';
  err.status = status || 0;
  return err;
}

/* ---------- REST ---------- */

async function request(path, { method = 'GET', body, query, skip401 = false } = {}) {
  if (isMock) {
    return mockRequest(path, { method, body, query });
  }
  let url = BASE + path;
  if (query && typeof query === 'object') {
    const q = new URLSearchParams();
    Object.entries(query).forEach(([k, v]) => {
      if (v === undefined || v === null || v === '') return;
      q.append(k, String(v));
    });
    const qs = q.toString();
    if (qs) url += (url.includes('?') ? '&' : '?') + qs;
  }
  const opts = {
    method,
    credentials: 'same-origin',
    headers: { 'Accept': 'application/json' }
  };
  if (body !== undefined) {
    opts.headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(body);
  }
  let res;
  try {
    res = await fetch(url, opts);
  } catch (e) {
    throw makeError('网络连接失败，请检查与路由器的连接', 'network_error', 0);
  }
  let data = null;
  const ct = res.headers.get('content-type') || '';
  if (ct.includes('application/json')) {
    try { data = await res.json(); } catch (_) { data = null; }
  }
  if (res.status === 401) {
    // 登录接口自身的 401 = 密码错误，不应触发"会话失效"全局处理
    // （否则登录页会同时出现「登录已失效」与「密码错误」两条矛盾提示）
    if (!skip401) handleUnauthorized();
    throw makeError('密码错误', 'unauthorized', 401);
  }
  if (!res.ok) {
    const msg = (data && data.error) || `请求失败（HTTP ${res.status}）`;
    throw makeError(msg, (data && data.code) || 'http_error', res.status);
  }
  return data === null ? {} : data;
}

function handleUnauthorized() {
  if (_sessionDead) return;
  _sessionDead = true;
  closeAllSubscriptions();
  _unauthorizedCbs.slice().forEach((cb) => { try { cb(); } catch (_) {} });
}

/* ---------- SSE ---------- */

class StreamSubscription {
  constructor(handler, opts = {}) {
    this.handler = handler;
    this.opts = opts;
    this.es = null;
    this.retry = 0;
    this.timer = null;
    this.closed = false;
    this.lastEvent = 'tick';
    this.start();
    _subs.add(this);
  }

  start() {
    if (this.closed) return;
    if (_sessionDead) return;
    const url = BASE + '/api/stream';
    let es;
    try {
      es = new EventSource(url, { withCredentials: true });
    } catch (e) {
      this.scheduleReconnect();
      return;
    }
    this.es = es;

    es.addEventListener('hello', (ev) => {
      this.retry = 0;
      this.emit('hello', safeParse(ev.data));
    });
    es.addEventListener('tick', (ev) => {
      this.retry = 0;
      this.emit('tick', safeParse(ev.data));
    });
    es.addEventListener('alert', (ev) => {
      this.emit('alert', safeParse(ev.data));
    });
    es.onerror = () => {
      try { es.close(); } catch (_) {}
      this.es = null;
      this.scheduleReconnect();
    };
  }

  scheduleReconnect() {
    if (this.closed || this.timer) return;
    const delay = Math.min(10000, 1000 * Math.pow(2, this.retry));
    this.retry = Math.min(this.retry + 1, 5);
    this.timer = setTimeout(() => {
      this.timer = null;
      this.start();
    }, delay);
  }

  emit(type, payload) {
    if (this.closed) return;
    try {
      this.handler(type, payload);
    } catch (e) {
      console.error('[api] stream handler error', e);
    }
  }

  dispose() {
    this.closed = true;
    if (this.timer) { clearTimeout(this.timer); this.timer = null; }
    if (this.es) { try { this.es.close(); } catch (_) {} this.es = null; }
    _subs.delete(this);
  }
}

function safeParse(s) {
  if (s === null || s === undefined) return null;
  try { return JSON.parse(s); } catch (_) { return null; }
}

/* ==========================================================================
   mock 合成数据
   —— 注意：下方所有 const 常量必须声明在 mockState 之前，
      否则 mockState 字面量引用它们会触发 TDZ（ReferenceError）导致整个模块加载失败。
   ========================================================================== */

/* ---- 开关体系（docs/api.md §7.1 两级开关） ---- */
const SWITCH_KEYS = ['enabled', 'collect', 'dnsTap', 'deviceControl', 'domainBlock', 'schedule', 'alerts', 'history'];

const SWITCH_LABEL = {
  enabled: '系统总开关', collect: '流量采集', dnsTap: 'DNS 行为日志',
  deviceControl: '设备管控', domainBlock: '域名封堵', schedule: '定时策略',
  alerts: '安全告警', history: '历史统计'
};

const DNS_BLOCKED = ['tracker.torrent.eu.org', 'api.telegram.org', 'douyin.com/ads'];

const mockState = {
  devices: [],
  policies: [],
  events: [],
  blocked: new Set(),
  limited: new Map(),
  aliases: new Map(),
  groups: new Map(),
  dnsBlocked: [...DNS_BLOCKED],
  whitelist: [],
  tickSeq: 0,
  alertSeq: 0,
  alertFreezeTs: Math.floor(Date.now() / 1000),
  settings: {
    // mock 下默认开启，保证离线预览可验收（见 §7.3）
    enabled: true, collect: true, dnsTap: true, deviceControl: true,
    domainBlock: true, schedule: true, alerts: true, history: true,
    collectIntervalSec: 2, retentionDays: 14,
    alert: { enable: true, scanPorts: 20, trafficMbPerHour: 500 },
    version: '1.0.0', dataDir: '/mnt/mmcblk2p4/guanlan'
  }
};

/** 系统是否处于「可用」状态（总开关开） */
export function isSystemEnabled() {
  return mockState.settings.enabled !== false;
}
/** 某功能开关是否生效 */
export function isSwitchOn(key) {
  if (mockState.settings.enabled === false) return false;
  return mockState.settings[key] !== false;
}

const CAT_DEFS = [
  { key: 'video', label: '视频流媒体', color: '#22d3ee' },
  { key: 'game', label: '游戏', color: '#a78bfa' },
  { key: 'social', label: '社交聊天', color: '#f472b6' },
  { key: 'web', label: '网页浏览', color: '#38bdf8' },
  { key: 'download', label: '下载更新', color: '#fbbf24' },
  { key: 'mail', label: '邮件', color: '#34d399' },
  { key: 'cloud', label: '云盘存储', color: '#2dd4bf' },
  { key: 'other', label: '其他', color: '#94a3b8' }
];

const MOCK_DEVICES = [
  { ip: '192.168.1.2', mac: '3c:22:fb:1a:44:07', hostname: 'OpenWrt-N1', vendor: '路由器', group: '基础设施', online: true, deviceType: '路由', topCat: 'other', topDomain: 'openwrt.org' },
  { ip: '192.168.1.14', mac: '90:f0:52:d5:9a:cb', hostname: 'MEIZU-Note-16', vendor: '魅族', group: '家人', online: true, deviceType: '手机', topCat: 'video', topDomain: 'bilibili.com' },
  { ip: '192.168.1.31', mac: 'f0:18:98:2c:71:d5', hostname: 'Redmi-Turbo-3', vendor: '小米', group: '孩子', online: true, deviceType: '手机', topCat: 'game', topDomain: 'steamcommunity.com' },
  { ip: '192.168.1.82', mac: 'a4:83:e7:04:6b:21', hostname: 'VYG-AL00', vendor: '华为', group: '孩子', online: true, deviceType: '手机', topCat: 'social', topDomain: 'qq.com' },
  { ip: '192.168.1.84', mac: '54:ef:44:9c:2a:8e', hostname: 'Redmi-Turbo-3-Pro', vendor: '小米', group: '访客', online: true, deviceType: '手机', topCat: 'other', topDomain: 'api.telegram.org' },
  { ip: '192.168.1.106', mac: '78:11:dc:53:0e:9a', hostname: 'xiaomi-airc-r09h00_mibt05CC', vendor: '小米', group: '客厅', online: true, deviceType: '电视', topCat: 'video', topDomain: 'tracker.torrent.eu.org' },
  { ip: '192.168.1.219', mac: 'b8:27:eb:5f:31:40', hostname: 'iPhone-15', vendor: '苹果', group: '家人', online: true, deviceType: '手机', topCat: 'video', topDomain: 'youtube.com' },
  { ip: '192.168.1.29', mac: 'dc:a6:32:11:9f:2c', hostname: 'DESKTOP-N8K2R1M', vendor: '联想', group: '书房', online: true, deviceType: '电脑', topCat: 'web', topDomain: 'github.com' },
  { ip: '192.168.1.37', mac: '1c:1a:df:74:2b:60', hostname: 'MiBOX4A', vendor: '小米', group: '客厅', online: true, deviceType: '电视', topCat: 'video', topDomain: 'iqiyi.com' },
  { ip: '192.168.1.52', mac: '9e:6b:1d:8f:44:0a', hostname: 'HUAWEI-Mate60', vendor: '华为', group: '父母', online: true, deviceType: '手机', topCat: 'social', topDomain: 'weixin.qq.com' },
  { ip: '192.168.1.64', mac: '24:4b:fe:1c:88:d3', hostname: 'HP-LaserJet-M233', vendor: '惠普', group: '书房', online: true, deviceType: '打印机', topCat: 'web', topDomain: 'hp.com' },
  { ip: '192.168.1.73', mac: '4c:11:bf:6d:02:e9', hostname: 'MiRobot-Vacuum', vendor: '小米', group: '客厅', online: false, deviceType: '其他', topCat: 'other', topDomain: 'mi.com' },
  { ip: '192.168.1.91', mac: '7a:55:c3:18:6d:40', hostname: 'GT-AX6000', vendor: '华硕', group: '基础设施', online: false, deviceType: '路由', topCat: 'other', topDomain: 'asus.com' },
  { ip: '192.168.1.143', mac: 'c3:90:2e:1a:77:b5', hostname: 'Nintendo-Switch', vendor: '任天堂', group: '孩子', online: true, deviceType: '游戏机', topCat: 'game', topDomain: 'nintendo.net' }
];

const MOCK_DOMAINS = [
  { domain: 'bilibili.com', label: '哔哩哔哩', category: 'video' },
  { domain: 'youtube.com', label: 'YouTube', category: 'video' },
  { domain: 'iqiyi.com', label: '爱奇艺', category: 'video' },
  { domain: 'douyin.com', label: '抖音', category: 'video' },
  { domain: 'v.qq.com', label: '腾讯视频', category: 'video' },
  { domain: 'steamcommunity.com', label: 'Steam', category: 'game' },
  { domain: 'lol.qq.com', label: '英雄联盟', category: 'game' },
  { domain: 'nintendo.net', label: '任天堂', category: 'game' },
  { domain: 'weixin.qq.com', label: '微信', category: 'social' },
  { domain: 'qq.com', label: 'QQ', category: 'social' },
  { domain: 'api.telegram.org', label: 'Telegram', category: 'social' },
  { domain: 'weibo.com', label: '微博', category: 'social' },
  { domain: 'github.com', label: 'GitHub', category: 'web' },
  { domain: 'taobao.com', label: '淘宝', category: 'web' },
  { domain: 'zhihu.com', label: '知乎', category: 'web' },
  { domain: 'tracker.torrent.eu.org', label: 'Torrent Tracker', category: 'download' },
  { domain: 'mirrors.aliyun.com', label: '阿里云镜像', category: 'download' },
  { domain: 'dl.google.com', label: 'Google 下载', category: 'download' },
  { domain: 'update.microsoft.com', label: 'Windows 更新', category: 'download' },
  { domain: 'mail.qq.com', label: 'QQ 邮箱', category: 'mail' },
  { domain: 'imap.gmail.com', label: 'Gmail', category: 'mail' },
  { domain: 'pan.baidu.com', label: '百度网盘', category: 'cloud' },
  { domain: 'drive.google.com', label: 'Google Drive', category: 'cloud' },
  { domain: 'aliyundrive.com', label: '阿里云盘', category: 'cloud' },
  { domain: 'cdn.jsdelivr.net', label: 'jsDelivr', category: 'other' },
  { domain: 'world.gm.com', label: '通用 Motors', category: 'other' }
];

const MOCK_POLICIES = [
  {
    id: 'p-1761900000-1', name: '22 点后禁止刷短视频', enabled: true,
    targets: { ips: ['192.168.1.31'], groups: [], all: false },
    schedule: { days: [1, 2, 3, 4, 5, 6, 7], start: '22:00', end: '23:59' },
    action: 'block', categories: ['video'], domains: ['douyin.com', 'bilibili.com'],
    limitKbps: { down: 0, up: 0 }, hits: 128, createdAt: 1761850000, updatedAt: 1761890000
  },
  {
    id: 'p-1761900000-2', name: '孩子设备夜间限速', enabled: true,
    targets: { ips: [], groups: ['孩子'], all: false },
    schedule: { days: [1, 2, 3, 4, 5, 6, 7], start: '20:30', end: '23:30' },
    action: 'limit', categories: ['game'], domains: [],
    limitKbps: { down: 2000, up: 512 }, hits: 64, createdAt: 1761840000, updatedAt: 1761880000
  },
  {
    id: 'p-1761900000-3', name: '工作日上学时段禁止娱乐', enabled: false,
    targets: { ips: ['192.168.1.82', '192.168.1.143'], groups: [], all: false },
    schedule: { days: [1, 2, 3, 4, 5], start: '07:00', end: '08:30' },
    action: 'block', categories: ['game', 'video'], domains: [],
    limitKbps: { down: 0, up: 0 }, hits: 0, createdAt: 1761800000, updatedAt: 1761800000
  },
  {
    id: 'p-1761900000-4', name: '访客设备白名单放行', enabled: true,
    targets: { ips: [], groups: ['访客'], all: false },
    schedule: { days: [], start: '00:00', end: '23:59' },
    action: 'allow', categories: [], domains: [],
    limitKbps: { down: 0, up: 0 }, hits: 12, createdAt: 1761790000, updatedAt: 1761790000
  }
];

const EVENT_POOL = [
  { severity: 'critical', type: 'port_scan', title: '疑似端口扫描：192.168.1.84', detail: '60 秒内对 28 个不同目的端口发起新连接', deviceIp: '192.168.1.84', deviceName: 'Redmi-Turbo-3-Pro', evidence: { ports: 28, windowSec: 60, sample: ['23', '445', '3389'] } },
  { severity: 'critical', type: 'bad_port', title: '高危端口外联：192.168.1.84 → 3389', detail: '与远程桌面端口建立长连接，存在入侵风险', deviceIp: '192.168.1.84', deviceName: 'Redmi-Turbo-3-Pro', evidence: { port: 3389, dst: '45.83.122.19' } },
  { severity: 'warn', type: 'dns_tunnel', title: 'DNS 隧道嫌疑：192.168.1.106', detail: '单域名 TXT 查询字节数达 812B，超出同类基线 6.4 倍', deviceIp: '192.168.1.106', deviceName: 'xiaomi-airc-r09h00_mibt05CC', evidence: { qname: 'a8f2.tracker.torrent.eu.org', bytes: 812, baseline: 126 } },
  { severity: 'warn', type: 'blacklist_domain', title: '命中黑名单域名：tracker.torrent.eu.org', detail: '设备 192.168.1.106 访问种子 tracker 域名', deviceIp: '192.168.1.106', deviceName: 'xiaomi-airc-r09h00_mibt05CC', evidence: { domain: 'tracker.torrent.eu.org', hits: 14 } },
  { severity: 'warn', type: 'traffic_anomaly', title: '流量异常：192.168.1.31', detail: '下行速率突增至 42.8 Mbps，持续 90 秒', deviceIp: '192.168.1.31', deviceName: 'Redmi-Turbo-3', evidence: { peakBps: 42800000, windowSec: 90, baselineBps: 3200000 } },
  { severity: 'warn', type: 'policy_hit', title: '策略命中：22 点后禁止刷短视频', detail: '目标设备 192.168.1.31 访问 bilibili.com 被拦截 3 次', deviceIp: '192.168.1.31', deviceName: 'Redmi-Turbo-3', evidence: { policy: '22 点后禁止刷短视频', hits: 3 } },
  { severity: 'info', type: 'new_device', title: '新设备入网：192.168.1.143', detail: 'MAC 54:ef:44:9c:2a:8e 首次出现，厂商推断 Nintendo', deviceIp: '192.168.1.143', deviceName: 'Nintendo-Switch', evidence: { mac: '54:ef:44:9c:2a:8e', vendor: '任天堂' } },
  { severity: 'info', type: 'device_online', title: '设备上线：192.168.1.219', detail: 'iPhone-15 已恢复连接', deviceIp: '192.168.1.219', deviceName: 'iPhone-15', evidence: {} },
  { severity: 'info', type: 'device_offline', title: '设备离线：192.168.1.73', detail: 'MiRobot-Vacuum 超过 120 秒无心跳', deviceIp: '192.168.1.73', deviceName: 'MiRobot-Vacuum', evidence: {} },
  { severity: 'info', type: 'policy_hit', title: '策略命中：孩子设备夜间限速', detail: 'Redmi-Turbo-3 被限速至 2000 Kbps', deviceIp: '192.168.1.31', deviceName: 'Redmi-Turbo-3', evidence: { limitKbps: 2000 } },
  { severity: 'info', type: 'device_online', title: '设备上线：192.168.1.82', detail: 'VYG-AL00 已恢复连接', deviceIp: '192.168.1.82', deviceName: 'VYG-AL00', evidence: {} },
  { severity: 'info', type: 'device_offline', title: '设备离线：192.168.1.91', detail: 'GT-AX6000 超过 120 秒无心跳', deviceIp: '192.168.1.91', deviceName: 'GT-AX6000', evidence: {} }
];

const COUNTRY_BY_IP = {
  '89.234.156.205': 'NL', '104.21.33.28': 'US', '180.163.28.105': 'CN', '110.242.68.66': 'CN',
  '14.215.177.163': 'CN', '47.246.24.1': 'HK', '185.199.108.153': 'US', '151.101.64.133': 'US',
  '183.47.61.11': 'CN', '52.109.12.44': 'US', '13.35.58.77': 'US', '223.5.5.5': 'CN',
  '203.107.1.85': 'CN', '162.159.128.233': 'US', '1.1.1.1': 'AU', '8.8.8.8': 'US',
  '45.83.122.19': 'NL', '118.25.11.87': 'CN', '220.181.38.148': 'CN', '172.217.14.142': 'US'
};

/* ---- mock 状态（模块级，供写操作改变）—— mockState 在上方定义 ---- */

function rnd(seedRef) {
  // 稳定的伪随机：基于种子变化，保证同一渲染稳定
  seedRef.v = (seedRef.v * 1664525 + 1013904223) % 4294967296;
  return seedRef.v / 4294967296;
}

function makeSeed(str) {
  let h = 2166136261;
  for (let i = 0; i < str.length; i++) { h ^= str.charCodeAt(i); h = Math.imul(h, 16777619); }
  return { v: h >>> 0 };
}

function pickByHash(arr, key) {
  if (!arr.length) return arr[0];
  const s = makeSeed(key);
  return arr[Math.floor(rnd(s) * arr.length)];
}

function buildDevices() {
  const now = Math.floor(Date.now() / 1000);
  mockState.devices = MOCK_DEVICES.map((d, idx) => {
    const s = makeSeed(d.ip);
    const online = d.online;
    const baseDown = 80_000 + Math.floor(rnd(s) * 4_000_000);
    const baseUp = 20_000 + Math.floor(rnd(s) * 900_000);
    const downBps = online ? Math.floor(baseDown * (0.55 + rnd(s) * 0.9)) : 0;
    const upBps = online ? Math.floor(baseUp * (0.5 + rnd(s) * 0.8)) : 0;
    const totalDown = 1024 * (1 + Math.floor(rnd(s) * 900000));
    const totalUp = 1024 * (1 + Math.floor(rnd(s) * 120000));
    const risk = d.ip === '192.168.1.84' ? 0.82 : d.ip === '192.168.1.106' ? 0.63 : d.ip === '192.168.1.31' ? 0.34 : Math.round(rnd(s) * 22) / 100;
    return {
      ip: d.ip, mac: d.mac, hostname: d.hostname, alias: mockState.aliases.get(d.ip) || '',
      vendor: d.vendor, group: mockState.groups.get(d.ip) || d.group,
      online, deviceType: d.deviceType,
      firstSeen: now - 86400 * (3 + idx),
      lastSeen: online ? now - Math.floor(rnd(s) * 30) : now - 600,
      upBps, downBps, totalUp, totalDown,
      conns: online ? 4 + Math.floor(rnd(s) * 180) : 0,
      risk: Math.round(risk * 100) / 100,
      blocked: mockState.blocked.has(d.ip),
      limitKbps: mockState.limited.get(d.ip) || { down: 0, up: 0 },
      topCat: d.topCat, topDomain: d.topDomain,
      policyIds: mockState.policies.filter((p) => p.enabled && (
        p.targets.all ||
        p.targets.ips.includes(d.ip) ||
        (p.targets.groups.length && p.targets.groups.includes(d.group))
      )).map((p) => p.id)
    };
  });
}

function buildPolicies() {
  mockState.policies = MOCK_POLICIES.map((p) => ({ ...p, targets: { ...p.targets }, schedule: { ...p.schedule }, limitKbps: { ...p.limitKbps }, categories: [...p.categories], domains: [...p.domains] }));
}

function buildEvents() {
  const now = Math.floor(Date.now() / 1000);
  mockState.events = EVENT_POOL.map((e, i) => ({
    ...e,
    id: `e-1761900000-${i + 1}`,
    ts: now - i * 137 - 45,
    acked: i >= 8
  }));
}

buildDevices();
buildPolicies();
buildEvents();

/* 应用 ?mockoff= 预置开关状态（用于验证 §7.3 降级路径） */
if (typeof window !== 'undefined' && window.__GL_MOCK_OFF__) {
  const off = window.__GL_MOCK_OFF__;
  if (off === 'all') {
    mockState.settings.enabled = false;
    SWITCH_KEYS.forEach((k) => { if (k !== 'enabled') mockState.settings[k] = false; });
  } else {
    mockState.settings[off] = false;
  }
}

function catShares() {
  const s = makeSeed('cats');
  const raw = CAT_DEFS.map((c) => ({ ...c, weight: rnd(s) + (c.key === 'video' ? 0.8 : 0) }));
  const total = raw.reduce((a, x) => a + x.weight, 0);
  return raw.map((x) => ({ ...x, share: x.weight / total }));
}

function makeCategories(scale = 1) {
  const shares = catShares();
  if (!scale) {
    // 未启用 / 未采集时：固定 8 项，值全为 0（api.md §2）
    return shares.map((c) => ({ key: c.key, label: c.label, color: c.color, upBps: 0, downBps: 0, share: 0 }));
  }
  return shares.map((c) => ({
    key: c.key, label: c.label, color: c.color,
    upBps: Math.round(c.share * 420000 * scale),
    downBps: Math.round(c.share * 8600000 * scale),
    share: c.share
  }));
}

function makeTrend(points = 60, spanSec = 120) {
  const now = Math.floor(Date.now() / 1000);
  const out = [];
  for (let i = points - 1; i >= 0; i--) {
    const wave = Math.sin((points - i) / 7.5) * 0.28 + Math.sin((points - i) / 2.7) * 0.12;
    const down = Math.max(12000, Math.round((4_200_000 + wave * 3_400_000) * (0.75 + ((i * 37) % 11) / 22)));
    const up = Math.max(2000, Math.round((620_000 + wave * 460_000) * (0.7 + ((i * 53) % 13) / 20)));
    out.push({ t: now - i * (spanSec / points), up, down });
  }
  return out;
}

function makeDeviceTrend(ip, points = 60) {
  const now = Math.floor(Date.now() / 1000);
  const dev = mockState.devices.find((d) => d.ip === ip);
  const out = [];
  for (let i = points - 1; i >= 0; i--) {
    const s = makeSeed(`${ip}-${i}`);
    const wave = Math.sin((points - i) / 6.3 + (ip.length % 5)) * 0.4;
    const down = dev && dev.online ? Math.max(1000, Math.round(dev.downBps * (1 + wave * 0.8) * (0.6 + rnd(s) * 0.8))) : 0;
    const up = dev && dev.online ? Math.max(500, Math.round(dev.upBps * (1 + wave * 0.6) * (0.6 + rnd(s) * 0.7))) : 0;
    out.push({ t: now - i * 2, up, down });
  }
  return out;
}

function makeConns(ip, limit = 40) {
  const dev = mockState.devices.find((d) => d.ip === ip);
  if (!dev) return [];
  const now = Math.floor(Date.now() / 1000);
  const out = [];
  for (let i = 0; i < limit; i++) {
    const s = makeSeed(`${ip}-conn-${i}`);
    const dom = pickByHash(MOCK_DOMAINS, `${ip}-${i}-d`);
    const dstIp = Object.keys(COUNTRY_BY_IP)[Math.floor(rnd(s) * Object.keys(COUNTRY_BY_IP).length)];
    const proto = rnd(s) > 0.82 ? 'udp' : 'tcp';
    const state = rnd(s) > 0.7 ? 'ESTABLISHED' : (rnd(s) > 0.5 ? 'TIME_WAIT' : 'CLOSE_WAIT');
    const upBytes = Math.floor(1024 * (1 + rnd(s) * 900));
    const downBytes = Math.floor(1024 * (1 + rnd(s) * 52000));
    out.push({
      id: `${proto}-${ip}-${50000 + i}-${dstIp}-${dom.category === 'web' ? 443 : 80}`,
      proto, srcIp: ip, srcPort: 50000 + i,
      dstIp, dstPort: dom.category === 'web' ? 443 : 80,
      domain: dom.domain, app: dom.label, category: dom.category,
      upBytes, downBytes, state,
      startedAt: now - Math.floor(rnd(s) * 3600),
      lastSeenAt: now - Math.floor(rnd(s) * 60),
      durationSec: Math.floor(rnd(s) * 3600),
      deviceName: dev.hostname
    });
  }
  return out;
}

function makeOverview() {
  const now = Math.floor(Date.now() / 1000);
  const live = isSwitchOn('collect');
  const devices = live ? mockState.devices : [];
  const online = devices.filter((d) => d.online).length;
  const conns = devices.reduce((a, d) => a + d.conns, 0);
  const upBps = devices.reduce((a, d) => a + d.upBps, 0);
  const downBps = devices.reduce((a, d) => a + d.downBps, 0);
  const alerts = isSwitchOn('alerts') ? mockState.events.filter((e) => !e.acked).length : 0;
  const categories = live ? makeCategories(1) : makeCategories(0);
  const topDevices = devices.slice().sort((a, b) => b.downBps - a.downBps).slice(0, 8)
    .map((d) => ({ ip: d.ip, name: d.hostname, alias: d.alias, upBps: d.upBps, downBps: d.downBps, totalDown: d.totalDown, risk: d.risk }));
  const topDomains = live ? MOCK_DOMAINS.slice(0, 10).map((d, i) => {
    const s = makeSeed(`td-${d.domain}`);
    return {
      domain: d.domain, label: d.label, category: d.category,
      hits: 12 + Math.floor(rnd(s) * 340),
      downBps: Math.round(80000 * (1 + rnd(s) * 22))
    };
  }) : [];
  return {
    ts: now,
    kpi: {
      online, devices: devices.length, conns, newConns: live ? 42 + (mockState.tickSeq % 27) : 0,
      dnsQps: live ? 3.5 : 0, alerts, upBps, downBps,
      riskLevel: isSwitchOn('alerts') ? 'guard' : 'low'
    },
    sys: {
      cpuPct: 23.4, memPct: 41.2, memUsedMb: 760, load1: 0.42, uptimeSec: 86400 * 3 + 4211,
      tempC: 52.0, wanRxBps: 2340000, wanTxBps: 312000, connCount: conns
    },
    categories,
    trend: live ? makeTrend(60, 120) : [],
    topDevices,
    topDomains,
    alerts: isSwitchOn('alerts') ? mockState.events.slice(0, 5) : []
  };
}

function makeTraffic(range) {
  const cfg = { '1h': { bucketSec: 30, points: 120 }, '6h': { bucketSec: 120, points: 180 }, '24h': { bucketSec: 300, points: 180 }, '7d': { bucketSec: 1800, points: 168 } }[range] || { bucketSec: 60, points: 120 };
  const now = Math.floor(Date.now() / 1000);
  const cats = catShares();
  const series = [];
  for (let i = cfg.points - 1; i >= 0; i--) {
    const t = now - i * cfg.bucketSec;
    const hour = new Date(t * 1000).getHours();
    const night = hour >= 0 && hour < 6 ? 0.28 : hour >= 19 && hour < 23 ? 1.35 : 1.0;
    const wave = 1 + Math.sin(i / 9) * 0.22 + Math.cos(i / 3.1) * 0.08;
    const byCat = {};
    let up = 0, down = 0;
    cats.forEach((c) => {
      const v = Math.round(c.share * 7_800_000 * night * wave * (0.72 + ((i * 31) % 17) / 20));
      byCat[c.key] = v;
      down += v;
      up += Math.round(v * 0.13);
    });    series.push({ t, up, down, byCat });
  }
  const totalDown = series.reduce((a, x) => a + x.down, 0) || 1;
  const byCategory = cats.map((c) => {
    const v = series.reduce((a, x) => a + (x.byCat[c.key] || 0), 0);
    return { key: c.key, label: c.label, up: Math.round(v * 0.13), down: v, share: v / totalDown, color: c.color };
  });
  const byDevice = mockState.devices.map((d) => {
    const v = Math.round(d.totalDown * 0.22);
    return { ip: d.ip, name: d.hostname, alias: d.alias, up: Math.round(v * 0.13), down: v, share: 0 };
  }).sort((a, b) => b.down - a.down).slice(0, 10);
  const sumDev = byDevice.reduce((a, x) => a + x.down, 0) || 1;
  byDevice.forEach((d) => { d.share = d.down / sumDev; });
  const byApp = byCategory.map((c) => ({ key: c.key, label: c.label, up: c.up, down: c.down, share: c.share }));
  return { range, bucketSec: cfg.bucketSec, series, byCategory, byDevice, byApp };
}

function makeDomains(range, limit) {
  const now = Math.floor(Date.now() / 1000);
  const n = Math.min(limit || 50, 50);
  return MOCK_DOMAINS.slice(0, n).map((d, i) => {
    const s = makeSeed(`md-${d.domain}-${range}`);
    const devCount = 1 + Math.floor(rnd(s) * 7);
    const deviceList = [];
    for (let k = 0; k < Math.min(devCount, mockState.devices.length); k++) {
      const dev = mockState.devices[(i + k * 3) % mockState.devices.length];
      const ds = makeSeed(`mdd-${d.domain}-${dev.ip}`);
      deviceList.push({
        ip: dev.ip, name: dev.hostname, alias: dev.alias,
        hits: 1 + Math.floor(rnd(ds) * 120),
        bytes: 1024 * (2 + Math.floor(rnd(ds) * 60000)),
        lastSeen: now - Math.floor(rnd(ds) * 3600)
      });
    }
    deviceList.sort((a, b) => b.bytes - a.bytes);
    return {
      domain: d.domain, label: d.label, category: d.category,
      hits: 8 + Math.floor(rnd(s) * 460),
      bytes: 1024 * (4 + Math.floor(rnd(s) * 240000)),
      devices: devCount,
      deviceList,
      lastSeen: now - Math.floor(rnd(s) * 7200)
    };
  });
}

function makeConnsList({ limit = 200, q = '', device = '' } = {}) {
  const now = Math.floor(Date.now() / 1000);
  const out = [];
  const devs = mockState.devices;
  const total = 3811;
  const count = Math.min(limit || 200, 200);
  for (let i = 0; i < count; i++) {
    const dev = devs[i % devs.length];
    const s = makeSeed(`cl-${i}-${dev.ip}`);
    const dom = pickByHash(MOCK_DOMAINS, `cl-${i}`);
    const dstIp = Object.keys(COUNTRY_BY_IP)[Math.floor(rnd(s) * Object.keys(COUNTRY_BY_IP).length)];
    const proto = rnd(s) > 0.84 ? 'udp' : 'tcp';
    out.push({
      id: `${proto}-${dev.ip}-${40000 + i}-${dstIp}-443`,
      proto, srcIp: dev.ip, srcPort: 40000 + i, dstIp, dstPort: 443,
      domain: dom.domain, app: dom.label, category: dom.category,
      upBytes: Math.floor(1024 * (0.2 + rnd(s) * 320)),
      downBytes: Math.floor(1024 * (0.5 + rnd(s) * 88000)),
      state: rnd(s) > 0.72 ? 'ESTABLISHED' : (rnd(s) > 0.5 ? 'TIME_WAIT' : 'CLOSE_WAIT'),
      startedAt: now - Math.floor(rnd(s) * 5400),
      lastSeenAt: now - Math.floor(rnd(s) * 120),
      durationSec: Math.floor(rnd(s) * 5400),
      deviceName: dev.hostname
    });
  }
  let list = out;
  if (device) list = list.filter((c) => c.srcIp === device);
  if (q) {
    const qq = q.toLowerCase();
    list = list.filter((c) => (c.domain || '').toLowerCase().includes(qq) || c.dstIp.includes(qq) || (c.app || '').toLowerCase().includes(qq) || c.srcIp.includes(qq));
  }
  return { conns: list, total };
}

function makeEvents(params = {}) {
  let list = mockState.events.slice();
  if (!isSwitchOn('alerts')) {
    // 关闭告警后不再产生新事件，但历史事件仍保留可查（api.md §7.1）
    list = list.filter((e) => e.ts < mockState.alertFreezeTs);
  }
  if (params.severity) list = list.filter((e) => e.severity === params.severity);
  if (params.type) list = list.filter((e) => e.type === params.type);
  if (params.ack === 'unacked') list = list.filter((e) => !e.acked);
  if (params.ack === 'acked') list = list.filter((e) => e.acked);
  const limit = Math.min(params.limit || 100, 500);
  list = list.slice(0, limit);
  const summary = {
    critical: list.filter((e) => e.severity === 'critical').length,
    warn: list.filter((e) => e.severity === 'warn').length,
    info: list.filter((e) => e.severity === 'info').length,
    total: list.length
  };
  return { events: list, summary };
}

function makeRisk() {
  const devices = mockState.devices
    .map((d) => {
      const reasons = [];
      if (d.ip === '192.168.1.84') {
        reasons.push({ type: 'port_scan', count: 2, lastTs: Math.floor(Date.now() / 1000) - 120 });
        reasons.push({ type: 'bad_port', count: 1, lastTs: Math.floor(Date.now() / 1000) - 300 });
      }
      if (d.ip === '192.168.1.106') {
        reasons.push({ type: 'dns_tunnel', count: 1, lastTs: Math.floor(Date.now() / 1000) - 480 });
      }
      if (d.risk > 0.3 && reasons.length === 0) {
        reasons.push({ type: 'traffic_anomaly', count: 1, lastTs: Math.floor(Date.now() / 1000) - 900 });
      }
      return { ip: d.ip, name: d.hostname, risk: d.risk, reasons };
    })
    .filter((x) => x.reasons.length)
    .sort((a, b) => b.risk - a.risk);
  return { level: 'guard', devices };
}

function makeSettings() {
  return { ...mockState.settings };
}

/**
 * 网络拓扑 mock（docs/api.md / task-5 契约）：
 * - nodes: id/type/name/cidr/up/rxBps/txBps（lan/zerotier/vpn/internet/proxy…）
 * - links: from/to/kind(upBps/downBps)（direct / proxy / zt / vpn）
 * 从 mock 设备实时速率推算各出口流量，保证 3D 大屏拓扑与设备/链路数据一致。
 */
function makeTopology() {
  const enabled = isSwitchOn('collect');
  const devices = enabled ? mockState.devices : [];
  const down = devices.reduce((a, d) => a + (Number(d.downBps) || 0), 0);
  const up = devices.reduce((a, d) => a + (Number(d.upBps) || 0), 0);
  const nodes = [
    { id: 'br-lan', type: 'lan', name: '内网 LAN', cidr: '192.168.1.0/24', up: enabled, rxBps: down, txBps: up },
    {
      id: 'zt6vwy3rne',
      type: 'zerotier',
      name: 'ZeroTier',
      cidr: '192.168.99.0/24',
      up: enabled,
      rxBps: Math.round(down * 0.08),
      txBps: Math.round(up * 0.08),
    },
    {
      id: 'tun0',
      type: 'vpn',
      name: 'VPN 网关',
      cidr: '10.8.0.0/24',
      up: enabled,
      rxBps: Math.round(down * 0.03),
      txBps: Math.round(up * 0.03),
    },
    {
      id: 'internet',
      type: 'internet',
      name: '互联网',
      cidr: '',
      up: enabled,
      rxBps: Math.round(down * 0.7),
      txBps: Math.round(up * 0.7),
    },
    { id: 'proxy', type: 'proxy', name: '代理', cidr: '', up: false, rxBps: 0, txBps: 0 },
  ];
  const links = [
    { from: 'br-lan', to: 'internet', kind: 'direct', upBps: Math.round(up * 0.7), downBps: Math.round(down * 0.7) },
    { from: 'br-lan', to: 'proxy', kind: 'proxy', upBps: 0, downBps: 0 },
    { from: 'br-lan', to: 'zt6vwy3rne', kind: 'zt', upBps: Math.round(up * 0.08), downBps: Math.round(down * 0.08) },
    { from: 'br-lan', to: 'tun0', kind: 'vpn', upBps: Math.round(up * 0.03), downBps: Math.round(down * 0.03) },
  ];
  return { nodes, links };
}

/** 后端未挂载 /api/topology 时的最小兜底拓扑（真实环境，仍可渲染） */
function makeTopologyFallback() {
  return {
    nodes: [
      { id: 'br-lan', type: 'lan', name: '内网 LAN', cidr: '', up: true, rxBps: 0, txBps: 0 },
      { id: 'internet', type: 'internet', name: '互联网', cidr: '', up: true, rxBps: 0, txBps: 0 },
    ],
    links: [{ from: 'br-lan', to: 'internet', kind: 'direct', upBps: 0, downBps: 0 }],
  };
}

/**
 * 按后端语义生成 pending / hint（backend-dev 确认：两字段始终返回，数组非 null）
 * - pending：固定顺序子开关中仍为 false 的 key（enabled=false 时也是全量 7 项）
 * - hint：三种形态 —— 系统未启用 / 已启用但功能开关均未开启 / 已启用但部分未开启
 */
function switchHintAndPending() {
  const s = mockState.settings;
  const pending = SWITCH_KEYS.filter((k) => k !== 'enabled' && s[k] === false);
  let hint;
  if (s.enabled === false) {
    hint = '系统未启用：当前仅显示配置状态，不采集、不管控、不影响路由器现有功能。';
  } else if (pending.length === 0) {
    hint = '系统已启用，全部功能开关均已开启。';
  } else if (pending.length === SWITCH_KEYS.length - 1) {
    hint = '系统已启用，但功能开关均未开启，系统当前不会采集任何数据。';
  } else {
    const names = pending.map((k) => SWITCH_LABEL[k]).join('、');
    hint = `系统已启用；以下功能开关仍为关闭状态：${names}。`;
  }
  return { pending, hint };
}

/**
 * 模拟后端开关变更语义（docs/api.md §7.1）：
 * - 关闭任何开关必须撤销该开关已下发的一切规则；
 * - 关闭 enabled 等价于级联关闭全部子开关。
 */
function applySwitchPatch(patch) {
  const applied = [];
  const revoked = [];
  const s = mockState.settings;
  const before = { ...s };

  // 总开关关闭 → 级联关闭全部子开关
  if (patch.enabled === false) {
    SWITCH_KEYS.forEach((k) => { if (k !== 'enabled') s[k] = false; });
  } else if (patch.enabled === true) {
    // 开启总开关时，不自动打开子开关（后端同样不自动开）
    SWITCH_KEYS.forEach((k) => { if (k !== 'enabled' && before[k] === false) s[k] = false; });
  }

  // 逐项处理功能开关
  SWITCH_KEYS.forEach((k) => {
    if (!(k in patch)) return;
    const next = !!patch[k];
    const was = before[k] === true;
    if (next === was) return;
    s[k] = next;
    if (next) {
      applied.push(`已启用「${SWITCH_LABEL[k]}」`);
      return;
    }
    // 关闭 → 撤销已下发规则
    switch (k) {
      case 'enabled':
        revoked.push('撤销全部管控规则（回到从未启用状态）');
        mockState.blocked.clear();
        mockState.limited.clear();
        mockState.dnsBlocked = [];
        mockState.devices.forEach((d) => { d.blocked = false; d.limitKbps = { down: 0, up: 0 }; });
        break;
      case 'deviceControl':
        if (mockState.blocked.size) {
          revoked.push(`撤销 UBM_FWD 规则 ${mockState.blocked.size} 条`);
          mockState.blocked.clear();
          mockState.devices.forEach((d) => { d.blocked = false; });
        }
        if (mockState.limited.size) {
          revoked.push(`撤销 tc 限速规则 ${mockState.limited.size} 条`);
          mockState.limited.clear();
          mockState.devices.forEach((d) => { d.limitKbps = { down: 0, up: 0 }; });
        }
        break;
      case 'domainBlock':
        if (mockState.dnsBlocked.length) {
          revoked.push(`还原 dnsmasq 旁挂拦截 ${mockState.dnsBlocked.length} 条`);
          mockState.dnsBlocked = [];
        }
        break;
      case 'dnsTap':
        revoked.push('移除 dnsmasq logqueries 旁挂配置');
        break;
      case 'alerts':
        mockState.alertFreezeTs = Math.floor(Date.now() / 1000);
        revoked.push('停止事件研判');
        break;
      case 'collect':
        revoked.push('停止流量采集');
        break;
      case 'schedule':
        revoked.push('停止定时策略自动启停');
        break;
      case 'history':
        revoked.push('停止写入历史统计桶');
        break;
      default:
        break;
    }
  });

  // 关闭 enabled 级联时也要记录子开关的撤销动作
  if (patch.enabled === false && before.enabled === true) {
    if (mockState.blocked.size || mockState.limited.size || mockState.dnsBlocked.length) {
      revoked.push('撤销全部已下发规则');
    }
  }
  return { applied, revoked };
}

function makeSystem() {
  return {
    model: 'Phicomm N1', arch: 'aarch64', kernel: '6.1.114',
    openwrt: 'SNAPSHOT R2024.11.05', uptimeSec: 86400 * 3 + 4211,
    memTotalMb: 1844, memFreeMb: 760, diskFreeMb: 4200, hostname: 'Ytwos-N1'
  };
}

function mockRequest(path, { method = 'GET', body, query = {} } = {}) {
  const p = path.split('?')[0];
  const q = query || {};
  const seg = p.split('/').filter(Boolean); // ['api','...']

  if (p === '/api/login') return { ok: true, expiresIn: 86400 };
  if (p === '/api/logout') return { ok: true };
  if (p === '/api/session') return { authed: true, username: 'admin' };
  if (p === '/api/password') return { ok: true };

  if (p === '/api/overview') return makeOverview();
  if (p === '/api/devices' && method === 'GET') {
    return { devices: isSwitchOn('collect') ? mockState.devices : [] };
  }
  if (seg[0] === 'api' && seg[1] === 'devices' && seg.length === 3 && method === 'GET') {
    const ip = decodeURIComponent(seg[2]);
    const dev = mockState.devices.find((d) => d.ip === ip);
    if (!dev) throw makeError('设备不存在', 'not_found', 404);
    const topDomains = MOCK_DOMAINS.slice(0, 6).map((d) => {
      const s = makeSeed(`${ip}-${d.domain}`);
      return { domain: d.domain, label: d.label, category: d.category, hits: 2 + Math.floor(rnd(s) * 40), bytes: 1024 * (1 + Math.floor(rnd(s) * 90000)) };
    });
    const topDsts = Object.keys(COUNTRY_BY_IP).slice(0, 6).map((dst) => ({
      ip: dst, country: COUNTRY_BY_IP[dst], bytes: 1024 * (10 + Math.floor(makeSeed(dst + ip).v % 500000))
    })).sort((a, b) => b.bytes - a.bytes);
    return { device: dev, trend: makeDeviceTrend(ip, 60), topDomains, topDsts, conns: makeConns(ip, 24) };
  }
  if (seg[1] === 'devices' && seg[3] === 'alias' && method === 'POST') {
    const ip = decodeURIComponent(seg[2]);
    const d = mockState.devices.find((x) => x.ip === ip);
    if (!d) throw makeError('设备不存在', 'not_found', 404);
    const alias = (body && body.alias) || '';
    if (alias) mockState.aliases.set(ip, alias); else mockState.aliases.delete(ip);
    d.alias = alias;
    return { ok: true, applied: [], device: d };
  }
  if (seg[1] === 'devices' && seg[3] === 'group' && method === 'POST') {
    const ip = decodeURIComponent(seg[2]);
    const d = mockState.devices.find((x) => x.ip === ip);
    if (!d) throw makeError('设备不存在', 'not_found', 404);
    const g = (body && body.group) || '';
    if (g) mockState.groups.set(ip, g); else mockState.groups.delete(ip);
    d.group = g || '未分组';
    return { ok: true, applied: [], device: d };
  }
  if (seg[1] === 'devices' && seg[3] === 'block' && method === 'POST') {
    const ip = decodeURIComponent(seg[2]);
    const d = mockState.devices.find((x) => x.ip === ip);
    if (!d) throw makeError('设备不存在', 'not_found', 404);
    const blocked = !!(body && body.blocked);
    if (blocked) mockState.blocked.add(ip); else mockState.blocked.delete(ip);
    d.blocked = blocked;
    d.online = blocked ? false : d.online;
    return { ok: true, applied: blocked ? [`iptables -I UBM_FWD -s ${ip} -j DROP`] : [`iptables -D UBM_FWD -s ${ip} -j DROP`], device: d };
  }
  if (seg[1] === 'devices' && seg[3] === 'limit' && method === 'POST') {
    const ip = decodeURIComponent(seg[2]);
    const d = mockState.devices.find((x) => x.ip === ip);
    if (!d) throw makeError('设备不存在', 'not_found', 404);
    const limitKbps = { down: Number((body && body.downKbps) || 0), up: Number((body && body.upKbps) || 0) };
    if (limitKbps.down || limitKbps.up) mockState.limited.set(ip, limitKbps); else mockState.limited.delete(ip);
    d.limitKbps = limitKbps;
    return { ok: true, applied: [`tc qdisc add dev eth0 root tbf rate ${limitKbps.down || 0}kbit`], device: d };
  }
  if (seg[1] === 'devices' && seg[3] === 'forget' && method === 'POST') {
    const ip = decodeURIComponent(seg[2]);
    mockState.devices = mockState.devices.filter((x) => x.ip !== ip);
    return { ok: true, applied: [] };
  }

  if (p === '/api/traffic') return makeTraffic(q.range || '1h');
  if (p === '/api/traffic/domains') {
    return { domains: isSwitchOn('collect') && isSwitchOn('dnsTap') ? makeDomains(q.range || '1h', q.limit ? Number(q.limit) : 50) : [] };
  }
  if (p === '/api/traffic/conns') {
    if (!isSwitchOn('collect')) return { conns: [], total: 0 };
    return makeConnsList({ limit: q.limit ? Number(q.limit) : 200, q: q.q || '', device: q.device || '' });
  }
  if (seg[1] === 'traffic' && seg[2] === 'conns' && seg[3] === 'block' && method === 'POST') {
    const scope = (body && body.scope) || 'dst';
    return { ok: true, applied: scope === 'device' ? ['iptables -I UBM_FWD -s <ip> -j DROP'] : ['iptables -I UBM_FWD -d <dst> -j DROP'] };
  }

  if (p === '/api/policies' && method === 'GET') return { policies: mockState.policies };
  if (p === '/api/policies' && method === 'POST') {
    const pol = {
      id: `p-${Math.floor(Date.now() / 1000)}-${mockState.policies.length + 1}`,
      name: (body && body.name) || '新策略', enabled: body?.enabled !== false,
      targets: body?.targets || { ips: [], groups: [], all: false },
      schedule: body?.schedule || { days: [], start: '00:00', end: '23:59' },
      action: body?.action || 'block',
      categories: body?.categories || [],
      domains: body?.domains || [],
      limitKbps: body?.limitKbps || { down: 0, up: 0 },
      hits: 0,
      createdAt: Math.floor(Date.now() / 1000),
      updatedAt: Math.floor(Date.now() / 1000)
    };
    mockState.policies.push(pol);
    return { policy: pol };
  }
  if (seg[1] === 'policies' && seg.length === 3 && method === 'PUT') {
    const pol = mockState.policies.find((x) => x.id === seg[2]);
    if (!pol) throw makeError('策略不存在', 'not_found', 404);
    Object.assign(pol, body || {}, { updatedAt: Math.floor(Date.now() / 1000) });
    return { policy: pol };
  }
  if (seg[1] === 'policies' && seg.length === 3 && method === 'DELETE') {
    mockState.policies = mockState.policies.filter((x) => x.id !== seg[2]);
    return { ok: true };
  }
  if (seg[1] === 'policies' && seg[3] === 'toggle' && method === 'POST') {
    const pol = mockState.policies.find((x) => x.id === seg[2]);
    if (!pol) throw makeError('策略不存在', 'not_found', 404);
    pol.enabled = !!(body && body.enabled);
    pol.updatedAt = Math.floor(Date.now() / 1000);
    return { policy: pol };
  }
  if (p === '/api/enforce/status') {
    return {
      iptablesRules: mockState.blocked.size + 2,
      tcDevices: mockState.limited.size,
      dnsBlockedDomains: mockState.dnsBlocked.length,
      activePolicies: mockState.policies.filter((x) => x.enabled).length,
      dnsTap: true
    };
  }
  if (p === '/api/enforce/dns') {
    // 去重升序，空值强制 []（与后端一致）
    return { domains: [...new Set(mockState.dnsBlocked)].sort() };
  }
  if (p === '/api/enforce/reset' && method === 'POST') {
    const removed = [];
    mockState.blocked.forEach((ip) => removed.push(`iptables -D UBM_FWD -s ${ip} -j DROP`));
    mockState.blocked.clear();
    mockState.limited.clear();
    const n = mockState.dnsBlocked.length;
    mockState.dnsBlocked = [];
    mockState.devices.forEach((d) => { d.blocked = false; d.limitKbps = { down: 0, up: 0 }; });
    return { ok: true, removed: [...removed, `还原 ${n} 条 DNS 拦截`] };
  }
  if (p === '/api/enforce/blocks' && method === 'GET') {
    const now = Math.floor(Date.now() / 1000);
    const blocks = [];
    mockState.blocked.forEach((ip) => blocks.push({ ip, type: 'device', reason: '手动断网', at: now - 120, downKbps: 0, upKbps: 0 }));
    mockState.limited.forEach((v, ip) => blocks.push({ ip, type: 'limit', reason: '手动限速', at: now - 300, downKbps: v.down || 0, upKbps: v.up || 0 }));
    return { blocks };
  }
  if (seg[1] === 'enforce' && seg[2] === 'blocks' && seg.length === 5 && seg[4] === 'unblock' && method === 'POST') {
    const ip = decodeURIComponent(seg[3]);
    const type = q.get('type') || '';
    const revoked = [];
    if (!type || type === 'device') {
      mockState.blocked.delete(ip);
      const d = mockState.devices.find((x) => x.ip === ip);
      if (d) d.blocked = false;
      revoked.push(`已恢复 ${ip} 联网`);
    }
    if (!type || type === 'limit') {
      mockState.limited.delete(ip);
      const d = mockState.devices.find((x) => x.ip === ip);
      if (d) d.limitKbps = { down: 0, up: 0 };
      revoked.push(`已取消 ${ip} 限速`);
    }
    return { ok: true, applied: [], revoked };
  }

  if (p === '/api/events' && method === 'GET') return makeEvents(q);
  if (seg[1] === 'events' && seg[2] === 'clear' && method === 'POST') {
    const n = mockState.events.length;
    mockState.events = [];
    return { ok: true, removed: n };
  }
  if (seg[1] === 'events' && seg[3] === 'ack' && method === 'POST') {
    const ev = mockState.events.find((x) => x.id === seg[2]);
    if (ev) ev.acked = !!(body && body.acked);
    return { ok: true, event: ev };
  }
  if (p === '/api/security/risk') return makeRisk();
  if (p === '/api/security/whitelist' && method === 'GET') {
    return { items: [...mockState.whitelist] };
  }
  if (p === '/api/security/whitelist' && method === 'POST') {
    const t = body && body.type, tg = body && body.target;
    if (!t || !tg) throw makeError('缺少 type/target', 'bad_request', 400);
    const id = `${t}|${tg}`;
    if (!mockState.whitelist.some((w) => w.id === id)) {
      mockState.whitelist.push({ id, type: t, target: tg, note: (body && body.note) || '', at: Math.floor(Date.now() / 1000) });
    }
    return { ok: true, item: mockState.whitelist.find((w) => w.id === id) };
  }
  if (seg[1] === 'security' && seg[2] === 'whitelist' && seg.length === 4 && method === 'DELETE') {
    const id = decodeURIComponent(seg[3]);
    mockState.whitelist = mockState.whitelist.filter((w) => w.id !== id);
    return { ok: true };
  }
  if (p === '/api/threats' && method === 'GET') {
    const q = String(query.search || '').trim();
    const allDomains = [
      { target: 'pool.minexmr.com', kind: 'mining', source: 'Abuse.ch URLhaus', confidence: 90 },
      { target: 'bet365.com', kind: 'scam', source: '内置赌博库', confidence: 100 },
      { target: 'pornhub.com', kind: 'scam', source: '内置色情库', confidence: 100 }
    ];
    const allIps = [
      { target: '1.2.3.0/24', kind: 'c2', source: 'Feodo Tracker', confidence: 80 },
      { target: '203.0.113.5', kind: 'botnet', source: 'Feodo Tracker', confidence: 80 }
    ];
    if (q) {
      const ql = q.toLowerCase();
      const dm = allDomains.filter((d) => d.target.toLowerCase().includes(ql));
      const ip = allIps.filter((i) => i.target.toLowerCase().includes(ql));
      return { query: q, domains: dm, ips: ip, counts: { domains: allDomains.length, ips: allIps.length }, matched: { domains: dm.length, ips: ip.length }, updatedAt: 1730000000, errors: [] };
    }
    return { domains: allDomains, ips: allIps, counts: { domains: allDomains.length, ips: allIps.length }, updatedAt: 1730000000, errors: [] };
  }
  if (p === '/api/threats/update' && method === 'POST') {
    return { ok: true, updatedAt: 1730000000, domains: 5066, ips: 3063, errors: [] };
  }
  if (p === '/api/topology') return makeTopology();
  if (p === '/api/settings' && method === 'GET') {
    const { pending, hint } = switchHintAndPending();
    return { ...mockState.settings, pending, hint };
  }
  if (p === '/api/settings' && method === 'PUT') {
    const r = applySwitchPatch(body || {});
    const ph = switchHintAndPending();
    const out = { ok: true, settings: { ...mockState.settings }, applied: r.applied, revoked: r.revoked, pending: ph.pending, hint: ph.hint };
    queueMicrotask(() => notifySettings(out.settings));
    return out;
  }
  if (p === '/api/settings/toggle' && method === 'POST') {
    const key = (body && body.key) || '';
    const value = body ? body.value : undefined;
    const r = applySwitchPatch({ [key]: value });
    const ph = switchHintAndPending();
    const out = { ok: true, settings: { ...mockState.settings }, applied: r.applied, revoked: r.revoked, pending: ph.pending, hint: ph.hint };
    queueMicrotask(() => notifySettings(out.settings));
    return out;
  }
  if (p === '/api/system') return makeSystem();

  throw makeError(`未实现的接口：${p}`, 'not_implemented', 404);
}

/* ---------- mock SSE ---------- */
let mockStreamTimer = null;
const mockListeners = new Set();

function startMockStream() {
  if (mockStreamTimer) return;
  const push = () => {
    mockState.tickSeq++;
    const ov = makeOverview();
    const tick = {
      ts: ov.ts,
      // 与真实后端对齐（backend-dev）：devices 为全量帧
      full: true,
      deviceCount: mockState.devices.length,
      kpi: ov.kpi,
      sys: ov.sys,
      devices: mockState.devices.map((d) => ({
        ip: d.ip, name: d.hostname, alias: d.alias, online: d.online,
        upBps: d.upBps, downBps: d.downBps, conns: d.conns, risk: d.risk,
        blocked: d.blocked, topCat: d.topCat
      })),
      categories: ov.categories.map((c) => ({ key: c.key, upBps: c.upBps, downBps: c.downBps, share: c.share })),
      trendPoint: ov.trend[ov.trend.length - 1],
      wan: { rxBps: ov.sys.wanRxBps, txBps: ov.sys.wanTxBps }
    };
    mockListeners.forEach((fn) => { try { fn('tick', tick); } catch (_) {} });

    // 偶尔推送一条告警（每 12 帧一条）
    if (mockState.tickSeq % 12 === 0) {
      const pool = EVENT_POOL.filter((e) => e.severity !== 'info');
      const e = pool[mockState.tickSeq % pool.length];
      const alert = { ...e, id: `e-live-${mockState.alertSeq++}`, ts: Math.floor(Date.now() / 1000), acked: false };
      mockState.events.unshift(alert);
      mockListeners.forEach((fn) => { try { fn('alert', alert); } catch (_) {} });
    }
  };
  push();
  mockStreamTimer = setInterval(push, 2000);
}

function stopMockStream() {
  if (mockStreamTimer) { clearInterval(mockStreamTimer); mockStreamTimer = null; }
}

/* ==========================================================================
   对外 API
   ========================================================================== */

export const api = {
  mock: isMock,

  /* ---- 鉴权 ---- */
  async login(password) {
    const r = await request('/api/login', { method: 'POST', body: { password }, skip401: true });
    _sessionDead = false;
    return r;
  },
  async logout() {
    try { return await request('/api/logout', { method: 'POST' }); }
    finally { closeAllSubscriptions(); }
  },
  async session() {
    const r = await request('/api/session');
    if (r && r.authed === false) { _sessionDead = true; }
    else _sessionDead = false;
    return r || { authed: false };
  },
  async changePassword(oldPassword, newPassword) {
    return request('/api/password', { method: 'POST', body: { old: oldPassword, new: newPassword } });
  },

  /* ---- 总览 ---- */
  async getOverview() {
    return request('/api/overview');
  },

  /* ---- 设备 ---- */
  async getDevices() {
    const r = await request('/api/devices');
    return r && Array.isArray(r.devices) ? r.devices : [];
  },
  async getDevice(ip) {
    return request(`/api/devices/${encodeURIComponent(ip)}`);
  },
  async setAlias(ip, alias) {
    return request(`/api/devices/${encodeURIComponent(ip)}/alias`, { method: 'POST', body: { alias } });
  },
  async setGroup(ip, group) {
    return request(`/api/devices/${encodeURIComponent(ip)}/group`, { method: 'POST', body: { group } });
  },
  async setBlock(ip, blocked) {
    return request(`/api/devices/${encodeURIComponent(ip)}/block`, { method: 'POST', body: { blocked } });
  },
  async setLimit(ip, downKbps, upKbps) {
    return request(`/api/devices/${encodeURIComponent(ip)}/limit`, { method: 'POST', body: { downKbps, upKbps } });
  },
  async forget(ip) {
    return request(`/api/devices/${encodeURIComponent(ip)}/forget`, { method: 'POST' });
  },

  /* ---- 流量 ---- */
  async getTraffic(range = '1h') {
    return request('/api/traffic', { query: { range } });
  },
  async getDomains(range = '1h', limit = 50) {
    return request('/api/traffic/domains', { query: { range, limit } });
  },
  async getConns({ limit = 200, q = '', device = '' } = {}) {
    return request('/api/traffic/conns', { query: { limit, q, device } });
  },
  async blockConn(id, scope = 'dst') {
    return request(`/api/traffic/conns/${encodeURIComponent(id)}/block`, { method: 'POST', body: { scope } });
  },

  /* ---- 策略 ---- */
  async getPolicies() {
    const r = await request('/api/policies');
    return r && Array.isArray(r.policies) ? r.policies : [];
  },
  async createPolicy(p) {
    return request('/api/policies', { method: 'POST', body: p });
  },
  async updatePolicy(id, p) {
    return request(`/api/policies/${encodeURIComponent(id)}`, { method: 'PUT', body: p });
  },
  async deletePolicy(id) {
    return request(`/api/policies/${encodeURIComponent(id)}`, { method: 'DELETE' });
  },
  async togglePolicy(id, enabled) {
    return request(`/api/policies/${encodeURIComponent(id)}/toggle`, { method: 'POST', body: { enabled } });
  },
  async getEnforceStatus() {
    return request('/api/enforce/status');
  },
  /**
   * DNS 拦截域名明细（docs/api.md §5）。
   * 响应：{"domains": string[]} —— 去重升序，空值强制为 []。
   */
  async getDnsBlocked() {
    const r = await request('/api/enforce/dns');
    return (r && Array.isArray(r.domains)) ? r.domains : [];
  },
  async enforceReset() {
    return request('/api/enforce/reset', { method: 'POST' });
  },

  /* ---- 安全 ---- */
  async getEvents(params = {}) {
    return request('/api/events', { query: params });
  },
  async ackEvent(id, acked = true) {
    return request(`/api/events/${encodeURIComponent(id)}/ack`, { method: 'POST', body: { acked } });
  },
  async clearEvents() {
    return request('/api/events/clear', { method: 'POST' });
  },
  async getRisk() {
    return request('/api/security/risk');
  },

  /* ---- 告警白名单（task-5 契约：GET/POST/DELETE /api/security/whitelist） ---- */
  async getWhitelist() {
    return request('/api/security/whitelist');
  },
  async addWhitelist(type, target, note = '') {
    return request('/api/security/whitelist', { method: 'POST', body: { type, target, note } });
  },
  async removeWhitelist(id) {
    return request(`/api/security/whitelist/${encodeURIComponent(id)}`, { method: 'DELETE' });
  },

  /* ---- 威胁情报库（task-5 契约：GET /api/threats，search 查询窗口） ---- */
  async getThreats(opts = {}) {
    const query = {};
    if (opts.search) query.search = opts.search;
    if (opts.limit != null) query.limit = opts.limit;
    return request('/api/threats', { query });
  },
  async updateThreats() {
    return request('/api/threats/update', { method: 'POST' });
  },

  /* ---- 封禁列表 / 解封（task-5 契约：GET /api/enforce/blocks + POST unblock） ---- */
  async getBlocks() {
    return request('/api/enforce/blocks');
  },
  /** 解封。type 可省略（全部解封）或为 device|dst|limit。 */
  async unblock(ip, type = '') {
    const q = type ? `?type=${encodeURIComponent(type)}` : '';
    return request(`/api/enforce/blocks/${encodeURIComponent(ip)}/unblock${q}`, { method: 'POST', body: {} });
  },

  /* ---- 网络拓扑（docs/api.md / task-5 契约） ---- */
  /** GET /api/topology：节点（lan/zerotier/vpn/internet/proxy…）+ 链路（direct/proxy/zt/vpn）。 */
  async getTopology() {
    try {
      return await request('/api/topology');
    } catch (err) {
      // 后端尚未挂载 / 旧版本时降级，保证 3D 大屏仍能渲染拓扑层
      if (isMock) return makeTopology();
      return makeTopologyFallback();
    }
  },

  /* ---- 设置与系统 ---- */
  async getSettings() {
    return request('/api/settings');
  },
  async saveSettings(s) {
    return request('/api/settings', { method: 'PUT', body: s });
  },
  /** 便捷开关：POST /api/settings/toggle {"key":"enabled","value":false} */
  async toggleSetting(key, value) {
    return request('/api/settings/toggle', { method: 'POST', body: { key, value } });
  },
  async getSystem() {
    return request('/api/system');
  },

  /* ---- SSE 订阅 ---- */
  /**
   * 订阅 /api/stream。handler(type, payload) 收到 'hello' | 'tick' | 'alert'。
   * 返回 unsubscribe 函数。
   */
  subscribe(handler) {
    if (isMock) {
      const fn = (type, payload) => { try { handler(type, payload); } catch (e) { console.error(e); } };
      mockListeners.add(fn);
      startMockStream();
      const sub = {
        dispose() {
          mockListeners.delete(fn);
          if (mockListeners.size === 0) stopMockStream();
          _subs.delete(sub);
        }
      };
      _subs.add(sub);
      return () => sub.dispose();
    }
    const sub = new StreamSubscription(handler);
    return () => sub.dispose();
  },

  /** 关闭全部订阅（登录失效 / 登出） */
  closeAllSubscriptions,

  /** 全局 401 回调 */
  onUnauthorized,
  offUnauthorized,

  /** 模拟：mock 模式下触发一次 alert（便于演示） */
  mockEmitAlert(event) {
    if (!isMock) return;
    mockListeners.forEach((fn) => { try { fn('alert', event); } catch (_) {} });
  }
};

export default api;

/* ==========================================================================
   开关状态共享（docs/api.md §7.1 / §7.3）
   页面通过 subscribeSettings() 订阅开关变化，实时联动空态与提示条
   ========================================================================== */
export const SWITCH_DEFS = [
  { key: 'collect', name: '流量采集', icon: 'activity', desc: '不开启则看不到设备与流量数据' },
  { key: 'dnsTap', name: 'DNS 行为日志', icon: 'globe', desc: '不开启则无域名/应用维度归因' },
  { key: 'deviceControl', name: '设备管控', icon: 'shield', desc: '不开启则断网/限速按钮不生效' },
  { key: 'domainBlock', name: '域名封堵', icon: 'ban', desc: '不开启则不拦截域名' },
  { key: 'schedule', name: '定时策略', icon: 'clock', desc: '不开启则不按时间窗自动启停' },
  { key: 'alerts', name: '安全告警', icon: 'alert', desc: '不开启则不做风险研判' },
  { key: 'history', name: '历史统计', icon: 'layers', desc: '不开启则只保留实时数据' }
];

/** 关闭某开关需要撤销已下发规则（需要二次确认） */
export const REVOKE_SWITCHES = ['dnsTap', 'deviceControl', 'domainBlock', 'enabled'];

let _settings = null;
const _settingsListeners = new Set();

export function getSettingsCache() { return _settings; }
export function isEnabled() { return !(_settings && _settings.enabled === false); }
export function isFeatureOn(key) {
  if (!(_settings && _settings.enabled !== false)) return false;
  return _settings[key] !== false;
}

/** 订阅开关变化，返回 unsubscribe */
export function subscribeSettings(fn) {
  _settingsListeners.add(fn);
  return () => _settingsListeners.delete(fn);
}
function notifySettings(s) {
  _settings = s;
  _settingsListeners.forEach((fn) => { try { fn(s); } catch (e) { console.error('[settings]', e); } });
}

/** 拉取设置并广播（启动时调用一次） */
export async function refreshSettings() {
  try {
    const s = await api.getSettings();
    notifySettings(s);
    return s;
  } catch (e) {
    console.warn('[settings] load failed', e.message);
    return null;
  }
}

/**
 * 跨标签页同步：契约中没有 settings 的 SSE 推送，
 * 因此在标签页重新获得焦点 / 可见时主动重新拉一次 GET /api/settings。
 */
let _syncBound = false;
function bindVisibilitySync() {
  if (_syncBound || typeof document === 'undefined') return;
  _syncBound = true;
  const onVisible = () => {
    if (document.visibilityState === 'visible') refreshSettings();
  };
  document.addEventListener('visibilitychange', onVisible);
  window.addEventListener('focus', () => { if (document.visibilityState === 'visible') refreshSettings(); });
}
bindVisibilitySync();

/** 变更开关（走 toggleSetting），返回 {settings, applied, revoked, pending, hint} */
export async function setSwitch(key, value) {
  const r = await api.toggleSetting(key, value);
  const s = (r && r.settings) || null;
  if (s) notifySettings(s);
  return {
    settings: s,
    applied: (r && r.applied) || [],
    revoked: (r && r.revoked) || [],
    pending: (r && r.pending) || (s ? SWITCH_DEFS.filter((d) => s[d.key] === false).map((d) => d.key) : []),
    hint: (r && typeof r.hint === 'string') ? r.hint : ''
  };
}

/** 保存设置（PUT），返回 {settings, applied, revoked, pending, hint} */
export async function putSettings(patch) {
  const r = await api.saveSettings(patch);
  const s = (r && r.settings) || null;
  if (s) notifySettings(s);
  return {
    settings: s,
    applied: (r && r.applied) || [],
    revoked: (r && r.revoked) || [],
    pending: (r && r.pending) || (s ? SWITCH_DEFS.filter((d) => s[d.key] === false).map((d) => d.key) : []),
    hint: (r && typeof r.hint === 'string') ? r.hint : ''
  };
}
