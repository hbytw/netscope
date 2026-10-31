/* ==========================================================================
   观澜 NetScope · 格式化工具
   约定（docs/api.md）：时间戳为 Unix 秒；速率为 bit/s；流量为字节。
   ========================================================================== */

const BYTE_UNITS = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
const BIT_UNITS = ['bps', 'Kbps', 'Mbps', 'Gbps', 'Tbps'];

/** 字节数 → 人类可读（自动 B/KB/MB/GB/TB） */
export function formatBytes(n, digits = 1) {
  const v = Number(n);
  if (!Number.isFinite(v)) return '—';
  if (v === 0) return '0 B';
  const neg = v < 0;
  let x = Math.abs(v);
  let i = 0;
  while (x >= 1024 && i < BYTE_UNITS.length - 1) { x /= 1024; i++; }
  const d = i === 0 ? 0 : digits;
  return `${neg ? '-' : ''}${x.toFixed(d)} ${BYTE_UNITS[i]}`;
}

/** 速率（bit/s）→ 人类可读（统一按字节速率显示：bit/s ÷ 8 = byte/s，MB/s）
 *  用户要求全站流量统一 MB（字节），不再用 bps/Mbps（比特）。 */
export function formatBps(n, digits = 1) {
  const v = Number(n);
  if (!Number.isFinite(v)) return '—';
  if (v === 0) return '0 B/s';
  const neg = v < 0;
  let x = Math.abs(v) / 8; // bit/s → byte/s
  let i = 0;
  while (x >= 1024 && i < BYTE_UNITS.length - 1) { x /= 1024; i++; }
  const d = i === 0 ? 0 : digits;
  return `${neg ? '-' : ''}${x.toFixed(d)} ${BYTE_UNITS[i]}/s`;
}

/** 秒 → 时长（1d 2h 3m / 2h 03m / 45s） */
export function formatDuration(sec) {
  const s = Math.max(0, Math.floor(Number(sec) || 0));
  if (s === 0) return '0s';
  const d = Math.floor(s / 86400);
  const h = Math.floor((s % 86400) / 3600);
  const m = Math.floor((s % 3600) / 60);
  const ss = s % 60;
  if (d > 0) return `${d}d ${h}h ${m}m`;
  if (h > 0) return `${h}h ${String(m).padStart(2, '0')}m`;
  if (m > 0) return `${m}m ${String(ss).padStart(2, '0')}s`;
  return `${ss}s`;
}

/** 时间戳 → 绝对时间 HH:mm:ss（今天）或 MM-DD HH:mm（往年） */
export function formatTime(ts, withDate = false) {
  if (ts === null || ts === undefined || ts === 0) return '—';
  const n = Number(ts);
  if (!Number.isFinite(n)) return '—';
  const d = new Date(n * 1000);
  const p = (x) => String(x).padStart(2, '0');
  const time = `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
  if (withDate) return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${time}`;
  const now = new Date();
  const sameDay = d.getFullYear() === now.getFullYear() && d.getMonth() === now.getMonth() && d.getDate() === now.getDate();
  if (sameDay) return time;
  return `${p(d.getMonth() + 1)}-${p(d.getDate())} ${time}`;
}

/** 时间戳 → 相对时间（刚刚 / 3分钟前 / 2小时前 / 3天前） */
export function formatRelative(ts) {
  if (ts === null || ts === undefined || ts === 0) return '—';
  const n = Number(ts);
  if (!Number.isFinite(n)) return '—';
  const diff = Math.floor(Date.now() / 1000) - n;
  if (diff < 0) return '刚刚';
  if (diff < 45) return '刚刚';
  if (diff < 3600) return `${Math.floor(diff / 60)} 分钟前`;
  if (diff < 86400) return `${Math.floor(diff / 3600)} 小时前`;
  if (diff < 86400 * 30) return `${Math.floor(diff / 86400)} 天前`;
  return formatTime(n, true);
}

/** 0~1 → 百分比字符串 */
export function formatPercent(v, digits = 1) {
  const n = Number(v);
  if (!Number.isFinite(n)) return '—';
  const pct = n <= 1 && n >= 0 ? n * 100 : n;
  return `${pct.toFixed(digits)}%`;
}

/** 0~1 → 风险等级（low / guard / high） */
export function riskLevel(v) {
  const n = Number(v) || 0;
  if (n >= 0.7) return 'high';
  if (n >= 0.35) return 'guard';
  return 'low';
}

export const RISK_LABEL = { low: '低风险', guard: '需关注', high: '高风险' };
export const RISK_SEM = { low: 'ok', guard: 'warn', high: 'crit' };

/** 逗号分隔千分位 */
export function formatNumber(n) {
  const v = Number(n);
  if (!Number.isFinite(v)) return '—';
  return v.toLocaleString('zh-CN');
}

/** 事件严重级别 → 语义色 class 后缀 */
export const SEVERITY_SEM = { critical: 'crit', warn: 'warn', info: 'info' };
export const SEVERITY_LABEL = { critical: '严重', warn: '警告', info: '提示' };

export const CATEGORY_ORDER = ['video', 'game', 'social', 'web', 'download', 'mail', 'cloud', 'other'];
export const CATEGORY_COLOR = {
  video: '#22d3ee', game: '#a78bfa', social: '#f472b6', web: '#38bdf8',
  download: '#fbbf24', mail: '#34d399', cloud: '#2dd4bf', other: '#94a3b8'
};
export const CATEGORY_LABEL = {
  video: '视频流媒体', game: '游戏', social: '社交聊天', web: '网页浏览',
  download: '下载更新', mail: '邮件', cloud: '云盘存储', other: '其他'
};

/** 时间范围 → 毫秒跨度 */
export const RANGE_LABEL = { '1h': '1 小时', '6h': '6 小时', '24h': '24 小时', '7d': '7 天' };
