/*!
 * 观澜 NetScope · 3D 托盘态势场景
 * ------------------------------------------------------------------
 * 契约（docs/design.md §6.1，冻结）：
 *   const scene = createTrayScene(container, {
 *     onSelectDevice(ip|null), onHoverDevice(ip|null), quality: 'high'|'medium'
 *   });
 *   scene.update(state);        // state = api.md §8 tick 数据，内部 lerp
 *   scene.setHighlight(ip|null);
 *   scene.focusDevice(ip);      // 平滑聚焦某设备
 *   scene.resize();
 *   scene.dispose();
 *
 * 资源约束（路由器 N1 / 低端 GPU 友好）：
 *   - rAF 自适应跳帧：常态 30fps / 交互 60fps / 无数据 12fps 巡航 / hidden 暂停
 *   - 设备芯片、光柱共享 geometry + 4 套状态色材质；8 个分类扇柱合并为
 *     「顶面 / 侧面」两套 BufferGeometry（各 8 个 group，共用 8 套分类材质，
 *     顶点色负责侧面压暗）；粒子为单个 Points + 属性缓冲
 *   - CanvasTexture 标签 LRU 缓存（≤64，refcount 不驱逐在用项）
 *   - 无 shadowMap（托盘下方假阴影贴图）；不启用后处理 Bloom（加法辉光替代）
 *   - 固定 4 个光源：Hemisphere + 2 Point + 1 Directional
 * 注：本模块只消费 tick 数据，不直接访问 API / 不依赖任何运行时 CDN。
 */

import * as THREE from 'three';
import { OrbitControls } from 'three/addons/controls/OrbitControls.js';

/* ================================================================== */
/* 常量与工具                                                          */
/* ================================================================== */

const TAU = Math.PI * 2;
const UP = new THREE.Vector3(0, 1, 0);

/** 分类固定键 / 名称 / 色值（与 docs/api.md §8 严格一致，勿改） */
export const CATEGORY_META = Object.freeze([
  { key: 'video', label: '视频流媒体', color: '#22d3ee' },
  { key: 'game', label: '游戏', color: '#a78bfa' },
  { key: 'social', label: '社交聊天', color: '#f472b6' },
  { key: 'web', label: '网页浏览', color: '#38bdf8' },
  { key: 'download', label: '下载更新', color: '#fbbf24' },
  { key: 'mail', label: '邮件', color: '#34d399' },
  { key: 'cloud', label: '云盘存储', color: '#2dd4bf' },
  { key: 'other', label: '其他', color: '#94a3b8' },
]);

const CATEGORY_INDEX = new Map(CATEGORY_META.map((c, i) => [c.key, i]));

/**
 * 设备状态色（docs/design.md §6.2 / 任务书）
 * 语义与「设备」页（ui/devices.js）一致：已断网 = crit 红、离线 = mute 灰。
 * unknown：状态字段缺失时的「未知」灰，既不冒充正常在线，也不误报离线。
 */
const STATUS_META = {
  normal: '#22d3ee', // 正常
  limit: '#fbbf24', // 限速
  blocked: '#fb7185', // 已断网（crit 红，同「设备」页）
  offline: '#5d6f8c', // 离线（mute 灰，同「设备」页）
  risk: '#a78bfa', // 风险 > 0.6
  unknown: '#8a9bb5', // 状态未知（online/blocked 字段缺失）
};

const BRAND = '#22d3ee';
const FOG_COLOR = 0x04070e;

const CFG = {
  trayRadius: 13,
  trayThickness: 0.7,
  trayTop: 0.7,
  sectorInner: 3.4,
  sectorOuter: 10.4,
  sectorSegments: 24,
  sectorBaseY: 0.72,
  sectorMinHeight: 0.8,
  sectorMaxHeight: 4.2,
  sectorMinArc: 0.05,
  sectorGap: 0.014,
  trendRadius: 11.1,
  trendCount: 60,
  trendBaseY: 0.74,
  deviceInner: 15.5,
  deviceOuter: 17,
  deviceMax: 24,
  chipRadius: 0.85,
  chipThickness: 0.22,
  pillarBaseY: 0.02,
  pillarRadius: 0.09,
  pillarMinHeight: 0.8,
  pillarMaxHeight: 7,
  deviceParticles: 6,
  particleMax: 200,
  orbitSamples: 32,
  labelHeight: 1.45,
  /* 网络拓扑层（LAN/ZeroTier/VPN/互联网/代理 + 链路流向） */
  topoRadius: 22,
  topoNodeHeight: 0.24,
  topoLabelHeight: 1.55,
  topoLinkMaxWidth: 0.085,
  topoFlowLabelHeight: 1.25,
  topoParticlesPerLink: 5,
  autoRotateRadPerSec: 0.25 / 60, // 0.25 rad/min（手动按 dt 旋转，帧率无关）
  entryDuration: 1.2,
  focusDuration: 1.1,
  cameraFov: 45,
  cameraNear: 0.1,
  cameraFar: 260,
  cameraHome: new THREE.Vector3(0, 30, 40),
  cameraTarget: new THREE.Vector3(0, 3, 0),
  minPolarAngle: Math.PI * 0.25,
  maxPolarAngle: Math.PI * 0.48,
  minDistance: 24,
  maxDistance: 70,
  labelCacheMax: 64,
};

/* ---------- 数值工具 ---------- */

const clamp = (v, a, b) => (v < a ? a : v > b ? b : v);

/** 三态取值：字段缺失或非法 → null（未知），不做乐观默认 */
function numOrNull(v) {
  if (typeof v === 'number') return Number.isFinite(v) ? v : null;
  if (typeof v === 'string' && v.trim() !== '') {
    const n = Number(v);
    return Number.isFinite(n) ? n : null;
  }
  return null;
}

/** 帧率无关的指数平滑：cur → target，lambda 越大越快 */
function damp(cur, target, lambda, dt) {
  return target + (cur - target) * Math.exp(-lambda * dt);
}

function easeInOutCubic(t) {
  return t < 0.5 ? 4 * t * t * t : 1 - Math.pow(-2 * t + 2, 3) / 2;
}

function formatRate(bps) {
  // 统一按字节速率显示（bit/s ÷ 8 = byte/s，MB/s）
  const v = Math.max(0, Number(bps) || 0) / 8;
  if (v >= 1024 * 1024 * 1024) return (v / (1024 * 1024 * 1024)).toFixed(2) + ' GB/s';
  if (v >= 1024 * 1024) return (v / (1024 * 1024)).toFixed(1) + ' MB/s';
  if (v >= 1024) return (v / 1024).toFixed(0) + ' KB/s';
  return v.toFixed(0) + ' B/s';
}

function truncateChars(str, max) {
  const arr = Array.from(String(str == null ? '' : str));
  if (arr.length <= max) return arr.join('');
  return arr.slice(0, max).join('') + '…';
}

/* ================================================================== */
/* 纹理工厂（一次性生成，全程复用）                                     */
/* ================================================================== */

/** 径向渐变光晕纹理（白 → 透明） */
function makeGlowTexture(size = 128) {
  const c = document.createElement('canvas');
  c.width = c.height = size;
  const ctx = c.getContext('2d');
  const g = ctx.createRadialGradient(size / 2, size / 2, 0, size / 2, size / 2, size / 2);
  g.addColorStop(0, 'rgba(255,255,255,1)');
  g.addColorStop(0.25, 'rgba(255,255,255,.62)');
  g.addColorStop(0.55, 'rgba(255,255,255,.18)');
  g.addColorStop(1, 'rgba(255,255,255,0)');
  ctx.fillStyle = g;
  ctx.fillRect(0, 0, size, size);
  const tex = new THREE.CanvasTexture(c);
  tex.colorSpace = THREE.SRGBColorSpace;
  return tex;
}

/** 深空背景：径向渐变 + 深蓝紫星云 + 星点，一次性生成 */
function makeBackgroundTexture(size = 1024) {
  const c = document.createElement('canvas');
  c.width = c.height = size;
  const ctx = c.getContext('2d');
  const g = ctx.createRadialGradient(size * 0.5, size * 0.42, size * 0.02, size * 0.5, size * 0.5, size * 0.72);
  g.addColorStop(0, '#172a4f');
  g.addColorStop(0.28, '#101b38');
  g.addColorStop(0.62, '#080e1e');
  g.addColorStop(1, '#03050c');
  ctx.fillStyle = g;
  ctx.fillRect(0, 0, size, size);

  // 两团极淡的星云（蓝 / 紫），增加层次
  const nebula = [
    [0.26, 0.66, 0.3, 'rgba(38,86,170,.10)'],
    [0.74, 0.3, 0.26, 'rgba(96,64,178,.09)'],
  ];
  for (const [nx, ny, nr, color] of nebula) {
    const ng = ctx.createRadialGradient(nx * size, ny * size, 0, nx * size, ny * size, nr * size);
    ng.addColorStop(0, color);
    ng.addColorStop(1, 'rgba(0,0,0,0)');
    ctx.fillStyle = ng;
    ctx.fillRect(0, 0, size, size);
  }

  // 星点：少量聚集星团 + 弥散细星
  const rnd = mulberry32(20261031);
  const clusters = [];
  for (let i = 0; i < 7; i++) clusters.push([rnd() * size, rnd() * size, 20 + rnd() * 90]);
  for (let i = 0; i < 640; i++) {
    let x;
    let y;
    let r;
    let a;
    if (i < 260) {
      const cl = clusters[Math.floor(rnd() * clusters.length)];
      const ang = rnd() * TAU;
      const rad = Math.pow(rnd(), 1.7) * cl[2];
      x = cl[0] + Math.cos(ang) * rad;
      y = cl[1] + Math.sin(ang) * rad;
      r = rnd() * 1.15 + 0.25;
      a = rnd() * 0.22 + 0.05;
    } else {
      x = rnd() * size;
      y = rnd() * size;
      r = rnd() * 0.95 + 0.2;
      a = rnd() * 0.13 + 0.025;
    }
    ctx.fillStyle = `rgba(170,210,255,${a.toFixed(3)})`;
    ctx.beginPath();
    ctx.arc(x, y, r, 0, TAU);
    ctx.fill();
  }
  // 轻噪声，抑制色带
  const img = ctx.getImageData(0, 0, size, size);
  for (let i = 0; i < img.data.length; i += 4) {
    const n = (rnd() - 0.5) * 3;
    img.data[i] += n;
    img.data[i + 1] += n;
    img.data[i + 2] += n;
  }
  ctx.putImageData(img, 0, 0);
  const tex = new THREE.CanvasTexture(c);
  tex.colorSpace = THREE.SRGBColorSpace;
  return tex;
}

/** 托盘下方假阴影（径向黑渐变） */
function makeShadowTexture(size = 256) {
  const c = document.createElement('canvas');
  c.width = c.height = size;
  const ctx = c.getContext('2d');
  const g = ctx.createRadialGradient(size / 2, size / 2, size * 0.04, size / 2, size / 2, size * 0.5);
  g.addColorStop(0, 'rgba(0,0,0,.86)');
  g.addColorStop(0.55, 'rgba(0,0,0,.42)');
  g.addColorStop(1, 'rgba(0,0,0,0)');
  ctx.fillStyle = g;
  ctx.fillRect(0, 0, size, size);
  const tex = new THREE.CanvasTexture(c);
  tex.colorSpace = THREE.SRGBColorSpace;
  return tex;
}

function mulberry32(seed) {
  let a = seed >>> 0;
  return function () {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/* ---------- 设备标签：CanvasTexture + LRU 缓存 ---------- */

const LABEL_CANVAS_W = 512;
const LABEL_CANVAS_H = 160;
const LABEL_NAME_FONT = '700 40px -apple-system,"Segoe UI","PingFang SC","Microsoft YaHei",system-ui,sans-serif';
const LABEL_RATE_FONT = '500 26px -apple-system,"Segoe UI","PingFang SC","Microsoft YaHei",system-ui,sans-serif';

/**
 * 绘制标签纹理。key = `${name}\n${downText}\n${upText}`。
 * 深色圆角底板 + 细边框 + 白字名称 + 青色下行 / 紫色上行。
 * 另支持流向专用紧凑标签：key = `FLOW|#rrggbb\n${downText}\n${upText}`（无名称行，字号更大）。
 */
function drawLabelTexture(key) {
  const raw = String(key);
  if (raw.startsWith('FLOW|')) return drawFlowLabelTexture(raw.slice(5));

  const [name, downText, upText] = raw.split('\n');
  const c = document.createElement('canvas');
  c.width = LABEL_CANVAS_W;
  c.height = LABEL_CANVAS_H;
  const ctx = c.getContext('2d');
  ctx.clearRect(0, 0, LABEL_CANVAS_W, LABEL_CANVAS_H);
  ctx.textAlign = 'center';
  ctx.textBaseline = 'middle';

  // 半透明深色底板 + 细边框
  const pad = 5;
  const r = 18;
  const x0 = pad;
  const y0 = pad;
  const w = LABEL_CANVAS_W - pad * 2;
  const h = LABEL_CANVAS_H - pad * 2;
  ctx.beginPath();
  if (ctx.roundRect) {
    ctx.roundRect(x0, y0, w, h, r);
  } else {
    ctx.moveTo(x0 + r, y0);
    ctx.arcTo(x0 + w, y0, x0 + w, y0 + h, r);
    ctx.arcTo(x0 + w, y0 + h, x0, y0 + h, r);
    ctx.arcTo(x0, y0 + h, x0, y0, r);
    ctx.arcTo(x0, y0, x0 + w, y0, r);
    ctx.closePath();
  }
  ctx.fillStyle = 'rgba(5,10,20,.72)';
  ctx.fill();
  ctx.lineWidth = 2;
  ctx.strokeStyle = 'rgba(34,211,238,.34)';
  ctx.stroke();

  // 名称
  ctx.font = LABEL_NAME_FONT;
  ctx.fillStyle = '#f2f8ff';
  ctx.fillText(name, LABEL_CANVAS_W / 2, 54);

  // 速率：下行青色 + 上行紫色
  ctx.font = LABEL_RATE_FONT;
  const downTxt = '↓ ' + downText;
  const upTxt = '  ↑ ' + upText;
  const wDown = ctx.measureText(downTxt).width;
  const wUp = ctx.measureText(upTxt).width;
  const totalW = wDown + wUp;
  const startX = (LABEL_CANVAS_W - totalW) / 2;
  ctx.textAlign = 'left';
  ctx.fillStyle = '#7fe9fb';
  ctx.fillText(downTxt, startX, 112);
  ctx.fillStyle = '#b9a8ff';
  ctx.fillText(upTxt, startX + wDown, 112);

  const tex = new THREE.CanvasTexture(c);
  tex.colorSpace = THREE.SRGBColorSpace;
  tex.anisotropy = 4;
  tex.minFilter = THREE.LinearFilter;
  tex.magFilter = THREE.LinearFilter;
  tex.generateMipmaps = false;
  return tex;
}

/** 流向速率标签：两行大字号（↓ 下行 / ↑ 上行），边框按 kind 着色，无名称行。 */
function drawFlowLabelTexture(rest) {
  const [kindHex, downText, upText] = String(rest).split('\n');
  const c = document.createElement('canvas');
  c.width = LABEL_CANVAS_W;
  c.height = LABEL_CANVAS_H;
  const ctx = c.getContext('2d');
  ctx.clearRect(0, 0, LABEL_CANVAS_W, LABEL_CANVAS_H);
  ctx.textAlign = 'center';
  ctx.textBaseline = 'middle';

  const pad = 5;
  const r = 18;
  const x0 = pad;
  const y0 = pad;
  const w = LABEL_CANVAS_W - pad * 2;
  const h = LABEL_CANVAS_H - pad * 2;
  ctx.beginPath();
  if (ctx.roundRect) {
    ctx.roundRect(x0, y0, w, h, r);
  } else {
    ctx.moveTo(x0 + r, y0);
    ctx.arcTo(x0 + w, y0, x0 + w, y0 + h, r);
    ctx.arcTo(x0 + w, y0 + h, x0, y0 + h, r);
    ctx.arcTo(x0, y0 + h, x0, y0, r);
    ctx.arcTo(x0, y0, x0 + w, y0, r);
    ctx.closePath();
  }
  ctx.fillStyle = 'rgba(5,10,20,.78)';
  ctx.fill();
  ctx.lineWidth = 2;
  ctx.strokeStyle = (kindHex || '#22d3ee') + '99';
  ctx.stroke();

  ctx.font = '600 46px -apple-system,"Segoe UI","PingFang SC","Microsoft YaHei",system-ui,sans-serif';
  ctx.fillStyle = '#8ff0ff';
  ctx.fillText('↓ ' + (downText || '0'), LABEL_CANVAS_W / 2, 56);
  ctx.fillStyle = '#c2b1ff';
  ctx.fillText('↑ ' + (upText || '0'), LABEL_CANVAS_W / 2, 112);

  const tex = new THREE.CanvasTexture(c);
  tex.colorSpace = THREE.SRGBColorSpace;
  tex.anisotropy = 4;
  tex.minFilter = THREE.LinearFilter;
  tex.magFilter = THREE.LinearFilter;
  tex.generateMipmaps = false;
  return tex;
}

/** LRU CanvasTexture 缓存（key=文本；refcount 保护在用纹理不被释放） */
function createLabelCache(max = CFG.labelCacheMax) {
  const entries = new Map(); // key -> { texture, refs, lastUse }
  let clock = 0;

  function acquire(key) {
    clock += 1;
    let e = entries.get(key);
    if (!e) {
      e = { texture: drawLabelTexture(key), refs: 0, lastUse: clock };
      entries.set(key, e);
    }
    e.refs += 1;
    e.lastUse = clock;
    evict();
    return e.texture;
  }

  function release(key) {
    if (!key) return;
    const e = entries.get(key);
    if (!e) return;
    e.refs = Math.max(0, e.refs - 1);
  }

  function evict() {
    if (entries.size <= max) return;
    // 从最久未使用开始，跳过仍被引用的纹理
    const sorted = [...entries.entries()].sort((a, b) => a[1].lastUse - b[1].lastUse);
    for (const [key, e] of sorted) {
      if (entries.size <= max) break;
      if (e.refs > 0) continue;
      e.texture.dispose();
      entries.delete(key);
    }
    // 极端情况：全部在用，仍未降到上限则放弃本次驱逐（不会发生：设备 ≤24）
  }

  return {
    acquire,
    release,
    get size() {
      return entries.size;
    },
    dispose() {
      for (const e of entries.values()) e.texture.dispose();
      entries.clear();
    },
  };
}

/* ================================================================== */
/* 分类扇柱：8 个环形扇合并为一个 BufferGeometry（8 个 group）           */
/* ================================================================== */

const SECTOR_TOP_VPS = 6; // 顶面：每分段 2 个三角形
const SECTOR_SIDE_VPS = 12; // 外壁 6 + 内壁 6
const SECTOR_CAP_VPS = 12; // 起止端面各 6

/**
 * 分类扇柱几何（合并 8 个扇区，每个扇区一个 material group）。
 * kind='top' 只含顶面（顶点色白）；kind='side' 只含内外壁+端面（顶点色压暗）。
 * 两套几何共用同一组 8 个分类材质（vertexColors 负责侧面压暗）。
 */
function createSectorGeometry(kind, count, innerR, outerR, segments) {
  const isTop = kind === 'top';
  const perSector = isTop ? segments * SECTOR_TOP_VPS : segments * SECTOR_SIDE_VPS + SECTOR_CAP_VPS;
  const total = perSector * count;
  const geo = new THREE.BufferGeometry();
  const pos = new Float32Array(total * 3);
  const nor = new Float32Array(total * 3);
  const col = new Float32Array(total * 3);
  geo.setAttribute('position', new THREE.BufferAttribute(pos, 3).setUsage(THREE.DynamicDrawUsage));
  geo.setAttribute('normal', new THREE.BufferAttribute(nor, 3).setUsage(THREE.DynamicDrawUsage));
  geo.setAttribute('color', new THREE.BufferAttribute(col, 3));
  // 侧面顶点色压暗 → 与顶面共用 8 套分类材质也能清晰区分明暗
  const tint = isTop ? 0.86 : 0.4;
  for (let i = 0; i < total; i++) {
    col[i * 3] = tint;
    col[i * 3 + 1] = tint;
    col[i * 3 + 2] = tint;
  }
  for (let i = 0; i < count; i++) geo.addGroup(i * perSector, perSector, i);
  // 顶点是动态写入的，跳过逐帧包围球计算
  geo.boundingSphere = new THREE.Sphere(new THREE.Vector3(0, 3, 0), 18);
  geo.userData.sector = { kind, count, innerR, outerR, segments, perSector, total };
  return geo;
}

/**
 * 把一批扇柱同时写入顶面 / 侧面缓冲。
 * sectors[i] = { start, end, height }；i 与 material group 一一对应。
 */
function updateSectorGeometries(topGeo, sideGeo, sectors) {
  const info = topGeo.userData.sector;
  const topPos = topGeo.attributes.position.array;
  const topNor = topGeo.attributes.normal.array;
  const sidePos = sideGeo.attributes.position.array;
  const sideNor = sideGeo.attributes.normal.array;
  const seg = info.segments;
  const ri = info.innerR;
  const ro = info.outerR;
  const baseY = CFG.sectorBaseY;

  for (let s = 0; s < info.count; s++) {
    const sector = sectors[s];
    const startAngle = sector.start;
    const endAngle = sector.end;
    const topY = baseY + Math.max(sector.height, 0.001);
    const span = endAngle - startAngle;
    let ot = s * info.perSector * 3;
    let os = s * sideGeo.userData.sector.perSector * 3;

    const tw = (x, y, z, nx, ny, nz) => {
      topPos[ot] = x;
      topPos[ot + 1] = y;
      topPos[ot + 2] = z;
      topNor[ot] = nx;
      topNor[ot + 1] = ny;
      topNor[ot + 2] = nz;
      ot += 3;
    };
    const sw = (x, y, z, nx, ny, nz) => {
      sidePos[os] = x;
      sidePos[os + 1] = y;
      sidePos[os + 2] = z;
      sideNor[os] = nx;
      sideNor[os + 1] = ny;
      sideNor[os + 2] = nz;
      os += 3;
    };

    for (let k = 0; k < seg; k++) {
      const a0 = startAngle + (span * k) / seg;
      const a1 = startAngle + (span * (k + 1)) / seg;
      const c0 = Math.cos(a0);
      const s0 = Math.sin(a0);
      const c1 = Math.cos(a1);
      const s1 = Math.sin(a1);

      const inAx = c0 * ri;
      const inAz = s0 * ri;
      const outAx = c0 * ro;
      const outAz = s0 * ro;
      const inBx = c1 * ri;
      const inBz = s1 * ri;
      const outBx = c1 * ro;
      const outBz = s1 * ro;

      // 顶面（法线 +Y）
      tw(inAx, topY, inAz, 0, 1, 0);
      tw(outBx, topY, outBz, 0, 1, 0);
      tw(outAx, topY, outAz, 0, 1, 0);
      tw(inAx, topY, inAz, 0, 1, 0);
      tw(inBx, topY, inBz, 0, 1, 0);
      tw(outBx, topY, outBz, 0, 1, 0);

      // 外壁
      const cm = Math.cos((a0 + a1) / 2);
      const sm = Math.sin((a0 + a1) / 2);
      sw(outAx, topY, outAz, cm, 0, sm);
      sw(outBx, topY, outBz, cm, 0, sm);
      sw(outBx, baseY, outBz, cm, 0, sm);
      sw(outAx, topY, outAz, cm, 0, sm);
      sw(outBx, baseY, outBz, cm, 0, sm);
      sw(outAx, baseY, outAz, cm, 0, sm);

      // 内壁
      sw(inAx, topY, inAz, -cm, 0, -sm);
      sw(inBx, topY, inBz, -cm, 0, -sm);
      sw(inBx, baseY, inBz, -cm, 0, -sm);
      sw(inAx, topY, inAz, -cm, 0, -sm);
      sw(inBx, baseY, inBz, -cm, 0, -sm);
      sw(inAx, baseY, inAz, -cm, 0, -sm);
    }

    // 起端面
    const cS = Math.cos(startAngle);
    const sS = Math.sin(startAngle);
    const nxS = sS;
    const nzS = -cS;
    sw(cS * ri, topY, sS * ri, nxS, 0, nzS);
    sw(cS * ro, topY, sS * ro, nxS, 0, nzS);
    sw(cS * ro, baseY, sS * ro, nxS, 0, nzS);
    sw(cS * ri, topY, sS * ri, nxS, 0, nzS);
    sw(cS * ro, baseY, sS * ro, nxS, 0, nzS);
    sw(cS * ri, baseY, sS * ri, nxS, 0, nzS);

    // 末端面
    const cE = Math.cos(endAngle);
    const sE = Math.sin(endAngle);
    const nxE = -sE;
    const nzE = cE;
    sw(cE * ri, topY, sE * ri, nxE, 0, nzE);
    sw(cE * ro, baseY, sE * ro, nxE, 0, nzE);
    sw(cE * ro, topY, sE * ro, nxE, 0, nzE);
    sw(cE * ri, topY, sE * ri, nxE, 0, nzE);
    sw(cE * ri, baseY, sE * ri, nxE, 0, nzE);
    sw(cE * ro, baseY, sE * ro, nxE, 0, nzE);
  }

  topGeo.attributes.position.needsUpdate = true;
  topGeo.attributes.normal.needsUpdate = true;
  sideGeo.attributes.position.needsUpdate = true;
  sideGeo.attributes.normal.needsUpdate = true;
}

/* ================================================================== */
/* 轨道流动线（单个 LineSegments + 自定义 shader）                      */
/* ================================================================== */

const ORBIT_VERT = /* glsl */ `
  attribute float aDist;
  attribute float aSpeed;
  attribute vec3 aColor;
  varying float vDist;
  varying float vSpeed;
  varying vec3 vColor;
  void main() {
    vDist = aDist;
    vSpeed = aSpeed;
    vColor = aColor;
    gl_Position = projectionMatrix * modelViewMatrix * vec4(position, 1.0);
  }
`;

const ORBIT_FRAG = /* glsl */ `
  uniform float uTime;
  varying float vDist;
  varying float vSpeed;
  varying vec3 vColor;
  void main() {
    float flow = fract(vDist * 0.55 - uTime * vSpeed);
    float dash = smoothstep(0.0, 0.05, flow) * (1.0 - smoothstep(0.38, 0.52, flow));
    float alpha = dash * 0.55;
    if (alpha < 0.015) discard;
    gl_FragColor = vec4(vColor * (0.7 + 0.55 * dash), alpha);
  }
`;

/* ================================================================== */
/* 粒子（单个 Points + 属性缓冲）                                       */
/* ================================================================== */

const PARTICLE_VERT = /* glsl */ `
  attribute float aSize;
  attribute vec3 aColor;
  uniform float uPixelRatio;
  varying vec3 vColor;
  void main() {
    vColor = aColor;
    vec4 mv = modelViewMatrix * vec4(position, 1.0);
    gl_PointSize = aSize * uPixelRatio * (160.0 / max(-mv.z, 1.0));
    gl_Position = projectionMatrix * mv;
  }
`;

const PARTICLE_FRAG = /* glsl */ `
  varying vec3 vColor;
  void main() {
    vec2 d = gl_PointCoord - vec2(0.5);
    float r = length(d);
    if (r > 0.5) discard;
    float a = smoothstep(0.5, 0.06, r);
    gl_FragColor = vec4(vColor * 1.15, a * 0.65);
  }
`;

/* ================================================================== */
/* 主入口                                                              */
/* ================================================================== */

/**
 * @param {HTMLElement} container
 * @param {{
 *   onSelectDevice?: (ip: string|null) => void,
 *   onHoverDevice?: (ip: string|null) => void,
 *   quality?: 'high'|'medium',
 *   fx?: 'off'|'bloom',           // 预留：Bloom 默认关闭
 * }} [options]
 */
export function createTrayScene(container, options = {}) {
  if (!container) throw new Error('[tray] createTrayScene: container 不能为空');

  const onSelectDevice = typeof options.onSelectDevice === 'function' ? options.onSelectDevice : () => {};
  const onHoverDevice = typeof options.onHoverDevice === 'function' ? options.onHoverDevice : () => {};
  const onSelectNode = typeof options.onSelectNode === 'function' ? options.onSelectNode : () => {};
  const onHoverNode = typeof options.onHoverNode === 'function' ? options.onHoverNode : () => {};
  const quality = options.quality === 'medium' ? 'medium' : 'high';
  const isHigh = quality === 'high';
  const fx = options.fx === 'bloom' ? 'bloom' : 'off';

  if (getComputedStyle(container).position === 'static') container.style.position = 'relative';

  /* ---------------------------------------------------------------- */
  /* 渲染器 / 场景 / 相机 / 控制器                                     */
  /* ---------------------------------------------------------------- */

  const renderer = new THREE.WebGLRenderer({
    antialias: isHigh,
    alpha: false,
    powerPreference: 'high-performance',
    stencil: false,
  });
  renderer.outputColorSpace = THREE.SRGBColorSpace;
  renderer.toneMapping = THREE.ACESFilmicToneMapping;
  renderer.toneMappingExposure = 0.96;
  renderer.shadowMap.enabled = false; // 资源约束：默认关闭阴影，用假阴影贴图
  renderer.setClearColor(FOG_COLOR, 1);

  const canvas = renderer.domElement;
  canvas.style.cssText = 'position:absolute;inset:0;display:block;width:100%;height:100%;outline:none;touch-action:none;';
  container.appendChild(canvas);

  const scene = new THREE.Scene();
  scene.fog = new THREE.Fog(FOG_COLOR, 52, 135);

  const camera = new THREE.PerspectiveCamera(CFG.cameraFov, 1, CFG.cameraNear, CFG.cameraFar);
  camera.position.copy(CFG.cameraHome);
  camera.lookAt(CFG.cameraTarget);

  const controls = new OrbitControls(camera, canvas);
  controls.target.copy(CFG.cameraTarget);
  controls.enableDamping = true;
  controls.dampingFactor = 0.06;
  controls.enablePan = false;
  controls.autoRotate = false; // 手动按 dt 旋转，避免帧率影响速度
  controls.rotateSpeed = 0.55;
  controls.zoomSpeed = 0.65;
  controls.minPolarAngle = CFG.minPolarAngle;
  controls.maxPolarAngle = CFG.maxPolarAngle;
  controls.minDistance = CFG.minDistance;
  controls.maxDistance = CFG.maxDistance;
  controls.update();

  /* ---------------------------------------------------------------- */
  /* 纹理 / 材质（固定套数，不随设备数增长）                            */
  /* ---------------------------------------------------------------- */

  const glowTex = makeGlowTexture();
  const bgTex = makeBackgroundTexture(isHigh ? 1024 : 512);
  const shadowTex = makeShadowTexture(256);
  scene.background = bgTex;

  /** 分类色材质（8 套，扇柱顶面/侧面共用；顶点色负责侧面压暗） */
  const categoryMaterials = CATEGORY_META.map(
    (c) =>
      new THREE.MeshStandardMaterial({
        color: new THREE.Color(c.color).multiplyScalar(0.95),
        emissive: new THREE.Color(c.color),
        emissiveIntensity: 0.3,
        metalness: 0.42,
        roughness: 0.46,
        vertexColors: true,
        side: THREE.DoubleSide,
      }),
  );

  /** 设备状态材质（4 套 MeshStandardMaterial，芯片共用） */
  const statusMaterials = {};
  const statusPillarMaterials = {};
  const statusPillarGlowMaterials = {};
  const statusGlowDiscMaterials = {};
  const statusGlowMaterials = {};
  for (const [key, hex] of Object.entries(STATUS_META)) {
    statusMaterials[key] = new THREE.MeshStandardMaterial({
      color: new THREE.Color(hex).multiplyScalar(0.72),
      emissive: new THREE.Color(hex),
      emissiveIntensity: 0.42,
      metalness: 0.55,
      roughness: 0.32,
      flatShading: true,
    });
    statusPillarMaterials[key] = new THREE.MeshBasicMaterial({
      // 实心暗柱（外层再用加法发光柱叠加）
      color: new THREE.Color(hex).multiplyScalar(0.34),
      transparent: true,
      opacity: 0.9,
      depthWrite: true,
    });
    statusPillarGlowMaterials[key] = new THREE.MeshBasicMaterial({
      // 外层加法发光柱：顶点色做「底暗顶亮」渐变
      color: new THREE.Color(hex),
      vertexColors: true,
      transparent: true,
      opacity: 0.55,
      blending: THREE.AdditiveBlending,
      depthWrite: false,
    });
    statusGlowDiscMaterials[key] = new THREE.MeshBasicMaterial({
      map: glowTex,
      color: new THREE.Color(hex),
      transparent: true,
      opacity: 0.5,
      blending: THREE.AdditiveBlending,
      depthWrite: false,
    });
    statusGlowMaterials[key] = new THREE.SpriteMaterial({
      map: glowTex,
      color: new THREE.Color(hex),
      transparent: true,
      opacity: 0.5,
      blending: THREE.AdditiveBlending,
      depthWrite: false,
    });
  }
  // 核心复用「正常」青色材质（clone 一份，避免共享的呼吸光影响设备芯片）
  const coreMaterial = statusMaterials.normal.clone();
  // 核心光塔专用材质：深色基体 + 强自发光棱边，保证白热光晕下仍可辨识
  const spireMaterial = new THREE.MeshStandardMaterial({
    color: 0x0a3b4a,
    emissive: 0x2ad8f6,
    emissiveIntensity: 0.8,
    metalness: 0.55,
    roughness: 0.26,
    flatShading: true,
  });
  const trayMaterial = new THREE.MeshStandardMaterial({
    color: 0x0a1220,
    metalness: 0.82,
    roughness: 0.46,
    emissive: 0x03101a,
    emissiveIntensity: 0.55,
  });
  const glassMaterial = new THREE.MeshBasicMaterial({
    color: 0x8fe9ff,
    transparent: true,
    opacity: 0.1,
    side: THREE.DoubleSide,
    depthWrite: false,
  });

  /* ---------------------------------------------------------------- */
  /* 光源：固定 4 个（Hemisphere + 2 Point + 1 Directional）            */
  /* ---------------------------------------------------------------- */

  const hemi = new THREE.HemisphereLight(0x4a86b8, 0x070b14, 0.8);
  scene.add(hemi);

  const coreLight = new THREE.PointLight(0x22d3ee, 15, 80, 2);
  coreLight.position.set(0, 11, 0);
  scene.add(coreLight);

  const rimLight = new THREE.PointLight(0x7c5cff, 128, 90, 2);
  rimLight.position.set(-20, 14, -14);
  scene.add(rimLight);

  const dirLight = new THREE.DirectionalLight(0x9ec8ff, 1.0);
  dirLight.position.set(22, 38, 18);
  scene.add(dirLight);

  /* ---------------------------------------------------------------- */
  /* 地面 + 极坐标网格 + 假阴影                                        */
  /* ---------------------------------------------------------------- */

  const ground = new THREE.Mesh(
    new THREE.CircleGeometry(30, 112),
    new THREE.MeshBasicMaterial({ color: 0x060b14 }),
  );
  ground.rotation.x = -Math.PI / 2;
  ground.position.y = -0.02;
  scene.add(ground);

  // 假阴影（托盘 + 中心压暗，托住画面重心）
  const fakeShadow = new THREE.Mesh(
    new THREE.CircleGeometry(23, 72),
    new THREE.MeshBasicMaterial({ map: shadowTex, transparent: true, opacity: 0.74, depthWrite: false }),
  );
  fakeShadow.rotation.x = -Math.PI / 2;
  fakeShadow.position.y = 0.005;
  scene.add(fakeShadow);

  // 中心地面光斑（径向渐变 + 加法，替代真实 GI）
  const groundGlow = new THREE.Mesh(
    new THREE.CircleGeometry(23, 72),
    new THREE.MeshBasicMaterial({
      map: glowTex,
      color: 0x0f5a72,
      transparent: true,
      opacity: 0.5,
      blending: THREE.AdditiveBlending,
      depthWrite: false,
    }),
  );
  groundGlow.rotation.x = -Math.PI / 2;
  groundGlow.position.y = 0.012;
  scene.add(groundGlow);

  // 极坐标网格：8 环 × 24 辐（一次性生成）
  {
    const positions = [];
    const rings = 8;
    for (let r = 1; r <= rings; r++) {
      const radius = 3.4 + (26.2 * r) / rings;
      const segs = 96;
      for (let i = 0; i < segs; i++) {
        const a0 = (i / segs) * TAU;
        const a1 = ((i + 1) / segs) * TAU;
        positions.push(Math.cos(a0) * radius, 0, Math.sin(a0) * radius);
        positions.push(Math.cos(a1) * radius, 0, Math.sin(a1) * radius);
      }
    }
    const spokes = 24;
    for (let i = 0; i < spokes; i++) {
      const a = (i / spokes) * TAU;
      positions.push(Math.cos(a) * 3.4, 0, Math.sin(a) * 3.4);
      positions.push(Math.cos(a) * 30, 0, Math.sin(a) * 30);
    }
    const g = new THREE.BufferGeometry();
    g.setAttribute('position', new THREE.Float32BufferAttribute(positions, 3));
    const grid = new THREE.LineSegments(
      g,
      new THREE.LineBasicMaterial({ color: 0x3a7ba3, transparent: true, opacity: 0.18, depthWrite: false }),
    );
    grid.position.y = 0.01;
    scene.add(grid);
  }

  // 星空（世界空间，旋转时有视差）
  {
    const count = isHigh ? 460 : 220;
    const pos = new Float32Array(count * 3);
    const rnd = mulberry32(77123);
    for (let i = 0; i < count; i++) {
      const theta = rnd() * TAU;
      const phi = Math.acos(rnd() * 1.55 - 0.55); // 略偏上半球
      const r = 78 + rnd() * 30;
      pos[i * 3] = Math.sin(phi) * Math.cos(theta) * r;
      pos[i * 3 + 1] = Math.abs(Math.cos(phi)) * r * 0.85 + 2;
      pos[i * 3 + 2] = Math.sin(phi) * Math.sin(theta) * r;
    }
    const g = new THREE.BufferGeometry();
    g.setAttribute('position', new THREE.BufferAttribute(pos, 3));
    const stars = new THREE.Points(
      g,
      new THREE.PointsMaterial({
        color: 0x9dc9ff,
        size: 0.7,
        map: glowTex,
        transparent: true,
        opacity: 0.72,
        depthWrite: false,
        blending: THREE.AdditiveBlending,
        sizeAttenuation: true,
        fog: false,
      }),
    );
    scene.add(stars);
  }

  /* ---------------------------------------------------------------- */
  /* 数据托盘（自转）：盘体 + 玻璃 + 外缘光环 + 分类扇柱 + 刻度环        */
  /* ---------------------------------------------------------------- */

  const trayGroup = new THREE.Group();
  scene.add(trayGroup);

  {
    const body = new THREE.Mesh(
      new THREE.CylinderGeometry(CFG.trayRadius, CFG.trayRadius, CFG.trayThickness, 96, 1, false),
      trayMaterial,
    );
    body.position.y = CFG.trayThickness / 2;
    trayGroup.add(body);

    // 顶面玻璃层（0.12 透明）
    const glass = new THREE.Mesh(new THREE.CircleGeometry(CFG.trayRadius - 0.02, 96), glassMaterial);
    glass.rotation.x = -Math.PI / 2;
    glass.position.y = CFG.trayTop + 0.035;
    trayGroup.add(glass);

    // 外缘发光细环 ×2
    const edgeMat = new THREE.MeshBasicMaterial({
      color: 0x4be3ff,
      transparent: true,
      opacity: 0.55,
      blending: THREE.AdditiveBlending,
      depthWrite: false,
    });
    const edge = new THREE.Mesh(new THREE.TorusGeometry(CFG.trayRadius + 0.02, 0.035, 6, 220), edgeMat);
    edge.rotation.x = -Math.PI / 2;
    edge.position.y = CFG.trayTop + 0.02;
    trayGroup.add(edge);

    const edge2 = new THREE.Mesh(
      new THREE.TorusGeometry(CFG.trayRadius - 0.42, 0.016, 6, 220),
      new THREE.MeshBasicMaterial({
        color: 0x2bb6d6,
        transparent: true,
        opacity: 0.35,
        blending: THREE.AdditiveBlending,
        depthWrite: false,
      }),
    );
    edge2.rotation.x = -Math.PI / 2;
    edge2.position.y = CFG.trayTop + 0.015;
    trayGroup.add(edge2);

    // 同心环刻度：3 道细线环 + 每 30° 短刻度线，让托盘更像专业仪表
    const scaleMat = new THREE.MeshBasicMaterial({
      color: 0x2fa9c9,
      transparent: true,
      opacity: 0.26,
      blending: THREE.AdditiveBlending,
      depthWrite: false,
    });
    for (const r of [11.65, 12.3, 12.92]) {
      const ring = new THREE.Mesh(new THREE.TorusGeometry(r, 0.008, 4, 240), scaleMat);
      ring.rotation.x = -Math.PI / 2;
      ring.position.y = CFG.trayTop + 0.012;
      trayGroup.add(ring);
    }
    const tickPositions = [];
    for (let i = 0; i < 12; i++) {
      const a = (i / 12) * TAU;
      const c = Math.cos(a);
      const s = Math.sin(a);
      tickPositions.push(c * 12.48, 0, s * 12.48, c * 12.94, 0, s * 12.94);
    }
    const tickGeo = new THREE.BufferGeometry();
    tickGeo.setAttribute('position', new THREE.Float32BufferAttribute(tickPositions, 3));
    const tickLines = new THREE.LineSegments(
      tickGeo,
      new THREE.LineBasicMaterial({
        color: 0x6fe0f5,
        transparent: true,
        opacity: 0.5,
        blending: THREE.AdditiveBlending,
        depthWrite: false,
      }),
    );
    tickLines.position.y = CFG.trayTop + 0.014;
    trayGroup.add(tickLines);

    // 内圈光环（框住中心核心）
    const innerRing = new THREE.Mesh(
      new THREE.TorusGeometry(CFG.sectorInner + 0.02, 0.014, 4, 200),
      new THREE.MeshBasicMaterial({
        color: 0x57d9ee,
        transparent: true,
        opacity: 0.4,
        blending: THREE.AdditiveBlending,
        depthWrite: false,
      }),
    );
    innerRing.rotation.x = -Math.PI / 2;
    innerRing.position.y = CFG.trayTop + 0.012;
    trayGroup.add(innerRing);
  }

  // 分类扇柱：侧面（顶点色压暗）+ 顶面（亮色）两套合并几何，共用 8 套分类材质
  const sectorCount = CATEGORY_META.length;
  const sectorTopGeo = createSectorGeometry('top', sectorCount, CFG.sectorInner, CFG.sectorOuter, CFG.sectorSegments);
  const sectorSideGeo = createSectorGeometry('side', sectorCount, CFG.sectorInner, CFG.sectorOuter, CFG.sectorSegments);
  const sectorTopMesh = new THREE.Mesh(sectorTopGeo, categoryMaterials);
  const sectorSideMesh = new THREE.Mesh(sectorSideGeo, categoryMaterials);
  sectorTopMesh.frustumCulled = false;
  sectorSideMesh.frustumCulled = false;
  trayGroup.add(sectorSideMesh, sectorTopMesh);

  // 扇柱顶面霓虹描边（合并为 1 个 LineSegments，随高度/角度实时更新）
  const edgeSegsPerSector = CFG.sectorSegments * 2 + 2;
  const edgeVertCount = sectorCount * edgeSegsPerSector * 2;
  const sectorEdgeGeo = new THREE.BufferGeometry();
  const sectorEdgePos = new Float32Array(edgeVertCount * 3);
  const sectorEdgeCol = new Float32Array(edgeVertCount * 3);
  sectorEdgeGeo.setAttribute(
    'position',
    new THREE.BufferAttribute(sectorEdgePos, 3).setUsage(THREE.DynamicDrawUsage),
  );
  sectorEdgeGeo.setAttribute('color', new THREE.BufferAttribute(sectorEdgeCol, 3));
  {
    const c = new THREE.Color();
    for (let s = 0; s < sectorCount; s++) {
      c.set(CATEGORY_META[s].color);
      const startIdx = s * edgeSegsPerSector * 2;
      for (let v = 0; v < edgeSegsPerSector * 2; v++) {
        const idx = (startIdx + v) * 3;
        sectorEdgeCol[idx] = c.r;
        sectorEdgeCol[idx + 1] = c.g;
        sectorEdgeCol[idx + 2] = c.b;
      }
    }
  }
  const sectorEdgeLines = new THREE.LineSegments(
    sectorEdgeGeo,
    new THREE.LineBasicMaterial({
      vertexColors: true,
      transparent: true,
      opacity: 0.5,
      blending: THREE.AdditiveBlending,
      depthWrite: false,
    }),
  );
  sectorEdgeLines.frustumCulled = false;
  trayGroup.add(sectorEdgeLines);

  // 刻度环（60 段 InstancedMesh，高度=最近 60 趋势点）
  const trendGeo = new THREE.CylinderGeometry(0.07, 0.07, 1, 5);
  trendGeo.translate(0, 0.5, 0);
  const trendMat = new THREE.MeshBasicMaterial({
    color: 0xffffff,
    transparent: true,
    opacity: 0.82,
    blending: THREE.AdditiveBlending,
    depthWrite: false,
  });
  const trendMesh = new THREE.InstancedMesh(trendGeo, trendMat, CFG.trendCount);
  trendMesh.frustumCulled = false;
  trendMesh.instanceMatrix.setUsage(THREE.DynamicDrawUsage);
  const trendDummy = new THREE.Object3D();
  const trendColorDim = new THREE.Color('#155a72');
  const trendColorBright = new THREE.Color('#6fe9fb');
  const trendScratchColor = new THREE.Color();
  // 初始化实例矩阵（否则 60 根柱子会叠在原点）
  for (let i = 0; i < CFG.trendCount; i++) {
    const a = (i / CFG.trendCount) * TAU;
    trendDummy.position.set(Math.cos(a) * CFG.trendRadius, CFG.trendBaseY, Math.sin(a) * CFG.trendRadius);
    trendDummy.rotation.set(0, 0, 0);
    trendDummy.scale.set(1, 0.1, 1);
    trendDummy.updateMatrix();
    trendMesh.setMatrixAt(i, trendDummy.matrix);
    trendColorDim.clone();
    trendMesh.setColorAt(i, trendColorDim);
  }
  trendMesh.instanceMatrix.needsUpdate = true;
  if (trendMesh.instanceColor) trendMesh.instanceColor.needsUpdate = true;
  trayGroup.add(trendMesh);

  /* ---------------------------------------------------------------- */
  /* 中心路由核心                                                      */
  /* ---------------------------------------------------------------- */

  const coreGroup = new THREE.Group();
  scene.add(coreGroup);
  const coreRings = [];
  const pulseRings = [];
  let coreBody = null;
  let coreGlowSprite = null;

  {
    const baseY = CFG.trayTop;

    // 核心底座平台（暗色六边形，压住中心）
    const platform = new THREE.Mesh(new THREE.CircleGeometry(3.36, 6), trayMaterial);
    platform.rotation.x = -Math.PI / 2;
    platform.position.y = baseY + 0.006;
    coreGroup.add(platform);

    coreBody = new THREE.Mesh(new THREE.CylinderGeometry(2.2, 2.2, 0.9, 6), coreMaterial);
    coreBody.position.y = baseY + 0.45;
    coreGroup.add(coreBody);

    // 棱边高光
    const edges = new THREE.LineSegments(
      new THREE.EdgesGeometry(coreBody.geometry),
      new THREE.LineBasicMaterial({ color: 0x9af3ff, transparent: true, opacity: 0.7 }),
    );
    edges.position.copy(coreBody.position);
    coreGroup.add(edges);

    // 内部线框（反向旋转）
    const innerWire = new THREE.LineSegments(
      new THREE.EdgesGeometry(new THREE.CylinderGeometry(1.35, 1.35, 1.5, 6)),
      new THREE.LineBasicMaterial({ color: 0x6fe6ff, transparent: true, opacity: 0.42 }),
    );
    innerWire.position.y = baseY + 0.92;
    innerWire.rotation.y = 0.4;
    coreGroup.add(innerWire);

    // 顶部六边形光片
    const topCap = new THREE.Mesh(
      new THREE.CircleGeometry(2.12, 6),
      new THREE.MeshBasicMaterial({
        color: 0x36e0ff,
        transparent: true,
        opacity: 0.14,
        blending: THREE.AdditiveBlending,
        depthWrite: false,
        side: THREE.DoubleSide,
      }),
    );
    topCap.rotation.x = -Math.PI / 2;
    topCap.position.y = baseY + 0.92;
    coreGroup.add(topCap);

    // 核心光塔：从六棱柱顶部升起，保证扇柱再高也有视觉焦点
    const spire = new THREE.Mesh(new THREE.CylinderGeometry(0.3, 0.55, 3.8, 6), spireMaterial);
    spire.position.y = baseY + 0.9 + 1.9;
    coreGroup.add(spire);
    const spireEdges = new THREE.LineSegments(
      new THREE.EdgesGeometry(spire.geometry),
      new THREE.LineBasicMaterial({ color: 0xa9f7ff, transparent: true, opacity: 0.85 }),
    );
    spireEdges.position.copy(spire.position);
    coreGroup.add(spireEdges);
    const spireGlow = new THREE.Mesh(
      new THREE.CylinderGeometry(0.58, 1.02, 4.0, 6, 1, true),
      new THREE.MeshBasicMaterial({
        color: 0x2ad4f0,
        transparent: true,
        opacity: 0.045,
        blending: THREE.AdditiveBlending,
        depthWrite: false,
        side: THREE.DoubleSide,
      }),
    );
    spireGlow.position.copy(spire.position);
    coreGroup.add(spireGlow);

    // 3 个不同倾角的 Torus 光环（反向旋转，围绕核心与光塔下段）
    const ringDefs = [
      { radius: 2.62, tube: 0.03, y: baseY + 1.55, tilt: 0.0, speed: 0.34, color: 0x6ceeff },
      { radius: 2.96, tube: 0.024, y: baseY + 2.15, tilt: 0.38, speed: -0.22, color: 0x9d86ff },
      { radius: 3.24, tube: 0.02, y: baseY + 2.72, tilt: -0.48, speed: 0.16, color: 0x6ceeff },
    ];
    for (const def of ringDefs) {
      const pivot = new THREE.Group();
      pivot.position.y = def.y;
      const ring = new THREE.Mesh(
        new THREE.TorusGeometry(def.radius, def.tube, 6, 128),
        new THREE.MeshBasicMaterial({
          color: def.color,
          transparent: true,
          opacity: 0.72,
          blending: THREE.AdditiveBlending,
          depthWrite: false,
        }),
      );
      ring.rotation.x = Math.PI / 2 + def.tilt;
      pivot.add(ring);
      coreGroup.add(pivot);
      coreRings.push({ pivot, speed: def.speed });
    }

    // 底部脉冲扩散环 ×2
    for (let i = 0; i < 2; i++) {
      const ring = new THREE.Mesh(
        new THREE.RingGeometry(2.3, 2.4, 96),
        new THREE.MeshBasicMaterial({
          color: 0x59e8ff,
          transparent: true,
          opacity: 0.32,
          blending: THREE.AdditiveBlending,
          depthWrite: false,
          side: THREE.DoubleSide,
        }),
      );
      ring.rotation.x = -Math.PI / 2;
      ring.position.y = CFG.trayTop + 0.05;
      coreGroup.add(ring);
      pulseRings.push({ mesh: ring, offset: i * 0.5 });
    }

    // 顶部光晕 Sprite（收敛：小尺寸 + 低不透明度，避免压住扇柱顶面）
    coreGlowSprite = new THREE.Sprite(
      new THREE.SpriteMaterial({
        map: glowTex,
        color: 0x39dcff,
        transparent: true,
        opacity: 0.09,
        blending: THREE.AdditiveBlending,
        depthWrite: false,
      }),
    );
    coreGlowSprite.scale.set(4.2, 4.2, 1);
    coreGlowSprite.position.set(0, baseY + 3.3, 0);
    coreGroup.add(coreGlowSprite);

    const coreSpark = new THREE.Sprite(
      new THREE.SpriteMaterial({
        map: glowTex,
        color: 0xc4fbff,
        transparent: true,
        opacity: 0.14,
        blending: THREE.AdditiveBlending,
        depthWrite: false,
      }),
    );
    coreSpark.scale.set(1.6, 1.6, 1);
    coreSpark.position.set(0, baseY + 1.05, 0);
    coreGroup.add(coreSpark);

    // 塔尖亮点
    const spireTip = new THREE.Sprite(
      new THREE.SpriteMaterial({
        map: glowTex,
        color: 0xd8fdff,
        transparent: true,
        opacity: 0.38,
        blending: THREE.AdditiveBlending,
        depthWrite: false,
      }),
    );
    spireTip.scale.set(1.4, 1.4, 1);
    spireTip.position.set(0, baseY + 5.3, 0);
    coreGroup.add(spireTip);
  }

  /* ---------------------------------------------------------------- */
  /* 设备层（共享 geometry + 状态材质，最多 24 台）                     */
  /* ---------------------------------------------------------------- */

  const deviceRoot = new THREE.Group();
  scene.add(deviceRoot);

  // 共享几何体（整个场景只创建一次，所有设备复用）
  const chipGeo = new THREE.CylinderGeometry(CFG.chipRadius, CFG.chipRadius, CFG.chipThickness, 6);
  // 实心暗柱（单位高，底部在 y=0）
  const pillarGeo = new THREE.CylinderGeometry(CFG.pillarRadius, CFG.pillarRadius, 1, 8);
  pillarGeo.translate(0, 0.5, 0);
  // 外层发光柱：同一几何 + 顶点色「底暗顶亮」渐变
  const pillarGlowGeo = pillarGeo.clone();
  {
    const pos = pillarGlowGeo.attributes.position;
    const colors = new Float32Array(pos.count * 3);
    for (let i = 0; i < pos.count; i++) {
      const y = pos.getY(i); // 0..1
      const f = 0.12 + Math.pow(clamp(y, 0, 1), 1.35) * 0.88;
      colors[i * 3] = f;
      colors[i * 3 + 1] = f;
      colors[i * 3 + 2] = f;
    }
    pillarGlowGeo.setAttribute('color', new THREE.BufferAttribute(colors, 3));
  }
  // 柱底落点光晕
  const baseDiscGeo = new THREE.CircleGeometry(0.62, 24);

  const labelCache = createLabelCache(CFG.labelCacheMax);

  /** @type {Map<string, any>} ip -> device record */
  const devices = new Map();
  /** @type {Map<string, any>} ip -> 归一化设备（SSE 增量帧语义：full 替换 / 增量合并） */
  const knownDevices = new Map();
  let deviceSig = '';
  const chipMeshes = []; // raycaster 目标
  let hoveredIp = null;
  let selectedIp = null;

  // 选中光环（复用 1 个 mesh）
  const selectionRing = new THREE.Mesh(
    new THREE.RingGeometry(1.15, 1.42, 6),
    new THREE.MeshBasicMaterial({
      color: 0x9df3ff,
      transparent: true,
      opacity: 0.85,
      blending: THREE.AdditiveBlending,
      depthWrite: false,
      side: THREE.DoubleSide,
    }),
  );
  selectionRing.rotation.x = -Math.PI / 2;
  selectionRing.visible = false;
  scene.add(selectionRing);

  /* ---------- 轨道 + 粒子（合并对象，成员变化时重建） ---------- */

  let orbit = null; // { line, geo, pos, color, dist, speed, count, samples, devices }
  let particle = null; // { points, geo, pos, color, size, count, items }
  let orbitColorsDirty = false;

  const lineMaterial = new THREE.ShaderMaterial({
    uniforms: { uTime: { value: 0 } },
    vertexShader: ORBIT_VERT,
    fragmentShader: ORBIT_FRAG,
    transparent: true,
    depthWrite: false,
    blending: THREE.AdditiveBlending,
  });
  const particleMaterial = new THREE.ShaderMaterial({
    uniforms: { uPixelRatio: { value: 1 } },
    vertexShader: PARTICLE_VERT,
    fragmentShader: PARTICLE_FRAG,
    transparent: true,
    depthWrite: false,
    blending: THREE.AdditiveBlending,
  });

  /* ---------------------------------------------------------------- */
  /* 网络拓扑层：LAN / ZeroTier / VPN / 互联网 / 代理 + 流向链路          */
  /* ---------------------------------------------------------------- */

  /** 节点类型色 / 链路 kind 色（与设计语义一致） */
  const TOPO_TYPE_COLORS = {
    lan: '#38bdf8',
    zerotier: '#34d399',
    vpn: '#a78bfa',
    internet: '#22d3ee',
    proxy: '#c084fc',
    docker: '#94a3b8',
    other: '#94a3b8',
  };
  const TOPO_KIND_COLORS = {
    lan: '#38bdf8', // 内网 LAN
    direct: '#22d3ee', // 直接出网：青
    proxy: '#a78bfa', // 代理：紫
    zt: '#34d399', // ZeroTier：绿
    vpn: '#8b5cf6', // VPN：紫罗兰
    docker: '#94a3b8',
  };

  const topoRoot = new THREE.Group();
  scene.add(topoRoot);

  // 共享几何体（节点底盘 / 外环 / 链路方向箭头）
  const topoNodeGeo = new THREE.CylinderGeometry(1.02, 1.02, 0.26, 6);
  topoNodeGeo.translate(0, 0.13, 0);
  const topoRingGeo = new THREE.TorusGeometry(1.3, 0.025, 4, 44);
  const topoConeGeo = new THREE.ConeGeometry(0.26, 0.78, 8);

  const topoNodeMaterials = new Map(); // `${type}|${up}` -> MeshStandardMaterial
  const topoRingMaterials = new Map(); // `${type}|${up}` -> MeshBasicMaterial
  const topoGlowMaterials = new Map(); // `${type}|${up}` -> SpriteMaterial
  const topoFlowDotMaterials = new Map(); // kind -> SpriteMaterial（链路源端发光点）
  const topoArrowMaterials = new Map(); // kind -> MeshBasicMaterial（链路终点箭头）
  const topoMeshes = []; // raycaster 目标
  const topoNodes = new Map(); // id -> node record
  let topoLinks = []; // link records
  let topoSignature = '';
  let topoLabelAt = 0;
  let hoveredNodeId = null;
  let selectedNodeId = null;
  let topoParticles = null; // 单个 Points（所有链路流动粒子）
  let topoParticleItems = [];

  const topoNodeSelectionRing = new THREE.Mesh(
    new THREE.RingGeometry(1.55, 1.88, 6),
    new THREE.MeshBasicMaterial({
      color: 0x9df3ff,
      transparent: true,
      opacity: 0.85,
      blending: THREE.AdditiveBlending,
      depthWrite: false,
      side: THREE.DoubleSide,
    }),
  );
  topoNodeSelectionRing.rotation.x = -Math.PI / 2;
  topoNodeSelectionRing.visible = false;
  scene.add(topoNodeSelectionRing);

  /* ---------------------------------------------------------------- */
  /* 状态数据（目标值）与平滑值                                         */
  /* ---------------------------------------------------------------- */

  const categoryState = CATEGORY_META.map((meta) => ({
    key: meta.key,
    targetShare: 1 / sectorCount,
    share: 1 / sectorCount,
    start: 0,
    end: 0,
    height: CFG.sectorMinHeight,
  }));
  const scratchSectors = categoryState.map(() => ({ start: 0, end: 0, height: 0 }));

  const trendBuf = new Array(CFG.trendCount).fill(0);
  const trendTarget = new Array(CFG.trendCount).fill(0);
  const trendDisplay = new Array(CFG.trendCount).fill(0);
  let trendLastT = 0;
  let trendReady = false;

  let lastDataAt = performance.now();
  let lastUpdatePayload = null;

  // 相机入场 / 聚焦
  const entry = { active: true, t: 0, startedAt: performance.now(), from: new THREE.Vector3(0, 56, 74) };
  const focusAnim = {
    active: false,
    t: 0,
    duration: CFG.focusDuration,
    fromPos: new THREE.Vector3(),
    fromTarget: new THREE.Vector3(),
    toPos: new THREE.Vector3(),
    toTarget: new THREE.Vector3(),
  };
  const scratchV1 = new THREE.Vector3();
  const scratchV2 = new THREE.Vector3();
  const scratchV3 = new THREE.Vector3();
  const scratchV4 = new THREE.Vector3();

  /* ---------------------------------------------------------------- */
  /* 数据接入                                                          */
  /* ---------------------------------------------------------------- */

  function updateCategories(cats) {
    let sum = 0;
    const shares = new Array(sectorCount).fill(0);
    for (const c of cats) {
      if (!c || !CATEGORY_INDEX.has(c.key)) continue;
      const idx = CATEGORY_INDEX.get(c.key);
      let share = Number(c.share);
      if (!Number.isFinite(share)) {
        share = (Number(c.upBps) || 0) + (Number(c.downBps) || 0);
      }
      shares[idx] += Math.max(0, share);
      sum += Math.max(0, share);
    }
    for (let i = 0; i < sectorCount; i++) {
      categoryState[i].targetShare = sum > 0 ? shares[i] / sum : 1 / sectorCount;
    }
  }

  function applyTrendArray(trend) {
    const n = trend.length;
    if (!n) return;
    for (let i = 0; i < CFG.trendCount; i++) {
      const src = trend[Math.max(0, n - CFG.trendCount) + i];
      trendBuf[i] = src ? Number(src.down) || 0 : 0;
    }
    const last = trend[n - 1];
    if (last && Number.isFinite(Number(last.t))) trendLastT = Number(last.t);
    trendReady = true;
  }

  function pushTrendPoint(point) {
    if (!point) return;
    const t = Number(point.t);
    if (Number.isFinite(t) && t === trendLastT) return;
    const down = Number(point.down) || 0;
    trendBuf.push(down);
    while (trendBuf.length > CFG.trendCount) trendBuf.shift();
    if (Number.isFinite(t)) trendLastT = t;
    trendReady = true;
  }

  /**
   * 归一化设备记录：字段缺失一律记为 null（未知），不使用乐观默认值。
   * online 不得因为「字段没传」就当成在线，blocked 也不得当成未断网；
   * 否则离线/被断网设备会在大屏里被显示成正常在线（与「设备」页不一致）。
   */
  function normalizeDevice(d) {
    const src = d || {};
    return {
      ip: String(src.ip || ''),
      // 名称缺失时留 null（未知），避免用 IP 兜底覆盖掉已知的别名/主机名
      name: src.alias || src.name || src.hostname || null,
      online: typeof src.online === 'boolean' ? src.online : null,
      blocked: typeof src.blocked === 'boolean' ? src.blocked : null,
      up: numOrNull(src.upBps),
      down: numOrNull(src.downBps),
      conns: numOrNull(src.conns),
      risk: numOrNull(src.risk),
      limited: src.limitKbps
        ? (Number(src.limitKbps.down) > 0 || Number(src.limitKbps.up) > 0)
        : null,
      topCat: src.topCat || null,
    };
  }

  /**
   * 合并设备记录：只写入源数据中确实存在的字段。
   * null / undefined 一律视为「未知」，不得覆盖已有的真实状态（online / blocked 尤其关键）；
   * 状态在合并完成后按合并结果重新解析，避免用默认值冲掉真实状态。
   */
  function mergeDeviceRecord(prev, next) {
    const out = prev ? { ...prev } : {};
    if (next && typeof next === 'object') {
      for (const key of Object.keys(next)) {
        if (key === 'status') continue;
        const v = next[key];
        if (v === undefined || v === null) continue; // 未知 → 保留已有真实值
        out[key] = v;
      }
    }
    if (typeof out.online !== 'boolean') out.online = null;
    if (typeof out.blocked !== 'boolean') out.blocked = null;
    if (!Number.isFinite(out.down)) out.down = 0;
    if (!Number.isFinite(out.up)) out.up = 0;
    if (!Number.isFinite(out.risk)) out.risk = null;
    if (!Number.isFinite(out.conns)) out.conns = null;
    if (typeof out.limited !== 'boolean') out.limited = null;
    if (!out.name) out.name = out.ip || '未知设备';
    if (!out.topCat) out.topCat = null;
    out.status = resolveStatus(out);
    return out;
  }

  /**
   * 设备状态：与「设备」页（ui/devices.js）一致 —— 已断网 > 离线 > 风险 > 限速 > 正常。
   * online / blocked 未知（null）时返回 'unknown'，不伪装成「正常在线」。
   */
  function resolveStatus(rec) {
    const blocked = rec.blocked === true;
    const online = rec.online;
    if (blocked) return 'blocked'; // 已断网
    if (online === false) return 'offline'; // 离线
    if ((Number(rec.risk) || 0) > 0.6) return 'risk';
    if (rec.limited === true) return 'limit';
    if (online !== true) return 'unknown'; // 在线状态未知
    return 'normal';
  }

  /** 接收「已归一化」的设备数组（全量或合并后的全量） */
  function applyDevices(normalized) {
    const picked = pickRendered(normalized);
    const sig = picked.map((d) => d.ip).join('|');
    if (sig !== deviceSig) {
      rebuildDevices(picked);
      deviceSig = sig;
    } else {
      for (const nd of picked) {
        const dev = devices.get(nd.ip);
        if (!dev) continue;
        const down = Number.isFinite(nd.down) ? nd.down : 0;
        const up = Number.isFinite(nd.up) ? nd.up : 0;
        dev.target.down = down;
        dev.target.up = up;
        dev.target.height = clamp(
          (down + up) / 200000,
          CFG.pillarMinHeight,
          CFG.pillarMaxHeight,
        );
        dev.name = nd.name;
        if (nd.status !== dev.status) {
          dev.status = nd.status;
          applyDeviceStatusMaterials(dev);
          orbitColorsDirty = true;
        }
      }
    }
  }

  function pickRendered(normalized) {
    if (normalized.length <= CFG.deviceMax) {
      return normalized.slice().sort((a, b) => (a.ip < b.ip ? -1 : a.ip > b.ip ? 1 : 0));
    }
    // 流量 Top-N + 已在场的设备给一点粘性，避免每帧换人
    const scored = normalized.map((d) => ({
      d,
      score:
        ((Number(d.down) || 0) + (Number(d.up) || 0)) * (devices.has(d.ip) ? 1.35 : 1),
    }));
    scored.sort((a, b) => b.score - a.score || (a.d.ip < b.d.ip ? -1 : 1));
    return scored
      .slice(0, CFG.deviceMax)
      .map((s) => s.d)
      .sort((a, b) => (a.ip < b.ip ? -1 : a.ip > b.ip ? 1 : 0));
  }

  function applyDeviceStatusMaterials(dev) {
    dev.chip.material = statusMaterials[dev.status];
    dev.pillar.material = statusPillarMaterials[dev.status];
    dev.pillarGlow.material = statusPillarGlowMaterials[dev.status];
    dev.baseDisc.material = statusGlowDiscMaterials[dev.status];
    dev.glow.material = statusGlowMaterials[dev.status];
  }

  /* ---------------------------------------------------------------- */
  /* 设备重建（成员变化时）                                            */
  /* ---------------------------------------------------------------- */

  function disposeDeviceRecord(dev) {
    if (dev.labelKey) {
      labelCache.release(dev.labelKey);
      dev.labelKey = null;
    }
    if (dev.labelMaterial) {
      dev.labelMaterial.map = null;
      dev.labelMaterial.dispose();
      dev.labelMaterial = null;
    }
    deviceRoot.remove(dev.group);
  }

  function rebuildDevices(picked) {
    for (const dev of devices.values()) disposeDeviceRecord(dev);
    devices.clear();
    chipMeshes.length = 0;

    const n = picked.length;
    const labelScaleBase = n > 16 ? 0.74 : n > 10 ? 0.84 : 1;
    for (let i = 0; i < n; i++) {
      const nd = picked[i];
      // 外环交错排布：半径按索引交替，外侧再错开半个角步，避免标签挤在一起
      const angle = -Math.PI / 2 + (i / n) * TAU + (i % 2 === 0 ? 0 : TAU / (n * 2));
      const radius = i % 2 === 0 ? CFG.deviceInner : CFG.deviceOuter;
      const x = Math.cos(angle) * radius;
      const z = Math.sin(angle) * radius;

      const group = new THREE.Group();
      group.position.set(x, 0, z);

      const chip = new THREE.Mesh(chipGeo, statusMaterials[nd.status]);
      chip.position.y = CFG.pillarBaseY + CFG.pillarMinHeight + CFG.chipThickness / 2;

      const pillar = new THREE.Mesh(pillarGeo, statusPillarMaterials[nd.status]);
      pillar.position.y = CFG.pillarBaseY;
      pillar.scale.y = CFG.pillarMinHeight;

      const pillarGlow = new THREE.Mesh(pillarGlowGeo, statusPillarGlowMaterials[nd.status]);
      pillarGlow.position.y = CFG.pillarBaseY;
      pillarGlow.scale.set(1, CFG.pillarMinHeight, 1);

      const baseDisc = new THREE.Mesh(baseDiscGeo, statusGlowDiscMaterials[nd.status]);
      baseDisc.rotation.x = -Math.PI / 2;
      baseDisc.position.y = 0.03;

      const glow = new THREE.Sprite(statusGlowMaterials[nd.status]);
      glow.scale.set(0.68, 0.68, 1);
      glow.position.y = chip.position.y + 0.14;

      const labelMaterial = new THREE.SpriteMaterial({
        map: null,
        transparent: true,
        depthWrite: false,
        depthTest: true,
      });
      const label = new THREE.Sprite(labelMaterial);
      const labelScale = labelScaleBase;
      label.scale.set(CFG.labelHeight * (LABEL_CANVAS_W / LABEL_CANVAS_H) * labelScale, CFG.labelHeight * labelScale, 1);
      label.visible = false;
      label.position.y = chip.position.y + 1.25 + (i % 2) * 0.55;
      label.userData.baseScale = labelScale;

      group.add(pillar, pillarGlow, baseDisc, chip, glow, label);
      deviceRoot.add(group);

      chip.userData.ip = nd.ip;
      chipMeshes.push(chip);

      const devDown = Number.isFinite(nd.down) ? nd.down : 0;
      const devUp = Number.isFinite(nd.up) ? nd.up : 0;
      const devHeight = clamp(
        (devDown + devUp) / 200000,
        CFG.pillarMinHeight,
        CFG.pillarMaxHeight,
      );

      const dev = {
        ip: nd.ip,
        name: nd.name,
        status: nd.status,
        angle,
        radius,
        group,
        chip,
        pillar,
        pillarGlow,
        baseDisc,
        glow,
        label,
        labelMaterial,
        labelKey: null,
        lastLabelAt: 0,
        labelNameLen: Array.from(nd.name).length,
        slot: i,
        target: {
          down: devDown,
          up: devUp,
          height: devHeight,
        },
        cur: {
          down: devDown,
          up: devUp,
          height: devHeight,
          scale: 1,
        },
        curve: new THREE.QuadraticBezierCurve3(
          new THREE.Vector3(x, CFG.pillarBaseY + CFG.pillarMinHeight + 0.3, z),
          new THREE.Vector3(x * 0.52, CFG.pillarMinHeight + 3.0, z * 0.52),
          new THREE.Vector3(0, CFG.trayTop + 2.2, 0),
        ),
      };
      devices.set(nd.ip, dev);
    }

    // 若之前选中的设备已不在场，清理高亮
    if (selectedIp && !devices.has(selectedIp)) selectedIp = null;
    if (hoveredIp && !devices.has(hoveredIp)) {
      hoveredIp = null;
      onHoverDevice(null);
    }

    rebuildOrbitsAndParticles(picked);
  }

  /* ---------- 轨道 / 粒子构建 ---------- */

  function disposeOrbits() {
    if (orbit) {
      scene.remove(orbit.line);
      orbit.geo.dispose();
      orbit = null;
    }
  }

  function disposeParticles() {
    if (particle) {
      scene.remove(particle.points);
      particle.geo.dispose();
      particle = null;
    }
  }

  function rebuildOrbitsAndParticles(picked) {
    disposeOrbits();
    disposeParticles();

    const n = picked.length;
    const samples = CFG.orbitSamples;
    const segs = samples - 1;
    const count = n * segs * 2;
    if (!n) {
      orbitColorsDirty = false;
      return;
    }

    const pos = new Float32Array(count * 3);
    const color = new Float32Array(count * 3);
    const dist = new Float32Array(count);
    const speed = new Float32Array(count);
    const geo = new THREE.BufferGeometry();
    geo.setAttribute('position', new THREE.BufferAttribute(pos, 3).setUsage(THREE.DynamicDrawUsage));
    geo.setAttribute('aColor', new THREE.BufferAttribute(color, 3));
    geo.setAttribute('aDist', new THREE.BufferAttribute(dist, 1).setUsage(THREE.DynamicDrawUsage));
    geo.setAttribute('aSpeed', new THREE.BufferAttribute(speed, 1).setUsage(THREE.DynamicDrawUsage));
    const line = new THREE.LineSegments(geo, lineMaterial);
    line.frustumCulled = false;
    scene.add(line);

    orbit = {
      line,
      geo,
      pos,
      color,
      dist,
      speed,
      count,
      samples,
      segs,
      deviceList: picked.slice(),
    };

    // 粒子：单个 Points，最多 6/设备
    const perDevice = CFG.deviceParticles;
    const pCount = Math.min(CFG.particleMax, n * perDevice);
    const particleItems = [];
    for (let i = 0; i < n && particleItems.length < pCount; i++) {
      for (let k = 0; k < perDevice && particleItems.length < pCount; k++) {
        particleItems.push({
          devIndex: i,
          offset: (k + i * 0.17) / perDevice,
          speed: 0.06 + Math.random() * 0.03,
        });
      }
    }
    const pPos = new Float32Array(particleItems.length * 3);
    const pColor = new Float32Array(particleItems.length * 3);
    const pSize = new Float32Array(particleItems.length);
    const pGeo = new THREE.BufferGeometry();
    pGeo.setAttribute('position', new THREE.BufferAttribute(pPos, 3).setUsage(THREE.DynamicDrawUsage));
    pGeo.setAttribute('aColor', new THREE.BufferAttribute(pColor, 3).setUsage(THREE.DynamicDrawUsage));
    pGeo.setAttribute('aSize', new THREE.BufferAttribute(pSize, 1).setUsage(THREE.DynamicDrawUsage));
    const points = new THREE.Points(pGeo, particleMaterial);
    points.frustumCulled = false;
    points.visible = isHigh; // medium 关闭粒子
    scene.add(points);

    particle = { points, geo: pGeo, pos: pPos, color: pColor, size: pSize, items: particleItems };

    updateOrbitColors();
  }

  const orbitScratchColor = new THREE.Color();
  const brandColor = new THREE.Color(BRAND);

  function updateOrbitColors() {
    if (!orbit) return;
    const { deviceList, color } = orbit;
    const samples = orbit.samples;
    const segs = orbit.segs;
    // 每设备的速度衰减：速率越大流动越快
    const speedArr = orbit.speed;
    for (let i = 0; i < deviceList.length; i++) {
      const dev = devices.get(deviceList[i].ip);
      const col = dev ? new THREE.Color(STATUS_META[dev.status]) : brandColor;
      const rateNorm = dev ? clamp((dev.target.down + dev.target.up) / 2e6, 0, 1) : 0;
      const lineSpeed = 0.14 + rateNorm * 0.95;
      for (let k = 0; k < segs; k++) {
        const base = (i * segs + k) * 2;
        const t0 = k / segs;
        const t1 = (k + 1) / segs;
        orbitScratchColor.copy(col).lerp(brandColor, t0 * 0.75);
        color[(base) * 3] = orbitScratchColor.r;
        color[(base) * 3 + 1] = orbitScratchColor.g;
        color[(base) * 3 + 2] = orbitScratchColor.b;
        orbitScratchColor.copy(col).lerp(brandColor, t1 * 0.75);
        color[(base + 1) * 3] = orbitScratchColor.r;
        color[(base + 1) * 3 + 1] = orbitScratchColor.g;
        color[(base + 1) * 3 + 2] = orbitScratchColor.b;
        speedArr[base] = lineSpeed;
        speedArr[base + 1] = lineSpeed;
      }
    }
    orbit.geo.attributes.aColor.needsUpdate = true;
    orbit.geo.attributes.aSpeed.needsUpdate = true;

    // 粒子颜色
    if (particle) {
      const pc = particle.color;
      for (let j = 0; j < particle.items.length; j++) {
        const dev = devices.get(deviceList[particle.items[j].devIndex]?.ip);
        const c = dev ? new THREE.Color(STATUS_META[dev.status]) : brandColor;
        pc[j * 3] = Math.min(1, c.r * 1.1 + 0.05);
        pc[j * 3 + 1] = Math.min(1, c.g * 1.1 + 0.05);
        pc[j * 3 + 2] = Math.min(1, c.b * 1.1 + 0.05);
        particle.size[j] = 1.15 + (dev ? clamp((dev.target.down + dev.target.up) / 2e6, 0, 1) : 0) * 1.4;
      }
      particle.geo.attributes.aColor.needsUpdate = true;
      particle.geo.attributes.aSize.needsUpdate = true;
    }

    orbitColorsDirty = false;
  }

  /* ---------------------------------------------------------------- */
  /* 每帧更新                                                          */
  /* ---------------------------------------------------------------- */

  const scratchLabelPos = new THREE.Vector3();
  const labelProject = new THREE.Vector3();
  const camDir = new THREE.Vector3();
  const tmpColor = new THREE.Color();

  function updateDevicesFrame(dt) {
    for (const dev of devices.values()) {
      dev.cur.height = damp(dev.cur.height, dev.target.height, 3.0, dt);
      dev.cur.down = damp(dev.cur.down, dev.target.down, 4.5, dt);
      dev.cur.up = damp(dev.cur.up, dev.target.up, 4.5, dt);

      const chipY = CFG.pillarBaseY + dev.cur.height + CFG.chipThickness / 2;
      dev.chip.position.y = chipY;
      dev.pillar.scale.y = Math.max(dev.cur.height, 0.01);
      dev.pillar.position.y = CFG.pillarBaseY;
      dev.pillarGlow.scale.set(1, Math.max(dev.cur.height, 0.01), 1);
      dev.pillarGlow.position.y = CFG.pillarBaseY;
      dev.glow.position.y = chipY + 0.14;

      const isHover = hoveredIp === dev.ip;
      const isSelected = selectedIp === dev.ip;
      const targetScale = isHover || isSelected ? 1.4 : 1;
      dev.cur.scale = damp(dev.cur.scale, targetScale, 10, dt);
      dev.chip.scale.setScalar(dev.cur.scale);
      dev.glow.scale.setScalar(0.68 * (isHover || isSelected ? 1.5 : 1));
      dev.baseDisc.scale.setScalar(1 + dev.cur.height * 0.03);

      const labelBaseY = chipY + 1.35 + ((dev.slot || 0) % 2) * 0.55;
      dev.label.position.y = labelBaseY;
      dev.label.scale.set(
        CFG.labelHeight * (LABEL_CANVAS_W / LABEL_CANVAS_H) * (dev.label.userData.baseScale || 1),
        CFG.labelHeight * (dev.label.userData.baseScale || 1),
        1,
      );

      if (dev.status === 'offline') {
        // 离线设备：芯片压暗一点（通过缩放表达，材质仍复用）
        dev.chip.scale.multiplyScalar(0.86);
      }
    }

    // 选中光环跟随
    if (selectedIp && devices.has(selectedIp)) {
      const dev = devices.get(selectedIp);
      selectionRing.visible = true;
      selectionRing.position.set(
        dev.group.position.x,
        CFG.pillarBaseY + dev.cur.height + 0.16,
        dev.group.position.z,
      );
      const pulse = 1 + Math.sin(elapsed * 3.2) * 0.08;
      selectionRing.scale.setScalar(pulse);
      selectionRing.rotation.z = elapsed * 0.8;
    } else {
      selectionRing.visible = false;
    }
  }

  function updateCategoryFrame(dt) {
    let sum = 0;
    for (let i = 0; i < sectorCount; i++) {
      const st = categoryState[i];
      st.share = damp(st.share, st.targetShare, 3.4, dt);
      if (st.share < 0) st.share = 0;
      sum += st.share;
    }
    if (sum <= 1e-9) sum = 1;
    let maxShare = 0;
    for (let i = 0; i < sectorCount; i++) maxShare = Math.max(maxShare, categoryState[i].share);
    if (maxShare <= 1e-9) maxShare = 1;
    const gap = CFG.sectorGap;
    const minArc = CFG.sectorMinArc;
    const avail = TAU - gap * sectorCount - minArc * sectorCount;
    let cursor = -Math.PI / 2;

    for (let i = 0; i < sectorCount; i++) {
      const st = categoryState[i];
      const width = minArc + (st.share / sum) * Math.max(avail, 0.2);
      const start = cursor;
      const end = cursor + width;
      cursor = end + gap;

      const height = clamp(
        CFG.sectorMinHeight + clamp(st.share, 0, 1) * (CFG.sectorMaxHeight - CFG.sectorMinHeight),
        CFG.sectorMinHeight,
        CFG.sectorMaxHeight,
      );
      st.start = start;
      st.end = end;
      st.height = height;
      scratchSectors[i].start = start;
      scratchSectors[i].end = end;
      scratchSectors[i].height = height;
    }
    updateSectorGeometries(sectorTopGeo, sectorSideGeo, scratchSectors);
    updateSectorEdges();
  }

  /** 顶面霓虹描边：内弧 → 径向外 → 外弧反向 → 径向内，随扇区角度/高度更新 */
  function updateSectorEdges() {
    const ri = CFG.sectorInner;
    const ro = CFG.sectorOuter;
    const seg = CFG.sectorSegments;
    const pos = sectorEdgePos;
    let o = 0;
    const put = (xa, ya, za, xb, yb, zb) => {
      pos[o] = xa;
      pos[o + 1] = ya;
      pos[o + 2] = za;
      pos[o + 3] = xb;
      pos[o + 4] = yb;
      pos[o + 5] = zb;
      o += 6;
    };
    for (let s = 0; s < sectorCount; s++) {
      const { start, end, height } = scratchSectors[s];
      const y = CFG.sectorBaseY + height + 0.008;
      const span = end - start;
      for (let k = 0; k < seg; k++) {
        const a0 = start + (span * k) / seg;
        const a1 = start + (span * (k + 1)) / seg;
        put(Math.cos(a0) * ri, y, Math.sin(a0) * ri, Math.cos(a1) * ri, y, Math.sin(a1) * ri);
      }
      put(Math.cos(end) * ri, y, Math.sin(end) * ri, Math.cos(end) * ro, y, Math.sin(end) * ro);
      for (let k = 0; k < seg; k++) {
        const a0 = end - (span * k) / seg;
        const a1 = end - (span * (k + 1)) / seg;
        put(Math.cos(a0) * ro, y, Math.sin(a0) * ro, Math.cos(a1) * ro, y, Math.sin(a1) * ro);
      }
      put(Math.cos(start) * ro, y, Math.sin(start) * ro, Math.cos(start) * ri, y, Math.sin(start) * ri);
    }
    sectorEdgeGeo.attributes.position.needsUpdate = true;
  }

  function updateTrendFrame(dt) {
    if (!trendReady) return;
    let max = 0;
    for (let i = 0; i < CFG.trendCount; i++) max = Math.max(max, trendBuf[i]);
    if (max <= 1) max = 1;
    for (let i = 0; i < CFG.trendCount; i++) {
      trendTarget[i] = trendBuf[i] / max;
      trendDisplay[i] = damp(trendDisplay[i], trendTarget[i], 5, dt);
      const h = 0.12 + trendDisplay[i] * 1.0;
      const a = (i / CFG.trendCount) * TAU;
      trendDummy.position.set(Math.cos(a) * CFG.trendRadius, CFG.trendBaseY, Math.sin(a) * CFG.trendRadius);
      trendDummy.rotation.set(0, 0, 0);
      trendDummy.scale.set(1, h, 1);
      trendDummy.updateMatrix();
      trendMesh.setMatrixAt(i, trendDummy.matrix);
      tmpColor.copy(trendColorDim).lerp(trendColorBright, trendDisplay[i]);
      trendMesh.setColorAt(i, tmpColor);
    }
    trendMesh.instanceMatrix.needsUpdate = true;
    if (trendMesh.instanceColor) trendMesh.instanceColor.needsUpdate = true;
  }

  function updateOrbitFrame(dt) {
    if (!orbit) return;
    const { deviceList, pos, dist, samples, segs, speed } = orbit;
    for (let i = 0; i < deviceList.length; i++) {
      const dev = devices.get(deviceList[i].ip);
      if (!dev) continue;
      const chipY = CFG.pillarBaseY + dev.cur.height + CFG.chipThickness / 2;
      // 起点跟随芯片，终点固定核心顶部，控制点略高
      const curve = dev.curve;
      curve.v0.set(dev.group.position.x, chipY + 0.16, dev.group.position.z);
      curve.v1.set(
        dev.group.position.x * 0.52,
        Math.max(chipY, CFG.pillarMinHeight) + 2.4 + dev.cur.height * 0.12,
        dev.group.position.z * 0.52,
      );
      curve.v2.set(0, CFG.trayTop + 2.1, 0);

      // 流动速度 ∝ 速率（每帧更新，无需重建颜色）
      const rateNorm = clamp((dev.cur.down + dev.cur.up) / 2e6, 0, 1);
      const lineSpeed = 0.14 + rateNorm * 0.95;
      const baseLine = i * segs * 2;
      for (let k = 0; k < segs * 2; k++) speed[baseLine + k] = lineSpeed;

      let prevX = 0;
      let prevY = 0;
      let prevZ = 0;
      let d = 0;
      for (let k = 0; k < samples; k++) {
        const t = k / segs;
        curve.getPoint(t, scratchV1);
        if (k > 0) {
          const dx = scratchV1.x - prevX;
          const dy = scratchV1.y - prevY;
          const dz = scratchV1.z - prevZ;
          d += Math.sqrt(dx * dx + dy * dy + dz * dz);
          // 写入上一段线段（prev → current）
          const base = (i * segs + (k - 1)) * 2;
          pos[(base) * 3] = prevX;
          pos[(base) * 3 + 1] = prevY;
          pos[(base) * 3 + 2] = prevZ;
          pos[(base + 1) * 3] = scratchV1.x;
          pos[(base + 1) * 3 + 1] = scratchV1.y;
          pos[(base + 1) * 3 + 2] = scratchV1.z;
          dist[base] = d;
          dist[base + 1] = d;
        }
        prevX = scratchV1.x;
        prevY = scratchV1.y;
        prevZ = scratchV1.z;
      }
    }
    orbit.geo.attributes.position.needsUpdate = true;
    orbit.geo.attributes.aDist.needsUpdate = true;
    orbit.geo.attributes.aSpeed.needsUpdate = true;

    // 粒子沿曲线运动，速度 ∝ 速率
    if (particle && particle.points.visible) {
      const items = particle.items;
      const pp = particle.pos;
      for (let j = 0; j < items.length; j++) {
        const item = items[j];
        const dev = devices.get(deviceList[item.devIndex]?.ip);
        if (!dev) continue;
        const rateNorm = clamp((dev.cur.down + dev.cur.up) / 2e6, 0, 1);
        const speed = item.speed + rateNorm * 0.22;
        const t = (item.offset + elapsed * speed) % 1;
        dev.curve.getPoint(t, scratchV2);
        pp[j * 3] = scratchV2.x;
        pp[j * 3 + 1] = scratchV2.y;
        pp[j * 3 + 2] = scratchV2.z;
      }
      particle.geo.attributes.position.needsUpdate = true;
    }
  }

  /* ---------------------------------------------------------------- */
  /* 网络拓扑：节点 / 链路 / 流向（数据来自 GET /api/topology）          */
  /* ---------------------------------------------------------------- */

  const TOPO_NODE_ORDER = ['lan', 'internet', 'proxy', 'zerotier', 'vpn', 'docker', 'other'];

  function topoTypeColor(type) {
    return TOPO_TYPE_COLORS[type] || TOPO_TYPE_COLORS.other;
  }

  function pickTopoMaterial(store, type, up, make) {
    const key = type + '|' + (up ? 'up' : 'down');
    let m = store.get(key);
    if (!m) {
      m = make(new THREE.Color(topoTypeColor(type)), up);
      store.set(key, m);
    }
    return m;
  }

  function topoNodeMaterial(type, up) {
    return pickTopoMaterial(topoNodeMaterials, type, up, (color, isUp) => {
      if (isUp) {
        return new THREE.MeshStandardMaterial({
          color: color.clone().multiplyScalar(0.72),
          emissive: color,
          emissiveIntensity: 0.8,
          metalness: 0.42,
          roughness: 0.36,
          flatShading: true,
        });
      }
      return new THREE.MeshStandardMaterial({
        color: 0x3b4a60,
        emissive: 0x263447,
        emissiveIntensity: 0.55,
        metalness: 0.4,
        roughness: 0.55,
        flatShading: true,
      });
    });
  }

  function topoRingMaterial(type, up) {
    return pickTopoMaterial(topoRingMaterials, type, up, (color, isUp) => {
      return new THREE.MeshBasicMaterial({
        color: isUp ? color : new THREE.Color(0x64748b),
        transparent: true,
        opacity: isUp ? 0.85 : 0.55,
        blending: THREE.AdditiveBlending,
        depthWrite: false,
      });
    });
  }

  function topoGlowMaterial(type, up) {
    return pickTopoMaterial(topoGlowMaterials, type, up, (color, isUp) => {
      return new THREE.SpriteMaterial({
        map: glowTex,
        color: isUp ? color : new THREE.Color(0x94a3b8),
        transparent: true,
        opacity: isUp ? 0.5 : 0.3,
        blending: THREE.AdditiveBlending,
        depthWrite: false,
      });
    });
  }

  /** 链路源端发光点材质（按 kind 缓存，所有同 kind 链路共享；提亮以区别同色弧管） */
  function topoFlowDotMaterial(kind, color) {
    let m = topoFlowDotMaterials.get(kind);
    if (!m) {
      m = new THREE.SpriteMaterial({
        map: glowTex,
        color: color.clone().lerp(new THREE.Color(0xffffff), 0.35),
        transparent: true,
        opacity: 0.9,
        blending: THREE.AdditiveBlending,
        depthWrite: false,
        depthTest: false,
      });
      topoFlowDotMaterials.set(kind, m);
    }
    return m;
  }

  /** 链路终点箭头材质（按 kind 缓存；提亮成实色，避免与同色弧管混在一起） */
  function topoArrowMaterial(kind, color) {
    let m = topoArrowMaterials.get(kind);
    if (!m) {
      m = new THREE.MeshBasicMaterial({
        color: color.clone().lerp(new THREE.Color(0xffffff), 0.55),
        transparent: true,
        opacity: 1,
        depthWrite: false,
        depthTest: false,
        side: THREE.DoubleSide,
      });
      topoArrowMaterials.set(kind, m);
    }
    return m;
  }

  function normalizeTopology(topo) {
    const nodes = [];
    const seen = new Set();
    const rawNodes = topo && Array.isArray(topo.nodes) ? topo.nodes : [];
    for (const n of rawNodes) {
      if (!n || !n.id) continue;
      const id = String(n.id);
      if (seen.has(id)) continue;
      seen.add(id);
      nodes.push({
        id,
        type: String(n.type || 'other'),
        name: String(n.name || n.id),
        cidr: String(n.cidr || ''),
        up: n.up !== false,
        rxBps: Number(n.rxBps) || 0,
        txBps: Number(n.txBps) || 0,
      });
    }
    const ids = new Set(nodes.map((n) => n.id));
    const links = [];
    const rawLinks = topo && Array.isArray(topo.links) ? topo.links : [];
    for (const l of rawLinks) {
      if (!l || !l.from || !l.to) continue;
      const from = String(l.from);
      const to = String(l.to);
      if (!ids.has(from) || !ids.has(to)) continue;
      links.push({
        from,
        to,
        kind: String(l.kind || 'direct'),
        upBps: Number(l.upBps) || 0,
        downBps: Number(l.downBps) || 0,
      });
    }
    return { nodes, links };
  }

  function topologySignature(topo) {
    return (
      topo.nodes
        .map((n) => n.id + ':' + n.type + ':' + (n.up ? 1 : 0))
        .join(',') +
      '|' +
      topo.links
        .map((l) => l.from + '>' + l.to + ':' + l.kind)
        .join(',')
    );
  }

  function layoutTopologyNodes(nodes) {
    const list = nodes.slice().sort((a, b) => {
      const ia = TOPO_NODE_ORDER.indexOf(a.type);
      const ib = TOPO_NODE_ORDER.indexOf(b.type);
      return (ia < 0 ? 99 : ia) - (ib < 0 ? 99 : ib) || (a.id < b.id ? -1 : 1);
    });
    const n = list.length || 1;
    return list.map((node, i) => {
      // 半环布局：左 → 上 → 右（π→2π），避开 HUD 底部/角落面板；
      // 节点少时也能保持分散，不会被 Top5/图例/提示条遮挡。
      const angle = n <= 1 ? -Math.PI / 2 : Math.PI + (i / (n - 1)) * Math.PI;
      node.angle = angle;
      node.radius = CFG.topoRadius;
      return node;
    });
  }

  function topoNodeWorldPosition(rec, target) {
    const out = target || new THREE.Vector3();
    return out.set(Math.cos(rec.angle) * rec.radius, 0, Math.sin(rec.angle) * rec.radius);
  }

  function disposeTopoLinks() {
    for (const link of topoLinks) {
      if (link.obj) {
        topoRoot.remove(link.obj);
        link.obj.geometry.dispose();
        link.obj.material.dispose();
      }
      if (link.sourceDot) {
        topoRoot.remove(link.sourceDot);
        link.sourceDot = null;
      }
      if (link.arrow) {
        topoRoot.remove(link.arrow);
        link.arrow = null;
      }
      if (link.flowLabel) {
        topoRoot.remove(link.flowLabel);
        if (link.flowLabelMat) {
          link.flowLabelMat.map = null;
          link.flowLabelMat.dispose();
          link.flowLabelMat = null;
        }
        if (link.flowLabelKey) {
          labelCache.release(link.flowLabelKey);
          link.flowLabelKey = null;
        }
        link.flowLabel = null;
      }
    }
    topoLinks = [];
    disposeTopoParticles();
  }

  function disposeTopoParticles() {
    if (topoParticles) {
      scene.remove(topoParticles.points);
      topoParticles.geo.dispose();
      topoParticles = null;
    }
    topoParticleItems = [];
  }

  function disposeTopologyObjects() {
    for (const rec of topoNodes.values()) {
      topoRoot.remove(rec.group);
      if (rec.labelKey) {
        labelCache.release(rec.labelKey);
        rec.labelKey = null;
      }
      if (rec.labelMaterial) {
        rec.labelMaterial.map = null;
        rec.labelMaterial.dispose();
        rec.labelMaterial = null;
      }
    }
    topoNodes.clear();
    topoMeshes.length = 0;
    disposeTopoLinks();
    hoveredNodeId = null;
    selectedNodeId = null;
  }

  function rebuildTopologyNodes(topo) {
    const layout = layoutTopologyNodes(topo.nodes);
    for (const nd of layout) {
      const group = new THREE.Group();
      topoNodeWorldPosition(nd, group.position);
      group.userData.nodeId = nd.id;

      const mesh = new THREE.Mesh(topoNodeGeo, topoNodeMaterial(nd.type, nd.up));
      mesh.userData.nodeId = nd.id;

      const ring = new THREE.Mesh(topoRingGeo, topoRingMaterial(nd.type, nd.up));
      ring.rotation.x = -Math.PI / 2;
      ring.position.y = 0.27;

      const glow = new THREE.Sprite(topoGlowMaterial(nd.type, nd.up));
      glow.scale.set(1.75, 1.75, 1);
      glow.position.y = 0.6;

      const labelMaterial = new THREE.SpriteMaterial({
        map: null,
        transparent: true,
        depthWrite: false,
        depthTest: true,
      });
      const label = new THREE.Sprite(labelMaterial);
      label.scale.set(
        CFG.topoLabelHeight * (LABEL_CANVAS_W / LABEL_CANVAS_H),
        CFG.topoLabelHeight,
        1,
      );
      label.position.y = 1.35 + CFG.topoLabelHeight * 0.5;
      labelMaterial.color = new THREE.Color(nd.up ? 0xffffff : 0xc7d6ea);

      group.add(mesh, ring, glow, label);
      topoRoot.add(group);
      topoMeshes.push(mesh);

      const rec = {
        ...nd,
        group,
        mesh,
        ring,
        glow,
        label,
        labelMaterial,
        labelKey: null,
        lastLabelAt: 0,
        scale: 1,
      };
      topoNodes.set(nd.id, rec);
    }
  }

  function buildTopoLinkObject(curve, kind, active, bps, upBps, downBps) {
    const colorHex = TOPO_KIND_COLORS[kind] || TOPO_KIND_COLORS.direct;
    const color = new THREE.Color(colorHex);
    if (active) {
      const strength = clamp(bps / 2e6, 0, 1);
      const radius = 0.022 + strength * CFG.topoLinkMaxWidth;
      const geo = new THREE.TubeGeometry(curve, 40, radius, 5, false);
      const mat = new THREE.MeshBasicMaterial({
        color,
        transparent: true,
        opacity: 0.82,
        blending: THREE.AdditiveBlending,
        depthWrite: false,
      });
      const obj = new THREE.Mesh(geo, mat);
      obj.frustumCulled = false;
      topoRoot.add(obj);

      // 源端（中心核心）发光圆点：落在弧线起始段、抬高一点避免与弧管/核心重叠
      const sourceDot = new THREE.Sprite(topoFlowDotMaterial(kind, color));
      sourceDot.scale.set(1.1, 1.1, 1);
      sourceDot.renderOrder = 15;
      sourceDot.position.copy(curve.getPoint(0.1));
      sourceDot.position.y += 0.5;
      topoRoot.add(sourceDot);

      // 终点（节点方向）箭头锥体：放在节点前一段、抬高一点，指向节点
      const arrow = new THREE.Mesh(topoConeGeo, topoArrowMaterial(kind, color));
      arrow.renderOrder = 15;
      arrow.position.copy(curve.getPoint(0.82));
      arrow.position.y += 0.45;
      const tangent = curve.getTangent(0.999).normalize();
      arrow.quaternion.setFromUnitVectors(new THREE.Vector3(0, 1, 0), tangent);
      topoRoot.add(arrow);

      // 弧线中点速率标签（↓下行 ↑上行），1s 节流更新
      const flowLabelMat = new THREE.SpriteMaterial({
        map: null,
        transparent: true,
        depthWrite: false,
        depthTest: false,
      });
      const flowLabel = new THREE.Sprite(flowLabelMat);
      flowLabel.renderOrder = 20;
      flowLabel.scale.set(
        CFG.topoFlowLabelHeight * (LABEL_CANVAS_W / LABEL_CANVAS_H),
        CFG.topoFlowLabelHeight,
        1,
      );
      const mid = curve.getPoint(0.5);
      flowLabel.position.set(mid.x, mid.y + 0.95, mid.z);
      topoRoot.add(flowLabel);

      return {
        obj,
        active: true,
        curve,
        kind,
        bps,
        upBps,
        downBps,
        color,
        colorHex,
        sourceDot,
        arrow,
        flowLabel,
        flowLabelMat,
        flowLabelKey: null,
        lastFlowLabelAt: 0,
      };
    }
    const pts = curve.getPoints(36);
    const geo = new THREE.BufferGeometry().setFromPoints(pts);
    const mat = new THREE.LineDashedMaterial({
      color,
      transparent: true,
      opacity: 0.34,
      dashSize: 0.34,
      gapSize: 0.24,
      depthWrite: false,
    });
    const obj = new THREE.Line(geo, mat);
    obj.computeLineDistances();
    topoRoot.add(obj);
    return { obj, active: false, curve, kind, bps, upBps, downBps, color, colorHex };
  }

  function rebuildTopoLinks(topo) {
    disposeTopoLinks();
    const corePoint = new THREE.Vector3(0, CFG.trayTop + 2.3, 0);
    const scratchStart = new THREE.Vector3();
    const activeLinks = [];

    const addLink = (targetRec, kind, upBps, downBps) => {
      if (!targetRec) return;
      const start = topoNodeWorldPosition(targetRec, scratchStart).clone().setY(0.7);
      const ctrl = new THREE.Vector3(start.x * 0.55, 4.3, start.z * 0.55);
      const curve = new THREE.QuadraticBezierCurve3(corePoint.clone(), ctrl, start);
      const bps = upBps + downBps;
      const active = bps > 0 && targetRec.up !== false;
      const record = buildTopoLinkObject(curve, kind, active, bps, upBps, downBps);
      record.from = topoLinkFrom;
      record.to = targetRec.id;
      record.upBps = upBps;
      record.downBps = downBps;
      record.target = targetRec;
      topoLinks.push(record);
      if (active) activeLinks.push(record);
    };

    let topoLinkFrom = '';
    for (const link of topo.links) {
      const target = topoNodes.get(link.to) || topoNodes.get(link.from);
      topoLinkFrom = link.from;
      addLink(target, link.kind, link.upBps, link.downBps);
    }

    // LAN 节点链路：后端已显式给出 kind='lan' 自环链路（LAN 内网互访）。
    // 仅当后端未给出时才用节点计数兜底，避免与显式链路重复绘制（管线/粒子重影）。
    const hasExplicitLan = (topo.links || []).some((l) => l && l.kind === 'lan');
    let lanNode = null;
    for (const rec of topoNodes.values()) {
      if (rec.type === 'lan') {
        lanNode = rec;
        break;
      }
    }
    if (lanNode && !hasExplicitLan) {
      topoLinkFrom = lanNode.id;
      addLink(lanNode, 'lan', lanNode.txBps, lanNode.rxBps);
    }

    rebuildTopoParticles(activeLinks);
  }

  function rebuildTopoParticles(activeLinks) {
    disposeTopoParticles();
    if (!isHigh || !activeLinks.length) return;
    const perLink = Math.max(2, Math.min(6, CFG.topoParticlesPerLink));
    const items = [];
    for (const link of activeLinks) {
      const strength = clamp(link.bps / 2e6, 0, 1);
      const dir = (link.upBps || 0) >= (link.downBps || 0) ? 1 : -1;
      for (let k = 0; k < perLink; k++) {
        items.push({
          curve: link.curve,
          color: link.color,
          offset: (k + Math.random() * 0.35) / perLink,
          speed: 0.055 + strength * 0.16,
          dir,
        });
      }
    }
    if (!items.length) return;
    const pos = new Float32Array(items.length * 3);
    const color = new Float32Array(items.length * 3);
    const size = new Float32Array(items.length);
    const geo = new THREE.BufferGeometry();
    geo.setAttribute('position', new THREE.BufferAttribute(pos, 3).setUsage(THREE.DynamicDrawUsage));
    geo.setAttribute('aColor', new THREE.BufferAttribute(color, 3));
    geo.setAttribute('aSize', new THREE.BufferAttribute(size, 1));
    for (let i = 0; i < items.length; i++) {
      color[i * 3] = Math.min(1, items[i].color.r * 1.2 + 0.1);
      color[i * 3 + 1] = Math.min(1, items[i].color.g * 1.2 + 0.1);
      color[i * 3 + 2] = Math.min(1, items[i].color.b * 1.2 + 0.1);
      size[i] = 1.0;
    }
    const points = new THREE.Points(geo, particleMaterial);
    points.frustumCulled = false;
    scene.add(points);
    topoParticles = { points, geo, pos };
    topoParticleItems = items;
  }

  function updateTopologyLabels(nowMs, force = false) {
    for (const rec of topoNodes.values()) {
      if (!force && nowMs - rec.lastLabelAt < 900) continue;
      const key =
        truncateChars(rec.name, 10) +
        '\n' +
        formatRate(rec.rxBps) +
        '\n' +
        formatRate(rec.txBps);
      if (key === rec.labelKey) {
        rec.lastLabelAt = nowMs;
        continue;
      }
      const tex = labelCache.acquire(key);
      if (rec.labelKey) labelCache.release(rec.labelKey);
      rec.labelKey = key;
      rec.labelMaterial.map = tex;
      rec.labelMaterial.needsUpdate = true;
      rec.lastLabelAt = nowMs;
    }
  }

  function updateTopoFlowLabels(nowMs, force = false) {
    for (const link of topoLinks) {
      if (!link.active || !link.flowLabel || !link.flowLabelMat) continue;
      if (!force && nowMs - link.lastFlowLabelAt < 1000) continue;
      const key =
        'FLOW|' +
        (link.colorHex || '#22d3ee') +
        '\n' +
        formatRate(link.downBps || 0) +
        '\n' +
        formatRate(link.upBps || 0);
      if (key === link.flowLabelKey) {
        link.lastFlowLabelAt = nowMs;
        continue;
      }
      const tex = labelCache.acquire(key);
      if (link.flowLabelKey) labelCache.release(link.flowLabelKey);
      link.flowLabelKey = key;
      link.flowLabelMat.map = tex;
      link.flowLabelMat.needsUpdate = true;
      link.lastFlowLabelAt = nowMs;
    }
  }

  function applyTopologyNodeRates(topo) {
    for (const nd of topo.nodes) {
      const rec = topoNodes.get(nd.id);
      if (!rec) continue;
      rec.rxBps = nd.rxBps;
      rec.txBps = nd.txBps;
      rec.name = nd.name;
      rec.up = nd.up;
    }
    updateTopologyLabels(performance.now(), true);
  }

  function setTopology(topo) {
    if (disposed || !topo) return;
    const norm = normalizeTopology(topo);
    const sig = topologySignature(norm);
    const structureChanged = sig !== topoSignature;
    if (structureChanged) {
      topoSignature = sig;
      const prevSelected = selectedNodeId;
      disposeTopologyObjects();
      rebuildTopologyNodes(norm);
      selectedNodeId = prevSelected && topoNodes.has(prevSelected) ? prevSelected : null;
    } else {
      applyTopologyNodeRates(norm);
    }
    rebuildTopoLinks(norm);
    updateTopologyLabels(performance.now(), true);
    updateTopoFlowLabels(performance.now(), true);
    lastDataAt = performance.now();
  }

  function focusNode(id) {
    const rec = topoNodes.get(id);
    if (!rec) return;
    selectedNodeId = id;
    topoNodeWorldPosition(rec, scratchV1);
    const dir = scratchV1.lengthSq() > 0.0001 ? scratchV1.clone().normalize() : new THREE.Vector3(0, 0, 1);
    focusAnim.fromPos.copy(camera.position);
    focusAnim.fromTarget.copy(controls.target);
    focusAnim.toTarget.set(rec.group.position.x, 1.0, rec.group.position.z);
    focusAnim.toPos
      .copy(focusAnim.toTarget)
      .addScaledVector(dir, 19.5)
      .add(scratchV2.set(0, 17.5, 0));
    scratchV3.subVectors(focusAnim.toPos, focusAnim.toTarget);
    if (scratchV3.length() < CFG.minDistance) {
      focusAnim.toPos.copy(focusAnim.toTarget).addScaledVector(scratchV3.normalize(), CFG.minDistance);
    }
    focusAnim.t = 0;
    focusAnim.active = true;
    entry.active = false;
  }

  function updateTopologyFrame(dt) {
    if (!topoNodes.size) {
      topoNodeSelectionRing.visible = false;
      return;
    }
    for (const rec of topoNodes.values()) {
      const isHover = hoveredNodeId === rec.id;
      const isSelected = selectedNodeId === rec.id;
      const targetScale = isHover || isSelected ? 1.3 : 1;
      rec.scale = damp(rec.scale, targetScale, 10, dt);
      rec.mesh.scale.setScalar(rec.scale);
      rec.ring.scale.setScalar(rec.scale);
      rec.glow.scale.setScalar((isHover || isSelected ? 2.3 : 1.75) * (rec.up ? 1 : 0.7));
      // 有流量节点标签放大 18%，保证速率可读
      const busy = rec.rxBps + rec.txBps > 0;
      const ls = busy ? 1.18 : 1;
      rec.label.scale.set(
        CFG.topoLabelHeight * (LABEL_CANVAS_W / LABEL_CANVAS_H) * ls,
        CFG.topoLabelHeight * ls,
        1,
      );
    }
    // 链路方向标识：源端发光点 + 终点箭头轻微脉冲
    for (let i = 0; i < topoLinks.length; i++) {
      const link = topoLinks[i];
      if (!link.active) continue;
      if (link.sourceDot) {
        const s = 1.1 * (1 + 0.18 * Math.sin(elapsed * 4 + i * 1.7));
        link.sourceDot.scale.set(s, s, 1);
      }
      if (link.arrow) {
        const a = 1 + 0.12 * Math.sin(elapsed * 5 + i * 1.3);
        link.arrow.scale.set(a, a, a);
      }
    }
    if (selectedNodeId && topoNodes.has(selectedNodeId)) {
      const rec = topoNodes.get(selectedNodeId);
      topoNodeSelectionRing.visible = true;
      topoNodeSelectionRing.position.set(rec.group.position.x, 0.3, rec.group.position.z);
      topoNodeSelectionRing.scale.setScalar(1 + Math.sin(elapsed * 3.2) * 0.08);
      topoNodeSelectionRing.rotation.z = elapsed * 0.6;
    } else {
      topoNodeSelectionRing.visible = false;
    }
    // 流动粒子
    if (topoParticles && topoParticleItems.length) {
      const arr = topoParticles.pos;
      for (let i = 0; i < topoParticleItems.length; i++) {
        const item = topoParticleItems[i];
        let t = (item.offset + elapsed * item.speed) % 1;
        if (item.dir < 0) t = 1 - t;
        item.curve.getPoint(t, scratchV2);
        arr[i * 3] = scratchV2.x;
        arr[i * 3 + 1] = scratchV2.y;
        arr[i * 3 + 2] = scratchV2.z;
      }
      topoParticles.geo.attributes.position.needsUpdate = true;
      topoParticles.geo.attributes.aColor.needsUpdate = true;
    }
  }

  function disposeTopology() {
    disposeTopologyObjects();
    if (topoNodeSelectionRing) {
      scene.remove(topoNodeSelectionRing);
      topoNodeSelectionRing.geometry.dispose();
      topoNodeSelectionRing.material.dispose();
    }
    for (const m of topoNodeMaterials.values()) m.dispose();
    for (const m of topoRingMaterials.values()) m.dispose();
    for (const m of topoGlowMaterials.values()) m.dispose();
    for (const m of topoFlowDotMaterials.values()) m.dispose();
    for (const m of topoArrowMaterials.values()) m.dispose();
    topoNodeMaterials.clear();
    topoRingMaterials.clear();
    topoGlowMaterials.clear();
    topoFlowDotMaterials.clear();
    topoArrowMaterials.clear();
    topoNodeGeo.dispose();
    topoRingGeo.dispose();
    topoConeGeo.dispose();
    scene.remove(topoRoot);
  }

  function setHoverNode(id) {
    const next = id && topoNodes.has(id) ? id : null;
    if (hoveredNodeId === next) return;
    hoveredNodeId = next;
    container.style.cursor = next || hoveredIp ? 'pointer' : 'grab';
    onHoverNode(next);
  }

  function updateCoreFrame(dt) {
    const baseY = CFG.trayTop;
    if (coreBody) coreBody.rotation.y += dt * 0.06;
    for (const r of coreRings) r.pivot.rotation.y += r.speed * dt;
    for (const p of pulseRings) {
      const phase = (elapsed * 0.42 + p.offset) % 1;
      p.mesh.scale.setScalar(1 + phase * 3.4);
      p.mesh.material.opacity = 0.35 * (1 - phase);
    }
    if (coreGlowSprite) {
      coreGlowSprite.material.opacity = 0.08 + Math.sin(elapsed * 1.6) * 0.02;
      coreGlowSprite.position.y = baseY + 3.3 + Math.sin(elapsed * 0.9) * 0.1;
    }
    // 核心呼吸光（收敛，避免过曝盖住扇柱顶面）
    coreMaterial.emissiveIntensity = 0.5 + Math.sin(elapsed * 1.3) * 0.1;
    if (dirLight) dirLight.intensity = 1.0 + Math.sin(elapsed * 0.5) * 0.05;
  }

  function updateLabels(nowMs, force = false) {
    for (const dev of devices.values()) {
      const need = force || dev.labelKey === null || nowMs - dev.lastLabelAt > 900;
      if (!need) continue;
      const downText = formatRate(dev.cur.down);
      const upText = formatRate(dev.cur.up);
      const key = truncateChars(dev.name, 10) + '\n' + downText + '\n' + upText;
      if (key === dev.labelKey) {
        dev.lastLabelAt = nowMs;
        continue;
      }
      const tex = labelCache.acquire(key);
      if (dev.labelKey) labelCache.release(dev.labelKey);
      dev.labelKey = key;
      dev.labelMaterial.map = tex;
      dev.labelMaterial.needsUpdate = true;
      dev.labelNameLen = Array.from(key.split('\n')[0]).length;
      dev.label.visible = true;
      dev.lastLabelAt = nowMs;
    }
  }

  let lastDeclutter = 0;
  const declutterRects = [];
  function updateLabelDeclutter(nowMs) {
    if (nowMs - lastDeclutter < 240) return;
    lastDeclutter = nowMs;
    const W = currentWidth;
    const H = currentHeight;
    if (!W || !H) return;
    declutterRects.length = 0;

    const list = [];
    for (const dev of devices.values()) {
      dev.label.getWorldPosition(scratchLabelPos);
      labelProject.copy(scratchLabelPos).project(camera);
      const dist = camera.position.distanceTo(scratchLabelPos);
      const camDist = Math.max(dist, 1);
      const pxPerWorld = H / (2 * Math.tan((CFG.cameraFov * Math.PI) / 360) * camDist);
      const scale = dev.label.scale;
      // 标签有半透明底板，按底板实际尺寸做重叠规避
      const halfW = Math.max(1.2, scale.x * 0.5 * pxPerWorld) + 3;
      const halfH = Math.max(4, scale.y * 0.5 * 0.94 * pxPerWorld) + 2;
      const sx = (labelProject.x * 0.5 + 0.5) * W;
      const sy = (-labelProject.y * 0.5 + 0.5) * H;
      const behind = labelProject.z > 1;
      const priority = (hoveredIp === dev.ip ? 1000 : 0) + (selectedIp === dev.ip ? 900 : 0) + dev.cur.down;
      list.push({ dev, sx, sy, halfW, halfH, behind, priority });
    }
    list.sort((a, b) => b.priority - a.priority);

    for (const item of list) {
      const dev = item.dev;
      if (item.behind) {
        dev.label.visible = false;
        continue;
      }
      // 屏幕外
      if (item.sx < -80 || item.sx > W + 80 || item.sy < -60 || item.sy > H + 60) {
        dev.label.visible = false;
        continue;
      }
      const rect = [item.sx - item.halfW, item.sy - item.halfH, item.sx + item.halfW, item.sy + item.halfH];
      let overlap = false;
      for (let i = 0; i < declutterRects.length; i += 4) {
        if (
          rect[0] < declutterRects[i + 2] &&
          rect[2] > declutterRects[i] &&
          rect[1] < declutterRects[i + 3] &&
          rect[3] > declutterRects[i + 1]
        ) {
          overlap = true;
          break;
        }
      }
      const forced = hoveredIp === dev.ip || selectedIp === dev.ip;
      if (overlap && !forced) {
        dev.label.visible = false;
      } else {
        dev.label.visible = true;
        if (!forced) {
          declutterRects.push(rect[0], rect[1], rect[2], rect[3]);
        }
      }
    }
  }

  /* ---------------------------------------------------------------- */
  /* 尺寸 / 交互 / 循环                                                */
  /* ---------------------------------------------------------------- */

  let currentWidth = 1;
  let currentHeight = 1;
  let disposed = false;
  let elapsed = 0;
  let lastRenderAt = 0;
  let lastFrameTimestamp = 0;
  let rafId = 0;
  let mode = 'cruise';
  let fps = 30;
  let frameSampleCount = 0;
  let frameSampleAt = 0;
  let interactingUntil = 0;

  function applySize() {
    const w = Math.max(1, container.clientWidth || 1);
    const h = Math.max(1, container.clientHeight || 1);
    currentWidth = w;
    currentHeight = h;
    camera.aspect = w / h;
    camera.updateProjectionMatrix();
    renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, isHigh ? 2 : 1.5));
    renderer.setSize(w, h, false);
    particleMaterial.uniforms.uPixelRatio.value = renderer.getPixelRatio();
  }

  let resizeObserver = null;
  if (typeof ResizeObserver !== 'undefined') {
    resizeObserver = new ResizeObserver(() => {
      if (!disposed) applySize();
    });
    resizeObserver.observe(container);
  }
  applySize();

  /* ---------- 指针交互 ---------- */

  const pointer = { x: 0, y: 0, inside: false, downX: 0, downY: 0, downTime: 0, moved: 0 };
  const raycaster = new THREE.Raycaster();
  const ndc = new THREE.Vector2(0, 0);
  let hoverRaycastDirty = false;

  function setHover(ip) {
    if (hoveredIp === ip) return;
    hoveredIp = ip;
    container.style.cursor = ip || hoveredNodeId ? 'pointer' : 'grab';
    onHoverDevice(ip);
  }

  function updatePointerNdc(e) {
    const rect = canvas.getBoundingClientRect();
    if (!rect.width || !rect.height) return;
    ndc.x = ((e.clientX - rect.left) / rect.width) * 2 - 1;
    ndc.y = -((e.clientY - rect.top) / rect.height) * 2 + 1;
  }

  function markInteraction(ms = 900) {
    interactingUntil = performance.now() + ms;
  }

  function onPointerMove(e) {
    pointer.inside = true;
    updatePointerNdc(e);
    if (pointer.downTime) pointer.moved += Math.abs(e.movementX || 0) + Math.abs(e.movementY || 0);
    hoverRaycastDirty = true;
    markInteraction(800);
  }

  function onPointerDown(e) {
    pointer.downX = e.clientX;
    pointer.downY = e.clientY;
    pointer.downTime = performance.now();
    pointer.moved = 0;
    markInteraction(1200);
    container.style.cursor = 'grabbing';
  }

  function onPointerUp(e) {
    const dt = performance.now() - pointer.downTime;
    const dx = e.clientX - pointer.downX;
    const dy = e.clientY - pointer.downY;
    const isClick = pointer.downTime && dt < 700 && Math.hypot(dx, dy) < 8;
    pointer.downTime = 0;
    container.style.cursor = hoveredIp || hoveredNodeId ? 'pointer' : 'grab';
    if (!isClick) return;
    // 优先网络节点
    if (hoveredNodeId) {
      selectedNodeId = hoveredNodeId;
      selectedIp = null;
      onSelectDevice(null);
      onSelectNode(hoveredNodeId);
      focusNode(hoveredNodeId);
      return;
    }
    if (hoveredIp) {
      selectedIp = hoveredIp;
      selectedNodeId = null;
      onSelectNode(null);
      onSelectDevice(hoveredIp);
    } else {
      selectedIp = null;
      selectedNodeId = null;
      onSelectNode(null);
      onSelectDevice(null);
    }
  }

  function onPointerLeave() {
    pointer.inside = false;
    pointer.downTime = 0;
    setHover(null);
    setHoverNode(null);
    container.style.cursor = 'grab';
  }

  function onWheel() {
    markInteraction(1200);
  }

  function onDoubleClick() {
    if (hoveredNodeId) focusNode(hoveredNodeId);
    else if (hoveredIp) focusDevice(hoveredIp);
  }

  function onKeyDown() {
    markInteraction(400);
  }

  function raycastHover() {
    if (!pointer.inside) return;
    raycaster.setFromCamera(ndc, camera);
    const chipHits = chipMeshes.length ? raycaster.intersectObjects(chipMeshes, false) : [];
    const nodeHits = topoMeshes.length ? raycaster.intersectObjects(topoMeshes, false) : [];
    const chipDist = chipHits.length ? chipHits[0].distance : Infinity;
    const nodeDist = nodeHits.length ? nodeHits[0].distance : Infinity;
    if (nodeDist < chipDist) {
      setHover(null);
      setHoverNode(nodeHits[0].object.userData.nodeId || null);
    } else {
      setHoverNode(null);
      setHover(chipHits.length ? chipHits[0].object.userData.ip || null : null);
    }
  }

  canvas.addEventListener('pointermove', onPointerMove);
  canvas.addEventListener('pointerdown', onPointerDown);
  canvas.addEventListener('pointerup', onPointerUp);
  canvas.addEventListener('pointerleave', onPointerLeave);
  canvas.addEventListener('wheel', onWheel, { passive: true });
  canvas.addEventListener('dblclick', onDoubleClick);
  window.addEventListener('keydown', onKeyDown);

  /* ---------- 可见性 ---------- */

  function onVisibilityChange() {
    if (document.hidden) {
      cancelAnimationFrame(rafId);
      rafId = 0;
    } else if (!rafId && !disposed) {
      clock.getDelta(); // 丢弃隐藏期间累积的时间
      lastFrameTimestamp = 0;
      rafId = requestAnimationFrame(tick);
    }
  }
  document.addEventListener('visibilitychange', onVisibilityChange);

  /* ---------- 相机入场 / 聚焦 ---------- */

  function updateCameraAnimation(dt) {
    if (entry.active) {
      entry.t += dt;
      // 同时参考墙钟：标签页被节流/低帧率时入场动画也能按时完成
      const wall = (performance.now() - entry.startedAt) / 1000;
      const k = easeInOutCubic(clamp(Math.max(entry.t, wall) / CFG.entryDuration, 0, 1));
      camera.position.lerpVectors(entry.from, CFG.cameraHome, k);
      camera.lookAt(CFG.cameraTarget);
      if (k >= 1) {
        entry.active = false;
        controls.target.copy(CFG.cameraTarget);
        controls.update();
      }
      return true;
    }
    if (focusAnim.active) {
      focusAnim.t += dt;
      const k = easeInOutCubic(clamp(focusAnim.t / focusAnim.duration, 0, 1));
      camera.position.lerpVectors(focusAnim.fromPos, focusAnim.toPos, k);
      controls.target.lerpVectors(focusAnim.fromTarget, focusAnim.toTarget, k);
      camera.lookAt(controls.target);
      if (k >= 1) focusAnim.active = false;
      return true;
    }
    return false;
  }

  function applyAutoRotate(dt) {
    // 手动绕靶心旋转：与帧率无关，稳定 0.25 rad/min
    if (entry.active || focusAnim.active) return;
    scratchV1.copy(camera.position).sub(controls.target);
    scratchV1.applyAxisAngle(UP, CFG.autoRotateRadPerSec * dt);
    camera.position.copy(controls.target).add(scratchV1);
  }

  /* ---------- 主循环（自适应跳帧） ---------- */

  const clock = new THREE.Clock();

  function decideTargetInterval(nowMs) {
    if (nowMs < interactingUntil) {
      mode = 'interactive';
      return 1000 / 60;
    }
    if (nowMs - lastDataAt > 3000) {
      mode = 'cruise';
      return 1000 / 12;
    }
    mode = 'active';
    return 1000 / 30;
  }

  function tick(now) {
    if (disposed) return;
    rafId = requestAnimationFrame(tick);
    if (document.hidden) return;

    const nowMs = now || performance.now();
    const targetInterval = decideTargetInterval(nowMs);
    if (lastFrameTimestamp === 0) lastFrameTimestamp = nowMs;
    const sinceLast = nowMs - lastRenderAt;
    // 允许 ±1.5ms 抖动，避免固定 60Hz 显示器上 30fps 变 20fps
    if (lastRenderAt && sinceLast < targetInterval - 1.5) return;

    const dt = clamp(sinceLast / 1000, 0.001, 0.12);
    lastRenderAt = nowMs;
    lastFrameTimestamp = nowMs;

    // fps 统计
    frameSampleCount += 1;
    if (nowMs - frameSampleAt >= 1000) {
      fps = (frameSampleCount * 1000) / (nowMs - frameSampleAt);
      frameSampleCount = 0;
      frameSampleAt = nowMs;
    }

    stepFrame(dt, nowMs);
    if (pointer.inside && hoverRaycastDirty) {
      hoverRaycastDirty = false;
      raycastHover();
    }
    renderer.render(scene, camera);
  }

  /** 推进一帧逻辑（不渲染），dt 秒。 */
  function stepFrame(dt, nowMs) {
    elapsed += dt;
    const animating = updateCameraAnimation(dt);
    applyAutoRotate(dt);
    if (!animating) controls.update();

    if (orbitColorsDirty) updateOrbitColors();
    updateCategoryFrame(dt);
    updateDevicesFrame(dt);
    updateOrbitFrame(dt);
    updateTopologyFrame(dt);
    updateTrendFrame(dt);
    updateCoreFrame(dt);
    trayGroup.rotation.y = (trayGroup.rotation.y + 0.02 * dt) % TAU;

    updateLabels(nowMs, elapsed < 0.05);
    updateTopologyLabels(nowMs, elapsed < 0.05);
    updateTopoFlowLabels(nowMs, elapsed < 0.05);
    deviceRoot.updateMatrixWorld();
    updateLabelDeclutter(nowMs);
    lineMaterial.uniforms.uTime.value = elapsed;
  }

  /**
   * 预热：以 30fps 步进指定秒数并渲染一帧。
   * 用于无头截图 / 页面切入时立刻呈现稳定画面（不依赖真实 rAF 频率）。
   */
  function warmup(seconds = 2.5) {
    if (disposed) return;
    const steps = Math.min(360, Math.max(1, Math.round(seconds * 30)));
    for (let i = 0; i < steps; i++) stepFrame(1 / 30, performance.now());
    updateLabels(performance.now(), true);
    deviceRoot.updateMatrixWorld();
    updateLabelDeclutter(performance.now() + 1000);
    renderer.render(scene, camera);
  }

  /* ---------------------------------------------------------------- */
  /* 公开 API                                                          */
  /* ---------------------------------------------------------------- */

  /**
   * 数据入口。
   * - 兼容旧契约：state.devices 为全量数组（无 full 字段）→ 整体替换
   * - 后端新契约（docs 增量语义）：full=true 整体替换；full=false 按 ip 合并更新
   * - overview 兼容：无 devices 但有 topDevices 时按「部分快照」处理（screen.js 会给出 full 标记）
   */
  function update(state) {
    if (disposed || !state) return;
    lastDataAt = performance.now();
    lastUpdatePayload = state;

    if (Array.isArray(state.trend) && state.trend.length) applyTrendArray(state.trend);
    if (state.trendPoint) pushTrendPoint(state.trendPoint);
    if (state.trendPoint && !trendReady) trendReady = true;
    if (Array.isArray(state.categories)) updateCategories(state.categories);
    if (state.topology && Array.isArray(state.topology.nodes)) setTopology(state.topology);

    if (Array.isArray(state.devices)) {
      if (state.full === false) {
        // 增量帧：只更新本帧变化的设备，字典里其余设备保持
        for (const d of state.devices) {
          if (!d || !d.ip) continue;
          const key = String(d.ip);
          // 逐字段合并：帧里没带的字段（如 online/blocked）不覆盖已有真实状态
          knownDevices.set(key, mergeDeviceRecord(knownDevices.get(key), normalizeDevice(d)));
        }
        // removed：仅增量帧出现（被 forget/隐藏的设备），先合并 devices 再删除
        if (Array.isArray(state.removed)) {
          for (const ip of state.removed) {
            if (ip) knownDevices.delete(String(ip));
          }
        }
      } else {
        // 全量帧（full=true 或旧契约无 full 字段）：removed 可忽略
        knownDevices.clear();
        for (const d of state.devices) {
          if (!d || !d.ip) continue;
          knownDevices.set(String(d.ip), mergeDeviceRecord(null, normalizeDevice(d)));
        }
      }
      applyDevices([...knownDevices.values()]);
    } else if (Array.isArray(state.topDevices)) {
      // overview 快照：默认整体替换；screen.js 在轮询/首屏场景会带 full 标记
      if (state.full === false && knownDevices.size) {
        for (const d of state.topDevices) {
          if (!d || !d.ip) continue;
          const key = String(d.ip);
          knownDevices.set(key, mergeDeviceRecord(knownDevices.get(key), normalizeDevice(d)));
        }
      } else {
        knownDevices.clear();
        for (const d of state.topDevices) {
          if (!d || !d.ip) continue;
          knownDevices.set(String(d.ip), mergeDeviceRecord(null, normalizeDevice(d)));
        }
      }
      applyDevices([...knownDevices.values()]);
    }
  }

  function setHighlight(ip) {
    selectedIp = ip || null;
    if (selectedIp && !devices.has(selectedIp)) selectedIp = null;
  }

  function focusDevice(ip) {
    if (!ip || !devices.has(ip)) return;
    const dev = devices.get(ip);
    setHighlight(ip);
    scratchV1.set(dev.group.position.x, 0, dev.group.position.z);
    const dir = scratchV1.lengthSq() > 0.0001 ? scratchV1.clone().normalize() : new THREE.Vector3(0, 0, 1);
    focusAnim.fromPos.copy(camera.position);
    focusAnim.fromTarget.copy(controls.target);
    focusAnim.toTarget.set(
      dev.group.position.x * 0.96,
      CFG.pillarBaseY + dev.cur.height * 0.55 + 0.6,
      dev.group.position.z * 0.96,
    );
    focusAnim.toPos
      .copy(focusAnim.toTarget)
      .addScaledVector(dir, 19.5)
      .add(scratchV2.set(0, 17.5, 0));
    // 距离限制在 OrbitControls 范围内
    scratchV3.subVectors(focusAnim.toPos, focusAnim.toTarget);
    const dist = scratchV3.length();
    if (dist < CFG.minDistance) {
      focusAnim.toPos
        .copy(focusAnim.toTarget)
        .addScaledVector(scratchV3.normalize(), CFG.minDistance);
    }
    focusAnim.t = 0;
    focusAnim.active = true;
    entry.active = false;
  }

  function resetView() {
    entry.active = false;
    focusAnim.fromPos.copy(camera.position);
    focusAnim.fromTarget.copy(controls.target);
    focusAnim.toPos.copy(CFG.cameraHome);
    focusAnim.toTarget.copy(CFG.cameraTarget);
    focusAnim.t = 0;
    focusAnim.active = true;
  }

  function getPerf() {
    return {
      mode,
      fps: Math.round(fps),
      drawCalls: renderer.info.render.calls,
      triangles: renderer.info.render.triangles,
      points: renderer.info.render.points,
      deviceCount: devices.size,
      topoNodeCount: topoNodes.size,
      labelTextures: labelCache.size,
      quality,
      pixelRatio: renderer.getPixelRatio(),
      camDistance: Math.round(camera.position.distanceTo(controls.target) * 10) / 10,
      camX: Math.round(camera.position.x * 10) / 10,
      camY: Math.round(camera.position.y * 10) / 10,
      camZ: Math.round(camera.position.z * 10) / 10,
      size: [currentWidth, currentHeight],
      elapsed: Math.round(elapsed * 100) / 100,
      entryT: Math.round(entry.t * 100) / 100,
      entryActive: entry.active,
      heapMb:
        typeof performance !== 'undefined' && performance.memory
          ? Math.round((performance.memory.usedJSHeapSize || 0) / 1048576)
          : null,
    };
  }

  function dispose() {
    if (disposed) return;
    disposed = true;
    cancelAnimationFrame(rafId);
    rafId = 0;

    document.removeEventListener('visibilitychange', onVisibilityChange);
    window.removeEventListener('keydown', onKeyDown);
    canvas.removeEventListener('pointermove', onPointerMove);
    canvas.removeEventListener('pointerdown', onPointerDown);
    canvas.removeEventListener('pointerup', onPointerUp);
    canvas.removeEventListener('pointerleave', onPointerLeave);
    canvas.removeEventListener('wheel', onWheel);
    canvas.removeEventListener('dblclick', onDoubleClick);
    if (resizeObserver) resizeObserver.disconnect();

    controls.dispose();
    disposeOrbits();
    disposeParticles();
    disposeTopology();
    labelCache.dispose();

    // 统一释放场景内所有 geometry / material / texture
    const textures = new Set();
    const materials = new Set();
    scene.traverse((obj) => {
      if (obj.geometry && typeof obj.geometry.dispose === 'function') obj.geometry.dispose();
      const mat = obj.material;
      const arr = Array.isArray(mat) ? mat : mat ? [mat] : [];
      for (const m of arr) {
        if (!m) continue;
        if (materials.has(m)) continue;
        materials.add(m);
        for (const key of Object.keys(m)) {
          const v = m[key];
          if (v && v.isTexture) textures.add(v);
        }
        m.dispose();
      }
    });
    for (const t of textures) t.dispose();
    if (scene.background && scene.background.dispose) scene.background.dispose();

    // 显式释放：可能已从场景脱离 / 未被 traverse 覆盖的共享资源
    const sharedMaterials = [
      ...categoryMaterials,
      ...Object.values(statusMaterials),
      ...Object.values(statusPillarMaterials),
      ...Object.values(statusPillarGlowMaterials),
      ...Object.values(statusGlowDiscMaterials),
      ...Object.values(statusGlowMaterials),
      coreMaterial,
      spireMaterial,
      trayMaterial,
      glassMaterial,
      lineMaterial,
      particleMaterial,
      trendMat,
    ];
    for (const m of sharedMaterials) {
      if (m && typeof m.dispose === 'function') m.dispose();
    }
    const sharedTextures = [glowTex, bgTex, shadowTex];
    for (const t of sharedTextures) {
      if (t && typeof t.dispose === 'function') t.dispose();
    }
    scene.clear();

    renderer.dispose();
    if (renderer.forceContextLoss) {
      try {
        renderer.forceContextLoss();
      } catch (e) {
        /* ignore */
      }
    }
    if (canvas.parentNode) canvas.parentNode.removeChild(canvas);

    devices.clear();
    knownDevices.clear();
    chipMeshes.length = 0;
  }

  // 启动（页面隐藏时不启动 rAF，等 visibilitychange 唤醒）
  applySize();
  container.style.cursor = 'grab';
  if (!document.hidden) rafId = requestAnimationFrame(tick);

  return {
    update,
    setHighlight,
    focusDevice,
    setTopology,
    focusNode,
    resetView,
    resize: applySize,
    dispose,
    getPerf,
    warmup,
  };
}
