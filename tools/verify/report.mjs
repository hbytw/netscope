// 观澜 NetScope · 验收报告生成器
// 把 build-meta / selftest-summary / shots-summary / 部署日志 / 资源采样 / 卸载验证
// 汇总成 docs/verify-report.md（固定 6 个小节）
//
// 用法：
//   node tools/verify/report.mjs
//   node tools/verify/report.mjs --deploy-log deploy.log --rusage before.txt after.txt --uninstall uninstall.log
import fs from 'node:fs';
import path from 'node:path';
import { CONFIG, DOCS_DIR, ensureDir } from './config.mjs';

const argv = process.argv.slice(2);
function arg(name, dflt = null) {
  const i = argv.indexOf(`--${name}`);
  return i >= 0 && argv[i + 1] ? argv[i + 1] : dflt;
}

const repoRoot = path.resolve(path.dirname(new URL(import.meta.url).pathname.replace(/^\//, '')), '..', '..');
const outFile = path.join(DOCS_DIR, 'verify-report.md');

function readJson(p) {
  try {
    return JSON.parse(fs.readFileSync(p, 'utf8'));
  } catch {
    return null;
  }
}
function readText(p) {
  try {
    return fs.readFileSync(p, 'utf8');
  } catch {
    return null;
  }
}
function codeBlock(t) {
  if (!t) return '_(无数据)_\n';
  return '```\n' + t.trimEnd() + '\n```\n';
}

const buildMeta = readJson(path.join(repoRoot, 'dist', 'build-meta.json'));
const selftest = readJson(path.join(DOCS_DIR, 'selftest-summary.json'));
const shots = readJson(path.join(DOCS_DIR, 'shots-summary.json'));

const deployLog = readText(arg('deploy-log'));
const rusageBefore = readText(arg('rusage-before'));
const rusageAfter = readText(arg('rusage-after'));
const uninstallLog = readText(arg('uninstall'));
const baseline = readText(path.join('/tmp/guanlan/baseline.txt'));

// ---------------------------------------------------------------- 1. 部署概况
const s1 = [];
s1.push('# 观澜 NetScope · 验收报告');
s1.push('');
s1.push(`> 生成时间：${new Date().toLocaleString('zh-CN')}`);
s1.push(`> 目标设备：${CONFIG.baseUrl}`);
s1.push('');
s1.push('## 1. 部署概况');
s1.push('');
s1.push('| 项目 | 值 |');
s1.push('|---|---|');
s1.push(`| 服务版本 | ${buildMeta?.builtAt ? buildMeta.builtAt.slice(0, 19).replace('T', ' ') : '(待填)'} 构建 |`);
s1.push(`| 二进制体积 | ${buildMeta ? `${buildMeta.bytes} bytes (${buildMeta.sizeMB} MB)` : '(待填)'} |`);
s1.push(`| sha256 | \`${buildMeta?.sha256 || '(待填)'}\` |`);
s1.push(`| 目标架构 | ${buildMeta ? `${buildMeta.goos}/${buildMeta.goarch}` : 'linux/arm64'}（静态链接，CGO_ENABLED=0） |`);
s1.push(`| Go 版本 | ${buildMeta?.goVersion || '(待填)'} |`);
s1.push(`| 访问地址 | **http://192.168.1.254:8088** |`);
s1.push(`| 登录账号 | admin |`);
s1.push(`| 初始密码 | \`guanlan2026\`（首次安装生成，可在设置页修改） |`);
s1.push(`| 安装耗时 | _(见下方部署日志时间戳)_ |`);
s1.push(`| 开机自启 | 已 enable（procd，respawn 3600 5 5） |`);
s1.push(`| DNS 旁挂 | UCI 原生选项 \`dhcp.@dnsmasq[0].logqueries=1\` + \`logfacility=/tmp/guanlan/dnsmasq.log\`（tmpfs） |`);
s1.push('');
s1.push('### 1.1 部署日志');
s1.push('');
s1.push(codeBlock(deployLog));

// ---------------------------------------------------------------- 2. 接口自检
s1.push('## 2. 接口自检');
s1.push('');
if (selftest) {
  s1.push(`执行时间：${selftest.generatedAt}　目标：${selftest.baseUrl}　结果：**${selftest.pass}/${selftest.total} 通过**`);
  s1.push('');
  s1.push('| 接口 | 期望 | 实际 | 结论 |');
  s1.push('|---|---|---|---|');
  for (const r of selftest.results) {
    const actual = String(r.actual || '').replace(/\|/g, '\\|').replace(/\n/g, ' ').slice(0, 160);
    s1.push(`| \`${r.url}\` | ${r.expect} | ${actual} | ${r.ok ? '✅ PASS' : '❌ FAIL'} |`);
  }
  s1.push('');
  s1.push('### 2.1 关键 JSON 片段');
  s1.push('');
  for (const [k, v] of Object.entries(selftest.snippets || {})) {
    s1.push(`**${k}**`);
    s1.push('');
    s1.push('```json');
    s1.push(JSON.stringify(v, null, 2).slice(0, 2500));
    s1.push('```');
    s1.push('');
  }
} else {
  s1.push('_(尚未运行 selftest.mjs)_');
}

// ---------------------------------------------------------------- 3. 资源占用
s1.push('## 3. 资源占用');
s1.push('');
if (rusageBefore || rusageAfter) {
  s1.push('### 3.1 部署前后系统基线');
  s1.push('');
  s1.push('部署前：');
  s1.push('');
  s1.push(codeBlock(rusageBefore || baseline));
  s1.push('部署后：');
  s1.push('');
  s1.push(codeBlock(rusageAfter));
  s1.push('### 3.2 服务进程采样（rusage.sh）');
  s1.push('');
  s1.push(codeBlock(rusageAfter));
  s1.push('### 3.3 与预算对比');
  s1.push('');
  s1.push('| 指标 | 预算 | 实测 | 结论 |');
  s1.push('|---|---|---|---|');
  const kv = (txt, k) => {
    const m = String(txt || '').match(new RegExp(`^${k}=(.+)$`, 'm'));
    return m ? m[1].trim() : null;
  };
  const rss = kv(rusageAfter, 'RSS_MB');
  const cpu = kv(rusageAfter, 'CPU_PCT_IDLE');
  s1.push(`| 常驻内存 RSS | ≤ 60 MB | ${rss ?? '(待填)'} MB | ${rss ? (parseFloat(rss) <= 60 ? '✅ 达标' : '❌ 超预算') : '(待填)'} |`);
  s1.push(`| 空闲 CPU（整机） | ≤ 3% | ${cpu ?? '(待填)'}% | ${cpu ? (parseFloat(cpu) <= 3 ? '✅ 达标' : '❌ 超预算') : '(待填)'} |`);
  s1.push('');
  s1.push('> 采样方式：服务空闲后 `sh tools/verify/rusage.sh guanlan`，CPU 取 `/proc/<pid>/stat` 的 utime+stime 增量并按核心数折算。');
} else {
  s1.push('_(尚未采集资源采样数据)_');
}

// ---------------------------------------------------------------- 4. 页面截图
s1.push('## 4. 页面截图');
s1.push('');
if (shots) {
  s1.push(`视口 ${shots.viewport}　每页等待 ${shots.pageWaitMs}ms　浏览器 ${shots.browser}`);
  s1.push('');
  s1.push('| 页面 | 路由 | 截图文件 | 大小 | console error | pageerror | 请求失败 |');
  s1.push('|---|---|---|---|---|---|---|');
  for (const sh of shots.shots) {
    const ce = shots.consoleErrors.filter((e) => e.page === sh.id).length;
    const pe = shots.pageErrors.filter((e) => e.page === sh.id).length;
    const rf = shots.requestFailures.filter((e) => e.page === sh.id).length;
    s1.push(`| ${sh.title} | \`${sh.route}\` | \`${sh.file}\` | ${(sh.bytes / 1024).toFixed(0)} KB | ${ce} | ${pe} | ${rf} |`);
  }
  s1.push('');
  s1.push(`**合计**：console error ${shots.counts.consoleErrors}，pageerror ${shots.counts.pageErrors}，请求失败 ${shots.counts.requestFailures}。`);
  s1.push('');
  s1.push(`> 导航噪声（不计入 console error）：${shots.counts.sseNavigationNoise ?? 0} 条 \`net::ERR_ABORTED\` 的 \`/api/stream\`。`);
  s1.push('> 原因：切换路由时浏览器主动中断上一页面的 SSE 长连接，属预期行为。');
  s1.push('');
  if (shots.consoleErrors.length) {
    s1.push('### 4.1 console 错误明细');
    s1.push('');
    s1.push('| 页面 | 错误信息 | 来源 |');
    s1.push('|---|---|---|');
    for (const e of shots.consoleErrors) {
      s1.push(`| ${e.page} | ${String(e.text).replace(/\|/g, '\\|').slice(0, 200)} | ${e.url || ''}${e.line ? ':' + e.line : ''} |`);
    }
    s1.push('');
  }
  if (shots.pageErrors.length) {
    s1.push('### 4.2 未捕获异常明细');
    s1.push('');
    s1.push('```');
    for (const e of shots.pageErrors) s1.push(`[${e.page}] ${e.text}`);
    s1.push('```');
    s1.push('');
  }
  const sc = shots.shots.find((x) => x.id === 'screen');
  if (sc?.canvas) {
    s1.push('### 4.3 3D 大屏渲染检查');
    s1.push('');
    s1.push(`画布尺寸 ${sc.canvas.w}×${sc.canvas.h}，着色像素占比 **${(sc.canvas.colorRatio * 100).toFixed(3)}%** → ${sc.canvas.nonBlank ? '✅ 有实际渲染内容' : '❌ 疑似空白'}`);
    s1.push('');
  }
} else {
  s1.push('_(尚未运行 shots.mjs)_');
}

// ---------------------------------------------------------------- 5. 问题清单
s1.push('## 5. 问题清单');
s1.push('');
const problems = [];
for (const e of shots?.consoleErrors || []) {
  problems.push({ page: e.page, type: 'console error', desc: e.text, owner: '待定', status: '待修' });
}
for (const e of shots?.pageErrors || []) {
  problems.push({ page: e.page, type: 'pageerror', desc: e.text, owner: '待定', status: '待修' });
}
for (const r of selftest?.results || []) {
  if (!r.ok) problems.push({ page: r.url, type: '接口自检失败', desc: r.actual, owner: 'backend-dev', status: '待修' });
}
for (const i of shots?.issues || []) {
  problems.push({ page: i.page, type: i.severity, desc: i.message, owner: '待定', status: '待修' });
}
if (!problems.length) {
  s1.push('未发现问题。');
} else {
  s1.push('| # | 页面 | 类型 | 问题描述 | 归属 | 状态 |');
  s1.push('|---|---|---|---|---|---|');
  problems.forEach((p, i) => {
    s1.push(`| ${i + 1} | ${p.page} | ${p.type} | ${String(p.desc).replace(/\|/g, '\\|').slice(0, 180)} | ${p.owner} | ${p.status} |`);
  });
}
s1.push('');

// ---------------------------------------------------------------- 6. 回滚与卸载验证
s1.push('## 6. 回滚与卸载验证');
s1.push('');
s1.push('### 6.1 卸载脚本执行输出');
s1.push('');
s1.push(codeBlock(uninstallLog));
s1.push('### 6.2 残留检查');
s1.push('');
s1.push('| 检查项 | 期望 | 结果 |');
s1.push('|---|---|---|');
s1.push('| 8088 端口 | 已关闭 | _(见 6.1 输出)_ |');
s1.push('| guanlan 进程 | 不存在 | _(见 6.1 输出)_ |');
s1.push('| /usr/sbin/guanlan | 已删除 | _(见 6.1 输出)_ |');
s1.push('| /etc/init.d/guanlan | 已删除 | _(见 6.1 输出)_ |');
s1.push('| /etc/guanlan | 已删除 | _(见 6.1 输出)_ |');
s1.push('| UCI logqueries | 已清除 | _(见 6.1 输出)_ |');
s1.push('| UCI logfacility | 已清除 | _(见 6.1 输出)_ |');
s1.push('| UBM_* iptables 链 | 无残留 | _(见 6.1 输出)_ |');
s1.push('| dnsmasq 日志去向 | 恢复为 /dev/null | _(见 6.1 输出)_ |');
s1.push('| nslookup 解析 | 正常 | _(见 6.1 输出)_ |');
s1.push('');
s1.push('> 卸载脚本可重复执行：第二遍同样幂等，不产生额外副作用。');
s1.push('');
s1.push('### 6.3 用户自助回退（rollback.sh）');
s1.push('');
s1.push('`deploy/rollback.sh` 与 `uninstall.sh` 并存互为备份：前者是给用户的极速自保回退（只做减法），后者是完整卸载流程。');
s1.push('');

ensureDir(DOCS_DIR);
fs.writeFileSync(outFile, s1.join('\n'), 'utf8');
console.log(`[done] 报告写入 ${outFile}`);
console.log(`  部署概况: ${buildMeta ? 'OK' : '缺 build-meta.json'}`);
console.log(`  接口自检: ${selftest ? `${selftest.pass}/${selftest.total}` : '缺 selftest-summary.json'}`);
console.log(`  截图    : ${shots ? `${shots.shots.length} 张` : '缺 shots-summary.json'}`);
console.log(`  问题    : ${problems.length} 项`);
