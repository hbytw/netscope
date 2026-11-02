<#
  观澜 NetScope · 一键验收（构建 → 部署 → 自检 → 截图 → 报告）

  用法：
      powershell -ExecutionPolicy Bypass -File deploy\run-verify.ps1
      powershell -ExecutionPolicy Bypass -File deploy\run-verify.ps1 -SkipBuild
      powershell -ExecutionPolicy Bypass -File deploy\run-verify.ps1 -SkipShots

  步骤：
      1) deploy\deploy.ps1            构建 + 部署到路由器
      2) tools\verify\selftest.mjs    接口自检（healthz/登录/各 API）
      3) tools\verify\shots.mjs       无头 Chrome 截图（可选）
      4) tools\verify\report.mjs      汇总报告写入 docs/

  依赖：Node 18+、Python + paramiko；截图需要本机 Chrome（playwright-core 用系统 Chrome）。
  主机：环境变量 OWRT_HOST（或用 -Host_ 传入）必须设置 —— 脚本不内置任何默认 IP，
        不同路由器网段不同，默认到某个地址会把验收流量打到错误设备。
  密码：环境变量 OWRT_PASS（必须设置）。
#>
[CmdletBinding()]
param(
    [string]$Host_ = $(if ($env:OWRT_HOST) { $env:OWRT_HOST } else { '' }),
    [string]$Pass = $(if ($env:OWRT_PASS) { $env:OWRT_PASS } else { '' }),
    [switch]$SkipBuild,
    [switch]$SkipShots,
    [switch]$SkipDeploy
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-Step($m) { Write-Host "==> $m" -ForegroundColor Cyan }
function Write-Ok($m) { Write-Host "    OK  $m" -ForegroundColor Green }
function Write-Err($m) { Write-Host "    ERR $m" -ForegroundColor Red }

if (-not $Host_) {
    Write-Err '未指定目标主机：请设置环境变量 OWRT_HOST，或用 -Host_ 传入。'
    Write-Host '  例：$env:OWRT_HOST = "192.168.8.4"' -ForegroundColor Yellow
    Write-Host '  例：powershell -ExecutionPolicy Bypass -File deploy\run-verify.ps1 -Host_ 192.168.8.4' -ForegroundColor Yellow
    Write-Host '本脚本不内置任何默认 IP：不同路由器网段不同。' -ForegroundColor Yellow
    exit 2
}

if (-not $Pass) {
    Write-Err '请先设置环境变量 OWRT_PASS（路由器 root 密码）。'
    exit 2
}

$env:OWRT_HOST = $Host_
$env:OWRT_PASS = $Pass

$repoRoot = Split-Path -Parent $PSScriptRoot
$verifyDir = Join-Path $repoRoot 'tools\verify'
$nodeCmd = Get-Command node -ErrorAction SilentlyContinue
if (-not $nodeCmd) {
    Write-Err '需要 Node.js（tools/verify 自检脚本）。'
    exit 1
}
$nodeExe = $nodeCmd.Source

# 1) 部署
if (-not $SkipDeploy) {
    Write-Step '1/4 部署'
    $deployArgs = @('-ExecutionPolicy', 'Bypass', '-File', (Join-Path $PSScriptRoot 'deploy.ps1'))
    if ($SkipBuild) { $deployArgs += '-SkipBuild' }
    & powershell @deployArgs
    if ($LASTEXITCODE -ne 0) { Write-Err '部署失败，终止。'; exit $LASTEXITCODE }
    Write-Ok '部署完成'
} else {
    Write-Step '1/4 部署（已跳过）'
}

# 2) 接口自检
Write-Step '2/4 接口自检'
Push-Location $verifyDir
try {
    & $nodeExe 'selftest.mjs'
    if ($LASTEXITCODE -ne 0) { Write-Err '接口自检发现失败项（详见上方输出）。' }
    else { Write-Ok '接口自检通过' }
} finally { Pop-Location }

# 3) 截图
if (-not $SkipShots) {
    Write-Step '3/4 页面截图'
    Push-Location $verifyDir
    try {
        & $nodeExe 'shots.mjs'
        if ($LASTEXITCODE -ne 0) { Write-Err '截图失败（可能未配置 Chrome 路径）。' }
        else { Write-Ok '截图完成（docs/shots-*.png）' }
    } finally { Pop-Location }
} else {
    Write-Step '3/4 页面截图（已跳过）'
}

# 4) 报告
Write-Step '4/4 生成报告'
Push-Location $verifyDir
try {
    & $nodeExe 'report.mjs'
    if ($LASTEXITCODE -eq 0) { Write-Ok '报告已生成（docs/verify-report.md）' }
} finally { Pop-Location }

Write-Host ''
Write-Host ('全部完成。访问 http://' + $Host_ + ':8088 查看系统。') -ForegroundColor Green
exit 0
