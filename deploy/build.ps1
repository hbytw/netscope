<#
.SYNOPSIS
    观澜 NetScope · 交叉编译构建脚本（Windows → Linux arm64）

.DESCRIPTION
    在 app/ 目录下以 GOOS=linux GOARCH=arm64 CGO_ENABLED=0 交叉编译静态单文件二进制，
    输出到 dist/guanlan，并打印体积与 sha256 校验值。
    构建失败时给出清晰的可读错误（不打印 Go 堆栈噪声）。

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File deploy\build.ps1
    powershell -ExecutionPolicy Bypass -File deploy\build.ps1 -Verbose
#>
[CmdletBinding()]
param(
    # 输出目录（相对仓库根）
    [string]$OutputDir = 'dist',
    # Go 可执行文件
    [string]$Go = 'go',
    # 额外 ldflags
    [string]$Ldflags = '-s -w'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repoRoot = Split-Path -Parent $PSScriptRoot
$appDir = Join-Path $repoRoot 'app'
$outDir = Join-Path $repoRoot $OutputDir
$outFile = Join-Path $outDir 'guanlan'

function Write-Step($msg) { Write-Host "==> $msg" -ForegroundColor Cyan }
function Write-Ok($msg) { Write-Host "    OK  $msg" -ForegroundColor Green }
function Write-Err($msg) { Write-Host "    ERR $msg" -ForegroundColor Red }

# --- 前置检查 -----------------------------------------------------------
if (-not (Test-Path -LiteralPath $appDir)) {
    Write-Err "未找到 app 目录：$appDir"
    Write-Host "构建需要 app/main.go 等后端源码，请先确认 backend-dev 已提交代码。" -ForegroundColor Yellow
    exit 1
}

$goFiles = Get-ChildItem -LiteralPath $appDir -Filter '*.go' -File -ErrorAction SilentlyContinue
if (-not $goFiles -or $goFiles.Count -eq 0) {
    Write-Err "app 目录下没有任何 .go 源文件（$appDir）"
    Write-Host "后端源码尚未就绪，无法构建。请等待 backend-dev 完成 app/main.go 后重试。" -ForegroundColor Yellow
    exit 1
}

$mainGo = Join-Path $appDir 'main.go'
if (-not (Test-Path -LiteralPath $mainGo)) {
    Write-Err "缺少 app/main.go（包入口文件）"
    Write-Host "请确认 app/main.go 存在且属于 package main。" -ForegroundColor Yellow
    exit 1
}

Write-Step "检查 Go 工具链"
$goVersion = & $Go version 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Err "无法执行 go（$Go）。请确认已安装 Go 并加入 PATH。"
    exit 1
}
Write-Ok ($goVersion -join ' ')

# go.mod 检查（若存在则使用模块模式）
$goMod = Join-Path $appDir 'go.mod'
if (-not (Test-Path -LiteralPath $goMod)) {
    Write-Err "缺少 app/go.mod"
    Write-Host "请在 app/ 下初始化 Go module（go mod init guanlan）。" -ForegroundColor Yellow
    exit 1
}

# --- 构建 ---------------------------------------------------------------
New-Item -ItemType Directory -Force -Path $outDir | Out-Null
if (Test-Path -LiteralPath $outFile) { Remove-Item -LiteralPath $outFile -Force }

Write-Step "交叉编译 linux/arm64 (CGO_ENABLED=0, -trimpath)"
$env:GOOS = 'linux'
$env:GOARCH = 'arm64'
$env:CGO_ENABLED = '0'

$buildArgs = @(
    'build',
    '-trimpath',
    '-ldflags', $Ldflags,
    '-o', $outFile,
    '.'
)

Push-Location $appDir
try {
    $buildOutput = & $Go @buildArgs 2>&1
    $code = $LASTEXITCODE
} finally {
    Pop-Location
}

if ($code -ne 0) {
    Write-Err "go build 失败（退出码 $code）"
    Write-Host "--- go 输出 ---" -ForegroundColor Yellow
    $buildOutput | Select-Object -First 60 | ForEach-Object { Write-Host "  $_" -ForegroundColor Yellow }
    Write-Host "--- 提示 ---" -ForegroundColor Yellow
    Write-Host "常见原因：源码语法错误、缺少依赖包（go mod tidy）、或 import 路径不对应 module 名。" -ForegroundColor Yellow
    Write-Host "请把上面的错误转给 backend-dev 修复后再重试。" -ForegroundColor Yellow
    exit $code
}

if (-not (Test-Path -LiteralPath $outFile)) {
    Write-Err "构建命令返回成功，但未生成产物：$outFile"
    exit 1
}

# --- 产物信息 -----------------------------------------------------------
$size = (Get-Item -LiteralPath $outFile).Length
$sha = (Get-FileHash -LiteralPath $outFile -Algorithm SHA256).Hash.ToLower()
$sizeMB = [math]::Round($size / 1MB, 2)

Write-Step "构建产物"
Write-Host "    路径   : $outFile"
Write-Host "    大小   : $size bytes ($sizeMB MB)"
Write-Host "    sha256 : $sha"

# 架构校验：确保确实是 linux/arm64 ELF
$head = [System.IO.File]::ReadAllBytes($outFile)[0..19]
$isElf = ($head[0] -eq 0x7F -and $head[1] -eq 0x45 -and $head[2] -eq 0x4C -and $head[3] -eq 0x46)
if ($isElf) {
    $machine = [BitConverter]::ToUInt16($head, 18)
    $archName = switch ($machine) { 0xB7 { 'aarch64 (ARM64)' } 0x3E { 'x86-64' } 0x28 { 'ARM32' } default { "unknown(0x$('{0:x}' -f $machine))" } }
    Write-Host "    格式   : ELF / $archName / static" -ForegroundColor DarkGray
    if ($machine -ne 0xB7) {
        Write-Err "产物架构不是 aarch64（实际 $archName），不能部署到目标路由器"
        exit 1
    }
} else {
    Write-Err "产物不是有效的 ELF 文件"
    exit 1
}

# 输出机器可读信息，便于 deploy.ps1 复用
$meta = [ordered]@{
    file       = $outFile
    relative   = $outFile.Substring($repoRoot.Length).TrimStart('\', '/') -replace '\\', '/'
    bytes      = $size
    sizeMB     = $sizeMB
    sha256     = $sha
    goos       = 'linux'
    goarch     = 'arm64'
    builtAt    = (Get-Date).ToString('o')
    goVersion  = ($goVersion -join ' ')
}
$meta | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $outDir 'build-meta.json') -Encoding UTF8
Write-Ok "元数据写入 dist/build-meta.json"

Write-Step "构建完成"
exit 0
