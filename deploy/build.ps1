<#
.SYNOPSIS
    观澜 NetScope · 交叉编译构建脚本（Windows → Linux arm64 / amd64）

.DESCRIPTION
    在 app/ 目录下以 GOOS=linux、CGO_ENABLED=0 交叉编译静态单文件二进制。
    目标架构由 -GoArch 决定（默认 arm64，可选 amd64），-Both 可一次构建两种架构。
    不再假设目标一定是 aarch64：ELF machine 校验按所选架构的期望值进行。

    产物：
      dist/guanlan-arm64   aarch64 路由器（ELF machine 0xB7）
      dist/guanlan-amd64   x86_64 路由器（ELF machine 0x3E）
      dist/guanlan         兼容旧脚本的默认架构别名（通常为 arm64；只构建 amd64 时指向 amd64）
    并打印体积与 sha256 校验值。构建失败时给出清晰的可读错误（不打印 Go 堆栈噪声）。

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File deploy\build.ps1
    powershell -ExecutionPolicy Bypass -File deploy\build.ps1 -GoArch amd64
    powershell -ExecutionPolicy Bypass -File deploy\build.ps1 -Both
    powershell -ExecutionPolicy Bypass -File deploy\build.ps1 -Verbose
#>
[CmdletBinding()]
param(
    # 输出目录（相对仓库根）
    [string]$OutputDir = 'dist',
    # Go 可执行文件
    [string]$Go = 'go',
    # 额外 ldflags
    [string]$Ldflags = '-s -w',
    # 目标架构：arm64 = aarch64 路由器（默认）；amd64 = x86_64 路由器
    [ValidateSet('arm64', 'amd64')]
    [string]$GoArch = 'arm64',
    # 一次构建两种架构；默认别名 dist/guanlan 指向 arm64
    [switch]$Both
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repoRoot = Split-Path -Parent $PSScriptRoot
$appDir = Join-Path $repoRoot 'app'
$outDir = Join-Path $repoRoot $OutputDir
$aliasFile = Join-Path $outDir 'guanlan'

# ELF machine 与人类可读名称（按架构校验，不再写死 0xB7）
$ArchMachine = @{ arm64 = 0xB7; amd64 = 0x3E }
$ArchLabel = @{ arm64 = 'aarch64 (ARM64)'; amd64 = 'x86-64 (AMD64)' }

# 版本号单一来源：app/version.txt（编译期注入二进制）
$versionFile = Join-Path $appDir 'version.txt'
$appVersion = '1.0.0'
if (Test-Path -LiteralPath $versionFile) {
    $v = (Get-Content -LiteralPath $versionFile -Raw).Trim()
    if ($v) { $appVersion = $v }
}
if ($Ldflags -notmatch 'buildVersion') {
    $Ldflags = "$Ldflags -X main.buildVersion=$appVersion"
}

function Write-Step($msg) { Write-Host "==> $msg" -ForegroundColor Cyan }
function Write-Ok($msg) { Write-Host "    OK  $msg" -ForegroundColor Green }
function Write-Err($msg) { Write-Host "    ERR $msg" -ForegroundColor Red }

# 原生命令封装：合并 stdout/stderr 并取真实退出码。
# Windows PowerShell 5.1 在 $ErrorActionPreference='Stop' 下会把重定向的原生 stderr
# （go 的编译错误等）当成终止错误抛出堆栈，这里临时切成 Continue 再恢复，
# 保证构建失败时走下面清晰的可读错误分支。
function Invoke-NativeCapture {
    param([string]$Exe, [string[]]$Arguments)
    $prev = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $out = & $Exe @Arguments 2>&1
        $code = $LASTEXITCODE
        # 逐条转字符串再拼接：Out-String 会把 NativeCommandError 的报错位置也写进来
        $text = ($out | ForEach-Object { [string]$_ }) -join [Environment]::NewLine
        return [pscustomobject]@{ Code = $code; Out = $text }
    } finally {
        $ErrorActionPreference = $prev
    }
}

function Get-ArchName([int]$Machine) {
    switch ($Machine) {
        0xB7 { return 'aarch64 (ARM64)' }
        0x3E { return 'x86-64 (AMD64)' }
        0x28 { return 'ARM32' }
        0x08 { return 'MIPS' }
        default { return ("unknown(0x{0:x})" -f $Machine) }
    }
}

# 读取 ELF 头（返回 $null 表示不是 ELF；Machine 按小端解析）
function Get-ElfMachine {
    param([string]$Path)
    $bytes = [System.IO.File]::ReadAllBytes($Path)
    if ($bytes.Length -lt 20) { return $null }
    if (-not ($bytes[0] -eq 0x7F -and $bytes[1] -eq 0x45 -and $bytes[2] -eq 0x4C -and $bytes[3] -eq 0x46)) {
        return $null
    }
    $machine = ([int]$bytes[18]) -bor (([int]$bytes[19]) -shl 8)
    return [pscustomobject]@{
        Class   = [int]$bytes[4]   # 2 = ELF64
        Data    = [int]$bytes[5]   # 1 = 小端
        Machine = $machine
    }
}

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
try {
    $goProbe = Invoke-NativeCapture -Exe $Go -Arguments @('version')
}
catch {
    Write-Err "无法执行 go（$Go）：$($_.Exception.Message)"
    Write-Host "请确认已安装 Go 并加入 PATH，或用 -Go 指定 go.exe 的完整路径。" -ForegroundColor Yellow
    exit 1
}
if ($goProbe.Code -ne 0) {
    Write-Err "无法执行 go（$Go）。请确认已安装 Go 并加入 PATH。"
    exit 1
}
$goVersion = $goProbe.Out.Trim()
Write-Ok $goVersion

# go.mod 检查（若存在则使用模块模式）
$goMod = Join-Path $appDir 'go.mod'
if (-not (Test-Path -LiteralPath $goMod)) {
    Write-Err "缺少 app/go.mod"
    Write-Host "请在 app/ 下初始化 Go module（go mod init guanlan）。" -ForegroundColor Yellow
    exit 1
}

# --- 构建 ---------------------------------------------------------------
New-Item -ItemType Directory -Force -Path $outDir | Out-Null

# 注意：if 表达式返回单元素数组时 PowerShell 会把它展开成标量，
# 所以必须显式用 @() 收集，否则 -GoArch 单选时 $archs 会变成字符串。
$archs = @()
if ($Both) { $archs = @('arm64', 'amd64') } else { $archs = @($GoArch) }
# 默认架构（dist/guanlan 别名指向它）：能构建 arm64 时用 arm64，否则用单一架构
$primaryArch = if ($archs -contains 'arm64') { 'arm64' } else { $archs[0] }

# 保存并在结束时恢复调用方的 Go 环境，避免污染后续命令
$savedGoos = $env:GOOS
$savedGoarch = $env:GOARCH
$savedCgo = $env:CGO_ENABLED

$artifacts = @()
try {
    foreach ($arch in $archs) {
        $outFile = Join-Path $outDir ("guanlan-{0}" -f $arch)
        if (Test-Path -LiteralPath $outFile) { Remove-Item -LiteralPath $outFile -Force }

        Write-Step "交叉编译 linux/$arch (CGO_ENABLED=0, -trimpath)"
        $env:GOOS = 'linux'
        $env:GOARCH = $arch
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
            $buildResult = Invoke-NativeCapture -Exe $Go -Arguments $buildArgs
        } finally {
            Pop-Location
        }
        $code = $buildResult.Code
        $buildOutput = $buildResult.Out

        if ($code -ne 0) {
            Write-Err "go build 失败（linux/$arch，退出码 $code）"
            Write-Host "--- go 输出 ---" -ForegroundColor Yellow
            ($buildOutput -split "`r?`n") | Select-Object -First 60 | ForEach-Object { Write-Host "  $_" -ForegroundColor Yellow }
            Write-Host "--- 提示 ---" -ForegroundColor Yellow
            Write-Host "常见原因：源码语法错误、缺少依赖包（go mod tidy）、或 import 路径不对应 module 名。" -ForegroundColor Yellow
            Write-Host "请把上面的错误转给 backend-dev 修复后再重试。" -ForegroundColor Yellow
            exit $code
        }

        if (-not (Test-Path -LiteralPath $outFile)) {
            Write-Err "构建命令返回成功，但未生成产物：$outFile"
            exit 1
        }

        # 架构校验：按目标架构比对 ELF machine（arm64 → 0xB7，amd64 → 0x3E）
        $elf = Get-ElfMachine -Path $outFile
        if ($null -eq $elf) {
            Write-Err "产物不是有效的 ELF 文件：$outFile"
            exit 1
        }
        if ($elf.Class -ne 2) {
            Write-Err "产物不是 64 位 ELF（class=$($elf.Class)）：$outFile"
            exit 1
        }
        $wantMachine = [int]$ArchMachine[$arch]
        if ($elf.Machine -ne $wantMachine) {
            Write-Err ("产物架构与目标架构 {0} 不符（期望 0x{1:x} / {2}，实际 0x{3:x} / {4}）：{5}" -f `
                    $arch, $wantMachine, $ArchLabel[$arch], $elf.Machine, (Get-ArchName $elf.Machine), $outFile)
            Write-Host "请检查 GOARCH 与 Go 工具链；不要把这个产物部署到目标路由器。" -ForegroundColor Yellow
            exit 1
        }

        $size = (Get-Item -LiteralPath $outFile).Length
        $sha = (Get-FileHash -LiteralPath $outFile -Algorithm SHA256).Hash.ToLower()
        $sizeMB = [math]::Round($size / 1MB, 2)
        $relative = $outFile.Substring($repoRoot.Length).TrimStart('\', '/') -replace '\\', '/'

        Write-Ok ("{0}  {1} bytes ({2} MB)" -f $relative, $size, $sizeMB)
        Write-Host ("    格式   : ELF / {0} / static" -f $ArchLabel[$arch]) -ForegroundColor DarkGray
        Write-Host ("    sha256 : {0}" -f $sha) -ForegroundColor DarkGray

        $artifacts += [pscustomobject]@{
            Arch     = $arch
            File     = $outFile
            Relative = $relative
            Bytes    = $size
            SizeMB   = $sizeMB
            Sha256   = $sha
            Machine  = ('0x{0:x}' -f $elf.Machine)
        }
    }

    # 兼容旧脚本：<输出目录>/guanlan 始终指向默认架构的产物（这里是副本）
    $primary = $artifacts | Where-Object { $_.Arch -eq $primaryArch } | Select-Object -First 1
    Copy-Item -LiteralPath $primary.File -Destination $aliasFile -Force
    $aliasRelative = $aliasFile.Substring($repoRoot.Length).TrimStart('\', '/') -replace '\\', '/'
    Write-Step "默认架构别名"
    Write-Host ("    {0} -> linux/{1}（{2} 的副本，兼容旧脚本）" -f $aliasRelative, $primaryArch, $primary.Relative) -ForegroundColor DarkGray

    # --- 产物信息 -------------------------------------------------------
    Write-Step "构建产物"
    foreach ($a in $artifacts) {
        Write-Host ("    linux/{0} : {1}" -f $a.Arch, $a.Relative)
    }
    Write-Host ("    路径   : {0}" -f $aliasFile)
    Write-Host ("    大小   : {0} bytes ({1} MB)" -f $primary.Bytes, $primary.SizeMB)
    Write-Host ("    sha256 : {0}" -f $primary.Sha256)

    # 输出机器可读信息，便于 deploy.ps1 复用（顶层字段 = 默认架构，保持旧字段兼容）
    $meta = [ordered]@{
        file      = $primary.File
        relative  = $primary.Relative
        bytes     = $primary.Bytes
        sizeMB    = $primary.SizeMB
        sha256    = $primary.Sha256
        goos      = 'linux'
        goarch    = $primaryArch
        alias     = $aliasRelative
        builtAt   = (Get-Date).ToString('o')
        goVersion = ($goVersion -join ' ')
        artifacts = @($artifacts | ForEach-Object {
                [ordered]@{
                    arch     = $_.Arch
                    file     = $_.File
                    relative = $_.Relative
                    bytes    = $_.Bytes
                    sizeMB   = $_.SizeMB
                    sha256   = $_.Sha256
                    machine  = $_.Machine
                }
            })
    }
    $metaFile = Join-Path $outDir 'build-meta.json'
    $meta | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $metaFile -Encoding UTF8
    $metaRelative = $metaFile.Substring($repoRoot.Length).TrimStart('\', '/') -replace '\\', '/'
    Write-Ok "元数据写入 $metaRelative（默认架构 linux/$primaryArch）"

    Write-Step "构建完成"
}
finally {
    # 恢复调用方环境（脚本自身退出码不受影响）
    foreach ($pair in @(@('GOOS', $savedGoos), @('GOARCH', $savedGoarch), @('CGO_ENABLED', $savedCgo))) {
        $name = $pair[0]
        $old = $pair[1]
        if ($null -eq $old) {
            Remove-Item -LiteralPath ("Env:{0}" -f $name) -ErrorAction SilentlyContinue
        } else {
            Set-Item -LiteralPath ("Env:{0}" -f $name) -Value $old
        }
    }
}

exit 0
