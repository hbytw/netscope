<#
.SYNOPSIS
    观澜 NetScope · 一键构建 + 部署到 OpenWrt 旁路由

.DESCRIPTION
    流程：按远端架构构建 → 上传 dist/guanlan-<架构> 到 /tmp/guanlan.new
          → 上传 install.sh 到 /tmp/install.sh → ssh 执行 sh /tmp/install.sh
          → 输出部署结果与访问地址。

    目标主机必须显式指定：环境变量 OWRT_HOST，或用 -Host_ 传入。
    脚本不内置任何默认 IP —— 不同路由器网段不同（192.168.8.0/24、192.168.1.0/24 …），
    默认到某个地址会把二进制和口令发给错误的设备。

    架构：先 SSH 执行 uname -m 探测远端（aarch64 → arm64，x86_64 → amd64），
    再选用 dist/guanlan-<架构> 并以该架构构建；探测失败时回退到默认 arm64（可用 -GoArch 强制）。
    对应产物缺失或 ELF 架构与远端不符时直接报错，绝不会上传错误架构的二进制。

    所有密码从环境变量 OWRT_PASS 读取（请先设置环境变量），也可用 -Password 传入；
    未提供口令时直接报错，不会回退到任何默认口令。
    主机密钥由 tools/owssh.py / tools/owrt.py 校验：首次连接打印指纹供人工核对并登记，
    之后严格校验（密钥不一致即中止）。新设备需要显式登记时设置 OWRT_ACCEPT_HOSTKEY=1。

.EXAMPLE
    $env:OWRT_HOST = '192.168.8.4'; $env:OWRT_PASS = '***'
    powershell -ExecutionPolicy Bypass -File deploy\deploy.ps1
    powershell -ExecutionPolicy Bypass -File deploy\deploy.ps1 -SkipBuild -Password "xxx"
    powershell -ExecutionPolicy Bypass -File deploy\deploy.ps1 -GoArch amd64
    powershell -ExecutionPolicy Bypass -File deploy\deploy.ps1 -DryRun
#>
[CmdletBinding()]
param(
    # 目标主机（必须提供：OWRT_HOST 或 -Host_；脚本不内置任何默认 IP）
    [string]$Host_ = $(if ($env:OWRT_HOST) { $env:OWRT_HOST } else { '' }),
    [string]$User = $(if ($env:OWRT_USER) { $env:OWRT_USER } else { 'root' }),
    [string]$Password = $(if ($env:OWRT_PASS) { $env:OWRT_PASS } else { '' }),
    [int]$Port = 8088,
    # 目标架构：auto = 按远端 uname -m 自动判断；arm64 / amd64 可强制指定（探测失败时的回退）
    [ValidateSet('auto', 'arm64', 'amd64')]
    [string]$GoArch = 'auto',
    # 跳过构建（直接部署已有 dist/guanlan-<架构>）
    [switch]$SkipBuild,
    # 远端临时文件名
    [string]$RemoteBin = '/tmp/guanlan.new',
    [string]$RemoteScript = '/tmp/install.sh',
    # 部署脚本（留空则用脚本同目录的 install.sh；见下方 $PSScriptRoot 解析）
    [string]$InstallScript = '',
    # 构建脚本（留空则用脚本同目录的 build.ps1）
    [string]$BuildScript = '',
    # 干跑：上传后以 GL_APPLY=0 执行 install.sh，只打印命令不真实执行
    [switch]$DryRun,
    # 用户自助回退脚本（上传到路由器，用户可随时自己执行；留空则用同目录 rollback.sh）
    [string]$RollbackScript = '',
    # 远端回退脚本位置
    [string]$RemoteRollback = '/tmp/rollback.sh'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# 注意：带 [CmdletBinding()] 的脚本在 param 默认值里取 $PSScriptRoot 会拿到空串
#       （Windows PowerShell 5.1 实测），导致 Join-Path 直接报错、脚本起不来。
#       所以路径统一在脚本体内解析。
if (-not $InstallScript) { $InstallScript = Join-Path $PSScriptRoot 'install.sh' }
if (-not $BuildScript) { $BuildScript = Join-Path $PSScriptRoot 'build.ps1' }
if (-not $RollbackScript) { $RollbackScript = Join-Path $PSScriptRoot 'rollback.sh' }

$repoRoot = Split-Path -Parent $PSScriptRoot
$distDir = Join-Path $repoRoot 'dist'
$legacyBin = Join-Path $distDir 'guanlan'
$owssh = Join-Path $repoRoot 'tools\owssh.py'
$owrt = Join-Path $repoRoot 'tools\owrt.py'

function Write-Step($m) { Write-Host "==> $m" -ForegroundColor Cyan }
function Write-Ok($m) { Write-Host "    OK  $m" -ForegroundColor Green }
function Write-Err($m) { Write-Host "    ERR $m" -ForegroundColor Red }

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
        Class   = [int]$bytes[4]
        Data    = [int]$bytes[5]
        Machine = $machine
    }
}

# 远端 uname -m → Go GOARCH（无法识别时返回 $null）
function ConvertTo-GoArch([string]$Machine) {
    if (-not $Machine) { return $null }
    switch ($Machine.Trim().ToLowerInvariant()) {
        'aarch64' { return 'arm64' }
        'arm64' { return 'arm64' }
        'x86_64' { return 'amd64' }
        'amd64' { return 'amd64' }
        default { return $null }
    }
}

# ---------------------------------------------------------------------------
# 目标主机必须显式指定：不内置默认 IP（不同路由器网段不同）
# ---------------------------------------------------------------------------
if (-not $Host_) {
    Write-Err '未指定目标主机：请设置环境变量 OWRT_HOST，或用 -Host_ 传入。'
    Write-Host '  例：$env:OWRT_HOST = "192.168.8.4"' -ForegroundColor Yellow
    Write-Host '  例：powershell -ExecutionPolicy Bypass -File deploy\deploy.ps1 -Host_ 192.168.8.4' -ForegroundColor Yellow
    Write-Host '本脚本不内置任何默认 IP：不同路由器网段不同，默认到某个地址会把二进制和口令发给错误的设备。' -ForegroundColor Yellow
    exit 2
}

# ---------------------------------------------------------------------------
# 原生命令封装：合并 stdout/stderr 文本并取真实退出码。
# Windows PowerShell 5.1 在 $ErrorActionPreference='Stop' 下会把重定向的原生 stderr
# （python 的 hostkey 指纹提示、go 的编译错误等）当成终止错误抛出堆栈；
# 这里临时切成 Continue，拿到输出与退出码后再恢复，保证失败时走友好报错分支。
# ---------------------------------------------------------------------------
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

# ---------------------------------------------------------------------------
# 工具检测：优先用 Win32 OpenSSH，其次用 python + paramiko（tools/owrt.py）
# ---------------------------------------------------------------------------
$useParamiko = $false
$pythonExe = $null
foreach ($cand in @('python', 'python3', 'py')) {
    $cmd = Get-Command $cand -ErrorAction SilentlyContinue
    if ($cmd) { $pythonExe = $cmd.Source; break }
}
if ($pythonExe) {
    $pyProbe = Invoke-NativeCapture -Exe $pythonExe -Arguments @('-c', 'import paramiko,sys;print(paramiko.__version__)')
    if ($pyProbe.Code -eq 0) {
        $useParamiko = $true
        Write-Ok ("使用 paramiko（{0}，paramiko {1}）" -f $pythonExe, $pyProbe.Out.Trim())
    }
}
if (-not $useParamiko) {
    foreach ($c in @('ssh', 'scp')) {
        if (-not (Get-Command $c -ErrorAction SilentlyContinue)) {
            Write-Err "缺少 $c 且 Python paramiko 不可用，无法部署"
            exit 1
        }
    }
    Write-Ok "使用系统 ssh/scp"
}

# ---------------------------------------------------------------------------
# 远端执行封装
#
# 口令策略：只用 $env:OWRT_PASS / -Password 传入的口令；
#           未提供就直接报错，绝不回退到任何公开的默认口令。
# 主机密钥：owssh.py / owrt.py 负责 —— 首次连接打印指纹供人工核对并登记，
#           之后严格校验，密钥不一致直接中止；新设备可用 OWRT_ACCEPT_HOSTKEY=1 显式登记。
# ---------------------------------------------------------------------------
function Invoke-Remote {
    param([string]$Command, [int]$TimeoutSec = 180)
    if ($useParamiko) {
        $env:OWRT_HOST = $Host_
        $env:OWRT_USER = $User
        $env:OWRT_PASS = $Password
        $r = Invoke-NativeCapture -Exe $pythonExe -Arguments @($owrt, '--cmd', $Command, '--timeout', [string]$TimeoutSec)
        return [pscustomobject]@{ Code = $r.Code; Out = $r.Out }
    }
    else {
        # 用 sshpass 不可用时退回交互不可行 → 明确报错
        Write-Err "当前环境缺少 paramiko，OpenSSH 需要交互式密码输入，无法自动部署。请安装 paramiko：pip install paramiko"
        exit 1
    }
}

function Send-File {
    param([string]$Local, [string]$Remote)
    if ($useParamiko) {
        $env:OWRT_HOST = $Host_
        $env:OWRT_USER = $User
        $env:OWRT_PASS = $Password
        # 走 owssh.py：--upload 用 rsplit 解析，Windows 盘符路径不会切坏；
        # 同时复用同一套主机密钥校验（不再使用 AutoAddPolicy）。
        $r = Invoke-NativeCapture -Exe $pythonExe -Arguments @($owssh, '--upload', ("{0}:{1}" -f $Local, $Remote))
        return [pscustomobject]@{ Code = $r.Code; Out = $r.Out }
    }
    else {
        Write-Err "无 paramiko 时不支持文件上传"
        exit 1
    }
}

# 远端数据目录（不假设挂载点）：读取 /etc/guanlan/config.json 的 dataDir。
# 读到合法绝对路径就返回它，否则返回空串（调用方回退到通用描述）。
function Get-RemoteDataDir {
    $r = Invoke-Remote -Command 'grep -m1 dataDir /etc/guanlan/config.json 2>/dev/null' -TimeoutSec 20
    if ($r.Code -eq 0 -and $r.Out) {
        $m = [regex]::Match($r.Out, '"dataDir"\s*:\s*"([^"]+)"')
        if ($m.Success) {
            $d = $m.Groups[1].Value
            if ($d -match '^/[A-Za-z0-9._/-]+$') { return $d }
            Write-Host ("    [WARN] 远端 dataDir 含不受支持的字符，忽略：{0}" -f $d) -ForegroundColor Yellow
        }
    }
    return ''
}

# ---------------------------------------------------------------------------
# 0. 连接检查 + 远端架构探测
# ---------------------------------------------------------------------------
if (-not $Password) {
    Write-Err '未提供路由器口令：请设置环境变量 OWRT_PASS 或用 -Password 传入（不会回退到任何默认口令）。'
    exit 2
}

Write-Step "检查路由器连通性（$User@$Host_）"
# __ARCH__ 标记用于在混有 hostkey 提示的输出里稳定取出 uname -m 那一行
$probe = Invoke-Remote -Command "echo __ARCH__; uname -m; echo '---'; df -h / | tail -1; echo '---'; free -m | head -2" -TimeoutSec 40
if ($probe.Code -ne 0) {
    Write-Err "SSH 连接失败："
    Write-Host $probe.Out
    Write-Host "如为目标新设备且已人工核对指纹，可设置 OWRT_ACCEPT_HOSTKEY=1 再重试（登记后仍严格校验）。" -ForegroundColor Yellow
    exit 1
}
Write-Ok "SSH 连通"
Write-Host $probe.Out

# 从探测输出里取远端架构（uname -m 只用于选择产物，不写死任何架构）
$remoteMachine = ''
if ($probe.Out -match '(?m)^__ARCH__[ \t]*\r?\n([^\r\n]*)') {
    $remoteMachine = $Matches[1].Trim()
}
$detectedArch = $null
if ($remoteMachine) { $detectedArch = ConvertTo-GoArch $remoteMachine }

if ($GoArch -ne 'auto') {
    $buildArch = $GoArch
    if ($detectedArch -and $detectedArch -ne $buildArch) {
        Write-Host ("    [WARN] 远端 uname -m={0}（推断 {1}），但你用 -GoArch 指定了 {2}；按 {2} 继续" -f $remoteMachine, $detectedArch, $buildArch) -ForegroundColor Yellow
    } else {
        Write-Ok "按 -GoArch 指定使用 linux/$buildArch"
    }
} elseif ($detectedArch) {
    $buildArch = $detectedArch
    Write-Ok "远端架构 $remoteMachine → linux/$buildArch"
} else {
    # 探测失败的安全回退：arm64 是产品默认目标；可用 -GoArch 覆盖
    $buildArch = 'arm64'
    Write-Host ("    [WARN] 无法识别远端架构（uname -m 输出：'{0}'），回退默认 linux/arm64；目标为 x86_64 时请加 -GoArch amd64" -f $remoteMachine) -ForegroundColor Yellow
}

# ---------------------------------------------------------------------------
# 1. 按远端架构构建
# ---------------------------------------------------------------------------
if (-not $SkipBuild) {
    Write-Step "构建（build.ps1 -GoArch $buildArch）"
    & $BuildScript -GoArch $buildArch
    if ($LASTEXITCODE -ne 0) {
        Write-Err "构建失败，中止部署"
        exit $LASTEXITCODE
    }
}

$expectedMachine = if ($buildArch -eq 'arm64') { 0xB7 } else { 0x3E }
$archBin = Join-Path $distDir ("guanlan-{0}" -f $buildArch)

# 产物选择：优先架构专属产物；兼容旧的 dist/guanlan（仅当 ELF 架构确实匹配远端）
$distBin = $null
if (Test-Path -LiteralPath $archBin) {
    $distBin = $archBin
}
elseif (Test-Path -LiteralPath $legacyBin) {
    $legacyElf = Get-ElfMachine -Path $legacyBin
    if ($null -ne $legacyElf -and $legacyElf.Machine -eq $expectedMachine) {
        $distBin = $legacyBin
        Write-Host ("    [WARN] 未找到 dist/guanlan-{0}，改用兼容产物 dist/guanlan（ELF 架构匹配 linux/{0}）" -f $buildArch) -ForegroundColor Yellow
    }
    else {
        $actual = if ($null -eq $legacyElf) { '非 ELF' } else { Get-ArchName $legacyElf.Machine }
        Write-Host ("    [WARN] 已有 dist/guanlan 架构不匹配（{0}），不能用于 linux/{1}" -f $actual, $buildArch) -ForegroundColor Yellow
    }
}

if (-not $distBin) {
    Write-Err ("缺少 linux/{0} 构建产物：dist/guanlan-{0}（远端 uname -m={1}）" -f $buildArch, $remoteMachine)
    Write-Host ("请先构建：powershell -ExecutionPolicy Bypass -File deploy\build.ps1 -GoArch {0}" -f $buildArch) -ForegroundColor Yellow
    Write-Host "也可用 -Both 一次构建 arm64 + amd64；-SkipBuild 只在对应架构产物已存在时才可用。" -ForegroundColor Yellow
    exit 1
}

# 上传前最后校验一次 ELF 架构，避免把错误架构的二进制送到路由器
$binElf = Get-ElfMachine -Path $distBin
if ($null -eq $binElf -or $binElf.Machine -ne $expectedMachine) {
    $actual = if ($null -eq $binElf) { '非 ELF' } else { Get-ArchName $binElf.Machine }
    Write-Err ("产物架构与远端不符：{0} 是 {1}，远端需要 linux/{2}（{3}）" -f $distBin, $actual, $buildArch, (Get-ArchName $expectedMachine))
    Write-Host "请重新构建对应架构的产物后再部署。" -ForegroundColor Yellow
    exit 1
}
$binSize = (Get-Item -LiteralPath $distBin).Length
$binSha = (Get-FileHash -LiteralPath $distBin -Algorithm SHA256).Hash.ToLower()
Write-Ok "产物 $distBin ($binSize bytes, sha256 $binSha, linux/$buildArch)"

# ---------------------------------------------------------------------------
# 2. 上传（二进制与安装脚本先落 /tmp，避免 overlay 写一半损坏）
# ---------------------------------------------------------------------------
Write-Step "上传到 $RemoteBin"
$put = Send-File -Local $distBin -Remote $RemoteBin
if ($put.Code -ne 0) {
    Write-Err "上传二进制失败："
    Write-Host $put.Out
    exit 1
}
Write-Ok "二进制已上传"

Write-Step "上传安装脚本到 $RemoteScript"
$put2 = Send-File -Local $InstallScript -Remote $RemoteScript
if ($put2.Code -ne 0) {
    Write-Err "上传安装脚本失败："
    Write-Host $put2.Out
    exit 1
}
Write-Ok "安装脚本已上传"

# 上传用户自助回退脚本（不影响安装，失败也不中断部署）
if (Test-Path -LiteralPath $RollbackScript) {
    Write-Step "上传回退脚本到 $RemoteRollback"
    $putRb = Send-File -Local $RollbackScript -Remote $RemoteRollback
    if ($putRb.Code -eq 0) {
        Write-Ok "回退脚本已上传（用户可执行 sh $RemoteRollback）"
    } else {
        Write-Host "    [WARN] 回退脚本上传失败（不影响安装）：$($putRb.Out)" -ForegroundColor Yellow
    }
} else {
    Write-Host "    [WARN] 未找到 $RollbackScript，跳过回退脚本上传" -ForegroundColor Yellow
}

# 远端校验上传完整性
$verify = Invoke-Remote -Command "ls -l $RemoteBin $RemoteScript; wc -c < $RemoteBin" -TimeoutSec 40
Write-Host $verify.Out

# ---------------------------------------------------------------------------
# 3. 执行安装
# ---------------------------------------------------------------------------
if ($DryRun) { Write-Step "干跑安装脚本 sh $RemoteScript (GL_APPLY=0)" }
else { Write-Step "执行安装脚本 sh $RemoteScript" }
$applyEnv = if ($DryRun) { 'GL_APPLY=0 ' } else { '' }
$install = Invoke-Remote -Command "sh -c '$applyEnv GL_ROLLBACK_SH=$RemoteRollback sh $RemoteScript $RemoteBin'" -TimeoutSec 300
Write-Host $install.Out
if ($install.Code -ne 0) {
    Write-Err "安装脚本返回非零（$($install.Code)），部署失败"
    $diagDir = Get-RemoteDataDir
    if ($diagDir) {
        Write-Host "诊断：查看 $diagDir/logs/guanlan.log，或在路由器上执行 logread -e guanlan" -ForegroundColor Yellow
    } else {
        Write-Host "诊断：查看数据目录下的 logs/guanlan.log（数据目录见 /etc/guanlan/config.json 的 dataDir；未配置时以安装脚本默认位置为准），或执行 logread -e guanlan" -ForegroundColor Yellow
    }
    exit $install.Code
}

# ---------------------------------------------------------------------------
# 4. 结果
# ---------------------------------------------------------------------------
Write-Step "部署后自检"
# 数据目录与磁盘检查也走远端探测，不假设 /mnt/mmcblk2p4 这类具体挂载点
$dataDir = Get-RemoteDataDir
$dfSection = if ($dataDir) {
    "echo '--- df -h $dataDir ---'`ndf -h '$dataDir' || df -h /"
} else {
    "echo '--- 磁盘检查：/etc/guanlan/config.json 未给出 dataDir，跳过数据目录 ---'`ndf -h /"
}
$afterScript = @"
echo '--- healthz ---'
curl -s -m 5 http://127.0.0.1:$Port/healthz || echo 'HEALTHZ_FAIL'
echo ''
echo '--- free -m ---'
free -m
$dfSection
echo '--- ps ---'
ps w | grep guanlan | grep -v grep
"@
$after = Invoke-Remote -Command $afterScript -TimeoutSec 60
Write-Host $after.Out

Write-Ok "部署完成"
Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host " 目标设备   : $User@$($Host_)（$remoteMachine）" -ForegroundColor Green
Write-Host " 目标架构   : linux/$buildArch" -ForegroundColor Green
Write-Host " 访问地址   : http://$($Host_):$Port" -ForegroundColor Green
Write-Host " 初始密码   : 产品默认 guanlan2026（仅首次安装时生成；若安装时设置过" -ForegroundColor Green
Write-Host "              GUANLAN_DEFAULT_PASSWORD 则以实际为准；登录后请立即修改）" -ForegroundColor Green
Write-Host " 二进制 sha : $binSha" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
exit 0
