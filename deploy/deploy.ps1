<#
.SYNOPSIS
    观澜 NetScope · 一键构建 + 部署到 OpenWrt 旁路由

.DESCRIPTION
    流程：build.ps1 → scp dist/guanlan 到 /tmp/guanlan.new → scp install.sh 到 /tmp/install.sh
          → ssh 执行 sh /tmp/install.sh → 输出部署结果与访问地址。
    所有密码从环境变量 OWRT_PASS 读取（请先设置环境变量），也可用 -Password 传入；
    未提供口令时直接报错，不会回退到任何默认口令。
    主机密钥由 tools/owssh.py / tools/owrt.py 校验：首次连接打印指纹供人工核对并登记，
    之后严格校验（密钥不一致即中止）。

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File deploy\deploy.ps1
    powershell -ExecutionPolicy Bypass -File deploy\deploy.ps1 -SkipBuild -Password "xxx"
    powershell -ExecutionPolicy Bypass -File deploy\deploy.ps1 -DryRun
#>
[CmdletBinding()]
param(
    # 目标主机
    [string]$Host_ = $(if ($env:OWRT_HOST) { $env:OWRT_HOST } else { '192.168.1.254' }),
    [string]$User = $(if ($env:OWRT_USER) { $env:OWRT_USER } else { 'root' }),
    [string]$Password = $(if ($env:OWRT_PASS) { $env:OWRT_PASS } else { '' }),
    [int]$Port = 8088,
    # 跳过构建（直接部署已有 dist/guanlan）
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
$distBin = Join-Path $repoRoot 'dist\guanlan'
$owssh = Join-Path $repoRoot 'tools\owssh.py'
$owrt = Join-Path $repoRoot 'tools\owrt.py'

function Write-Step($m) { Write-Host "==> $m" -ForegroundColor Cyan }
function Write-Ok($m) { Write-Host "    OK  $m" -ForegroundColor Green }
function Write-Err($m) { Write-Host "    ERR $m" -ForegroundColor Red }

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
    $probe = & $pythonExe -c "import paramiko,sys;print(paramiko.__version__)" 2>&1
    if ($LASTEXITCODE -eq 0) { $useParamiko = $true; Write-Ok "使用 paramiko（$pythonExe，paramiko $probe）" }
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
#           之后严格校验，密钥不一致直接中止。
# ---------------------------------------------------------------------------
function Invoke-Remote {
    param([string]$Command, [int]$TimeoutSec = 180)
    if ($useParamiko) {
        $env:OWRT_HOST = $Host_
        $env:OWRT_USER = $User
        $env:OWRT_PASS = $Password
        $out = & $pythonExe $owrt --cmd $Command --timeout $TimeoutSec 2>&1
        $code = $LASTEXITCODE
        return [pscustomobject]@{ Code = $code; Out = ($out | Out-String) }
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
        $out = & $pythonExe $owssh --upload ("{0}:{1}" -f $Local, $Remote) 2>&1
        $code = $LASTEXITCODE
        return [pscustomobject]@{ Code = $code; Out = ($out | Out-String) }
    }
    else {
        Write-Err "无 paramiko 时不支持文件上传"
        exit 1
    }
}

# ---------------------------------------------------------------------------
# 0. 连接检查
# ---------------------------------------------------------------------------
if (-not $Password) {
    Write-Err '未提供路由器口令：请设置环境变量 OWRT_PASS 或用 -Password 传入（不会回退到任何默认口令）。'
    exit 2
}

Write-Step "检查路由器连通性（$User@$Host_）"
$probe = Invoke-Remote -Command "uname -m; echo '---'; df -h / | tail -1; echo '---'; free -m | head -2" -TimeoutSec 40
if ($probe.Code -ne 0) {
    Write-Err "SSH 连接失败："
    Write-Host $probe.Out
    exit 1
}
Write-Ok "SSH 连通"
Write-Host $probe.Out

# ---------------------------------------------------------------------------
# 1. 构建
# ---------------------------------------------------------------------------
if (-not $SkipBuild) {
    Write-Step "构建（build.ps1）"
    & $BuildScript
    if ($LASTEXITCODE -ne 0) {
        Write-Err "构建失败，中止部署"
        exit $LASTEXITCODE
    }
}
if (-not (Test-Path -LiteralPath $distBin)) {
    Write-Err "缺少构建产物：$distBin（可加 -SkipBuild 复用已有产物）"
    exit 1
}
$binSize = (Get-Item -LiteralPath $distBin).Length
$binSha = (Get-FileHash -LiteralPath $distBin -Algorithm SHA256).Hash.ToLower()
Write-Ok "产物 $distBin ($binSize bytes, sha256 $binSha)"

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
    Write-Host "诊断：查看 /mnt/mmcblk2p4/guanlan/logs/guanlan.log，或在路由器上执行 logread -e guanlan" -ForegroundColor Yellow
    exit $install.Code
}

# ---------------------------------------------------------------------------
# 4. 结果
# ---------------------------------------------------------------------------
Write-Step "部署后自检"
$after = Invoke-Remote -Command @"
echo '--- healthz ---'
curl -s -m 5 http://127.0.0.1:$Port/healthz || echo 'HEALTHZ_FAIL'
echo ''
echo '--- free -m ---'
free -m
echo '--- df -h / ---'
df -h /
echo '--- df -h /mnt/mmcblk2p4 ---'
df -h /mnt/mmcblk2p4
echo '--- ps ---'
ps w | grep guanlan | grep -v grep
"@ -TimeoutSec 60
Write-Host $after.Out

Write-Ok "部署完成"
Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host " 访问地址   : http://$($Host_):$Port" -ForegroundColor Green
Write-Host " 初始密码   : 产品默认 guanlan2026（仅首次安装时生成；若安装时设置过" -ForegroundColor Green
Write-Host "              GUANLAN_DEFAULT_PASSWORD 则以实际为准；登录后请立即修改）" -ForegroundColor Green
Write-Host " 二进制 sha : $binSha" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
exit 0
