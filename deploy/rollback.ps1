<#
  观澜 NetScope · Windows 侧一键回退（用户自保工具）

  用法（在任意 PowerShell 中）：
      .\deploy\rollback.ps1                # 标准回退，保留数据
      .\deploy\rollback.ps1 -Purge         # 连数据目录一并删除
      .\deploy\rollback.ps1 -DryRun        # 只打印将要执行的动作，不真正执行

  本脚本通过 SSH 把 deploy/rollback.sh 传到路由器 /tmp 再执行。
  路由器密码取环境变量 OWRT_PASS（必须设置），也可用 -Pass 传入。

  设计原则：任何时候都能自己跑，把路由器恢复到未安装本项目的状态。
#>
[CmdletBinding()]
param(
    [string]$Host_ = $(if ($env:OWRT_HOST) { $env:OWRT_HOST } else { '192.168.1.254' }),
    [string]$User = $(if ($env:OWRT_USER) { $env:OWRT_USER } else { 'root' }),
    [string]$Pass = $(if ($env:OWRT_PASS) { $env:OWRT_PASS } else { '' }),
    [switch]$Purge,
    [switch]$DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-Step($m) { Write-Host "==> $m" -ForegroundColor Cyan }
function Write-Ok($m) { Write-Host "    OK  $m" -ForegroundColor Green }
function Write-Err($m) { Write-Host "    ERR $m" -ForegroundColor Red }

if (-not $Pass) {
    Write-Err '请先设置环境变量 OWRT_PASS（路由器 root 密码），或用 -Pass 传入。'
    exit 2
}

$localSh = Join-Path $PSScriptRoot 'rollback.sh'
if (-not (Test-Path -LiteralPath $localSh)) {
    Write-Err "找不到回退脚本：$localSh"
    exit 1
}

$pythonExe = $null
foreach ($cand in @('python', 'python3', 'py')) {
    $cmd = Get-Command $cand -ErrorAction SilentlyContinue
    if ($cmd) { $pythonExe = $cmd.Source; break }
}
if (-not $pythonExe) {
    Write-Err '需要 Python（paramiko）才能通过 SSH 执行回退。'
    exit 1
}

$env:OWRT_HOST = $Host_
$env:OWRT_USER = $User
$env:OWRT_PASS = $Pass

$owssh = Join-Path (Split-Path -Parent $PSScriptRoot) 'tools\owssh.py'
if (-not (Test-Path -LiteralPath $owssh)) {
    Write-Err "找不到 tools/owssh.py：$owssh"
    exit 1
}

$remoteArgs = if ($Purge) { '--purge' } else { '' }
$remoteCmd = "sh /tmp/rollback.sh $remoteArgs".Trim()

if ($DryRun) {
    Write-Step 'DRY-RUN：以下命令不会真正执行'
    Write-Host ("    upload {0} -> {1}:/tmp/rollback.sh" -f $localSh, $Host_)
    Write-Host ("    ssh {0}@***:{1} 执行: {2}" -f $Host_, $Host_, $remoteCmd)
    exit 0
}

Write-Step ("回退目标 {0}@{1}" -f $User, $Host_)
$out = & $pythonExe $owssh --upload "${localSh}:/tmp/rollback.sh" -c $remoteCmd 2>&1
$code = $LASTEXITCODE
$out | ForEach-Object { Write-Host $_ }

if ($code -eq 0) {
    Write-Ok ('回退完成。可访问 http://' + $Host_ + ' 确认路由器恢复正常。')
} else {
    Write-Err ("回退失败（exit {0}）。路由器上也可手动执行：sh /tmp/rollback.sh" -f $code)
}
exit $code
