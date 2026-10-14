#Requires -Version 5.1
<#
.SYNOPSIS
  把 dsh-windows-acl-preflight 装进（或从）一个 DSH profile。

.DESCRIPTION
  安装做两件事，都幂等：
    1) 把本包源码目录复制到 <profile>\node_modules\dsh-windows-acl-preflight
       （加 -Link 则改为建目录 junction，改源码即时生效）
    2) 在 <profile>\cordis.patch.yml 末尾追加一条 insert 挂载记录（改前自动备份）

  卸载（-Uninstall）只撤销上面这两处：删掉我们自己的包目录与那一条记录，
  同样先备份 cordis.patch.yml。

  -DryRun 只打印将要发生的改动，不写任何文件。

.EXAMPLE
  & '<本包所在目录>\install.ps1' -DryRun
  & '<本包所在目录>\install.ps1'
  & '<本包所在目录>\install.ps1' -Uninstall
#>
[CmdletBinding()]
param(
  # DSH profile 目录；省略时用 $env:DSH_HOME\profiles\desktop，
  # 再退回"本包位于 <DSH_HOME>\plugins\<包名>"这一约定反推。
  [string]$ProfileDir,
  # 建 junction 而不是复制（便于调试本包）。
  [switch]$Link,
  # 撤销安装。
  [switch]$Uninstall,
  # 只打印计划。
  [switch]$DryRun
)

$ErrorActionPreference = 'Stop'
$packageName = 'dsh-windows-acl-preflight'
$entryId = 'windows-acl-preflight'
$sourceDir = $PSScriptRoot

$block = @"
- insert:
    - id: $entryId
      name: $packageName
"@

function Resolve-ProfileDir {
  param([string]$Given)
  if ($Given) {
    if (-not (Test-Path -LiteralPath $Given)) { throw "profile 目录不存在: $Given" }
    return (Resolve-Path -LiteralPath $Given).Path
  }
  if ($env:DSH_HOME) {
    $candidate = Join-Path $env:DSH_HOME 'profiles\desktop'
    if (Test-Path -LiteralPath $candidate) { return (Resolve-Path -LiteralPath $candidate).Path }
  }
  $derived = Join-Path (Split-Path -Parent (Split-Path -Parent $sourceDir)) 'profiles\desktop'
  if (Test-Path -LiteralPath $derived) { return (Resolve-Path -LiteralPath $derived).Path }
  throw "找不到 profile 目录，请用 -ProfileDir 指定（例如 <DSH_HOME>\profiles\desktop）"
}

function Test-Ours {
  param([string]$Dir)
  $manifest = Join-Path $Dir 'package.json'
  if (-not (Test-Path -LiteralPath $manifest)) { return $false }
  try {
    return ((Get-Content -LiteralPath $manifest -Raw | ConvertFrom-Json).name -eq $packageName)
  } catch {
    return $false
  }
}

function Backup-Patch {
  param([string]$Path)
  $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
  $backup = "$Path.bak-acl-preflight-$stamp"
  Copy-Item -LiteralPath $Path -Destination $backup -Force
  return $backup
}

# Write UTF-8 WITHOUT a BOM on both Windows PowerShell 5.1 and PowerShell 7+.
function Write-Text {
  param([string]$Path, [string]$Text)
  if ($PSVersionTable.PSVersion.Major -ge 7) {
    Set-Content -LiteralPath $Path -Value $Text -NoNewline -Encoding utf8NoBOM
  } else {
    [System.IO.File]::WriteAllText($Path, $Text, (New-Object System.Text.UTF8Encoding($false)))
  }
}

$profile = Resolve-ProfileDir -Given $ProfileDir
$patchPath = Join-Path $profile 'cordis.patch.yml'
if (-not (Test-Path -LiteralPath $patchPath)) { throw "不是 DSH profile（缺少 cordis.patch.yml）: $profile" }
$targetDir = Join-Path $profile "node_modules\$packageName"
$patchText = Get-Content -LiteralPath $patchPath -Raw
$mounted = $patchText -match [regex]::Escape("id: $entryId")
$installed = Test-Path -LiteralPath $targetDir

"profile:   $profile"
"package:   $sourceDir"
"目标目录:  $targetDir  (已存在: $installed)"
"挂载记录:  $patchPath  (已含 id: $($entryId): $mounted)"

if ($DryRun) {
  "`n--- DryRun：以下改动不会被执行 ---"
  if ($Uninstall) {
    if ($installed) { "删除目录: $targetDir" }
    if ($mounted) { "从 $patchPath 移除 id: $entryId 那一段（改前备份）" }
    if (-not $installed -and -not $mounted) { "无需改动。" }
  } else {
    if ($installed) { "删除并重建目录: $targetDir" } else { "创建目录: $targetDir" }
    "追加到 $patchPath（改前备份）:"
    $block -split "`n" | ForEach-Object { "    $_" }
  }
  "`n持久化路线（由 DSH 插件管理器写入依赖与锁文件，pnpm 不会清理）："
  "    plugin_manager install_bundle target='file:$sourceDir'"
  return
}

if ($Uninstall) {
  $changed = @()
  if ($installed) {
    if (Test-Ours -Dir $targetDir) {
      Remove-Item -LiteralPath $targetDir -Recurse -Force
      $changed += "已删除 $targetDir"
    } else {
      Write-Warning "$targetDir 不是 $packageName（package.json 名字不匹配），拒绝删除。"
    }
  }
  if ($mounted) {
    $backup = Backup-Patch -Path $patchPath
    $pattern = "(?ms)^\s*- insert:\s*\r?\n\s*- id: $([regex]::Escape($entryId))\s*\r?\n\s*name: $([regex]::Escape($packageName))\s*\r?\n?"
    $updated = [regex]::Replace($patchText, $pattern, '')
    if ($updated -eq $patchText) { $updated = $patchText -replace [regex]::Escape($block), '' }
    Write-Text -Path $patchPath -Text $updated
    $changed += "已更新 $patchPath（备份: $backup）"
  }
  if ($changed.Count -eq 0) { "无需改动。" } else { $changed | ForEach-Object { $_ }; "`n重启 DSH 后生效。" }
  return
}

# --- 安装 ---
if ($installed -and -not (Test-Ours -Dir $targetDir)) {
  throw "$targetDir 已存在且不是 $packageName，请先自行确认后再安装。"
}

if ($installed) {
  Remove-Item -LiteralPath $targetDir -Recurse -Force
}
if ($Link) {
  New-Item -ItemType Junction -Path $targetDir -Target $sourceDir | Out-Null
  "已创建 junction: $targetDir -> $sourceDir"
} else {
  New-Item -ItemType Directory -Force -Path $targetDir | Out-Null
  Get-ChildItem -LiteralPath $sourceDir -Force |
    Where-Object { $_.Name -notin @('node_modules', '.git') } |
    ForEach-Object { Copy-Item -LiteralPath $_.FullName -Destination $targetDir -Recurse -Force }
  "已复制到: $targetDir"
}

if ($mounted) {
  "挂载记录已存在，保持不变。"
} else {
  $backup = Backup-Patch -Path $patchPath
  if (-not $patchText.EndsWith("`n")) { $patchText += "`n" }
  if ($patchText.Trim() -in @('', '[]', '---')) { $patchText = '' }
  Write-Text -Path $patchPath -Text ($patchText + $block + "`n")
  "已追加挂载记录到: $patchPath（备份: $backup）"
}

"`n完成。重启 DSH 后生效。"
"验证方式：新开一个工作区，在 workspace-write 策略下执行一条 pwsh 命令；"
"日志里应出现 [dsh-windows-acl-preflight] granted Full control on <目录> (session/created)，"
"以及 [dsh-windows-acl-preflight] propagated workspace permissions to <n> object(s) in <目录>。"
"卸载：& '$sourceDir\install.ps1' -Uninstall"
