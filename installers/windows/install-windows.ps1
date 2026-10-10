$ErrorActionPreference = 'Stop'
$Root = 'C:\NC'
$TaskName = 'NC Client'
$Src = if ($env:NC_SRC) { (Resolve-Path $env:NC_SRC).Path } else { (Resolve-Path (Join-Path $PSScriptRoot '..')).Path }
$Stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw 'Administrator privileges required'
}
$Node = (Get-Command node.exe -ErrorAction SilentlyContinue).Source
if (-not $Node) { throw 'Node.js 22+ required' }
$Major = [int](& $Node -p "process.versions.node.split('.')[0]")
if ($Major -lt 22) { throw 'Node.js 22+ required' }
$Dirs = @('app','config','data','logs','releases','backups','tmp')
$Supervisor = Join-Path $Root 'nc-supervisor.ps1'
foreach ($d in $Dirs) { New-Item -ItemType Directory -Force -Path (Join-Path $Root $d) | Out-Null }
$Runtime = @('launcher.mjs','singleton.mjs','gui-launch.mjs','browser-adapter.mjs','browser-manager.mjs','browser-jobs.mjs','browser-runtime.mjs','egress-policy.mjs','client.mjs','ws-client.mjs','structured-ops.mjs','mutation-ops.mjs','process-sessions.mjs','service-ops.mjs','log-ops.mjs','shell.mjs','host-policy.mjs','device-proof.mjs','lifecycle.mjs','updater.mjs','nc-paths.mjs','privileged-helper-contract.mjs','privileged-helper-core.mjs','privileged-helper-ipc.mjs','linux-peer-credentials.mjs','privileged-helper-linux-daemon.mjs','privileged-helper-linux-operations.mjs','privileged-helper-bootstrap.mjs','privileged-helper-client.mjs','privileged-helper-linux-readiness.mjs','package.json')
$New = Join-Path $Root "tmp\app-new-$Stamp"
New-Item -ItemType Directory -Force -Path $New | Out-Null
foreach ($f in $Runtime) {
  $from = Join-Path $Src $f
  if (-not (Test-Path -LiteralPath $from -PathType Leaf)) { throw "Missing runtime file: $f" }
  Copy-Item -LiteralPath $from -Destination (Join-Path $New $f) -Force
}
& $Node --check (Join-Path $New 'launcher.mjs')
& $Node --check (Join-Path $New 'client.mjs')
& $Node --check (Join-Path $New 'updater.mjs')
$App = Join-Path $Root 'app'
# Stop only the NC scheduled task/process before replacing the live app tree.
Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
$Deadline = (Get-Date).AddSeconds(10)
do {
  $NcProcesses = @(Get-CimInstance Win32_Process -Filter "Name='node.exe'" -ErrorAction SilentlyContinue | Where-Object {
    $_.CommandLine -like '*C:\NC\app\launcher.mjs*' -or
    $_.CommandLine -like '*C:\NC\tmp\watchdog-*.mjs*'
  })
  if ($NcProcesses.Count -eq 0) { break }
  foreach ($proc in $NcProcesses) { Stop-Process -Id $proc.ProcessId -Force -ErrorAction SilentlyContinue }
  Start-Sleep -Milliseconds 250
} while ((Get-Date) -lt $Deadline)
$NcProcesses = @(Get-CimInstance Win32_Process -Filter "Name='node.exe'" -ErrorAction SilentlyContinue | Where-Object {
  $_.CommandLine -like '*C:\NC\app\launcher.mjs*' -or
  $_.CommandLine -like '*C:\NC\tmp\watchdog-*.mjs*'
})
if ($NcProcesses.Count -gt 0) { throw 'Unable to stop NC runtime/update helper processes' }
Remove-Item -LiteralPath (Join-Path $Root 'data\client.lock') -Force -ErrorAction SilentlyContinue
$MigrationBackup = Join-Path $Root "backups\migration-app-$Stamp"
New-Item -ItemType Directory -Force -Path $MigrationBackup | Out-Null
try {
  foreach ($item in @(Get-ChildItem -LiteralPath $App -Force -ErrorAction SilentlyContinue)) {
    Move-Item -LiteralPath $item.FullName -Destination $MigrationBackup -Force
  }
  foreach ($item in @(Get-ChildItem -LiteralPath $New -Force)) {
    Move-Item -LiteralPath $item.FullName -Destination $App -Force
  }
} catch {
  foreach ($item in @(Get-ChildItem -LiteralPath $App -Force -ErrorAction SilentlyContinue)) { Remove-Item -LiteralPath $item.FullName -Recurse -Force -ErrorAction SilentlyContinue }
  foreach ($item in @(Get-ChildItem -LiteralPath $MigrationBackup -Force -ErrorAction SilentlyContinue)) { Move-Item -LiteralPath $item.FullName -Destination $App -Force -ErrorAction SilentlyContinue }
  throw
}
Remove-Item -LiteralPath $New -Recurse -Force -ErrorAction SilentlyContinue
$EnvDst = Join-Path $Root 'config\nc-client.env'
$Candidates = @(
  $EnvDst,
  (Join-Path $Src 'client.env'),
  'C:\nc\client.env',
  'C:\Program Files\NC\client.env',
  'C:\ProgramData\NC\client.env'
)
$EnvSrc = $Candidates | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
if ($EnvSrc -and ($EnvSrc -ne $EnvDst)) {
  $Drop = '^(NC_ROOT|NC_AUDIT_FILE|NC_SERVER_LOG_FILE|NC_TUNNEL_LOG_FILE|NC_STATE_FILE|NC_CLIENT_LOG|NC_LOCAL_AUDIT_FILE)='
  Get-Content -LiteralPath $EnvSrc | Where-Object { $_ -notmatch $Drop } | Set-Content -LiteralPath $EnvDst -Encoding utf8
} elseif (-not (Test-Path -LiteralPath $EnvDst)) {
  New-Item -ItemType File -Path $EnvDst | Out-Null
}
function Copy-LegacyOne([string]$Destination, [string[]]$Sources) {
  if (Test-Path -LiteralPath $Destination) { return }
  foreach ($source in $Sources) {
    if (Test-Path -LiteralPath $source -PathType Leaf) { Copy-Item -LiteralPath $source -Destination $Destination; return }
  }
}
Copy-LegacyOne (Join-Path $Root 'data\client-state.json') @((Join-Path $Src 'state.json'),'C:\nc\state.json','C:\Program Files\NC\state.json','C:\ProgramData\NC\state.json')
Copy-LegacyOne (Join-Path $Root 'logs\client.log') @((Join-Path $Src 'client.log'),'C:\nc\client.log','C:\Program Files\NC\client.log','C:\ProgramData\NC\client.log')
Copy-LegacyOne (Join-Path $Root 'logs\audit.jsonl') @((Join-Path $Src 'audit.jsonl'),'C:\nc\audit.jsonl','C:\Program Files\NC\audit.jsonl','C:\ProgramData\NC\audit.jsonl')
& icacls.exe $Root /inheritance:r | Out-Null
& icacls.exe $Root /grant:r 'SYSTEM:(OI)(CI)(F)' 'Administrators:(OI)(CI)(F)' 'LOCAL SERVICE:(OI)(CI)(M)' | Out-Null
$BrokerSrc = Join-Path $Src 'install\nc-gui-broker.ps1'
$BrokerDst = Join-Path $Root 'nc-gui-broker.ps1'
if (-not (Test-Path -LiteralPath $BrokerSrc -PathType Leaf)) { throw 'Missing Windows GUI broker' }
Copy-Item -LiteralPath $BrokerSrc -Destination $BrokerDst -Force
$GuiBrokerDir = Join-Path $Root 'data\gui-brokers'
$GuiQueueDir = Join-Path $Root 'data\gui-queue'
$GuiResultDir = Join-Path $Root 'data\gui-results'
foreach ($d in @($GuiBrokerDir,$GuiQueueDir,$GuiResultDir)) { New-Item -ItemType Directory -Force -Path $d | Out-Null }
& icacls.exe $Root /grant '*S-1-5-32-545:(RX)' | Out-Null
& icacls.exe (Join-Path $Root 'data') /grant '*S-1-5-32-545:(RX)' | Out-Null
& icacls.exe $BrokerDst /grant '*S-1-5-32-545:(R)' | Out-Null
foreach ($d in @($GuiBrokerDir,$GuiQueueDir,$GuiResultDir)) { & icacls.exe $d /grant '*S-1-5-32-545:(OI)(CI)(M)' | Out-Null }
$CommonStartup = [Environment]::GetFolderPath('CommonStartup')
$StartupCmd = Join-Path $CommonStartup 'NC Interactive Broker.cmd'
('@echo off' + "`r`n" + 'start "" /min powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "C:\NC\nc-gui-broker.ps1"' + "`r`n") | Set-Content -LiteralPath $StartupCmd -Encoding ascii
$InteractiveUser = [Security.Principal.WindowsIdentity]::GetCurrent().Name
$InstallerSessionId = (Get-Process -Id $PID).SessionId
if (-not $InteractiveUser) { throw 'Unable to resolve interactive installer user' }
if ($InstallerSessionId -eq 0) { throw 'Installer must run from an interactive Windows user session' }
if ($InteractiveUser) {
  $BrokerTask = 'NC Interactive Broker'
  $Ba = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "C:\NC\nc-gui-broker.ps1"' -WorkingDirectory $Root
  $Bp = New-ScheduledTaskPrincipal -UserId $InteractiveUser -LogonType Interactive -RunLevel Limited
  $Bt = New-ScheduledTaskTrigger -AtLogOn -User $InteractiveUser
  $Bs = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero) -StartWhenAvailable
  Register-ScheduledTask -TaskName $BrokerTask -Action $Ba -Trigger $Bt -Principal $Bp -Settings $Bs -Force | Out-Null
  Start-ScheduledTask -TaskName $BrokerTask
  $BrokerDeadline = (Get-Date).AddSeconds(10)
  do {
    $BrokerReady = @(Get-ChildItem -LiteralPath $GuiBrokerDir -Filter '*.json' -File -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTimeUtc -gt (Get-Date).ToUniversalTime().AddSeconds(-10) }).Count -gt 0
    if ($BrokerReady) { break }
    Start-Sleep -Milliseconds 250
  } while ((Get-Date) -lt $BrokerDeadline)
  if (-not $BrokerReady) { throw 'NC interactive broker failed to start' }
}
@"
`$ErrorActionPreference = 'Continue'
`$Node = '$($Node.Replace("'", "''"))'
`$Root = 'C:\NC'
`$Lock = Join-Path `$Root 'data\update-switch.lock'
`$Retired = Join-Path `$Root 'data\retired.json'
while (`$true) {
  if (Test-Path -LiteralPath `$Retired) { exit 0 }
  while (Test-Path -LiteralPath `$Lock) { Start-Sleep -Milliseconds 500 }
  if (Test-Path -LiteralPath `$Retired) { exit 0 }
  `$Launcher = Join-Path `$Root 'app\launcher.mjs'
  if (-not (Test-Path -LiteralPath `$Launcher -PathType Leaf)) { Start-Sleep -Seconds 2; continue }
  `$p = Start-Process -FilePath `$Node -ArgumentList `$Launcher -WorkingDirectory (Join-Path `$Root 'app') -PassThru
  `$p.WaitForExit()
  if (Test-Path -LiteralPath `$Retired) { exit 0 }
  Start-Sleep -Seconds 1
}
"@ | Set-Content -LiteralPath $Supervisor -Encoding utf8
$Action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument ('-NoProfile -ExecutionPolicy Bypass -File "' + $Supervisor + '"') -WorkingDirectory $Root
$Trigger = New-ScheduledTaskTrigger -AtStartup
$Principal = New-ScheduledTaskPrincipal -UserId 'NT AUTHORITY\LOCAL SERVICE' -LogonType ServiceAccount -RunLevel Limited
$Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -StartWhenAvailable
Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Principal $Principal -Settings $Settings | Out-Null
Remove-Item -LiteralPath (Join-Path $Root 'data\retired.json') -Force -ErrorAction SilentlyContinue
$UninstallSrc = Join-Path $Src 'install\uninstall-windows.ps1'
$UninstallDst = Join-Path $Root 'uninstall.ps1'
if (-not (Test-Path -LiteralPath $UninstallSrc -PathType Leaf)) { throw 'Missing Windows uninstall script' }
Copy-Item -LiteralPath $UninstallSrc -Destination $UninstallDst -Force
& icacls.exe $UninstallDst /inheritance:r /grant:r 'SYSTEM:(F)' 'Administrators:(F)' | Out-Null
Start-ScheduledTask -TaskName $TaskName
$ExpectedVersion = (Get-Content -LiteralPath (Join-Path $App 'package.json') -Raw | ConvertFrom-Json).version
$ClientLog = Join-Path $Root 'logs\client.log'
$StartupDeadline = (Get-Date).AddSeconds(15)
$RuntimeReady = $false
while ((Get-Date) -lt $StartupDeadline) {
  $Runtime = @(Get-CimInstance Win32_Process -Filter "Name='node.exe'" -ErrorAction SilentlyContinue | Where-Object { $_.CommandLine -like '*C:\NC\app\launcher.mjs*' })
  if ($Runtime.Count -gt 0 -and (Test-Path -LiteralPath $ClientLog)) {
    $Recent = @(Get-Content -LiteralPath $ClientLog -Tail 30 -ErrorAction SilentlyContinue)
    if ($Recent | Where-Object { $_ -like ('*"message":"nc-client starting"*"version":"' + $ExpectedVersion + '"*') }) { $RuntimeReady = $true; break }
  }
  Start-Sleep -Milliseconds 500
}
$Task = Get-ScheduledTask -TaskName $TaskName
$Info = Get-ScheduledTaskInfo -TaskName $TaskName
if ($Task.State -eq 'Disabled') { throw 'NC task is disabled' }
if ($Info.LastTaskResult -notin @(0,267009)) { throw "NC task failed: $($Info.LastTaskResult)" }
if (-not $RuntimeReady) {
  Write-Host '--- NC startup diagnostics ---'
  Get-CimInstance Win32_Process -Filter "Name='node.exe'" -ErrorAction SilentlyContinue | Where-Object { $_.CommandLine -like '*C:\NC*' } | Select-Object ProcessId,ParentProcessId,CommandLine | Format-List | Out-Host
  if (Test-Path -LiteralPath $ClientLog) { Get-Content -LiteralPath $ClientLog -Tail 30 | Out-Host }
  throw "NC runtime failed to start release $ExpectedVersion"
}
# Provision the managed browser runtime (Playwright + NC-managed Chromium).
# Optional: BROWSER_READY stays false when the payload is absent or the
# install fails. No OS-dependency step on Windows; the client health gate
# hides browser tools until the runtime is present.
$BrowserReady = $false
$BrowserSrc = Join-Path $Src 'browser-runtime'
$BrowserBase = Join-Path $Root 'data\browser'
$BrowserRt = Join-Path $BrowserBase 'browser-runtime'
$BrowserBrowsers = Join-Path $BrowserBase 'playwright-browsers'
$RtPkg = Join-Path $BrowserSrc 'playwright-core\package.json'
$RtCli = Join-Path $BrowserSrc 'playwright-core\cli.js'
if ((Test-Path -LiteralPath $RtPkg -PathType Leaf) -and (Test-Path -LiteralPath $RtCli -PathType Leaf)) {
  $AppUrl = 'file://' + ($App -replace '\\', '/') + '/browser-runtime.mjs'
  $PinVersion = (& $Node -e "import('$AppUrl').then((m) => console.log(m.BROWSER_RUNTIME_PIN.playwright))" 2>$null)
  $RtPkgUrl = $RtPkg -replace '\\', '/'
  $RtVersion = (& $Node -p "require('$RtPkgUrl').version" 2>$null)
  if ($PinVersion -and ($PinVersion.Trim() -eq $RtVersion.Trim())) {
    if (Test-Path -LiteralPath $BrowserRt) { Remove-Item -LiteralPath $BrowserRt -Recurse -Force }
    New-Item -ItemType Directory -Force -Path $BrowserBase | Out-Null
    Copy-Item -LiteralPath $BrowserSrc -Destination "$BrowserRt.new" -Recurse -Force
    if (Test-Path -LiteralPath $BrowserRt) { Remove-Item -LiteralPath $BrowserRt -Recurse -Force }
    Rename-Item -LiteralPath "$BrowserRt.new" -NewName 'browser-runtime'
    $env:PLAYWRIGHT_BROWSERS_PATH = $BrowserBrowsers
    & $Node (Join-Path $BrowserRt 'playwright-core\cli.js') install chromium >$null 2>&1
    if (($LASTEXITCODE -eq 0) -and (Get-ChildItem -LiteralPath $BrowserBrowsers -Directory -Filter 'chromium-*' -ErrorAction SilentlyContinue)) {
      $BrowserReady = $true
    } else {
      Write-Host 'Warning: managed Chromium install failed (offline?); browser tools unavailable until installed.'
    }
  } else {
    Write-Host "Warning: browser-runtime payload version ($RtVersion) does not match client pin ($PinVersion); skipping browser install."
  }
} else {
  Write-Host 'Warning: no browser-runtime payload in bootstrap; browser tools unavailable until OTA delivers it.'
}
if ($BrowserReady) {
  Write-Host "NC canonical install complete: $Root (managed browser runtime ready)"
} else {
  Write-Host "NC canonical install complete: $Root (managed browser runtime NOT ready; browser tools hidden until installed)"
}
