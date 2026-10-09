$ErrorActionPreference = 'Stop'
# Self-locating: this script lives at $Root\uninstall.ps1 in every install
# layout (machine-wide ProgramData or a per-user profile tree).
$Root = Split-Path -Parent $PSCommandPath
$TaskName = 'NC Client'
$BrokerTask = 'NC Interactive Broker'
$ServiceName = 'NCClient'
# Safety: only ever delete a real agent tree (marker files must exist).
if (-not ((Test-Path -LiteralPath (Join-Path $Root 'config\nc-client.env') -PathType Leaf) -or (Test-Path -LiteralPath (Join-Path $Root 'app') -PathType Container))) {
  throw 'Not an NC install root; refusing'
}
$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# User-mode installs (Faz A) run as the operator who owns the tree: no
# SCM service exists and no elevation is needed for removal. Detect via the
# installer stamp; fall back to the admin path whenever a service is present.
$UserMode = $false
$EnvStamp = Join-Path $Root 'config\nc-client.env'
if ((Test-Path -LiteralPath $EnvStamp -PathType Leaf) -and
    (Select-String -LiteralPath $EnvStamp -Pattern '^NC_SERVICE_MODE=user' -Quiet) -and
    (-not (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue))) {
  $UserMode = $true
  Write-Host 'User-mode uninstall: running without elevation (admin-only leftovers reported, not fatal).'
}
if (-not $UserMode -and -not $IsAdmin) {
  throw 'Administrator privileges required'
}

# SCM service first (Faz 3): stop and delete before touching the tree.
# Stop-Service has no timeout and can hang in StopPending forever (which
# used to wedge the whole uninstall with runners still locking the tree).
# Bound it with a job; leftovers are killed precisely below regardless.
$Svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($Svc) {
  $StopJob = Start-Job -ScriptBlock { param($n) Stop-Service -Name $n -Force -ErrorAction SilentlyContinue } -ArgumentList $ServiceName
  if (-not (Wait-Job $StopJob -Timeout 20)) { Stop-Job $StopJob | Out-Null }
  Remove-Job $StopJob -Force -ErrorAction SilentlyContinue
  & sc.exe delete $ServiceName | Out-Null
  Write-Host 'NC Windows service removed.'
}

Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
Stop-ScheduledTask -TaskName $BrokerTask -ErrorAction SilentlyContinue

$Deadline = (Get-Date).AddSeconds(10)
do {
  $Processes = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object {
    $_.CommandLine -like "*$Root\app\launcher.mjs*" -or
    $_.CommandLine -like "*$Root\app\client.mjs*" -or
    $_.CommandLine -like "*$Root\nc-supervisor.ps1*" -or
    $_.CommandLine -like "*$Root\nc-gui-broker.ps1*" -or
    $_.CommandLine -like "*$Root\nc-supervisor.mjs*" -or
    $_.CommandLine -like "*$Root\nc-gui-broker.mjs*" -or
    ($_.Name -eq 'nc-hide.exe' -and $_.CommandLine -like "*$Root*")
  })
  if ($Processes.Count -eq 0) { break }
  foreach ($proc in $Processes) { Stop-Process -Id $proc.ProcessId -Force -ErrorAction SilentlyContinue }
  Start-Sleep -Milliseconds 250
} while ((Get-Date) -lt $Deadline)

Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName $BrokerTask -Confirm:$false -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName 'NC Uninstall' -Confirm:$false -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName 'NC Privileged Helper' -Confirm:$false -ErrorAction SilentlyContinue

$StartupCmd = Join-Path ([Environment]::GetFolderPath('CommonStartup')) 'NC Interactive Broker.cmd'
Remove-Item -LiteralPath $StartupCmd -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $Root -Recurse -Force -ErrorAction SilentlyContinue
if (Test-Path -LiteralPath $Root) {
  if ($UserMode) {
    $Left = @(Get-ChildItem -LiteralPath $Root -Recurse -Force -ErrorAction SilentlyContinue | Select-Object -First 10 FullName)
    Write-Host ("NC user-mode uninstall complete with leftovers for admin sweep: " + (($Left | ForEach-Object { $_.FullName }) -join '; '))
  } else {
    throw 'NC root could not be removed completely'
  }
}

Write-Host 'NC client uninstalled from Windows.'
