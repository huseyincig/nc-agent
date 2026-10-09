$ErrorActionPreference = 'SilentlyContinue'
$Root = Join-Path $env:ProgramData 'NC'
$SessionId = (Get-Process -Id $PID).SessionId
$UserName = [Security.Principal.WindowsIdentity]::GetCurrent().Name
$Data = Join-Path $Root 'data'
# Startup self-log: if the broker never heartbeats, this file tells why it
# died at boot (trigger fired but process crashed early). Best-effort only.
try {
  $BootLog = Join-Path $Data 'gui-broker-boot.log'
  "[$(Get-Date -Format o)] start user=$UserName session=$SessionId pid=$PID root=$Root" | Out-File -LiteralPath $BootLog -Append -Encoding utf8
} catch {}
$BrokerDir = Join-Path $Data 'gui-brokers'
$QueueDir = Join-Path $Data ("gui-queue\$SessionId")
$ResultDir = Join-Path $Data 'gui-results'
$Lock = Join-Path $BrokerDir ("gui-broker-$SessionId.lock")
foreach ($d in @($BrokerDir,$QueueDir,$ResultDir)) { New-Item -ItemType Directory -Force -Path $d | Out-Null }
try { $LockHandle = [IO.File]::Open($Lock,[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::Write,[IO.FileShare]::None) } catch { exit 0 }
try {
  "[$(Get-Date -Format o)] ready session=$SessionId" | Out-File -LiteralPath (Join-Path $Data 'gui-broker-boot.log') -Append -Encoding utf8
} catch {}
try {
  $Heartbeat = Join-Path $BrokerDir ("$SessionId.json")
  while ($true) {
    @{session_id=$SessionId;username=$UserName;pid=$PID;last_seen=(Get-Date).ToUniversalTime().ToString('o')} | ConvertTo-Json -Compress | Set-Content -LiteralPath "$Heartbeat.tmp" -Encoding utf8
    Move-Item -LiteralPath "$Heartbeat.tmp" -Destination $Heartbeat -Force
    foreach ($file in @(Get-ChildItem -LiteralPath $QueueDir -Filter '*.json' -File | Sort-Object CreationTimeUtc)) {
      $claim = "$($file.FullName).claim-$PID"
      try { Move-Item -LiteralPath $file.FullName -Destination $claim -ErrorAction Stop } catch { continue }
      $r = @{ok=$false;username=$UserName;session_id=$SessionId;pid=$null;error='GUI_LAUNCH_FAILED'}
      try {
        $q = Get-Content -LiteralPath $claim -Raw | ConvertFrom-Json
        if (-not $q.id) { throw 'GUI_REQUEST_ID_REQUIRED' }
        if ($q.action -eq 'close') {
          $cpid = 0
          try { $cpid = [int]$q.pid } catch { $cpid = 0 }
          if ($cpid -le 0) { throw 'GUI_PID_REQUIRED' }
          $killed = $false
          try {
            $victim = Get-Process -Id $cpid -ErrorAction Stop
            if ($victim.SessionId -ne $SessionId -and $victim.SessionId -ne 0) { throw 'GUI_PID_FOREIGN_SESSION' }
            Stop-Process -Id $cpid -Force -ErrorAction Stop
            $killed = $true
          } catch {
            if ($_.Exception.Message -eq 'GUI_PID_FOREIGN_SESSION') { throw }
          }
          $stillThere = $false
          try { $stillThere = $null -ne (Get-Process -Id $cpid -ErrorAction Stop) } catch {}
          if ($killed -and $stillThere) {
            # Teardown is async; poll briefly before verdict.
            for ($i = 0; ($i -lt 20) -and $stillThere; $i++) {
              Start-Sleep -Milliseconds 150
              try { $stillThere = $null -ne (Get-Process -Id $cpid -ErrorAction Stop) } catch { $stillThere = $false }
            }
          }
          $r.ok = ($killed -and -not $stillThere); $r.error = $null; $r.pid = $cpid; $r.closed = $r.ok
          if (-not $r.ok) { $r.error = 'GUI_CLOSE_FAILED' }
          $result = Join-Path $ResultDir ("$($q.id).json")
          $r | ConvertTo-Json -Compress | Set-Content -LiteralPath "$result.tmp" -Encoding utf8
          Move-Item -LiteralPath "$result.tmp" -Destination $result -Force
          Remove-Item -LiteralPath $claim -Force -ErrorAction SilentlyContinue
          continue
        }
        $app = [string]$q.application; $target = [string]$q.target
        if ($app -notin @('default_browser','edge','chrome','explorer','notepad','code','cursor','terminal')) { throw 'GUI_APPLICATION_NOT_ALLOWED' }
        if ($app -in @('default_browser','edge','chrome')) { $u=[Uri]$target; if ($u.Scheme -notin @('http','https')) { throw 'GUI_URL_SCHEME_NOT_ALLOWED' } }
        $launchTime = Get-Date
        if ($app -eq 'default_browser') { $p = Start-Process -FilePath $target -PassThru }
        elseif ($app -eq 'edge') {
          $exe = @("$env:ProgramFiles (x86)\Microsoft\Edge\Application\msedge.exe","$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe") | Where-Object { Test-Path $_ } | Select-Object -First 1
          if (-not $exe) { throw 'EDGE_NOT_FOUND' }; $p = Start-Process -FilePath $exe -ArgumentList @($target) -PassThru
        }
        elseif ($app -eq 'chrome') {
          $exe = @("$env:ProgramFiles\Google\Chrome\Application\chrome.exe","$env:ProgramFiles (x86)\Google\Chrome\Application\chrome.exe","$env:LOCALAPPDATA\Google\Chrome\Application\chrome.exe") | Where-Object { Test-Path $_ } | Select-Object -First 1
          if (-not $exe) { throw 'CHROME_NOT_FOUND' }; $p = Start-Process -FilePath $exe -ArgumentList @($target) -PassThru
        }
        elseif ($app -eq 'explorer') { $p = Start-Process -FilePath 'explorer.exe' -ArgumentList @($target) -PassThru }
        elseif ($app -eq 'code') {
          $codeExe = @(
            "$env:LOCALAPPDATA\Programs\Microsoft VS Code\bin\code.cmd",
            "$env:LOCALAPPDATA\Programs\Microsoft VS Code\Code.exe",
            "$env:ProgramFiles\Microsoft VS Code\bin\code.cmd",
            "$env:ProgramFiles\Microsoft VS Code\Code.exe"
          ) | Where-Object { Test-Path $_ } | Select-Object -First 1
          if (-not $codeExe) { $codeExe = (Get-Command code -ErrorAction SilentlyContinue).Source }
          if (-not $codeExe) { throw 'VSCODE_NOT_FOUND' }
          $p = if ($target) { Start-Process -FilePath $codeExe -ArgumentList @($target) -PassThru } else { Start-Process -FilePath $codeExe -PassThru }
        }
        elseif ($app -eq 'cursor') {
          $cursorExe = @(
            "$env:LOCALAPPDATA\Programs\cursor\Cursor.exe",
            "$env:LOCALAPPDATA\cursor\Cursor.exe"
          ) | Where-Object { Test-Path $_ } | Select-Object -First 1
          if (-not $cursorExe) { $cursorExe = (Get-Command cursor -ErrorAction SilentlyContinue).Source }
          if (-not $cursorExe) { throw 'CURSOR_NOT_FOUND' }
          $p = if ($target) { Start-Process -FilePath $cursorExe -ArgumentList @($target) -PassThru } else { Start-Process -FilePath $cursorExe -PassThru }
        }
        elseif ($app -eq 'terminal') {
          $p = Start-Process -FilePath 'cmd.exe' -PassThru
        }
        else { $p = Start-Process -FilePath 'notepad.exe' -PassThru }
        # Single-instance/Store apps (Win11 Notepad, browsers) may exit the
        # spawned launcher and activate another process. Correlate by process
        # name + start time so the reported PID is the live GUI process;
        # keep the launcher PID when it is still alive.
        $realPid = $p.Id
        try {
          Start-Sleep -Milliseconds 800
          $procName = $null
          try { $procName = (Get-Process -Id $p.Id -ErrorAction Stop).ProcessName } catch {}
          if ($procName) {
            $cand = Get-Process -Name $procName -ErrorAction SilentlyContinue |
              Where-Object { $_.StartTime -ge $launchTime.AddSeconds(-2) -and $_.SessionId -eq $SessionId } |
              Sort-Object StartTime -Descending | Select-Object -First 1
            if ($cand -and $cand.Id -ne $p.Id) {
              $alive = $false
              try { $alive = $null -ne (Get-Process -Id $p.Id -ErrorAction Stop) } catch {}
              if (-not $alive) { $realPid = $cand.Id }
            }
          }
        } catch {}
        $r.ok=$true; $r.error=$null; $r.pid=$realPid
      } catch { $r.error=$_.Exception.Message }
      $result = Join-Path $ResultDir ("$($q.id).json")
      $r | ConvertTo-Json -Compress | Set-Content -LiteralPath "$result.tmp" -Encoding utf8
      Move-Item -LiteralPath "$result.tmp" -Destination $result -Force
      Remove-Item -LiteralPath $claim -Force -ErrorAction SilentlyContinue
    }
    Start-Sleep -Milliseconds 500
  }
} finally { $LockHandle.Dispose(); Remove-Item -LiteralPath $Lock -Force -ErrorAction SilentlyContinue }
