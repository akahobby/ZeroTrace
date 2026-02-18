# ENGINE_MARKER_PS51_OK
param(
    [switch]$FullCleanup,
  [switch]$ScanOnly,
  [switch]$RestorePoint,
  [switch]$SkipUninstall,
  [string]$LogDir
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ZeroTraceVersion = "1.0"
$EngineVersion    = "1.6.0"

$Script:FullCleanup   = [bool]$FullCleanup
$Script:ScanOnly      = [bool]$ScanOnly
$Script:RestorePoint  = [bool]$RestorePoint
$Script:SkipUninstall = [bool]$SkipUninstall

# -----------------------------
# Logging
# -----------------------------
if ($LogDir) {
  if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }
  $Script:LogPath = Join-Path $LogDir ("ZT_{0:yyyyMMdd_HHmmss}.log" -f (Get-Date))
} else {
  $Script:LogPath = Join-Path $env:TEMP ("ZT_{0:yyyyMMdd_HHmmss}.log" -f (Get-Date))
}

function Write-Log {
  param([string]$Message, [ValidateSet("INFO","OK","WARN","ERR")] [string]$Level="INFO")
  $line = "[{0:HH:mm:ss}] [{1}] {2}" -f (Get-Date), $Level, $Message
  Add-Content -Path $Script:LogPath -Value $line -Encoding UTF8

  switch ($Level) {
    "OK"   { Write-Host $line -ForegroundColor Green }
    "WARN" { Write-Host $line -ForegroundColor Yellow }
    "ERR"  { Write-Host $line -ForegroundColor Red }
    default{ Write-Host $line -ForegroundColor Gray }
  }
}

function Get-ModeText {
  if ($Script:ScanOnly) { return "SCAN-ONLY" }
  return "LIVE"
}

# -----------------------------
# UI helpers (PS 5.1 safe, ASCII)
# -----------------------------
function _Lower([string]$s) {
  if ($null -eq $s) { return "" }
  try { return $s.ToString().ToLowerInvariant() } catch { return "$s" }
}

function _ConfColor([string]$c) {
  switch (_Lower $c) {
    "high"   { return "Green" }
    "medium" { return "Yellow" }
    "low"    { return "Red" }
    default  { return "DarkGray" }
  }
}

function _KindColor([string]$k) {
  switch (_Lower $k) {
    "path"          { return "Cyan" }
    "registrykey"   { return "Magenta" }
    "service"       { return "Yellow" }
    "scheduledtask" { return "Blue" }
    "firewallrule"  { return "DarkCyan" }
    default         { return "Gray" }
  }
}

function UI-Rule([int]$Width=0) {
  if ($Width -le 0) {
    try { $Width = [Console]::WindowWidth } catch { $Width = 90 }
  }
  if ($Width -lt 70)  { $Width = 70 }
  if ($Width -gt 120) { $Width = 120 }
  Write-Host ("-" * $Width) -ForegroundColor DarkCyan
}

function UI-Title([string]$Text) { Write-Host $Text -ForegroundColor Cyan }
function UI-Note ([string]$Text) { Write-Host $Text -ForegroundColor DarkGray }
function UI-Warn ([string]$Text) { Write-Host $Text -ForegroundColor Yellow }
function UI-Label([string]$Key, [string]$Value) {
  Write-Host ("{0,-10}: " -f $Key) -ForegroundColor DarkGray -NoNewline
  Write-Host $Value -ForegroundColor Gray
}



function Pause-Enter { Read-Host "Press Enter to continue" | Out-Null }

function Test-IsAdmin {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  $p  = New-Object Security.Principal.WindowsPrincipal($id)
  return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Ensure-Admin {
  if (-not (Test-IsAdmin)) {
    Write-Host ""
    Write-Host "ERROR: Run ZeroTrace.bat as Administrator."
    Write-Host ""
    Pause-Enter
    exit 1
  }
}

function Normalize-Name([string]$s) {
  if (-not $s) { return "" }
  return (($s -replace "[^a-zA-Z0-9]+","").ToLowerInvariant())
}

function Confirm-YN([string]$Prompt, [bool]$DefaultYes=$false) {
  $suffix = ""
  if ($DefaultYes) { $suffix = "[Y/n]" } else { $suffix = "[y/N]" }
  $raw = Read-Host "$Prompt $suffix"
  if (-not $raw) { return $DefaultYes }
  return ($raw.Trim().ToLowerInvariant() -in @("y","yes"))
}

function Invoke-Action([string]$What, [scriptblock]$Do) {
  if ($Script:ScanOnly) { Write-Log ("SCAN-ONLY: Would do -> " + $What) "INFO"; return }
  & $Do
  Write-Log $What "OK"
}

function Get-PropValue {
  param([Parameter(Mandatory=$true)] [object]$Obj, [Parameter(Mandatory=$true)] [string]$Name)
  $p = $Obj.PSObject.Properties[$Name]
  if ($null -eq $p) { return $null }
  return $p.Value
}

function Format-Bytes([int64]$Bytes) {
  if ($Bytes -lt 1024) { return "$Bytes B" }
  $kb = $Bytes / 1024.0
  if ($kb -lt 1024) { return ("{0:N1} KB" -f $kb) }
  $mb = $kb / 1024.0
  if ($mb -lt 1024) { return ("{0:N1} MB" -f $mb) }
  $gb = $mb / 1024.0
  return ("{0:N2} GB" -f $gb)
}

function Get-PathStats([string]$Path) {
  $out = [ordered]@{ Exists=$false; Files=0; Bytes=0 }
  if (-not $Path) { return [pscustomobject]$out }
  if (-not (Test-Path -LiteralPath $Path)) { return [pscustomobject]$out }
  $out.Exists = $true
  try {
    $item = Get-Item -LiteralPath $Path -ErrorAction Stop
    if ($item.PSIsContainer) {
      $m = Get-ChildItem -LiteralPath $Path -Recurse -Force -File -ErrorAction SilentlyContinue |
        Measure-Object -Property Length -Sum
      $out.Files = [int]$m.Count
      $out.Bytes = [int64]$m.Sum
    } else {
      $out.Files = 1
      $out.Bytes = [int64]$item.Length
    }
  } catch { }
  return [pscustomobject]$out
}

# -----------------------------
# Environment / safety
# -----------------------------
$ProtectedPublishers = @("microsoft","google","nvidia","intel","amd","valve","adobe","apple","mozilla")

$StandardFolders = @($env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:ProgramData) |
  Where-Object { $_ -and (Test-Path $_) } | Select-Object -Unique

$UserFolders = @($env:LOCALAPPDATA, $env:APPDATA) |
  Where-Object { $_ -and (Test-Path $_) } | Select-Object -Unique

$StartMenuFolders = @(
  (Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs"),
  (Join-Path $env:APPDATA     "Microsoft\Windows\Start Menu\Programs")
) | Where-Object { $_ -and (Test-Path $_) } | Select-Object -Unique

function Is-ProtectedPath([string]$Path) {
  if (-not $Path) { return $true }

  try {
    $full = [IO.Path]::GetFullPath($Path)
  } catch {
    return $true
  }

  # Absolute hard blocks only
  $hardBlocks = @(
    "C:\",
    $env:windir,
    (Join-Path $env:windir "System32"),
    (Join-Path $env:windir "SysWOW64"),
    $env:ProgramFiles,
    ${env:ProgramFiles(x86)}
  ) | Where-Object { $_ }

  foreach ($b in $hardBlocks) {
    try {
      $bFull = [IO.Path]::GetFullPath($b)
      if ($full.TrimEnd('\') -ieq $bFull.TrimEnd('\')) {
        return $true
      }
    } catch {}
  }

  return $false
}

function Is-SaneInstallLocation([string]$Path) {
  if (-not $Path) { return $false }
  try { $full = [IO.Path]::GetFullPath($Path) } catch { return $false }
  if (-not (Test-Path $full)) { return $false }
  return (-not (Is-ProtectedPath $full))
}

# -----------------------------
# Target objects
# -----------------------------
function New-Target {
  param(
    [Parameter(Mandatory=$true)][ValidateSet("Path","RegistryKey","Service","ScheduledTask","FirewallRule")] [string]$Kind,
    [Parameter(Mandatory=$true)][string]$Value,
    [Parameter(Mandatory=$true)][string]$Source,
    [Parameter(Mandatory=$true)][ValidateSet("High","Medium","Low")] [string]$Confidence
  )
  [pscustomobject]@{ Kind=$Kind; Value=$Value; Source=$Source; Confidence=$Confidence }
}

function Make-TaskValue([string]$TaskPath, [string]$TaskName) {
  if (-not $TaskPath) { $TaskPath = "\" }
  return ($TaskPath + "::" + $TaskName)
}
function Split-TaskValue([string]$v) {
  $tp = "\"
  $tn = $v
  if ($v -and ($v -like "*::*")) {
    $parts = $v.Split(@("::"), 2, [System.StringSplitOptions]::None)
    $tp = $parts[0]
    $tn = $parts[1]
  }
  return @($tp, $tn)
}

# -----------------------------
# Discovery
# -----------------------------
function Get-InstalledApps {
  $roots = @(
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
  )

  $apps = @()
  foreach ($r in $roots) {
    Get-ItemProperty -Path $r -ErrorAction SilentlyContinue | ForEach-Object {
      $dn = [string](Get-PropValue -Obj $_ -Name "DisplayName")
      if (-not $dn) { return }
      $apps += [pscustomobject]@{
        DisplayName          = $dn
        Publisher            = [string](Get-PropValue -Obj $_ -Name "Publisher")
        DisplayVersion       = [string](Get-PropValue -Obj $_ -Name "DisplayVersion")
        InstallLocation      = [string](Get-PropValue -Obj $_ -Name "InstallLocation")
        UninstallString      = [string](Get-PropValue -Obj $_ -Name "UninstallString")
        QuietUninstallString = [string](Get-PropValue -Obj $_ -Name "QuietUninstallString")
      }
    }
  }

  $apps | Group-Object DisplayName,Publisher | ForEach-Object {
    $_.Group | Sort-Object `
      @{Expression={ [bool]($_.InstallLocation) }; Descending=$true},
      @{Expression={ [bool]($_.QuietUninstallString) }; Descending=$true},
      @{Expression={ [bool]($_.UninstallString) }; Descending=$true} |
      Select-Object -First 1
  } | Sort-Object DisplayName
}

function Get-CandidateNames($App) {
  $names = @()
  if ($App.DisplayName) { $names += $App.DisplayName }
  if ($App.Publisher)   { $names += $App.Publisher }

  $extra = @()
  foreach ($n in $names) {
    $extra += ($n -split "[\-\|\(\)\[\]:,]" | ForEach-Object { $_.Trim() } | Where-Object { $_ })
  }

  $all = ($names + $extra) | Where-Object { $_ } | Select-Object -Unique
  $norm = @()
  foreach ($n in $all) {
    $nn = Normalize-Name $n
    if ($nn.Length -ge 4) { $norm += $nn }
  }
  return $norm | Select-Object -Unique
}

function Find-ExactChildFolderMatches([string[]]$CandidateNormNames, [string[]]$Roots) {
  $hits = New-Object System.Collections.Generic.List[string]
  foreach ($root in $Roots) {
    if (-not (Test-Path $root)) { continue }
    Get-ChildItem -LiteralPath $root -Directory -ErrorAction SilentlyContinue | ForEach-Object {
      $childNorm = Normalize-Name $_.Name
      if ($CandidateNormNames -contains $childNorm) {
        if (-not $hits.Contains($_.FullName)) { [void]$hits.Add($_.FullName) }
      }
    }
  }
  return @($hits | Select-Object -Unique)
}

function Find-StartMenuEntries([string[]]$CandidateNormNames) {
  $hits = New-Object System.Collections.Generic.List[string]
  foreach ($sm in $StartMenuFolders) {
    Get-ChildItem -LiteralPath $sm -Directory -ErrorAction SilentlyContinue | ForEach-Object {
      $dn = Normalize-Name $_.Name
      if ($CandidateNormNames -contains $dn) {
        if (-not $hits.Contains($_.FullName)) { [void]$hits.Add($_.FullName) }
      }
    }
    Get-ChildItem -LiteralPath $sm -Recurse -File -Include *.lnk,*.url -ErrorAction SilentlyContinue | ForEach-Object {
      $fn = Normalize-Name $_.BaseName
      if ($CandidateNormNames -contains $fn) {
        if (-not $hits.Contains($_.FullName)) { [void]$hits.Add($_.FullName) }
      }
    }
  }
  return @($hits | Select-Object -Unique)
}

function Find-RegistryVendorKeys([string[]]$CandidateNormNames) {
  $hits = New-Object System.Collections.Generic.List[string]
  $roots = @("HKCU:\Software","HKLM:\Software","HKLM:\Software\WOW6432Node")
  foreach ($r in $roots) {
    if (-not (Test-Path $r)) { continue }
    Get-ChildItem -LiteralPath $r -ErrorAction SilentlyContinue | ForEach-Object {
      $kn = Normalize-Name $_.PSChildName
      if ($CandidateNormNames -contains $kn) {
        if (-not $hits.Contains($_.PSPath)) { [void]$hits.Add($_.PSPath) }
      }
    }
  }
  return @($hits | Select-Object -Unique)
}

function Find-Services([string[]]$CandidateNormNames) {
  $hits = @()
  try {
    $svcs = Get-Service -ErrorAction Stop
    foreach ($s in $svcs) {
      $n1 = Normalize-Name $s.Name
      $n2 = Normalize-Name $s.DisplayName
      if (($CandidateNormNames -contains $n1) -or ($CandidateNormNames -contains $n2)) { $hits += $s }
    }
  } catch {}
  return @($hits | Sort-Object Name -Unique)
}

function Find-ScheduledTasks([string[]]$CandidateNormNames) {
  $hits = @()
  if (-not (Get-Command Get-ScheduledTask -ErrorAction SilentlyContinue)) { return @() }
  try {
    $tasks = Get-ScheduledTask -ErrorAction Stop
    foreach ($t in $tasks) {
      $n1 = Normalize-Name $t.TaskName
      $n2 = Normalize-Name $t.TaskPath
      $match = $false

      if ($CandidateNormNames -contains $n1) { $match = $true }
      if (-not $match -and $n2) {
        foreach ($c in $CandidateNormNames) {
          if ($n2 -like "*$c*") { $match = $true; break }
        }
      }

      if ($match) { $hits += $t }
    }
  } catch {}
  return @($hits | Sort-Object TaskPath,TaskName -Unique)
}

function Find-FirewallRules([string[]]$CandidateNormNames) {
  $hits = @()
  if (-not (Get-Command Get-NetFirewallRule -ErrorAction SilentlyContinue)) { return @() }
  try {
    $rules = Get-NetFirewallRule -ErrorAction Stop
    foreach ($r in $rules) {
      $dn = $null
      try { $dn = $r.DisplayName } catch {}
      $n1 = Normalize-Name $dn
      if ($n1 -and ($CandidateNormNames -contains $n1)) { $hits += $r }
    }
  } catch {}
  return @($hits | Sort-Object DisplayName -Unique)
}

# -----------------------------
# UI
# -----------------------------
function Show-Banner {
  $w = 90
  try { $w = [Console]::WindowWidth } catch {}
  if ($w -lt 70)  { $w = 70 }
  if ($w -gt 120) { $w = 120 }

  $mode = Get-ModeText
  $modeColor = "Green"
  if ($mode -eq "SCAN-ONLY") { $modeColor = "Yellow" }

  $fc = "OFF"; if ($Script:FullCleanup) { $fc = "ON" }
  $su = "OFF"; if ($Script:SkipUninstall) { $su = "ON" }
  $rp = "OFF"; if ($Script:RestorePoint) { $rp = "ON" }

  Write-Host ""
  UI-Rule $w
  Write-Host " ZeroTrace " -ForegroundColor Cyan -NoNewline
  Write-Host ("| Engine {0} " -f $EngineVersion) -ForegroundColor DarkGray -NoNewline
  Write-Host "| Mode:" -ForegroundColor DarkGray -NoNewline
  Write-Host $mode -ForegroundColor $modeColor -NoNewline
  Write-Host (" | FullCleanup:{0} | SkipUninstall:{1} | RestorePoint:{2}" -f $fc,$su,$rp) -ForegroundColor DarkGray
  Write-Host (" Log: {0}" -f $Script:LogPath) -ForegroundColor DarkGray
  UI-Rule $w
  Write-Host ""
}


function Select-AppInteractive([object[]]$Apps) {
  while ($true) {
    Clear-Host
    Show-Banner
    UI-Title "App Picker"
    UI-Note  "Type to filter. Press Enter for top 50. Type 'q' to quit."
    Write-Host ""

    $q = Read-Host "Search"
    if ($q) {
      if ($q.Trim().ToLowerInvariant() -eq "q") { return $null }
    }

    $list = $null
    if ($q) { $list = $Apps | Where-Object { $_.DisplayName -like "*$q*" } | Select-Object -First 200 }
    else    { $list = $Apps | Select-Object -First 50 }

    if (-not $list -or $list.Count -eq 0) {
      UI-Warn "No matches."
      Pause-Enter
      continue
    }

    Clear-Host
    Show-Banner
    UI-Title ("Matches ({0})" -f $list.Count)
    UI-Note  "Tip: Type the number and press Enter. Blank cancels."
    Write-Host ""

    for ($i=0; $i -lt $list.Count; $i++) {
      $a = $list[$i]
      $pub = $a.Publisher; if (-not $pub) { $pub = "-" }
      $ver = $a.DisplayVersion; if (-not $ver) { $ver = "-" }

      Write-Host ("[{0,2}] " -f $i) -ForegroundColor DarkGray -NoNewline
      $dn = "$($a.DisplayName)"
      if ($dn.ToLowerInvariant().EndsWith(" (remove only)")) {
        $base = $dn.Substring(0, $dn.Length - 12)
        Write-Host $base -ForegroundColor Cyan -NoNewline
        Write-Host " (remove only)" -ForegroundColor Yellow -NoNewline
      } else {
        Write-Host $dn -ForegroundColor Cyan -NoNewline
      }
      Write-Host "  " -NoNewline
      Write-Host "(Publisher: " -ForegroundColor DarkGray -NoNewline
      Write-Host $pub -ForegroundColor Gray -NoNewline
      Write-Host ", Version: " -ForegroundColor DarkGray -NoNewline
      Write-Host $ver -ForegroundColor Gray -NoNewline
      Write-Host ")" -ForegroundColor DarkGray
    }

    Write-Host ""
    $pick = Read-Host "Select #"
    if (-not $pick) { return $null }
    if ($pick -match "^[0-9]+$") {
      $n = [int]$pick
      if ($n -ge 0 -and $n -lt $list.Count) { return $list[$n] }
    }

    UI-Warn "Invalid selection."
    Pause-Enter
  }
}


# -----------------------------
# Uninstall
# -----------------------------
function Invoke-Uninstall($App) {
  if ($Script:ScanOnly) { Write-Log "Scan-only mode: skipping uninstall." "INFO"; return $true }
  if ($Script:SkipUninstall) { Write-Log "SkipUninstall: skipping uninstall (residual cleanup only)." "INFO"; return $true }

  $cmd = $null
  if ($App.QuietUninstallString) { $cmd = $App.QuietUninstallString.Trim() }
  elseif ($App.UninstallString)  { $cmd = $App.UninstallString.Trim() }

  if (-not $cmd) { Write-Log "No uninstall command found for: $($App.DisplayName)" "ERR"; return $false }

  Write-Log "Uninstall command: $cmd" "INFO"
  if (-not (Confirm-YN "Run uninstaller now?" $true)) { Write-Log "User cancelled uninstall." "WARN"; return $false }

  if ($false) { Write-Log "LIVE: Would run: $cmd" "WARN"; return $true }

  Start-Process -FilePath "cmd.exe" -ArgumentList "/c", $cmd -Wait
  Write-Log "Uninstall command returned." "OK"
  return $true
}

# -----------------------------
# Scan build
# -----------------------------
function Build-ScanResult($App) {
  $cand = Get-CandidateNames $App
  Write-Log ("Candidate identifiers: {0}" -f ($cand -join ", ")) "INFO"

  $targets = New-Object System.Collections.Generic.List[object]

  if (Is-SaneInstallLocation $App.InstallLocation) {
    [void]$targets.Add((New-Target -Kind Path -Value $App.InstallLocation -Source "InstallLocation" -Confidence High))
  }

  foreach ($p in (Find-ExactChildFolderMatches -CandidateNormNames $cand -Roots $StandardFolders)) {
    [void]$targets.Add((New-Target -Kind Path -Value $p -Source "ExactFolder(Standard)" -Confidence High))
  }

  foreach ($p in (Find-StartMenuEntries -CandidateNormNames $cand)) {
    [void]$targets.Add((New-Target -Kind Path -Value $p -Source "StartMenu" -Confidence Medium))
  }

  if ($Script:FullCleanup) {
    foreach ($p in (Find-ExactChildFolderMatches -CandidateNormNames $cand -Roots $UserFolders)) {
      [void]$targets.Add((New-Target -Kind Path -Value $p -Source "ExactFolder(AppData)" -Confidence Medium))
    }

    $pubNorm = Normalize-Name $App.Publisher
    if ($pubNorm -and ($ProtectedPublishers -contains $pubNorm)) {
      Write-Log "Protected publisher rule applied in AppData (no broad vendor deletions)." "INFO"
    }
  }

  foreach ($rk in (Find-RegistryVendorKeys -CandidateNormNames $cand)) {
    [void]$targets.Add((New-Target -Kind RegistryKey -Value $rk -Source "VendorKey" -Confidence Medium))
  }

  foreach ($s in (Find-Services -CandidateNormNames $cand)) {
    [void]$targets.Add((New-Target -Kind Service -Value $s.Name -Source "ServiceName/DisplayName" -Confidence Medium))
  }

  foreach ($t in (Find-ScheduledTasks -CandidateNormNames $cand)) {
    [void]$targets.Add((New-Target -Kind ScheduledTask -Value (Make-TaskValue $t.TaskPath $t.TaskName) -Source "TaskName/Path" -Confidence Medium))
  }

  foreach ($r in (Find-FirewallRules -CandidateNormNames $cand)) {
    $dn = $null
    try { $dn = $r.DisplayName } catch {}
    if ($dn) { [void]$targets.Add((New-Target -Kind FirewallRule -Value $dn -Source "FirewallRule" -Confidence Low)) }
  }

  $uniq = @{}
  foreach ($t in $targets) {
    $k = ($t.Kind + "|" + $t.Value).ToLowerInvariant()
    if (-not $uniq.ContainsKey($k)) { $uniq[$k] = $t }
  }
  return @($uniq.Values)
}

# -----------------------------
# Audit + deselect
# -----------------------------
function Show-AuditAndSelectTargets($App, [object[]]$Targets) {
  $rows = @()
  $idx = 1

  foreach ($t in @($Targets)) {
    $exists = $false
    $meta = ""
    $blocked = $false

    if ($t.Kind -eq "Path") {
      $stats = Get-PathStats -Path $t.Value
      $exists = [bool]$stats.Exists
      if ($exists) { $meta = ("Files:{0}  Size:{1}" -f $stats.Files, (Format-Bytes $stats.Bytes)) } else { $meta = "Missing" }
      $blocked = (Is-ProtectedPath $t.Value)
    }
    elseif ($t.Kind -eq "RegistryKey") {
      $exists = (Test-Path -LiteralPath $t.Value)
      $meta = $(if ($exists) { "Exists" } else { "Missing" })
    }
    elseif ($t.Kind -eq "Service") {
      try { $null = Get-Service -Name $t.Value -ErrorAction Stop; $exists = $true } catch { $exists = $false }
      $meta = $(if ($exists) { "Exists" } else { "Missing" })
    }
    elseif ($t.Kind -eq "ScheduledTask") {
      $parts = Split-TaskValue $t.Value
      $tp = $parts[0]; $tn = $parts[1]
      $exists = $false
      if (Get-Command Get-ScheduledTask -ErrorAction SilentlyContinue) {
        try { $null = Get-ScheduledTask -TaskPath $tp -TaskName $tn -ErrorAction Stop; $exists = $true } catch { $exists = $false }
      }
      $meta = $(if ($exists) { "Exists" } else { "Missing/Unavailable" })
    }
    elseif ($t.Kind -eq "FirewallRule") {
      $exists = $false
      if (Get-Command Get-NetFirewallRule -ErrorAction SilentlyContinue) {
        try { $null = Get-NetFirewallRule -DisplayName $t.Value -ErrorAction Stop; $exists = $true } catch { $exists = $false }
      }
      $meta = $(if ($exists) { "Exists" } else { "Missing/Unavailable" })
    }

    $rows += [pscustomobject]@{
      Id=$idx; Kind=$t.Kind; Target=$t.Value; Source=$t.Source; Conf=$t.Confidence;
      Exists=$exists; Meta=$meta; Blocked=$blocked
    }
    $idx++
  }

  Clear-Host
  Show-Banner

  $pubText = "-"
  if ($App.Publisher) { $pubText = $App.Publisher }

  UI-Title "Audit"
  UI-Note  "Review the targets below. Exclude anything that looks wrong."
  Write-Host ""

  UI-Label "App" $App.DisplayName
  UI-Label "Publisher" $pubText
  Write-Host ""

  foreach ($r in $rows) {
    $kindColor = _KindColor $r.Kind
    $confColor = _ConfColor $r.Conf

    $badge = "OK"
    $badgeColor = "Green"
    if (-not $r.Exists) { $badge = "MISSING"; $badgeColor = "Red" }
    elseif ($r.Blocked) { $badge = "BLOCKED"; $badgeColor = "Red" }

    Write-Host ("[{0}] " -f $r.Id) -ForegroundColor DarkGray -NoNewline
    Write-Host ($r.Kind) -ForegroundColor $kindColor -NoNewline
    Write-Host " | " -ForegroundColor DarkGray -NoNewline
    Write-Host $r.Target -ForegroundColor Gray -NoNewline
    Write-Host " [" -ForegroundColor DarkGray -NoNewline
    Write-Host $badge -ForegroundColor $badgeColor -NoNewline
    Write-Host "]" -ForegroundColor DarkGray

    Write-Host "     Source: " -ForegroundColor DarkGray -NoNewline
    Write-Host ($r.Source) -ForegroundColor Gray -NoNewline
    Write-Host "  Confidence: " -ForegroundColor DarkGray -NoNewline
    Write-Host ($r.Conf) -ForegroundColor $confColor -NoNewline
    Write-Host "  " -ForegroundColor DarkGray -NoNewline
    Write-Host ($r.Meta) -ForegroundColor DarkGray
  }

  Write-Host ""
  UI-Warn "Exclude targets (optional)"
  UI-Note "Enter numbers to EXCLUDE (comma-separated), or press Enter to keep all shown."
  $raw = Read-Host "Exclude"
  $exclude = @{}
  if ($raw) {
    foreach ($part in ($raw -split ",")) {
      $p = $part.Trim()
      if ($p -match "^[0-9]+$") { $exclude[[int]$p] = $true }
    }
  }

  $kept = @()
  foreach ($r in $rows) {
    if ($exclude.ContainsKey($r.Id)) { continue }
    $kept += $r
  }
  return @($kept)
}


# -----------------------------
# Restore point
# -----------------------------
function Try-CreateRestorePoint {
  if (-not $Script:RestorePoint) { return }
  if ($Script:ScanOnly -or $false) { Write-Log "Restore point requested but not created in SCAN-ONLY/LIVE." "INFO"; return }
  try {
    Write-Log "Creating system restore point..." "INFO"
    Checkpoint-Computer -Description ("ZeroTrace Cleanup - " + $env:COMPUTERNAME) -RestorePointType "MODIFY_SETTINGS"
    Write-Log "Restore point created." "OK"
  } catch {
    Write-Log ("Restore point failed (may be disabled): " + $_.Exception.Message) "WARN"
  }
}

# -----------------------------
# RunOnce locked deletes
# -----------------------------
function Add-RunOnceDelete([string[]]$PathsToDelete) {
  if (-not $PathsToDelete -or $PathsToDelete.Count -eq 0) { return }

  if ($Script:ScanOnly -or $false) {
    Write-Log ("Would schedule RunOnce delete for {0} locked item(s)." -f $PathsToDelete.Count) "WARN"
    return
  }

  $cleanupPs1 = Join-Path $env:TEMP ("ZeroTrace_RunOnceDelete_{0:yyyyMMdd_HHmmss}.ps1" -f (Get-Date))
  $lines = New-Object System.Collections.Generic.List[string]
  [void]$lines.Add('$ErrorActionPreference="SilentlyContinue"')
  [void]$lines.Add('function Rm($p){ if(Test-Path -LiteralPath $p){ Remove-Item -LiteralPath $p -Recurse -Force -ErrorAction SilentlyContinue } }')
  foreach ($p in $PathsToDelete) {
    $escaped = $p -replace "'", "''"
    [void]$lines.Add(("Rm '{0}'" -f $escaped))
  }
  $escapedSelf = $cleanupPs1 -replace "'", "''"
  [void]$lines.Add(("Remove-Item -LiteralPath '{0}' -Force -ErrorAction SilentlyContinue" -f $escapedSelf))
  Set-Content -Path $cleanupPs1 -Value $lines -Encoding UTF8

  $cmd = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$cleanupPs1`""
  Invoke-Action "Schedule locked deletes on reboot (RunOnce)" {
    New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce" `
      -Name ("ZeroTraceDelete_{0}" -f ([Guid]::NewGuid().ToString("N"))) `
      -Value $cmd -PropertyType String -Force | Out-Null
  }

  Write-Log ("RunOnce cleanup script: {0}" -f $cleanupPs1) "INFO"
  Write-Log "Locked items scheduled. Reboot required to finish." "WARN"
}

# -----------------------------
# Cleanup ops
# -----------------------------
function Try-RemovePath([string]$Path) {
  if (-not $Path) { return $true }
  if (-not (Test-Path -LiteralPath $Path)) { return $true }
  try {
    Invoke-Action ("Remove path: " + $Path) { Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction Stop }
    return $true
  } catch {
    Write-Log ("Could not remove now (locked/denied): " + $Path + " :: " + $_.Exception.Message) "WARN"
    return $false
  }
}

function Remove-RegistryKeySafe([string]$KeyPath) {
  if (-not $KeyPath) { return $true }
  if (-not (Test-Path -LiteralPath $KeyPath)) { return $true }
  try {
    Invoke-Action ("Remove registry key: " + $KeyPath) { Remove-Item -LiteralPath $KeyPath -Recurse -Force -ErrorAction Stop }
    return $true
  } catch {
    Write-Log ("Could not remove registry key: " + $KeyPath + " :: " + $_.Exception.Message) "WARN"
    return $false
  }
}

function Remove-ServiceSafe([string]$ServiceName) {
  if (-not $ServiceName) { return $true }
  try { $svc = Get-Service -Name $ServiceName -ErrorAction Stop } catch { return $true }

  try {
    if ($svc.Status -ne "Stopped") { Invoke-Action ("Stop service: " + $ServiceName) { Stop-Service -Name $ServiceName -Force -ErrorAction Stop } }
  } catch { Write-Log ("Could not stop service: " + $ServiceName + " :: " + $_.Exception.Message) "WARN" }

  try {
    Invoke-Action ("Delete service: " + $ServiceName) { & sc.exe delete "$ServiceName" | Out-Null }
    return $true
  } catch {
    Write-Log ("Could not delete service: " + $ServiceName + " :: " + $_.Exception.Message) "WARN"
    return $false
  }
}

function Remove-TaskSafe([string]$TaskValue) {
  if (-not $TaskValue) { return $true }
  if (-not (Get-Command Get-ScheduledTask -ErrorAction SilentlyContinue)) { return $true }
  $parts = Split-TaskValue $TaskValue
  $tp = $parts[0]; $tn = $parts[1]
  try { $null = Get-ScheduledTask -TaskPath $tp -TaskName $tn -ErrorAction Stop } catch { return $true }

  try {
    Invoke-Action ("Remove scheduled task: " + $tp + $tn) { Unregister-ScheduledTask -TaskPath $tp -TaskName $tn -Confirm:$false -ErrorAction Stop }
    return $true
  } catch {
    Write-Log ("Could not remove task: " + $tp + $tn + " :: " + $_.Exception.Message) "WARN"
    return $false
  }
}

function Remove-FirewallRuleSafe([string]$DisplayName) {
  if (-not $DisplayName) { return $true }
  if (-not (Get-Command Get-NetFirewallRule -ErrorAction SilentlyContinue)) { return $true }
  try { $null = Get-NetFirewallRule -DisplayName $DisplayName -ErrorAction Stop } catch { return $true }

  try {
    Invoke-Action ("Remove firewall rule: " + $DisplayName) { Remove-NetFirewallRule -DisplayName $DisplayName -ErrorAction Stop }
    return $true
  } catch {
    Write-Log ("Could not remove firewall rule: " + $DisplayName + " :: " + $_.Exception.Message) "WARN"
    return $false
  }
}

function Execute-Cleanup($AuditRows) {
  $locked = New-Object System.Collections.Generic.List[string]

  foreach ($r in @($AuditRows)) {
    if (-not $r.Exists) { continue }

    if ($r.Kind -eq "Path") {
      if ($r.Blocked) { 
        Write-Log ("SKIP (protected): " + $r.Target) "WARN"
        continue
      }
      $ok = Try-RemovePath -Path $r.Target
      if (-not $ok -and (Test-Path -LiteralPath $r.Target)) {
        if (-not $locked.Contains($r.Target)) { [void]$locked.Add($r.Target) }
      }
    }
    elseif ($r.Kind -eq "RegistryKey")   { [void](Remove-RegistryKeySafe -KeyPath $r.Target) }
    elseif ($r.Kind -eq "Service")       { [void](Remove-ServiceSafe -ServiceName $r.Target) }
    elseif ($r.Kind -eq "ScheduledTask") { [void](Remove-TaskSafe -TaskValue $r.Target) }
    elseif ($r.Kind -eq "FirewallRule")  { [void](Remove-FirewallRuleSafe -DisplayName $r.Target) }
  }

  if ($Script:ScanOnly) { Write-Log "Scan complete. No changes were made." "OK"; return }
  if ($locked.Count -gt 0) {
    Write-Log ("Locked items detected: {0}. Scheduling RunOnce cleanup." -f $locked.Count) "WARN"
    Add-RunOnceDelete -PathsToDelete @($locked | Select-Object -Unique)
  } else {
    Write-Log "Cleanup finished. No locked leftovers detected." "OK"
  }
}

function Print-Summary($Kept) {
  $paths = @($Kept | Where-Object { $_.Kind -eq "Path" -and $_.Exists -and (-not $_.Blocked) }).Count
  $regs  = @($Kept | Where-Object { $_.Kind -eq "RegistryKey" -and $_.Exists }).Count
  $svcs  = @($Kept | Where-Object { $_.Kind -eq "Service" -and $_.Exists }).Count
  $tasks = @($Kept | Where-Object { $_.Kind -eq "ScheduledTask" -and $_.Exists }).Count
  $fw    = @($Kept | Where-Object { $_.Kind -eq "FirewallRule" -and $_.Exists }).Count

  $mode = Get-ModeText
  $modeColor = "Green"
  if ($mode -eq "SCAN-ONLY") { $modeColor = "Yellow" }

  Write-Host ""
  UI-Rule 90
  UI-Title "Summary"
  UI-Rule 90

  Write-Host ("Mode     : ") -ForegroundColor DarkGray -NoNewline
  Write-Host $mode -ForegroundColor $modeColor

  Write-Host ("Targets  : ") -ForegroundColor DarkGray -NoNewline
  Write-Host (@($Kept).Count) -ForegroundColor Gray

  Write-Host ("Paths    : ") -ForegroundColor DarkGray -NoNewline
  Write-Host $paths -ForegroundColor Cyan

  Write-Host ("Registry : ") -ForegroundColor DarkGray -NoNewline
  Write-Host $regs -ForegroundColor Magenta

  Write-Host ("Services : ") -ForegroundColor DarkGray -NoNewline
  Write-Host $svcs -ForegroundColor Yellow

  Write-Host ("Tasks    : ") -ForegroundColor DarkGray -NoNewline
  Write-Host $tasks -ForegroundColor Blue

  Write-Host ("Firewall : ") -ForegroundColor DarkGray -NoNewline
  Write-Host $fw -ForegroundColor DarkCyan

  Write-Host ("Log      : ") -ForegroundColor DarkGray -NoNewline
  Write-Host $Script:LogPath -ForegroundColor Gray

  UI-Rule 90
  Write-Host ""
}


# -----------------------------
# Main
# -----------------------------
Ensure-Admin
Show-Banner
Write-Log ("ZeroTrace " + $ZeroTraceVersion + " | Engine " + $EngineVersion + " | Mode: " + (Get-ModeText)) "INFO"
Write-Log ("Log: " + $Script:LogPath) "INFO"

Write-Host "Loading installed applications..."
$apps = Get-InstalledApps
if (-not $apps -or $apps.Count -eq 0) { Write-Log "No installed apps found in uninstall registry." "ERR"; exit 1 }

while ($true) {
  $app = Select-AppInteractive -Apps $apps
  if (-not $app) { break }

  Clear-Host
  Show-Banner

  $pubOut = "-"; if ($app.Publisher) { $pubOut = $app.Publisher }
  $verOut = "-"; if ($app.DisplayVersion) { $verOut = $app.DisplayVersion }
  $locOut = "-"; if ($app.InstallLocation) { $locOut = $app.InstallLocation }

  Write-Host "Selected:"
  Write-Host ("  Name      : {0}" -f $app.DisplayName)
  Write-Host ("  Publisher : {0}" -f $pubOut)
  Write-Host ("  Version   : {0}" -f $verOut)
  Write-Host ("  InstallLoc: {0}" -f $locOut)
  Write-Host ""

  if (-not (Confirm-YN "Continue?" $true)) { continue }

  Write-Host ""
  Write-Host "Running uninstaller..."
  $ok = Invoke-Uninstall -App $app
  if (-not $ok) {
    Write-Log "Uninstall did not run; skipping cleanup." "WARN"
    if (-not (Confirm-YN "Do another app?" $true)) { break }
    continue
  }

  Write-Host ""
  Write-Host "Scanning for leftovers..."
  $targets = @(Build-ScanResult -App $app)
  $auditKept = @(Show-AuditAndSelectTargets -App $app -Targets $targets)

  Write-Host ""
  Write-Host ("Kept Targets: {0}" -f @($auditKept).Count)
  Write-Host ("Mode: {0}  FullCleanup: {1}" -f (Get-ModeText), $Script:FullCleanup)
  Write-Host ("Log: {0}" -f $Script:LogPath)
  Write-Host ""

  if (-not $Script:ScanOnly) {
    UI-Warn "LIVE MODE ENABLED - changes will be permanent."
  }
  if (-not (Confirm-YN "Proceed with kept targets?" $false)) {
    Write-Log "User cancelled at audit confirmation." "WARN"
    if (-not (Confirm-YN "Do another app?" $true)) { break }
    continue
  }

  Try-CreateRestorePoint
  Execute-Cleanup -AuditRows $auditKept
  Print-Summary -Kept $auditKept

  if (-not (Confirm-YN "Do another app?" $true)) { break }
}

Write-Log "Exiting ZeroTrace." "INFO"
Write-Host ("Log saved at: {0}" -f $Script:LogPath)
