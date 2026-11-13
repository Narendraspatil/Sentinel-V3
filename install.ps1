<#
.SYNOPSIS
  Sentinel laptop installer. Downloads the signed-off release from GitHub, verifies it, registers this
  laptop with your Sentinel server and starts the protection service.

.EXAMPLE
  .\install.ps1 -Code 'SNTL1.xxxxxxxx'          # install / register
  .\install.ps1 -Code '...' -Reenroll           # wipe the old registration and register again
  .\install.ps1 -Uninstall                      # remove the service and program files (keeps logs)
  .\install.ps1 -Uninstall -PurgeData           # ...and delete logs, buffer and credentials too
#>
[CmdletBinding()]
param(
  [string]$Code,
  [string]$Name = $env:COMPUTERNAME,
  [string]$Repo = 'Narendraspatil/Sentinel-V3',
  [string]$Tag  = 'latest',
  [switch]$Reenroll,
  [switch]$Uninstall,
  [switch]$PurgeData,
  [switch]$Elevated
)
$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'
try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}

$Service   = 'SentinelAgent'
$InstallDir = Join-Path $env:ProgramFiles 'Sentinel'
$DataDir    = Join-Path $env:ProgramData  'Sentinel'
$Exe        = Join-Path $InstallDir 'SentinelAgent.exe'

function Say([string]$m, [string]$c = 'Cyan') { Write-Host "[Sentinel] $m" -ForegroundColor $c }
function Stop-WithError([string]$m) {
  Write-Host "[Sentinel] PROBLEM: $m" -ForegroundColor Red
  if ($Host.Name -eq 'ConsoleHost') { Read-Host 'Press Enter to close' | Out-Null }
  exit 1
}

# ── 1. Administrator rights (re-launches itself with the normal Windows permission prompt) ──
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  if ($Elevated -or -not $PSCommandPath) { Stop-WithError 'Administrator permission is required. Right-click PowerShell, choose "Run as administrator", and try again.' }
  if (-not $Uninstall -and -not $Code) { $Code = Read-Host 'Paste your Sentinel install code' }
  Say 'Windows will ask for permission to continue. Please click Yes.'
  $a = @('-NoProfile','-ExecutionPolicy','Bypass','-File',"`"$PSCommandPath`"",'-Name',"`"$Name`"",'-Repo',$Repo,'-Tag',$Tag,'-Elevated')
  if ($Code)      { $a += @('-Code', "`"$Code`"") }
  if ($Reenroll)  { $a += '-Reenroll' }
  if ($Uninstall) { $a += '-Uninstall' }
  if ($PurgeData) { $a += '-PurgeData' }
  try { Start-Process -FilePath powershell.exe -Verb RunAs -ArgumentList $a } catch { Stop-WithError 'Permission was not granted.' }
  exit 0
}

function Get-ServiceState { $o = (& sc.exe query $Service 2>&1 | Out-String); if ($o -match 'RUNNING') {'RUNNING'} elseif ($o -match 'STOPPED') {'STOPPED'} elseif ($o -match '1060') {'MISSING'} else {'OTHER'} }
function Stop-SentinelService {
  if ((Get-ServiceState) -eq 'MISSING') { return }
  & sc.exe stop $Service | Out-Null
  for ($i = 0; $i -lt 30; $i++) { if ((Get-ServiceState) -in 'STOPPED','MISSING') { break }; Start-Sleep -Seconds 1 }
}
function Lock-Folder([string]$p) {
  & icacls.exe $p /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
}

# ── Uninstall ──
if ($Uninstall) {
  Say 'Removing Sentinel...'
  Stop-SentinelService
  if ((Get-ServiceState) -ne 'MISSING') { & sc.exe delete $Service | Out-Null }
  if (Test-Path $InstallDir) { Remove-Item -Recurse -Force $InstallDir }
  if ($PurgeData -and (Test-Path $DataDir)) { Remove-Item -Recurse -Force $DataDir }
  Say 'Sentinel was removed from this computer. Remember to revoke the device in the dashboard.' 'Green'
  exit 0
}

# ── 2. Validate input and system ──
if ($Code) { $Code = $Code.Trim() }
if (-not $Code) { $Code = (Read-Host 'Paste your Sentinel install code').Trim() }
if ($Code -notmatch '^SNTL1\.[A-Za-z0-9_-]{20,}$') { Stop-WithError 'That install code does not look right. Copy the whole command again from the Sentinel dashboard.' }
if (-not [Environment]::Is64BitOperatingSystem) { Stop-WithError 'This version needs 64-bit Windows 10 or 11.' }
if ([Environment]::OSVersion.Version.Major -lt 10) { Stop-WithError 'This version needs Windows 10 or 11.' }
if ($Name -notmatch '^[\w .()-]{1,100}$') { $Name = $env:COMPUTERNAME }

# ── 3. Download the release from GitHub and verify it ──
$base = if ($Tag -eq 'latest') { "https://github.com/$Repo/releases/latest/download" } else { "https://github.com/$Repo/releases/download/$Tag" }
$tmp  = Join-Path $env:TEMP ("sentinel-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
  Say 'Downloading Sentinel from GitHub...'
  try {
    Invoke-WebRequest -UseBasicParsing -Uri "$base/SentinelAgent.exe"        -OutFile (Join-Path $tmp 'SentinelAgent.exe')
    Invoke-WebRequest -UseBasicParsing -Uri "$base/SentinelAgent.exe.sha256" -OutFile (Join-Path $tmp 'SentinelAgent.exe.sha256')
  } catch { Stop-WithError "Could not download from GitHub ($($_.Exception.Message)). Check the internet connection, and that the repository and its release are public." }

  $expected = ((Get-Content (Join-Path $tmp 'SentinelAgent.exe.sha256') -Raw).Trim() -split '\s+')[0].ToLower()
  $actual   = (Get-FileHash -Algorithm SHA256 (Join-Path $tmp 'SentinelAgent.exe')).Hash.ToLower()
  if ($expected -notmatch '^[0-9a-f]{64}$' -or $expected -ne $actual) { Stop-WithError 'The downloaded file failed its integrity check, so it was NOT installed.' }
  Say 'Download verified.' 'Green'

  # ── 4. Install files ──
  $registered = (Test-Path (Join-Path $DataDir 'config.json')) -and (Test-Path (Join-Path $DataDir 'secret.bin'))
  Stop-SentinelService
  if ($Reenroll -and (Test-Path $DataDir)) { Remove-Item -Recurse -Force $DataDir; $registered = $false }
  if (-not (Test-Path $InstallDir)) { New-Item -ItemType Directory -Path $InstallDir | Out-Null }
  Copy-Item -Force (Join-Path $tmp 'SentinelAgent.exe') $Exe
  Lock-Folder $InstallDir

  # ── 5. Windows auditing so login / account events are recorded (language-independent GUIDs) ──
  $audit = @{ '{0CCE9215-69AE-11D9-BED3-505054503030}'='/success:enable /failure:enable';   # Logon
              '{0CCE9216-69AE-11D9-BED3-505054503030}'='/success:enable';                    # Logoff
              '{0CCE9217-69AE-11D9-BED3-505054503030}'='/failure:enable';                    # Account Lockout
              '{0CCE9235-69AE-11D9-BED3-505054503030}'='/success:enable /failure:enable';   # User Account Management
              '{0CCE9237-69AE-11D9-BED3-505054503030}'='/success:enable /failure:enable';   # Security Group Management
              '{0CCE922F-69AE-11D9-BED3-505054503030}'='/success:enable' }                   # Audit Policy Change
  foreach ($k in $audit.Keys) { & auditpol.exe /set "/subcategory:$k" ($audit[$k] -split ' ') 2>&1 | Out-Null }

  # ── 6. Register this laptop ──
  if ($registered) {
    Say 'This laptop is already registered - program files were updated and the existing registration was kept.' 'Yellow'
  } else {
    Say "Registering this laptop as '$Name'..."
    & $Exe register --code $Code --name $Name
    if ($LASTEXITCODE -ne 0) { Stop-WithError 'Registration failed. The install code may already be used or expired - ask your administrator for a new one.' }
  }

  # ── 7. Install and start the service ──
  & $Exe install
  if ($LASTEXITCODE -ne 0) { Stop-WithError 'The Sentinel service could not be installed.' }
  & $Exe start | Out-Null
  Start-Sleep -Seconds 5
  if ((Get-ServiceState) -ne 'RUNNING') { Stop-WithError "The service did not start. See $DataDir\logs\sentinel.log, or run: `"$Exe`" status" }
  Say 'Sentinel is installed and running. This laptop should appear as Online in the dashboard within a minute.' 'Green'
}
finally { Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue }
if ($Host.Name -eq 'ConsoleHost' -and $Elevated) { Read-Host 'Press Enter to close' | Out-Null }
