<#
.SYNOPSIS
  Installs (or removes) the CheckPoint Zero endpoint agent on Windows.

.DESCRIPTION
  Registers checkpointd as a task that runs as LocalSystem at boot and is restarted by Windows if it exits,
  locks its state directory to SYSTEM and Administrators, and optionally installs the checkpoint.sys
  minifilter (test-signed builds need `bcdedit /set testsigning on` and a reboot first).

  Running as SYSTEM, the agent protects the credential folders of every local user, not only the installer's.

.EXAMPLE
  .\agent\windows\install.ps1 -Server https://aiedr.example.com -EnrollToken <token> -Watch C:\work
.EXAMPLE
  .\agent\windows\install.ps1 -Driver .\agent\kernel\windows\x64\Release\checkpoint\checkpoint.inf
.EXAMPLE
  .\agent\windows\install.ps1 -Uninstall
#>
[CmdletBinding()]
param(
    [string]$Server = "http://127.0.0.1:8080",
    [string]$EnrollToken = "enroll-demo-default",
    [string]$StateDir = "$env:ProgramData\checkpointd",
    [string[]]$Watch = @(),
    [string[]]$AiProcess = @(),
    [ValidateSet("CANARY", "EARLY", "BROAD", "GA")][string]$Ring = "BROAD",
    [string]$Python = "",
    [string]$Driver = "",
    [switch]$NoStart,
    [switch]$Uninstall
)
$ErrorActionPreference = "Stop"
$TaskName = "CheckPointZero-checkpointd"
$Root = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path

$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) { throw "Run this from an elevated PowerShell (Run as administrator)." }

if ($Uninstall) {
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
        Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    }
    # the task stops python.exe; make sure no agent is left behind
    Get-CimInstance Win32_Process -Filter "Name like 'python%'" |
        Where-Object { $_.CommandLine -like "*agent.checkpointd*" } |
        ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
    if ((fltmc filters) -match "^checkpoint\s") { fltmc unload checkpoint | Out-Null }
    Write-Host "checkpointd removed (state kept in $StateDir)"
    return
}

if (-not $Python) {
    $venv = Join-Path $Root ".venv\Scripts\python.exe"
    $Python = if (Test-Path $venv) { $venv } else { (Get-Command python -ErrorAction Stop).Source }
}
& $Python -c "import psutil, cryptography, httpx" 2>$null
if ($LASTEXITCODE -ne 0) { throw "$Python is missing dependencies: run  $Python -m pip install -r requirements.txt" }

New-Item -ItemType Directory -Force -Path $StateDir | Out-Null
icacls $StateDir /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" | Out-Null   # SYSTEM, Administrators

$argv = @("-m", "agent.checkpointd", "--server", $Server, "--enroll-token", $EnrollToken, "--state-dir", $StateDir,
          "--ring", $Ring, "--log-file", (Join-Path $StateDir "checkpointd.log"))
foreach ($w in $Watch) { $argv += @("--watch", (Resolve-Path $w).Path) }
foreach ($a in $AiProcess) { $argv += @("--ai-process", $a) }
$argString = ($argv | ForEach-Object { if ($_ -match '[\s"]') { '"' + ($_ -replace '"', '\"') + '"' } else { $_ } }) -join " "

$action = New-ScheduledTaskAction -Execute $Python -Argument $argString -WorkingDirectory $Root
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId "S-1-5-18" -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) `
    -ExecutionTimeLimit ([TimeSpan]::Zero) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable `
    -MultipleInstances IgnoreNew
Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings `
    -Description "CheckPoint Zero AI-EDR endpoint agent" -Force | Out-Null

if ($Driver) {
    pnputil /add-driver (Resolve-Path $Driver).Path /install
    if ($LASTEXITCODE -ne 0) { throw "driver install failed (test signing on? bcdedit /set testsigning on + reboot)" }
    fltmc load checkpoint
    if ($LASTEXITCODE -ne 0) { throw "fltmc load checkpoint failed" }
}

if (-not $NoStart) { Start-ScheduledTask -TaskName $TaskName }
Write-Host "checkpointd installed: task '$TaskName' (LocalSystem, starts at boot)"
Write-Host "  server  $Server   ring $Ring   state $StateDir"
Write-Host "  log     $(Join-Path $StateDir 'checkpointd.log')"
