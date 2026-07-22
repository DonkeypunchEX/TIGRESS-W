<#
.SYNOPSIS
    TIGRESS launcher for Windows (PowerShell counterpart of tigress_launcher.sh).

.DESCRIPTION
    Starts the TIGRESS FastAPI dashboard in the background, optionally verifying
    the signed boot manifest first. Runs the same cross-platform pipeline the
    Termux launcher does — only the process/notification plumbing is native.

.PARAMETER Secure
    Verify the boot manifest before starting; abort if verification fails.

.PARAMETER Train
    Start in model-training mode.

.PARAMETER Dummy
    Use synthetic sensors (no real WiFi/Bluetooth scanning).

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\tigress_launcher.ps1 -Dummy
#>
[CmdletBinding()]
param(
    [switch]$Secure,
    [switch]$Train,
    [switch]$Dummy
)

$ErrorActionPreference = 'Stop'

Write-Host 'TIGRESS - Threat Intelligence Grid'
Write-Host '======================================'

# Run from the repository root (parent of this script's directory).
Set-Location (Join-Path $PSScriptRoot '..')

# So `from src...` imports resolve without an install step.
$env:PYTHONPATH = '.'

$pythonCmd = Get-Command python -ErrorAction SilentlyContinue
if (-not $pythonCmd) { $pythonCmd = Get-Command python3 -ErrorAction SilentlyContinue }
if (-not $pythonCmd) {
    Write-Error 'python not found on PATH'
    exit 1
}
$python = $pythonCmd.Source

foreach ($dir in 'data/raw', 'data/alerts', 'data/audit', 'models', 'config/secure') {
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
}

if ($Secure) {
    Write-Host 'Verifying secure boot...'
    & $python -c @'
from src.security.secure_boot import SecureBoot
import sys
sb = SecureBoot()
if not sb.verify_manifest():
    print('Boot verification failed - system may be compromised')
    sys.exit(1)
print('Boot verification passed')
'@
    if ($LASTEXITCODE -ne 0) { exit 1 }
}

$cmdArgs = @('-m', 'src.dashboard.app')
if ($Dummy) { $cmdArgs += '--dummy' }
if ($Train) { $cmdArgs += '--train' }
if ($Secure) { $cmdArgs += '--secure' }

$logPath = 'data/tigress.log'
$proc = Start-Process -FilePath $python -ArgumentList $cmdArgs `
    -RedirectStandardOutput $logPath -RedirectStandardError 'data/tigress.err.log' `
    -WindowStyle Hidden -PassThru

$proc.Id | Out-File -FilePath 'data/tigress.pid' -Encoding ascii

$mode = if ($Secure) { 'SECURE' } else { 'standard' }
if ($Train) { $mode += ' [training]' }

Write-Host "TIGRESS running (PID $($proc.Id))"
Write-Host "   Mode: $mode"
Write-Host 'Dashboard: http://127.0.0.1:8080'
Write-Host ''
Write-Host "Logs:  Get-Content -Wait $logPath"
Write-Host 'Stop:  Stop-Process -Id (Get-Content data/tigress.pid)'
