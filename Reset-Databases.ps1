param(
    [switch]$Force
)

$ErrorActionPreference = "Stop"

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "       SentryShield Database Reset" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan

$dbDir = "C:\ProgramData\SentryShield"

if (-not $Force) {
    $confirm = Read-Host "This will delete all vulnerabilities, history, and active threats in $dbDir. Are you sure? (Y/N)"
    if ($confirm -notmatch "^[Yy]$") {
        Write-Host "Reset cancelled." -ForegroundColor Yellow
        exit
    }
}

Write-Host "Stopping SentryShield services..." -ForegroundColor DarkGray
Stop-Process -Name SentryService -ErrorAction SilentlyContinue -Force
Stop-Process -Name SentryLegacyService -ErrorAction SilentlyContinue -Force
Stop-Process -Name SentryUI -ErrorAction SilentlyContinue -Force

$filesToDelete = @(
    "vulnerability.db",
    "sentry.db",
    "sentry_history.db"
)

foreach ($file in $filesToDelete) {
    $path = Join-Path $dbDir $file
    if (Test-Path $path) {
        Remove-Item $path -Force
        Write-Host "Deleted: $path" -ForegroundColor Green
    } else {
        Write-Host "Not found: $path (Skipping)" -ForegroundColor DarkGray
    }
}

Write-Host "`nDatabase reset complete! The databases will be recreated on next run." -ForegroundColor Cyan
