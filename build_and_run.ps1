param(
    [switch]$BuildOnly,
    [switch]$RunOnly,
    [switch]$ForceLegacy
)

$ErrorActionPreference = "Stop"

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host " SentryShield Intelligent Launcher" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan

# Handle UNC paths in Parallels
Set-Location -Path $PSScriptRoot

# 1. Detect Environment
$osVersion = [Environment]::OSVersion.Version
$isModernOs = $osVersion.Major -ge 10

$isNet10Installed = $false
try {
    $sdks = dotnet --list-sdks 2>$null
    if ($sdks -match "10\.") {
        $isNet10Installed = $true
    }
} catch {
    # dotnet command not found
}

$isLegacy = -not ($isModernOs -and $isNet10Installed)

if ($ForceLegacy) {
    Write-Host "[!] Forcing Legacy Mode via parameter." -ForegroundColor Yellow
    $isLegacy = $true
}

# 2. Build & Run Logic
if ($isLegacy) {
    Write-Host "Detected Environment: LEGACY (Pre-Windows 10 or missing .NET 10)" -ForegroundColor Yellow
    Write-Host "Target Framework  : net48" -ForegroundColor Gray
    
    if (-not $RunOnly) {
        Write-Host "`n--> Cleaning up old processes..." -ForegroundColor DarkGray
        Stop-Process -Name SentryLegacyService -ErrorAction SilentlyContinue -Force
        
        Write-Host "`n--> Building SentryLegacyService..." -ForegroundColor Cyan
        # Only build the legacy project. This skips the modern projects and prevents NU1702 conflicts.
        dotnet build SentryLegacyService/SentryLegacyService.csproj --configuration Debug --framework net48
        if ($LASTEXITCODE -ne 0) {
            Write-Host "Build failed." -ForegroundColor Red
            exit $LASTEXITCODE
        }
    }

    if (-not $BuildOnly) {
        Write-Host "`n--> Launching SentryLegacyService..." -ForegroundColor Green
        Start-Process "SentryLegacyService\bin\Debug\net48\SentryLegacyService.exe"
    }

} else {
    Write-Host "Detected Environment: MODERN (Windows 10+ and .NET 10 installed)" -ForegroundColor Green
    Write-Host "Target Framework  : net10.0-windows" -ForegroundColor Gray
    
    if (-not $RunOnly) {
        Write-Host "`n--> Cleaning up old processes..." -ForegroundColor DarkGray
        Stop-Process -Name SentryService -ErrorAction SilentlyContinue -Force
        Stop-Process -Name SentryUI -ErrorAction SilentlyContinue -Force
        
        Write-Host "`n--> Building SentryService & SentryUI..." -ForegroundColor Cyan
        
        dotnet build SentryService/SentryService.csproj --configuration Debug --framework net10.0-windows
        if ($LASTEXITCODE -ne 0) {
            Write-Host "Build failed for SentryService." -ForegroundColor Red
            exit $LASTEXITCODE
        }

        dotnet build SentryUI/SentryUI.csproj --configuration Debug --framework net10.0-windows
        if ($LASTEXITCODE -ne 0) {
            Write-Host "Build failed for SentryUI." -ForegroundColor Red
            exit $LASTEXITCODE
        }
    }

    if (-not $BuildOnly) {
        Write-Host "`n--> Launching Modern Services..." -ForegroundColor Green
        # Start Service headless
        Start-Process "SentryService\bin\Debug\net10.0-windows\SentryService.exe" -WindowStyle Hidden
        # Start UI and capture output (blocks the console so we can see errors)
        Write-Host "Running SentryUI via dotnet run..." -ForegroundColor Cyan
        dotnet run --project SentryUI/SentryUI.csproj --no-build --framework net10.0-windows
    }
}

Write-Host "`nDone." -ForegroundColor Cyan
