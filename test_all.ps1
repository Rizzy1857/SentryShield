param(
    [switch]$BuildOnly
)

$ErrorActionPreference = "Stop"

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "         SentryShield Test Runner         " -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan

# Handle UNC paths in Parallels
Set-Location -Path $PSScriptRoot

Write-Host "--> Cleaning previous test builds..." -ForegroundColor DarkGray
dotnet clean Tests/SentryCore.Tests/SentryCore.Tests.csproj --configuration Debug --nologo -v q

if ($BuildOnly) {
    Write-Host "--> Building Tests..." -ForegroundColor Cyan
    dotnet build Tests/SentryCore.Tests/SentryCore.Tests.csproj --configuration Debug
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Build failed." -ForegroundColor Red
        exit $LASTEXITCODE
    }
    Write-Host "Tests built successfully." -ForegroundColor Green
    exit 0
}

Write-Host "--> Running Unit Tests..." -ForegroundColor Cyan
# Run the tests with detailed output
dotnet test Tests/SentryCore.Tests/SentryCore.Tests.csproj --configuration Debug --verbosity normal

if ($LASTEXITCODE -ne 0) {
    Write-Host ""
    Write-Host "❌ Some tests failed. Check the output above." -ForegroundColor Red
} else {
    Write-Host ""
    Write-Host "✅ All tests passed successfully!" -ForegroundColor Green
}

Write-Host "Done." -ForegroundColor Cyan
