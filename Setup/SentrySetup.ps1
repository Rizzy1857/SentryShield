<#
.SYNOPSIS
    SentryShield One-Click Deployment Setup
    Run this ONCE on each target Windows machine after copying the release files.

.DESCRIPTION
    Automates everything in SETUP.md Sections 7-13:
      - Auto-detects Python 3.11 (checks PATH, common install locations, venv)
      - Creates all required directories with correct ACLs
      - Creates Python venv at C:\SentryShield\scripts\venv\
      - pip installs all dependencies
      - Prompts for NVD API key (or reads from env / -NvdApiKey param)
      - Runs init_db.py to bootstrap live CVE database (NVD + CERT-In)
      - Fetches real IOC hashes from MalwareBazaar (no key needed)
      - Creates trusted_suppliers.json template if not present
      - Updates appsettings.json PythonExe to the auto-detected venv path
      - Installs and starts the SentryShield Windows Service
      - Schedules nightly DB sync via Task Scheduler

.PARAMETER NvdApiKey
    NVD API key. If not provided, prompts interactively.
    Get a free key at: https://nvd.nist.gov/developers/request-an-api-key

.PARAMETER DaysBack
    How many days of CVE history to pull on first run. Default: 365.

.PARAMETER Unattended
    Skip all prompts. NvdApiKey must be set as an environment variable
    (NVD_API_KEY) or passed via -NvdApiKey. Used by the MSI installer.

.PARAMETER SkipService
    Skip service installation (useful for dev machines).

.PARAMETER ScriptsRoot
    Override the source directory for SentryPython scripts.
    Default: auto-detected relative to this script.

.EXAMPLE
    # Interactive (recommended for first install)
    .\SentrySetup.ps1

    # Silent with API key (for GPO/MSI deployment)
    .\SentrySetup.ps1 -NvdApiKey "your-key-here" -Unattended

    # Dev mode — no service install
    .\SentrySetup.ps1 -SkipService
#>

[CmdletBinding()]
param(
    [string]$NvdApiKey      = $env:NVD_API_KEY,
    [int]$DaysBack          = 365,
    [switch]$Unattended,
    [switch]$SkipService,
    [string]$ScriptsRoot    = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ─────────────────────────────────────────────────────────────────────────────
# Paths
# ─────────────────────────────────────────────────────────────────────────────
$SENTRY_BIN       = "C:\SentryShield\bin"
$SENTRY_SCRIPTS   = "C:\SentryShield\scripts"
$SENTRY_RULES     = "C:\SentryShield\rules"
$SENTRY_DOWNLOADS = "C:\SentryShield\Downloads"
$SENTRY_DATA      = "C:\ProgramData\SentryShield"
$SENTRY_BACKUPS   = "C:\ProgramData\SentryShield\backups"
$SENTRY_LOGS      = "C:\ProgramData\SentryShield\logs"
$SENTRY_DB        = "C:\ProgramData\SentryShield\vulnerability.db"
$SENTRY_SUPPLIERS = "C:\ProgramData\SentryShield\trusted_suppliers.json"
$SENTRY_VENV_PY   = "C:\SentryShield\scripts\venv\Scripts\python.exe"
$APPSETTINGS      = "C:\SentryShield\bin\appsettings.json"

# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────
function Write-Header([string]$text) {
    Write-Host ""
    Write-Host "══════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  $text" -ForegroundColor Cyan
    Write-Host "══════════════════════════════════════════════" -ForegroundColor Cyan
}

function Write-Step([string]$text) {
    Write-Host "  ► $text" -ForegroundColor White
}

function Write-OK([string]$text) {
    Write-Host "  ✓ $text" -ForegroundColor Green
}

function Write-Warn([string]$text) {
    Write-Host "  ⚠ $text" -ForegroundColor Yellow
}

function Write-Fail([string]$text) {
    Write-Host "  ✗ $text" -ForegroundColor Red
}

# ─────────────────────────────────────────────────────────────────────────────
# Step 0 — Admin check
# ─────────────────────────────────────────────────────────────────────────────
Write-Header "SentryShield Setup v1.0"
Write-Host ""

$currentPrincipal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Fail "This script must be run as Administrator."
    Write-Host "  Right-click PowerShell → Run as Administrator, then retry." -ForegroundColor Yellow
    exit 1
}
Write-OK "Running as Administrator"

# ─────────────────────────────────────────────────────────────────────────────
# Step 1 — Auto-detect Python 3.11
# ─────────────────────────────────────────────────────────────────────────────
Write-Header "Step 1/7 — Detecting Python 3.11"

function Find-Python311 {
    # Priority order: venv (already set up), common install locations, PATH
    $candidates = @(
        $SENTRY_VENV_PY,
        "C:\Python311\python.exe",
        "C:\Python3\python.exe",
        "$env:LOCALAPPDATA\Programs\Python\Python311\python.exe",
        "$env:LOCALAPPDATA\Programs\Python\Python3\python.exe",
        "$env:ProgramFiles\Python311\python.exe"
    )

    # Also check PATH
    $inPath = Get-Command python -ErrorAction SilentlyContinue
    if ($inPath) { $candidates += $inPath.Source }

    $inPath3 = Get-Command python3 -ErrorAction SilentlyContinue
    if ($inPath3) { $candidates += $inPath3.Source }

    foreach ($c in $candidates) {
        if (Test-Path $c) {
            $ver = & $c --version 2>&1
            if ($ver -match "Python 3\.1[01]") {
                return $c
            }
        }
    }
    return $null
}

$pythonExe = Find-Python311

if (-not $pythonExe) {
    Write-Fail "Python 3.11 not found."
    Write-Host "  Install from: https://www.python.org/downloads/release/python-3119/" -ForegroundColor Yellow
    Write-Host "  Then re-run this script." -ForegroundColor Yellow
    exit 1
}

Write-OK "Found Python: $pythonExe"
$pythonVer = & $pythonExe --version 2>&1
Write-OK "Version: $pythonVer"

# ─────────────────────────────────────────────────────────────────────────────
# Step 2 — Create directories
# ─────────────────────────────────────────────────────────────────────────────
Write-Header "Step 2/7 — Creating Directories"

$dirs = @(
    $SENTRY_BIN,
    $SENTRY_SCRIPTS,
    $SENTRY_RULES,
    $SENTRY_DOWNLOADS,
    $SENTRY_DATA,
    $SENTRY_BACKUPS,
    $SENTRY_LOGS
)

foreach ($d in $dirs) {
    if (-not (Test-Path $d)) {
        New-Item -ItemType Directory -Path $d -Force | Out-Null
        Write-OK "Created: $d"
    } else {
        Write-OK "Exists:  $d"
    }
}

# Set ACLs: SYSTEM full control on ProgramData\SentryShield
Write-Step "Setting ACLs on ProgramData\SentryShield..."
try {
    $acl = Get-Acl $SENTRY_DATA
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        "SYSTEM", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
    $acl.SetAccessRule($rule)
    Set-Acl -Path $SENTRY_DATA -AclObject $acl
    Write-OK "ACLs set (SYSTEM: FullControl)"
} catch {
    Write-Warn "Could not set ACLs: $_"
}

# ─────────────────────────────────────────────────────────────────────────────
# Step 3 — Copy scripts if not already in place
# ─────────────────────────────────────────────────────────────────────────────
Write-Header "Step 3/7 — Copying Python Scripts"

# Determine source of Python scripts
if ($ScriptsRoot -eq "") {
    $ScriptsRoot = Join-Path $PSScriptRoot "SentryPython"
    if (-not (Test-Path $ScriptsRoot)) {
        # Try one level up (running from Installer\)
        $ScriptsRoot = Join-Path (Split-Path $PSScriptRoot -Parent) "SentryPython"
    }
}

if (Test-Path $ScriptsRoot) {
    Copy-Item "$ScriptsRoot\*.py" $SENTRY_SCRIPTS -Force
    Write-OK "Scripts copied from: $ScriptsRoot"
} else {
    Write-Warn "SentryPython source not found at '$ScriptsRoot' — assuming scripts already in place."
}

# ─────────────────────────────────────────────────────────────────────────────
# Step 4 — Create Python venv + install dependencies
# ─────────────────────────────────────────────────────────────────────────────
Write-Header "Step 4/7 — Setting Up Python Environment"

$venvPath = Join-Path $SENTRY_SCRIPTS "venv"

if (-not (Test-Path (Join-Path $venvPath "Scripts\python.exe"))) {
    Write-Step "Creating virtual environment at $venvPath..."
    & $pythonExe -m venv $venvPath
    Write-OK "Virtual environment created"
} else {
    Write-OK "Virtual environment already exists"
}

$venvPython = Join-Path $venvPath "Scripts\python.exe"
$venvPip    = Join-Path $venvPath "Scripts\pip.exe"

Write-Step "Installing Python dependencies..."
& $venvPython -m pip install --upgrade pip --quiet
& $venvPython -m pip install yara-python requests schedule --quiet
Write-OK "Dependencies installed: yara-python, requests, schedule"

# Verify YARA
Write-Step "Verifying YARA..."
$yaraCheck = & $venvPython -c "import yara; print('OK')" 2>&1
if ($yaraCheck -eq "OK") {
    Write-OK "YARA import: OK"
} else {
    Write-Warn "YARA import check failed: $yaraCheck"
}

# ─────────────────────────────────────────────────────────────────────────────
# Step 5 — Update appsettings.json with real Python path
# ─────────────────────────────────────────────────────────────────────────────
Write-Header "Step 5/7 — Configuring appsettings.json"

if (Test-Path $APPSETTINGS) {
    $settings = Get-Content $APPSETTINGS -Raw | ConvertFrom-Json
    $settings.Paths.PythonExe = $venvPython
    $settings | ConvertTo-Json -Depth 10 | Set-Content $APPSETTINGS -Encoding UTF8
    Write-OK "Updated PythonExe: $venvPython"
} else {
    Write-Warn "appsettings.json not found at $APPSETTINGS — skipping (run after publishing service)"
}

# ─────────────────────────────────────────────────────────────────────────────
# Step 6 — NVD API key
# ─────────────────────────────────────────────────────────────────────────────
Write-Header "Step 6/7 — NVD API Key"

if (-not $NvdApiKey) {
    if ($Unattended) {
        Write-Warn "No NVD_API_KEY set. Database will sync without a key (slower, rate-limited)."
        Write-Warn "Set NVD_API_KEY as a system environment variable and re-run init_db.py."
    } else {
        Write-Host ""
        Write-Host "  A free NVD API key speeds up the initial database sync 10x." -ForegroundColor Cyan
        Write-Host "  Get one at: https://nvd.nist.gov/developers/request-an-api-key" -ForegroundColor Cyan
        Write-Host ""
        $NvdApiKey = Read-Host "  Enter your NVD API key (press Enter to skip)"
    }
}

if ($NvdApiKey) {
    # Set as system-wide persistent env var (SYSTEM account reads this for scheduled task)
    [System.Environment]::SetEnvironmentVariable("NVD_API_KEY", $NvdApiKey, "Machine")
    $env:NVD_API_KEY = $NvdApiKey
    Write-OK "NVD_API_KEY set as system environment variable"
} else {
    Write-Warn "No API key — proceeding without (rate-limited to 5 req/30s)"
}

# ─────────────────────────────────────────────────────────────────────────────
# Step 7 — Bootstrap vulnerability database
# ─────────────────────────────────────────────────────────────────────────────
Write-Header "Step 7/7 — Initialising Vulnerability Database"

$initScript = Join-Path $SENTRY_SCRIPTS "init_db.py"
if (Test-Path $initScript) {
    Write-Step "Running init_db.py (pulling $DaysBack days of CVEs from NVD + CERT-In)..."
    Write-Host "  This may take 15–30 minutes depending on your API key status." -ForegroundColor Yellow
    Write-Host ""

    $initArgs = @("$initScript", "--db", $SENTRY_DB, "--days-back", $DaysBack)
    & $venvPython @initArgs

    if ($LASTEXITCODE -eq 0) {
        Write-OK "Vulnerability database bootstrapped: $SENTRY_DB"
    } else {
        Write-Warn "init_db.py exited with code $LASTEXITCODE — check output above"
    }
} else {
    Write-Warn "init_db.py not found at $initScript — skipping DB bootstrap"
}

# Fetch real IOC hashes from MalwareBazaar
$iocScript = Join-Path $SENTRY_SCRIPTS "ioc_populate.py"
if (Test-Path $iocScript) {
    Write-Step "Fetching real IOC hashes from MalwareBazaar..."
    $tags = @("ransomware", "rat", "loader")
    foreach ($tag in $tags) {
        Write-Step "  Tag: $tag"
        & $venvPython $iocScript --db $SENTRY_DB --malwarebazaar --tag $tag
    }
    Write-OK "IOC hashes populated from MalwareBazaar (live, real hashes)"
} else {
    Write-Warn "ioc_populate.py not found — skipping IOC population"
}

# ─────────────────────────────────────────────────────────────────────────────
# Trusted supplier template (created if not present, never overwritten)
# ─────────────────────────────────────────────────────────────────────────────
if (-not (Test-Path $SENTRY_SUPPLIERS)) {
    $template = @'
[
  {
    "SupplierName": "Siemens",
    "ContactEmail": "security@siemens.com",
    "ExpectedHashes": {}
  },
  {
    "SupplierName": "Schneider Electric",
    "ContactEmail": "psirt@schneider-electric.com",
    "ExpectedHashes": {}
  }
]
'@
    Set-Content -Path $SENTRY_SUPPLIERS -Value $template -Encoding UTF8
    Write-OK "Created trusted_suppliers.json template at $SENTRY_SUPPLIERS"
    Write-Warn "Edit $SENTRY_SUPPLIERS to add your actual suppliers before using the gateway."
} else {
    Write-OK "trusted_suppliers.json already exists — not overwritten"
}

# ─────────────────────────────────────────────────────────────────────────────
# Windows Service install (skip if -SkipService)
# ─────────────────────────────────────────────────────────────────────────────
if (-not $SkipService) {
    Write-Header "Installing Windows Service"

    $serviceExe = Join-Path $SENTRY_BIN "SentryService.exe"
    if (Test-Path $serviceExe) {
        $existing = Get-Service -Name "SentryShield" -ErrorAction SilentlyContinue
        if ($existing) {
            Write-Step "Service already exists — stopping and removing..."
            Stop-Service -Name "SentryShield" -Force -ErrorAction SilentlyContinue
            sc.exe delete SentryShield | Out-Null
            Start-Sleep 2
        }

        Write-Step "Registering SentryShield service..."
        sc.exe create SentryShield binPath= "`"$serviceExe`"" start= auto DisplayName= "SentryShield Security Agent" | Out-Null
        sc.exe description SentryShield "SentryShield offline vulnerability scanner and USB threat monitor for manufacturing environments." | Out-Null
        sc.exe start SentryShield | Out-Null

        Start-Sleep 3
        $svc = Get-Service -Name "SentryShield" -ErrorAction SilentlyContinue
        if ($svc -and $svc.Status -eq "Running") {
            Write-OK "SentryShield service started successfully"
        } else {
            Write-Warn "Service may not have started — check Event Viewer > Application > SentryShield"
        }
    } else {
        Write-Warn "SentryService.exe not found at $serviceExe — skipping service install"
        Write-Warn "Publish the service first: dotnet publish SentryService -c Release -r win-x64 -o $SENTRY_BIN"
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# Task Scheduler — nightly DB sync
# ─────────────────────────────────────────────────────────────────────────────
Write-Header "Scheduling Nightly DB Sync"

$taskName   = "SentryShield DB Sync"
$taskAction = "`"$venvPython`" `"$(Join-Path $SENTRY_SCRIPTS 'db_sync.py')`" --db `"$SENTRY_DB`" --once"

# Remove if already exists
schtasks /delete /tn $taskName /f 2>&1 | Out-Null

schtasks /create `
    /tn $taskName `
    /tr $taskAction `
    /sc DAILY `
    /st "06:00" `
    /ru "SYSTEM" `
    /f | Out-Null

if ($LASTEXITCODE -eq 0) {
    Write-OK "Scheduled task created: '$taskName' — runs daily at 06:00"
} else {
    Write-Warn "Could not create scheduled task (exit $LASTEXITCODE)"
}

# ─────────────────────────────────────────────────────────────────────────────
# Done
# ─────────────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "══════════════════════════════════════════════════════" -ForegroundColor Green
Write-Host "  SentryShield Setup Complete" -ForegroundColor Green
Write-Host "══════════════════════════════════════════════════════" -ForegroundColor Green
Write-Host ""
Write-Host "  Database  : $SENTRY_DB" -ForegroundColor White
Write-Host "  Suppliers : $SENTRY_SUPPLIERS" -ForegroundColor White
Write-Host "  Service   : sc query SentryShield" -ForegroundColor White
Write-Host "  DB sync   : schtasks /query /tn '$taskName'" -ForegroundColor White
Write-Host ""
Write-Host "  NEXT STEPS:" -ForegroundColor Yellow
Write-Host "  1. Edit $SENTRY_SUPPLIERS with your actual supplier names" -ForegroundColor Yellow
Write-Host "  2. Open SentryUI.exe to verify findings are populating" -ForegroundColor Yellow
Write-Host "  3. Drop a test file in $SENTRY_DOWNLOADS\<SupplierName>\ to test the gateway" -ForegroundColor Yellow
Write-Host ""
