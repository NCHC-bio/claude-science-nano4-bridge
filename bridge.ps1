# Everything the bridge needs, in one run. Launched by start-bridge.cmd.
# First run also installs the helper program, asks for your iService account,
# opens the firewall port and writes the SSH entry. Later runs skip straight
# to the login.

# 'Continue', deliberately: with 'Stop', anything a native program writes to
# stderr (uv's own "Installed N packages" line) becomes a fatal error.
$ErrorActionPreference = 'Continue'
$root = Split-Path -Parent $MyInvocation.MyCommand.Definition
Set-Location $root

# Never let the window vanish on an unexpected error.
trap {
    Write-Host ""
    Write-Host "SOMETHING WENT WRONG" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    Write-Host ""
    Write-Host "Where it happened:" -ForegroundColor DarkGray
    Write-Host $_.ScriptStackTrace -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "Copy everything above and send it to whoever maintains this."
    Read-Host "Press Enter to close"
    exit 1
}

$PORT = 2200
$RULE = 'nano4 bridge 2200'
$ALIAS = 'nano4-bridge'
$confPath = Join-Path $root 'bridge.conf'

function Step($t) { Write-Host ""; Write-Host "== $t" -ForegroundColor Cyan }
function Fail($t) {
    Write-Host ""
    Write-Host "STOPPED: $t" -ForegroundColor Red
    Write-Host ""
    Read-Host "Press Enter to close"
    exit 1
}
function Find-Uv {
    $c = Get-Command uv -ErrorAction SilentlyContinue
    if ($c) { return $c.Source }
    foreach ($p in @("$env:USERPROFILE\.local\bin\uv.exe",
                     "$env:LOCALAPPDATA\Programs\uv\uv.exe")) {
        if (Test-Path $p) { return $p }
    }
    return $null
}

# ------------------------------------------------- helper program (first run)
$uv = Find-Uv
if (-not $uv) {
    Step "First run: installing the helper program (about a minute)"
    try {
        Invoke-RestMethod https://astral.sh/uv/install.ps1 | Invoke-Expression
    } catch {
        Fail "could not download the helper program. Check your internet connection."
    }
    $uv = Find-Uv
    if (-not $uv) { Fail "the helper program did not install. Try running this again." }
}
$env:PATH = (Split-Path $uv) + ";" + $env:PATH

# ------------------------------------------------------- settings (first run)
$settings = @{}
if (Test-Path $confPath) {
    foreach ($line in Get-Content $confPath) {
        if ($line -match '^\s*([A-Z_]+)\s*=\s*(.*)$') { $settings[$Matches[1]] = $Matches[2].Trim() }
    }
}
$account = $settings['BRIDGE_USER']
if (-not $account -or $account -eq 'your_account') {
    Step "Your iService account"
    Write-Host "This is the account name you use to log in to the cluster."
    $account = (Read-Host "iService account").Trim()
    if (-not $account) { Fail "an account name is required" }
}

$probe = & $uv run nano4_sshd.py --show-address 2>&1
$addr = ($probe | Where-Object { $_ -match '^\s*\d{1,3}(\.\d{1,3}){3}\s*$' } |
         Select-Object -Last 1)
if ($addr) { $addr = $addr.ToString().Trim() }
if (-not $addr) {
    Write-Host ""
    Write-Host "The helper program could not start. It said:" -ForegroundColor Yellow
    $probe | ForEach-Object { Write-Host "  $_" }
    Fail "could not work out this computer's address"
}

if ($settings['BRIDGE_USER'] -ne $account -or $settings['BRIDGE_EXPECT'] -ne $addr) {
    @(
        "BRIDGE_USER=$account"
        "BRIDGE_HOST=$(if ($settings['BRIDGE_HOST']) { $settings['BRIDGE_HOST'] } else { 'nano4.nchc.org.tw' })"
        "BRIDGE_PORT=$(if ($settings['BRIDGE_PORT']) { $settings['BRIDGE_PORT'] } else { '22' })"
        "BRIDGE_SFTP_PORT=$(if ($settings['BRIDGE_SFTP_PORT']) { $settings['BRIDGE_SFTP_PORT'] } else { '2222' })"
        "BRIDGE_EXPECT=$addr"
    ) | Set-Content -Path $confPath -Encoding ASCII
}

# -------------------------------------------------------- firewall (first run)
$haveFw = [bool](Get-Command Get-NetFirewallRule -ErrorAction SilentlyContinue)
if ($haveFw -and -not (Get-NetFirewallRule -DisplayName $RULE -ErrorAction SilentlyContinue)) {
    Step "Allowing other programs to reach the bridge"
    Write-Host "Windows will ask for permission - please click Yes."
    $cmd = "New-NetFirewallRule -DisplayName '$RULE' -Direction Inbound -Protocol TCP " +
           "-LocalPort $PORT -Action Allow " +
           "-RemoteAddress 172.16.0.0/12,192.168.0.0/16,10.0.0.0/8 | Out-Null"
    try {
        Start-Process powershell -Verb RunAs -Wait -WindowStyle Hidden `
            -ArgumentList '-NoProfile', '-Command', $cmd
    } catch { }
    if (-not (Get-NetFirewallRule -DisplayName $RULE -ErrorAction SilentlyContinue)) {
        Write-Host "Not allowed. The bridge will start, but nothing will be able to"
        Write-Host "reach it. Close this window and run it again, clicking Yes - or ask"
        Write-Host "IT support to allow incoming TCP port $PORT." -ForegroundColor Yellow
    }
}

# ------------------------------------------------------ ssh entry (keep fresh)
$sshDir = Join-Path $env:USERPROFILE '.ssh'
if (-not (Test-Path $sshDir)) { New-Item -ItemType Directory -Path $sshDir | Out-Null }
$cfgPath = Join-Path $sshDir 'config'
$wanted = @("Host $ALIAS", "    HostName $addr", "    Port $PORT", "    User $account",
            "    PreferredAuthentications password", "    PubkeyAuthentication no",
            "    StrictHostKeyChecking accept-new")
$current = if (Test-Path $cfgPath) { Get-Content $cfgPath } else { @() }
if (($current -join "`n") -notmatch [regex]::Escape(($wanted -join "`n"))) {
    $kept = @(); $skip = $false
    foreach ($line in $current) {
        if ($line -match '^\s*Host\s+') { $skip = ($line -match "^\s*Host\s+$ALIAS\s*$") }
        if (-not $skip) { $kept += $line }
    }
    if (Test-Path $cfgPath) { Copy-Item $cfgPath "$cfgPath.backup" -Force }
    ($kept + @("") + $wanted) | Set-Content -Path $cfgPath -Encoding ASCII
    if (Get-Command ssh-keygen -ErrorAction SilentlyContinue) {
        try { & ssh-keygen -R "[$addr]:$PORT" 2>$null | Out-Null } catch { }
    }
}

# ----------------------------------------------------------------- the login
Write-Host ""
Write-Host "-------------------------------------------------------------"
Write-Host " Settings for Claude for Science (Customize -> Compute):"
Write-Host "     Host      $addr"
Write-Host "     Port      $PORT"
Write-Host "     User      $account"
Write-Host "     Password  shown below once you have logged in"
Write-Host "-------------------------------------------------------------"
Write-Host ""
Write-Host "Now log in to the cluster:" -ForegroundColor Cyan
Write-Host "  1) type 1 and press Enter    2) your iService password (nothing"
Write-Host "  appears as you type)         3) the code from your phone app"
Write-Host ""

& $uv run nano4_sshd.py @args

Write-Host ""
Read-Host "Bridge stopped. Press Enter to close"
