#Requires -Version 5.1
<#
.SYNOPSIS
    Zero-side-effect M0 + M1 + M2 + M3 + M4 + M5 offline unit, boundary, SSHv2, QUIC v1/v2,
    Engine C ABI, Helper Protocol v8 Chaos Watchdog, SPSC Shared Ring, and 50-Theme verification suite.
    Never modifies host routing tables, system proxy, Windows Firewall/WFP, or DNS settings.
#>
[CmdletBinding()]
param(
    [string]$BuildDir = "",
    [int]$QuicBasePort = 25440
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
if (-not $BuildDir) {
    $BuildDir = Join-Path $RepoRoot ".build\cmake-win-x64"
}
if (-not (Test-Path -LiteralPath $BuildDir)) {
    throw "CMake build directory not found: $BuildDir. Build the project first."
}

function Write-Phase([string]$Title) {
    Write-Host "`n============================================================" -ForegroundColor Cyan
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan
}

function Find-TestBinary([string]$Name) {
    $candidates = @(
        (Join-Path $BuildDir "$Name.exe"),
        (Join-Path $BuildDir "Release\$Name.exe"),
        (Join-Path $BuildDir "Debug\$Name.exe")
    )
    foreach ($c in $candidates) {
        if (Test-Path -LiteralPath $c) { return $c }
    }
    throw "Test binary '$Name.exe' not found under $BuildDir"
}

# ============================================================================
# Phase 1: CTest Offline Unit, Codec, Routing, Protocol, Engine & Helper Checks
# ============================================================================
Write-Phase "Phase 1: CTest M0–M5 Offline Native Checks (DataPlane, Flow, Routing, 15-Proto, Engine, Helper)"
& ctest.exe --test-dir "$BuildDir" -C Release --output-on-failure --verbose
if ($LASTEXITCODE -ne 0) {
    throw "CTest suite failed with exit code $LASTEXITCODE"
}

# ============================================================================
# Phase 2: Explicit M2/M3/M5 Binary Self-Tests & Diagnostics Verification
# ============================================================================
Write-Phase "Phase 2: M2–M5 Engine Loopback, Helper Watchdog Chaos & Portable Launcher Gates"
$BenchV2Bin = Find-TestBinary "dataplane-v2-bench-check"
& $BenchV2Bin
if ($LASTEXITCODE -ne 0) { throw "dataplane-v2-bench-check failed with code $LASTEXITCODE" }

$EngineLoopbackBin = Find-TestBinary "engine-loopback-check"
& $EngineLoopbackBin
if ($LASTEXITCODE -ne 0) { throw "engine-loopback-check failed with code $LASTEXITCODE" }

$HelperBin = Find-TestBinary "HajimiHelperService"
& $HelperBin --self-test
if ($LASTEXITCODE -ne 0) { throw "HajimiHelperService --self-test failed with code $LASTEXITCODE" }

$CliBin = Find-TestBinary "hajimi-cli"
& $CliBin --self-test
if ($LASTEXITCODE -ne 0) { throw "hajimi-cli --self-test failed with code $LASTEXITCODE" }

$diagJson = & $CliBin --diagnostics
if ($LASTEXITCODE -ne 0 -or ($diagJson -notmatch '"ok":true')) {
    throw "hajimi-cli --diagnostics failed: $diagJson"
}

$PortableBin = Find-TestBinary "HajimiPortable"
& $PortableBin --self-test
if ($LASTEXITCODE -ne 0) { throw "HajimiPortable --self-test failed with code $LASTEXITCODE" }

# Validate M4 50-Theme JSON pack integrity
$ThemePack = Join-Path $RepoRoot "SharedAssets\Themes\hajimi-all-50-themes-pack.hajimitheme.json"
if (-not (Test-Path -LiteralPath $ThemePack)) {
    $ThemePack = Join-Path $RepoRoot "Resources\Themes\hajimi-all-50-themes-pack.hajimitheme.json"
}
$themeObj = Get-Content -LiteralPath $ThemePack -Raw -Encoding UTF8 | ConvertFrom-Json
if ($themeObj.themes.Count -lt 50) {
    throw "Expected 50 built-in themes in hajimi-all-50-themes-pack.hajimitheme.json, found $($themeObj.themes.Count)"
}
Write-Host "[PASS] Verified $($themeObj.themes.Count) built-in UI themes in hajimi-all-50-themes-pack.hajimitheme.json" -ForegroundColor Green

# ============================================================================
# Prepare Isolated Workspace-Local Python Venv for SSHv2 & QUIC Interop Peers
# ============================================================================
$VenvDir = Join-Path $RepoRoot ".build\WinInteropVenv"
$VenvPython = Join-Path $VenvDir "Scripts\python.exe"
if (-not (Test-Path -LiteralPath $VenvPython)) {
    Write-Phase "Creating isolated Python venv at $VenvDir"
    & python.exe -m venv "$VenvDir"
    if ($LASTEXITCODE -ne 0) { throw "Failed to create Python venv" }
}

& $VenvPython -c "import paramiko, aioquic, cryptography" 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Phase "Installing pinned loopback interop peers (paramiko==3.5.1, aioquic==1.3.0)"
    & $VenvPython -m pip install --upgrade pip --quiet
    & $VenvPython -m pip install --only-binary=:all: `
        "cryptography==44.0.3" `
        "pyopenssl==25.1.0" `
        "service-identity==24.2.0" `
        "aioquic==1.3.0" `
        "paramiko==3.5.1"
    if ($LASTEXITCODE -ne 0) { throw "Failed to install Python interop fixture packages" }
}

# ============================================================================
# Phase 3: Live Loopback SSHv2 Interop (paramiko <-> HajimiProtocolsCXX/SSH)
# ============================================================================
Write-Phase "Phase 3: Live Loopback SSHv2 Interop & Boundary Checks"
$SshBin = Find-TestBinary "SSH-check"
& $VenvPython (Join-Path $RepoRoot "SmokeTests\cpp_ssh_interop.py") --binary "$SshBin"
if ($LASTEXITCODE -ne 0) {
    throw "SSHv2 loopback interop check failed with exit code $LASTEXITCODE"
}

# ============================================================================
# Phase 4: Live Loopback QUIC v1/v2 Interop (Hysteria v1/v2 & TUIC v5)
# ============================================================================
Write-Phase "Phase 4: Live Loopback QUIC v1/v2 (Hysteria / Hysteria2 / TUIC v5) Interop"
$env:PYTHONPATH = Join-Path $RepoRoot "NativeTests"
& $VenvPython (Join-Path $RepoRoot "NativeTests\quic_fixture_test.py")
if ($LASTEXITCODE -ne 0) {
    throw "quic_fixture_test.py failed"
}

$QuicWorkDir = Join-Path $RepoRoot ".build\QUICInteropWin"
New-Item -ItemType Directory -Path $QuicWorkDir -Force | Out-Null
$ServerKey = Join-Path $QuicWorkDir "server-key.pem"
$ServerCert = Join-Path $QuicWorkDir "server-cert.pem"
$ServerLog = Join-Path $QuicWorkDir "server.log"
$ServerErr = Join-Path $QuicWorkDir "server.err.log"
Remove-Item -LiteralPath $ServerLog, $ServerErr -Force -ErrorAction SilentlyContinue

$certGenScript = @"
import datetime, ipaddress, pathlib, sys
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

key_path = pathlib.Path(sys.argv[1])
cert_path = pathlib.Path(sys.argv[2])
key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
now = datetime.datetime.now(datetime.timezone.utc)
subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
cert = (
    x509.CertificateBuilder()
    .subject_name(subject)
    .issuer_name(issuer)
    .public_key(key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(now - datetime.timedelta(minutes=5))
    .not_valid_after(now + datetime.timedelta(days=1))
    .add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName("localhost"),
            x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
        ]),
        critical=False,
    )
    .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    .sign(key, hashes.SHA256())
)
key_path.write_bytes(key.private_bytes(
    serialization.Encoding.PEM,
    serialization.PrivateFormat.TraditionalOpenSSL,
    serialization.NoEncryption(),
))
cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
"@
& $VenvPython -c $certGenScript "$ServerKey" "$ServerCert"
if ($LASTEXITCODE -ne 0) { throw "Failed to generate QUIC fixture certificate" }

$QuicBin = Find-TestBinary "quic-check"
$ServerScript = Join-Path $RepoRoot "NativeTests\quic_interop_server.py"

$serverProc = Start-Process -FilePath $VenvPython `
    -ArgumentList @("-u", $ServerScript, "--certificate", $ServerCert, "--private-key", $ServerKey, "--base-port", "$QuicBasePort") `
    -RedirectStandardOutput $ServerLog `
    -RedirectStandardError $ServerErr `
    -NoNewWindow -PassThru

try {
    $ready = $false
    for ($i = 0; $i -lt 40; $i++) {
        if ((Test-Path -LiteralPath $ServerLog) -and (Select-String -Path $ServerLog -Pattern "QUIC_INTEROP_READY" -Quiet)) {
            $ready = $true
            break
        }
        if ($serverProc.HasExited) {
            if (Test-Path -LiteralPath $ServerLog) { Get-Content -LiteralPath $ServerLog }
            if (Test-Path -LiteralPath $ServerErr) { Get-Content -LiteralPath $ServerErr }
            throw "QUIC interop server exited prematurely with code $($serverProc.ExitCode)"
        }
        Start-Sleep -Milliseconds 250
    }
    if (-not $ready) {
        if (Test-Path -LiteralPath $ServerLog) { Get-Content -LiteralPath $ServerLog }
        if (Test-Path -LiteralPath $ServerErr) { Get-Content -LiteralPath $ServerErr }
        throw "Timed out waiting for QUIC_INTEROP_READY"
    }

    function Invoke-QuicCase([string[]]$CaseArgs) {
        Write-Host "  -> quic-check $($CaseArgs -join ' ')"
        & $QuicBin @CaseArgs
        if ($LASTEXITCODE -ne 0) {
            throw "quic-check failed for args: $($CaseArgs -join ' ')"
        }
    }

    Invoke-QuicCase @("hysteria",  "$QuicBasePort",       $ServerCert)
    Invoke-QuicCase @("hysteria2", "$($QuicBasePort + 1)", $ServerCert)
    Invoke-QuicCase @("tuic",      "$($QuicBasePort + 2)", $ServerCert)
    Invoke-QuicCase @("tuic",      "$($QuicBasePort + 2)", $ServerCert, "quic")
    Invoke-QuicCase @("hysteria",  "$($QuicBasePort + 3)", $ServerCert, "obfs")
    Invoke-QuicCase @("hysteria2", "$($QuicBasePort + 4)", $ServerCert, "obfs")

    $offsets = @{ "hysteria" = 0; "hysteria2" = 1; "tuic" = 2 }
    foreach ($proto in @("hysteria", "hysteria2", "tuic")) {
        $p = $QuicBasePort + $offsets[$proto]
        Invoke-QuicCase @($proto, "$p", $ServerCert, "bad-auth")
        Invoke-QuicCase @($proto, "$p", $ServerCert, "cancel")
        Invoke-QuicCase @($proto, "$p", $ServerCert, "cancel-ready")
    }

    Invoke-QuicCase @("hysteria2", "$($QuicBasePort + 1)", $ServerCert, "reject")
    Invoke-QuicCase @("hysteria2", "$($QuicBasePort + 1)", $ServerCert, "system-reject")
    Invoke-QuicCase @("hysteria2", "$($QuicBasePort + 1)", $ServerCert, "skip")
} finally {
    if (-not $serverProc.HasExited) {
        Stop-Process -Id $serverProc.Id -Force -ErrorAction SilentlyContinue
    }
}

Write-Host "`nALL M0–M5 WINDOWS NATIVE, ENGINE, HELPER & INTEROP VERIFICATION GATES PASSED!" -ForegroundColor Green
