#Requires -Version 5.1
<#
.SYNOPSIS
    Unified Reproducible Static Native Dependency Builder for Hajimi on Windows (x64 & arm64).
    Defaults to AWS-LC (CMake + Ninja in ~60-90s, BoringSSL-compatible QUIC API + ML-KEM-768)
    with optional OpenSSL 3.5.9 LTS fallback, plus ngtcp2 1.18.0, nghttp3 1.12.0, libssh2, and WHQL Wintun 0.14.1.
#>
[CmdletBinding()]
param(
    [ValidateSet("x64", "arm64")]
    [string]$Arch = $(if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") { "arm64" } else { "x64" }),

    [ValidateSet("awslc", "openssl")]
    [string]$TlsBackend = $(if ($env:HAJIMI_TLS_BACKEND) { $env:HAJIMI_TLS_BACKEND.ToLowerInvariant() } else { "openssl" }),

    [int]$Jobs = $([Math]::Max(2, [Environment]::ProcessorCount))
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$VendorRoot = Join-Path $RepoRoot ".build\Vendor"

function Write-Step([string]$Message) {
    Write-Host "`n==> $Message" -ForegroundColor Cyan
}

function Add-PathIfExists([string]$Dir) {
    if ($Dir -and (Test-Path -LiteralPath $Dir)) {
        $parts = $env:PATH -split ';'
        if ($parts -notcontains $Dir) {
            $env:PATH = "$Dir;$env:PATH"
        }
    }
}

function Initialize-MsvcEnvironment([string]$TargetArch) {
    $vcvarsArch = if ($TargetArch -eq "arm64") {
        if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") { "arm64" } else { "amd64_arm64" }
    } else {
        "amd64"
    }

    $existingCl = Get-Command cl.exe -ErrorAction SilentlyContinue
    if ($existingCl -and $env:VSCMD_ARG_TGT_ARCH -eq $TargetArch) {
        Write-Host "Using active MSVC environment ($TargetArch): $($existingCl.Source)"
        return
    }

    $vswhere = Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio\Installer\vswhere.exe"
    if (-not (Test-Path -LiteralPath $vswhere)) {
        throw "Visual Studio / C++ Build Tools (vswhere.exe) not found."
    }

    $vsInstall = (& $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath | Select-Object -First 1)
    if (-not $vsInstall) {
        $vsInstall = (& $vswhere -latest -products * -property installationPath | Select-Object -First 1)
    }
    if (-not $vsInstall) {
        throw "Could not locate a Visual Studio installation with C++ tools."
    }

    $vcvarsall = Join-Path $vsInstall "VC\Auxiliary\Build\vcvarsall.bat"
    Write-Step "Initializing MSVC Developer Environment ($vcvarsArch) from $vsInstall"
    $dumpCmd = "`"$vcvarsall`" $vcvarsArch >nul && set"
    $envLines = & cmd.exe /d /c $dumpCmd
    if ($LASTEXITCODE -ne 0) {
        throw "vcvarsall.bat $vcvarsArch failed with exit code $LASTEXITCODE"
    }
    foreach ($line in $envLines) {
        if ($line -match '^([^=]+)=(.*)$') {
            [Environment]::SetEnvironmentVariable($matches[1], $matches[2], "Process")
        }
    }
}

function Get-VerifiedArchive {
    param(
        [Parameter(Mandatory = $true)][string]$Url,
        [Parameter(Mandatory = $true)][string]$Destination,
        [Parameter(Mandatory = $true)][string]$ExpectedSha256
    )
    $parent = Split-Path -Parent $Destination
    if (-not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
    if (-not (Test-Path -LiteralPath $Destination)) {
        Write-Host "Downloading $Url ..."
        & curl.exe --proto "=https" --tlsv1.2 --fail --location --retry 3 --max-time 240 "$Url" -o "$Destination"
        if ($LASTEXITCODE -ne 0) { throw "Failed to download $Url" }
    }
    $actualHash = (Get-FileHash -LiteralPath $Destination -Algorithm SHA256).Hash.ToLowerInvariant()
    $expectedNorm = $ExpectedSha256.ToLowerInvariant()
    if ($actualHash -ne $expectedNorm) {
        Remove-Item -LiteralPath $Destination -Force -ErrorAction SilentlyContinue
        throw "SHA-256 mismatch for $Destination! Expected $expectedNorm, got $actualHash."
    }
}

Add-PathIfExists "C:\Strawberry\perl\bin"
Add-PathIfExists "C:\Program Files\NASM"
Add-PathIfExists "$env:LOCALAPPDATA\bin\NASM"
Add-PathIfExists "C:\Program Files\CMake\bin"
Add-PathIfExists "C:\ProgramData\chocolatey\bin"

Initialize-MsvcEnvironment -TargetArch $Arch

function Expand-TarArchive {
    param(
        [Parameter(Mandatory = $true)][string]$Archive,
        [Parameter(Mandatory = $true)][string]$Destination,
        [switch]$StripTopComponent
    )
    New-Item -ItemType Directory -Path $Destination -Force | Out-Null
    if ($StripTopComponent) {
        $tmpExtract = Join-Path (Split-Path -Parent $Destination) ("_extract_" + [Guid]::NewGuid().ToString("N").Substring(0, 8))
        New-Item -ItemType Directory -Path $tmpExtract -Force | Out-Null
        try {
            Push-Location $tmpExtract
            & cmake.exe -E tar xf "$Archive"
            if ($LASTEXITCODE -ne 0) { throw "cmake -E tar xf failed for $Archive" }
        } finally {
            Pop-Location
        }
        $top = Get-ChildItem -LiteralPath $tmpExtract -Force
        if ($top.Count -eq 1 -and $top[0].PSIsContainer) {
            Get-ChildItem -LiteralPath $top[0].FullName -Force | Move-Item -Destination $Destination -Force
        } else {
            $top | Move-Item -Destination $Destination -Force
        }
        Remove-Item -LiteralPath $tmpExtract -Recurse -Force -ErrorAction SilentlyContinue
    } else {
        Push-Location $Destination
        try {
            & cmake.exe -E tar xf "$Archive"
            if ($LASTEXITCODE -ne 0) { throw "cmake -E tar xf failed for $Archive" }
        } finally {
            Pop-Location
        }
    }
}

foreach ($tool in @("cl.exe", "cmake.exe")) {
    if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) {
        throw "Required build tool '$tool' was not found in PATH."
    }
}

$cmakeGenArgs = if (Get-Command ninja.exe -ErrorAction SilentlyContinue) {
    @("-G", "Ninja")
} else {
    @("-G", "NMake Makefiles")
}
$cmakeCrossArgs = if ($Arch -eq "arm64") {
    @("-DCMAKE_SYSTEM_NAME=Windows", "-DCMAKE_SYSTEM_PROCESSOR=ARM64")
} else {
    @()
}

# ============================================================================
# 1. TLS Backend: AWS-LC (Default ~60-90s CMake+Ninja) or OpenSSL 3.5.9 LTS
# ============================================================================
$TlsPrefix = ""
$Ngtcp2CryptoStem = ""

if ($TlsBackend -eq "awslc") {
    $AwsLcRef = if ($env:HAJIMI_AWSLC_REF) { $env:HAJIMI_AWSLC_REF } else { "v1.40.0" }
    $AwsLcBase = Join-Path $VendorRoot "AWSLC"
    $AwsLcPrefix = Join-Path $AwsLcBase $Arch
    $AwsLcHeader = Join-Path $AwsLcPrefix "include\openssl\ssl.h"
    $AwsLcCrypto = Join-Path $AwsLcPrefix "lib\crypto.lib"
    $AwsLcSsl = Join-Path $AwsLcPrefix "lib\ssl.lib"

    if ((Test-Path -LiteralPath $AwsLcHeader) -and
        ((Test-Path -LiteralPath $AwsLcCrypto) -or (Test-Path -LiteralPath (Join-Path $AwsLcPrefix "lib\libcrypto.lib"))) -and
        ((Test-Path -LiteralPath $AwsLcSsl) -or (Test-Path -LiteralPath (Join-Path $AwsLcPrefix "lib\libssl.lib")))) {
        Write-Step "Reusing cached static AWS-LC ($Arch) at $AwsLcPrefix"
    } else {
        Write-Step "Building static AWS-LC ($AwsLcRef, $Arch) with CMake + Ninja (/MT)"
        $srcDir = Join-Path $AwsLcBase "src\aws-lc"
        if (-not (Test-Path -LiteralPath (Join-Path $srcDir "CMakeLists.txt"))) {
            New-Item -ItemType Directory -Path (Split-Path -Parent $srcDir) -Force | Out-Null
            if (Test-Path -LiteralPath $srcDir) { Remove-Item -LiteralPath $srcDir -Recurse -Force }
            & git.exe clone --depth 1 --branch $AwsLcRef https://github.com/aws/aws-lc.git "$srcDir"
            if ($LASTEXITCODE -ne 0) {
                & git.exe clone --depth 1 https://github.com/aws/aws-lc.git "$srcDir"
                if ($LASTEXITCODE -ne 0) { throw "Failed to clone aws/aws-lc" }
            }
        }

        $bldDir = Join-Path $AwsLcBase "build-$Arch"
        if (Test-Path -LiteralPath $bldDir) { Remove-Item -LiteralPath $bldDir -Recurse -Force }

        $asmFlags = @()
        $noAsm = $false
        if ($Arch -eq "arm64") {
            # MSVC armasm64 does not accept GAS syntax; portable C + compiler intrinsics avoids assembler mismatch
            $asmFlags += "-DOPENSSL_NO_ASM=ON"
            $noAsm = $true
        } elseif (-not (Get-Command nasm.exe -ErrorAction SilentlyContinue)) {
            $asmFlags += "-DOPENSSL_NO_ASM=ON"
            $noAsm = $true
        }
        if ($noAsm -or (-not (Get-Command perl.exe -ErrorAction SilentlyContinue))) {
            $asmFlags += "-DDISABLE_PERL=ON"
        }
        if (-not (Get-Command go.exe -ErrorAction SilentlyContinue)) {
            $asmFlags += "-DDISABLE_GO=ON"
        }

        $AwsLcPrefixCMake = $AwsLcPrefix -replace '\\', '/'
        & cmake.exe -S "$srcDir" -B "$bldDir" @cmakeGenArgs @cmakeCrossArgs @asmFlags `
            -DCMAKE_BUILD_TYPE=Release `
            -DCMAKE_POLICY_DEFAULT_CMP0091=NEW `
            -DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded `
            "-DCMAKE_INSTALL_PREFIX=$AwsLcPrefixCMake" `
            -DBUILD_SHARED_LIBS=OFF `
            -DBUILD_TESTING=OFF `
            -DBUILD_TOOL=OFF
        if ($LASTEXITCODE -ne 0) { throw "AWS-LC CMake configure failed" }

        & cmake.exe --build "$bldDir" --config Release --parallel $Jobs
        if ($LASTEXITCODE -ne 0) { throw "AWS-LC CMake build failed" }

        & cmake.exe --install "$bldDir" --config Release
        if ($LASTEXITCODE -ne 0) { throw "AWS-LC CMake install failed" }

        # Normalize library aliases so both crypto.lib/libcrypto.lib and ssl.lib/libssl.lib exist for downstream CMake finders
        $libDir = Join-Path $AwsLcPrefix "lib"
        if ((Test-Path -LiteralPath (Join-Path $libDir "crypto.lib")) -and (-not (Test-Path -LiteralPath (Join-Path $libDir "libcrypto.lib")))) {
            Copy-Item -LiteralPath (Join-Path $libDir "crypto.lib") -Destination (Join-Path $libDir "libcrypto.lib") -Force
        }
        if ((Test-Path -LiteralPath (Join-Path $libDir "libcrypto.lib")) -and (-not (Test-Path -LiteralPath (Join-Path $libDir "crypto.lib")))) {
            Copy-Item -LiteralPath (Join-Path $libDir "libcrypto.lib") -Destination (Join-Path $libDir "crypto.lib") -Force
        }
        if ((Test-Path -LiteralPath (Join-Path $libDir "ssl.lib")) -and (-not (Test-Path -LiteralPath (Join-Path $libDir "libssl.lib")))) {
            Copy-Item -LiteralPath (Join-Path $libDir "ssl.lib") -Destination (Join-Path $libDir "libssl.lib") -Force
        }
        if ((Test-Path -LiteralPath (Join-Path $libDir "libssl.lib")) -and (-not (Test-Path -LiteralPath (Join-Path $libDir "ssl.lib")))) {
            Copy-Item -LiteralPath (Join-Path $libDir "libssl.lib") -Destination (Join-Path $libDir "ssl.lib") -Force
        }

        Remove-Item -LiteralPath $bldDir -Recurse -Force -ErrorAction SilentlyContinue
    }
    $TlsPrefix = $AwsLcPrefix
    $Ngtcp2CryptoStem = "ngtcp2_crypto_boringssl"
} else {
    $OpenSslVer = "3.5.9"
    $OpenSslSha256 = "603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a"
    $OpenSslBase = Join-Path $VendorRoot "OpenSSL"
    $OpenSslPrefix = Join-Path $OpenSslBase $Arch
    $OpenSslHeader = Join-Path $OpenSslPrefix "include\openssl\ssl.h"
    $OpenSslCryptoLib = Join-Path $OpenSslPrefix "lib\libcrypto.lib"
    $OpenSslSslLib = Join-Path $OpenSslPrefix "lib\libssl.lib"

    if (-not ((Test-Path -LiteralPath $OpenSslHeader) -and (Test-Path -LiteralPath $OpenSslCryptoLib) -and (Test-Path -LiteralPath $OpenSslSslLib))) {
        Write-Step "Building static OpenSSL $OpenSslVer LTS ($Arch)"
        $sslArchive = Join-Path $OpenSslBase "downloads\openssl-$OpenSslVer.tar.gz"
        Get-VerifiedArchive -Url "https://github.com/openssl/openssl/releases/download/openssl-$OpenSslVer/openssl-$OpenSslVer.tar.gz" `
            -Destination $sslArchive -ExpectedSha256 $OpenSslSha256
        $sslBuildDir = Join-Path $OpenSslBase "build-$Arch"
        if (Test-Path -LiteralPath $sslBuildDir) { Remove-Item -LiteralPath $sslBuildDir -Recurse -Force }
        Expand-TarArchive -Archive $sslArchive -Destination $sslBuildDir -StripTopComponent

        $sslTarget = if ($Arch -eq "arm64") { "VC-WIN64-ARM" } else { "VC-WIN64A" }
        $asmArgs = if ($Arch -eq "arm64" -or (-not (Get-Command nasm.exe -ErrorAction SilentlyContinue))) { @("no-asm") } else { @() }
        Push-Location $sslBuildDir
        try {
            & perl.exe Configure $sslTarget --release no-shared no-module no-dso no-apps no-makedepend no-tests no-docs @asmArgs `
                "--prefix=$OpenSslPrefix" "--openssldir=$OpenSslPrefix\ssl"
            if (Test-Path -LiteralPath "makefile") {
                $mk = (Get-Content -LiteralPath "makefile" -Raw) -replace '/Zi\s+/Fdossl_static\.pdb', ''
                Set-Content -LiteralPath "makefile" -Value $mk -NoNewline
            }
            if (Get-Command jom.exe -ErrorAction SilentlyContinue) {
                & jom.exe /NOLOGO /J $Jobs build_libs
                if ($LASTEXITCODE -ne 0) { & nmake.exe /NOLOGO build_libs }
            } else {
                & nmake.exe /NOLOGO build_libs
            }
            if ($LASTEXITCODE -ne 0) { throw "OpenSSL build_libs failed" }
            New-Item -ItemType Directory -Path (Join-Path $OpenSslPrefix "lib") -Force | Out-Null
            New-Item -ItemType Directory -Path (Join-Path $OpenSslPrefix "include") -Force | Out-Null
            Copy-Item -LiteralPath (Join-Path $sslBuildDir "libssl.lib") -Destination $OpenSslSslLib -Force
            Copy-Item -LiteralPath (Join-Path $sslBuildDir "libcrypto.lib") -Destination $OpenSslCryptoLib -Force
            Copy-Item -LiteralPath (Join-Path $sslBuildDir "include\openssl") -Destination (Join-Path $OpenSslPrefix "include\openssl") -Recurse -Force
        } finally {
            Pop-Location
        }
        Remove-Item -LiteralPath $sslBuildDir -Recurse -Force -ErrorAction SilentlyContinue
    }
    $TlsPrefix = $OpenSslPrefix
    $Ngtcp2CryptoStem = "ngtcp2_crypto_ossl"
}

$TlsPrefixCMake = $TlsPrefix -replace '\\', '/'

# ============================================================================
# 2. ngtcp2 1.18.0 & nghttp3 1.12.0 (Static /MT)
# ============================================================================
$QuicBase = Join-Path $VendorRoot "HajimiQUIC"
$QuicPrefix = Join-Path $QuicBase $Arch
$QuicPrefixCMake = $QuicPrefix -replace '\\', '/'

$quicPackages = @(
    @{ Name = "ngtcp2";  Version = "1.18.0"; Sha256 = "aac91fbcb8af77216862cc1bf6e9ddcabfe42b4c373a438b7b1d36b763a4ac5f" },
    @{ Name = "nghttp3"; Version = "1.12.0"; Sha256 = "6ca1e523b7edd75c02502f2bcf961125c25577e29405479016589c5da48fc43d" }
)

$needQuic = -not (
    (Test-Path -LiteralPath (Join-Path $QuicPrefix "lib\ngtcp2.lib")) -and
    (Test-Path -LiteralPath (Join-Path $QuicPrefix "lib\$Ngtcp2CryptoStem.lib")) -and
    (Test-Path -LiteralPath (Join-Path $QuicPrefix "lib\nghttp3.lib")) -and
    (Test-Path -LiteralPath (Join-Path $QuicPrefix "include\ngtcp2\ngtcp2.h")) -and
    (Test-Path -LiteralPath (Join-Path $QuicPrefix "include\nghttp3\nghttp3.h"))
)

if (-not $needQuic) {
    Write-Step "Reusing cached static ngtcp2 & nghttp3 ($Arch, $TlsBackend) at $QuicPrefix"
} else {
    foreach ($pkg in $quicPackages) {
        $name = $pkg.Name
        $ver = $pkg.Version
        Write-Step "Building static $name $ver ($Arch, backend=$TlsBackend)"
        $archive = Join-Path $QuicBase "downloads\$name-$ver.tar.xz"
        Get-VerifiedArchive -Url "https://github.com/ngtcp2/$name/releases/download/v$ver/$name-$ver.tar.xz" `
            -Destination $archive -ExpectedSha256 $pkg.Sha256

        $srcRoot = Join-Path $QuicBase "src"
        $srcDir = Join-Path $srcRoot "$name-$ver"
        if (-not (Test-Path -LiteralPath $srcDir)) {
            Expand-TarArchive -Archive $archive -Destination $srcRoot
        }

        $bldDir = Join-Path $QuicBase "build-$name-$Arch"
        if (Test-Path -LiteralPath $bldDir) { Remove-Item -LiteralPath $bldDir -Recurse -Force }

        $tlsCmakeArgs = if ($TlsBackend -eq "awslc") {
            @(
                "-DENABLE_OPENSSL=OFF",
                "-DENABLE_BORINGSSL=ON",
                "-DBORINGSSL_INCLUDE_DIR=$TlsPrefixCMake/include",
                "-DBORINGSSL_LIBRARIES=$TlsPrefixCMake/lib/libssl.lib;$TlsPrefixCMake/lib/libcrypto.lib"
            )
        } else {
            @(
                "-DENABLE_OPENSSL=ON",
                "-DENABLE_BORINGSSL=OFF",
                "-DOPENSSL_ROOT_DIR=$TlsPrefixCMake",
                "-DOPENSSL_USE_STATIC_LIBS=TRUE",
                "-DOPENSSL_MSVC_STATIC_RT=TRUE"
            )
        }

        & cmake.exe -S "$srcDir" -B "$bldDir" @cmakeGenArgs @cmakeCrossArgs `
            -DCMAKE_BUILD_TYPE=Release `
            -DCMAKE_POLICY_DEFAULT_CMP0091=NEW `
            -DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded `
            "-DCMAKE_INSTALL_PREFIX=$QuicPrefixCMake" `
            -DBUILD_TESTING=OFF `
            -DENABLE_LIB_ONLY=ON `
            -DENABLE_STATIC_LIB=ON `
            -DENABLE_SHARED_LIB=OFF `
            -DENABLE_GNUTLS=OFF `
            -DENABLE_PICOTLS=OFF `
            -DENABLE_WOLFSSL=OFF `
            @tlsCmakeArgs
        if ($LASTEXITCODE -ne 0) { throw "CMake configure failed for $name" }

        & cmake.exe --build "$bldDir" --config Release --parallel $Jobs
        if ($LASTEXITCODE -ne 0) { throw "CMake build failed for $name" }

        & cmake.exe --install "$bldDir" --config Release
        if ($LASTEXITCODE -ne 0) { throw "CMake install failed for $name" }

        Remove-Item -LiteralPath $bldDir -Recurse -Force -ErrorAction SilentlyContinue
    }

    foreach ($stem in @("ngtcp2", $Ngtcp2CryptoStem, "nghttp3")) {
        $canonical = Join-Path $QuicPrefix "lib\$stem.lib"
        $staticAlt = Join-Path $QuicPrefix "lib\${stem}_static.lib"
        if ((-not (Test-Path -LiteralPath $canonical)) -and (Test-Path -LiteralPath $staticAlt)) {
            Copy-Item -LiteralPath $staticAlt -Destination $canonical -Force
        }
        if (-not (Test-Path -LiteralPath $canonical)) {
            throw "Expected static library missing: $canonical"
        }
    }
}

# ============================================================================
# 3. libssh2 (Pinned Security Snapshot 2e171745..., Static /MT)
# ============================================================================
$SshCommit = "2e1717456b8dd4c980e8e48d6dbfec524c2e62d1"
$SshSha256 = "cffa24d90bf14a26154b1124e0dcdaab1fe4038000a8f5a127acb77631a8ebe5"
$SshBase = Join-Path $VendorRoot "HajimiSSH"
$SshPrefix = Join-Path $SshBase $Arch
$SshPrefixCMake = $SshPrefix -replace '\\', '/'
$SshCanonicalLib = Join-Path $SshPrefix "lib\libssh2.lib"

if ((Test-Path -LiteralPath $SshCanonicalLib) -and (Test-Path -LiteralPath (Join-Path $SshPrefix "include\libssh2.h"))) {
    Write-Step "Reusing cached static libssh2 ($Arch) at $SshPrefix"
} else {
    Write-Step "Building static libssh2 ($SshCommit, $Arch)"
    $sshArchive = Join-Path $SshBase "downloads\libssh2-$SshCommit.tar.gz"
    Get-VerifiedArchive -Url "https://codeload.github.com/libssh2/libssh2/tar.gz/$SshCommit" `
        -Destination $sshArchive -ExpectedSha256 $SshSha256

    $sshSrcRoot = Join-Path $SshBase "src"
    $sshSrcDir = Join-Path $sshSrcRoot "libssh2-$SshCommit"
    if (-not (Test-Path -LiteralPath $sshSrcDir)) {
        Expand-TarArchive -Archive $sshArchive -Destination $sshSrcRoot
    }

    $sshBldDir = Join-Path $SshBase "build-$Arch"
    if (Test-Path -LiteralPath $sshBldDir) { Remove-Item -LiteralPath $sshBldDir -Recurse -Force }

    & cmake.exe -S "$sshSrcDir" -B "$sshBldDir" @cmakeGenArgs @cmakeCrossArgs `
        -DCMAKE_BUILD_TYPE=Release `
        -DCMAKE_POLICY_DEFAULT_CMP0091=NEW `
        -DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded `
        "-DCMAKE_INSTALL_PREFIX=$SshPrefixCMake" `
        -DCRYPTO_BACKEND=OpenSSL `
        "-DOPENSSL_ROOT_DIR=$TlsPrefixCMake" `
        -DOPENSSL_USE_STATIC_LIBS=ON `
        -DOPENSSL_MSVC_STATIC_RT=ON `
        -DBUILD_SHARED_LIBS=OFF `
        -DBUILD_STATIC_LIBS=ON `
        -DBUILD_EXAMPLES=OFF `
        -DBUILD_TESTING=OFF `
        -DLIBSSH2_BUILD_DOCS=OFF `
        -DPICKY_COMPILER=OFF `
        -DENABLE_ZLIB_COMPRESSION=OFF
    if ($LASTEXITCODE -ne 0) { throw "CMake configure failed for libssh2" }

    & cmake.exe --build "$sshBldDir" --config Release --parallel $Jobs
    if ($LASTEXITCODE -ne 0) { throw "CMake build failed for libssh2" }

    & cmake.exe --install "$sshBldDir" --config Release
    if ($LASTEXITCODE -ne 0) { throw "CMake install failed for libssh2" }

    Remove-Item -LiteralPath $sshBldDir -Recurse -Force -ErrorAction SilentlyContinue

    foreach ($alt in @("libssh2_static.lib", "ssh2.lib")) {
        $altPath = Join-Path $SshPrefix "lib\$alt"
        if ((-not (Test-Path -LiteralPath $SshCanonicalLib)) -and (Test-Path -LiteralPath $altPath)) {
            Copy-Item -LiteralPath $altPath -Destination $SshCanonicalLib -Force
        }
    }
    if (-not (Test-Path -LiteralPath $SshCanonicalLib)) {
        throw "Expected static library missing: $SshCanonicalLib"
    }
}

# ============================================================================
# 4. Official WireGuard WHQL Wintun 0.14.1 (Pinned ZIP + Per-DLL SHA-256)
# ============================================================================
$WintunVersion = "0.14.1"
$WintunZipSha256 = "07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51"
$WintunDllSha256 = if ($Arch -eq "arm64") {
    "f7ba89005544be9d85231a9e0d5f23b2d15b3311667e2dad0debd344918a3f80"
} else {
    "e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce"
}
$WintunZipMemberArch = if ($Arch -eq "arm64") { "arm64" } else { "amd64" }
$WintunBase = Join-Path $VendorRoot "Wintun"
$WintunPrefix = Join-Path $WintunBase $Arch
$WintunDllOut = Join-Path $WintunPrefix "wintun.dll"

if ((Test-Path -LiteralPath $WintunDllOut) -and
    ((Get-FileHash -LiteralPath $WintunDllOut -Algorithm SHA256).Hash.ToLowerInvariant() -eq $WintunDllSha256)) {
    Write-Step "Reusing verified WHQL Wintun $WintunVersion ($Arch) at $WintunDllOut"
} else {
    Write-Step "Downloading & verifying WHQL Wintun $WintunVersion ($Arch)"
    $wintunZip = Join-Path $WintunBase "downloads\wintun-$WintunVersion.zip"
    Get-VerifiedArchive -Url "https://www.wintun.net/builds/wintun-$WintunVersion.zip" `
        -Destination $wintunZip -ExpectedSha256 $WintunZipSha256

    $wintunExtract = Join-Path $WintunBase "extracted"
    if (Test-Path -LiteralPath $wintunExtract) { Remove-Item -LiteralPath $wintunExtract -Recurse -Force }
    Expand-Archive -LiteralPath $wintunZip -DestinationPath $wintunExtract -Force
    $extractedDll = Join-Path $wintunExtract "wintun\bin\$WintunZipMemberArch\wintun.dll"
    $actualDllHash = (Get-FileHash -LiteralPath $extractedDll -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actualDllHash -ne $WintunDllSha256) {
        throw "wintun.dll ($Arch) SHA-256 mismatch! Expected $WintunDllSha256, got $actualDllHash"
    }
    New-Item -ItemType Directory -Path $WintunPrefix -Force | Out-Null
    Copy-Item -LiteralPath $extractedDll -Destination $WintunDllOut -Force
    Copy-Item -LiteralPath (Join-Path $wintunExtract "wintun\LICENSE.txt") -Destination (Join-Path $WintunPrefix "LICENSE.txt") -Force -ErrorAction SilentlyContinue
}

Write-Host "`nAll native dependencies for '$Arch' (TLS=$TlsBackend) are ready:" -ForegroundColor Green
Write-Host "  TLS Backend   : $TlsPrefix"
Write-Host "  QUIC/HTTP3    : $QuicPrefix"
Write-Host "  libssh2       : $SshPrefix"
Write-Host "  Wintun 0.14.1 : $WintunDllOut"
