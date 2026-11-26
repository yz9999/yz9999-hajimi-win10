#!/bin/sh
# Unified macOS Native Core Builder (AWS-LC CMake+Ninja fast path by default, OpenSSL 3.5 fallback)
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
export MACOSX_DEPLOYMENT_TARGET=13.0
export HAJIMI_ARCHS=${HAJIMI_ARCHS:-$(uname -m)}
export HAJIMI_TLS_BACKEND=${HAJIMI_TLS_BACKEND:-awslc}
export PATH="/usr/local/bin:/opt/homebrew/bin:/Applications/CMake.app/Contents/bin:$ROOT/.build/Vendor/CMake/CMake.app/Contents/bin:${PATH:-/usr/bin:/bin:/usr/sbin:/sbin}"

ensure_cmake() {
    if command -v cmake >/dev/null 2>&1; then
        return 0
    fi
    if command -v brew >/dev/null 2>&1; then
        echo "Installing cmake & ninja via Homebrew..."
        brew install cmake ninja && return 0
    fi
    echo "CMake is required to build Hajimi native vendor dependencies." >&2
    exit 1
}

build_vendor_awslc() {
    VENDOR_AWSLC="$ROOT/.build/Vendor/AWSLC"
    AWSLC_REF="${HAJIMI_AWSLC_REF:-v1.40.0}"
    if [ -f "$VENDOR_AWSLC/include/openssl/ssl.h" ] && [ -f "$VENDOR_AWSLC/lib/libcrypto.a" ] && [ -f "$VENDOR_AWSLC/lib/libssl.a" ]; then
        OK_ALL=1
        for ARCH in $HAJIMI_ARCHS; do
            lipo "$VENDOR_AWSLC/lib/libcrypto.a" -verify_arch "$ARCH" >/dev/null 2>&1 || OK_ALL=0
        done
        if [ "$OK_ALL" = "1" ]; then
            echo "Reusing cached static AWS-LC ($HAJIMI_ARCHS) at $VENDOR_AWSLC"
            HAJIMI_AWSLC_ROOT="$VENDOR_AWSLC"
            export HAJIMI_AWSLC_ROOT
            return 0
        fi
    fi

    mkdir -p "$VENDOR_AWSLC/src" "$VENDOR_AWSLC/include" "$VENDOR_AWSLC/lib"
    SRC_DIR="$VENDOR_AWSLC/src/aws-lc"
    if [ ! -d "$SRC_DIR/.git" ]; then
        rm -rf "$SRC_DIR"
        echo "Cloning AWS-LC ($AWSLC_REF) shallow snapshot..."
        if ! git clone --depth 1 --branch "$AWSLC_REF" https://github.com/aws/aws-lc.git "$SRC_DIR"; then
            git clone --depth 1 https://github.com/aws/aws-lc.git "$SRC_DIR"
        fi
    fi

    JOBS=${HAJIMI_BUILD_JOBS:-$(sysctl -n hw.ncpu 2>/dev/null || echo 4)}
    GEN_ARGS=""
    if command -v ninja >/dev/null 2>&1; then
        GEN_ARGS="-GNinja"
    fi

    for ARCH in $HAJIMI_ARCHS; do
        BUILD_SUB="$VENDOR_AWSLC/build-$ARCH"
        PREFIX_SUB="$VENDOR_AWSLC/$ARCH"
        rm -rf "$BUILD_SUB"
        # shellcheck disable=SC2086
        cmake -S "$SRC_DIR" -B "$BUILD_SUB" $GEN_ARGS \
            -DCMAKE_POLICY_VERSION_MINIMUM=3.5 \
            -DCMAKE_BUILD_TYPE=Release \
            -DCMAKE_OSX_ARCHITECTURES="$ARCH" \
            -DCMAKE_OSX_DEPLOYMENT_TARGET=13.0 \
            -DCMAKE_INSTALL_PREFIX="$PREFIX_SUB" \
            -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
            -DBUILD_SHARED_LIBS=OFF \
            -DBUILD_TESTING=OFF \
            -DBUILD_TOOL=OFF \
            -DDISABLE_GO=ON \
            -DDISABLE_PERL=ON
        cmake --build "$BUILD_SUB" --parallel "$JOBS"
        cmake --install "$BUILD_SUB"
        rm -rf "$BUILD_SUB"
    done

    FIRST_ARCH=$(printf '%s\n' "$HAJIMI_ARCHS" | awk '{print $1}')
    rm -rf "$VENDOR_AWSLC/include/openssl"
    cp -pR "$VENDOR_AWSLC/$FIRST_ARCH/include/openssl" "$VENDOR_AWSLC/include/"
    for LIB in libssl.a libcrypto.a; do
        set --
        for ARCH in $HAJIMI_ARCHS; do
            if [ -f "$VENDOR_AWSLC/$ARCH/lib/$LIB" ]; then
                set -- "$@" "$VENDOR_AWSLC/$ARCH/lib/$LIB"
            elif [ -f "$VENDOR_AWSLC/$ARCH/lib64/$LIB" ]; then
                mkdir -p "$VENDOR_AWSLC/$ARCH/lib"
                cp -f "$VENDOR_AWSLC/$ARCH/lib64/$LIB" "$VENDOR_AWSLC/$ARCH/lib/$LIB"
                set -- "$@" "$VENDOR_AWSLC/$ARCH/lib/$LIB"
            fi
        done
        lipo -create "$@" -output "$VENDOR_AWSLC/lib/$LIB"
    done

    HAJIMI_AWSLC_ROOT="$VENDOR_AWSLC"
    export HAJIMI_AWSLC_ROOT
}

build_vendor_openssl() {
    VENDOR_SSL="$ROOT/.build/Vendor/OpenSSL"
    OPENSSL_VER="3.5.9"
    OPENSSL_SHA256="603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a"
    if [ -f "$VENDOR_SSL/include/openssl/ssl.h" ] && [ -f "$VENDOR_SSL/lib/libssl.a" ]; then
        OK_ALL=1
        for ARCH in $HAJIMI_ARCHS; do
            lipo "$VENDOR_SSL/lib/libssl.a" -verify_arch "$ARCH" >/dev/null 2>&1 || OK_ALL=0
        done
        if [ "$OK_ALL" = "1" ]; then
            HAJIMI_OPENSSL_ROOT="$VENDOR_SSL"
            export HAJIMI_OPENSSL_ROOT
            return 0
        fi
    fi
    mkdir -p "$VENDOR_SSL/downloads" "$VENDOR_SSL/include" "$VENDOR_SSL/lib"
    ARCHIVE="$VENDOR_SSL/downloads/openssl-$OPENSSL_VER.tar.gz"
    SSL_URL="https://github.com/openssl/openssl/releases/download/openssl-$OPENSSL_VER/openssl-$OPENSSL_VER.tar.gz"
    if [ ! -f "$ARCHIVE" ]; then
        ATTEMPT=1
        while [ "$ATTEMPT" -le 5 ]; do
            rm -f "$ARCHIVE"
            if curl --proto '=https' --tlsv1.2 --fail --location --retry 3 --retry-delay 2 --max-time 180 \
                -A "hajimi-ci/1.0" "$SSL_URL" -o "$ARCHIVE"; then
                break
            fi
            echo "Download attempt $ATTEMPT/5 failed for $SSL_URL; retrying..." >&2
            sleep $((ATTEMPT * 2))
            ATTEMPT=$((ATTEMPT + 1))
        done
        if [ ! -f "$ARCHIVE" ]; then
            echo "Failed to download $SSL_URL after 5 attempts" >&2
            exit 1
        fi
    fi
    ACTUAL_SSL_SHA=$(/usr/bin/shasum -a 256 "$ARCHIVE" | /usr/bin/awk '{print $1}')
    if [ "$ACTUAL_SSL_SHA" != "$OPENSSL_SHA256" ]; then
        echo "OpenSSL SHA-256 mismatch" >&2
        exit 1
    fi
    JOBS=${HAJIMI_BUILD_JOBS:-$(sysctl -n hw.ncpu 2>/dev/null || echo 4)}
    for ARCH in $HAJIMI_ARCHS; do
        case "$ARCH" in
            x86_64) TARGET="darwin64-x86_64-cc" ;;
            arm64)  TARGET="darwin64-arm64-cc" ;;
            *) echo "Unsupported architecture: $ARCH" >&2; exit 1 ;;
        esac
        BUILD_SUB="$VENDOR_SSL/build-$ARCH"
        PREFIX_SUB="$VENDOR_SSL/$ARCH"
        rm -rf "$BUILD_SUB" && mkdir -p "$BUILD_SUB"
        tar -xzf "$ARCHIVE" -C "$BUILD_SUB" --strip-components=1
        (
            cd "$BUILD_SUB"
            ./Configure "$TARGET" no-shared no-module no-dso no-apps no-makedepend no-tests no-docs \
                "-mmacosx-version-min=13.0" --prefix="$PREFIX_SUB" --openssldir="$PREFIX_SUB/ssl"
            make -j"$JOBS" build_libs
            mkdir -p "$PREFIX_SUB/lib" "$PREFIX_SUB/include"
            cp -f libssl.a libcrypto.a "$PREFIX_SUB/lib/"
            cp -pR include/openssl "$PREFIX_SUB/include/"
        )
        rm -rf "$BUILD_SUB"
    done
    FIRST_ARCH=$(printf '%s\n' "$HAJIMI_ARCHS" | awk '{print $1}')
    rm -rf "$VENDOR_SSL/include/openssl"
    cp -pR "$VENDOR_SSL/$FIRST_ARCH/include/openssl" "$VENDOR_SSL/include/"
    for LIB in libssl.a libcrypto.a; do
        set --
        for ARCH in $HAJIMI_ARCHS; do set -- "$@" "$VENDOR_SSL/$ARCH/lib/$LIB"; done
        lipo -create "$@" -output "$VENDOR_SSL/lib/$LIB"
    done
    HAJIMI_OPENSSL_ROOT="$VENDOR_SSL"
    export HAJIMI_OPENSSL_ROOT
}

ensure_cmake

if [ "$HAJIMI_TLS_BACKEND" = "awslc" ]; then
    build_vendor_awslc
    export HAJIMI_OPENSSL_ROOT="$HAJIMI_AWSLC_ROOT"
    echo "Using AWS-LC static library from: $HAJIMI_AWSLC_ROOT"
else
    build_vendor_openssl
    echo "Using OpenSSL 3.5+ static library from: $HAJIMI_OPENSSL_ROOT"
fi

sh "$ROOT/scripts/build_cpp_quic.sh"
sh "$ROOT/scripts/build_cpp_ssh.sh"

echo "Unified static vendor dependencies ($HAJIMI_ARCHS, backend=$HAJIMI_TLS_BACKEND) ready."
