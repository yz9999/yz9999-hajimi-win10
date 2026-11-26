#!/bin/sh
# Reproducible, repository-local C QUIC/HTTP3 dependencies (supports AWS-LC / BoringSSL & OpenSSL 3.5+).
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
BUILD="$ROOT/.build/Vendor/HajimiQUIC"
TLS_BACKEND=${HAJIMI_TLS_BACKEND:-openssl}
ARCHS=${HAJIMI_ARCHS:-$(uname -m)}
JOBS=${HAJIMI_BUILD_JOBS:-$(sysctl -n hw.ncpu 2>/dev/null || echo 4)}

if [ "$TLS_BACKEND" = "awslc" ]; then
    TLS_ROOT=${HAJIMI_AWSLC_ROOT:-$ROOT/.build/Vendor/AWSLC}
    CRYPTO_LIB_NAME="ngtcp2_crypto_boringssl"
else
    DEFAULT_SSL=/usr/local/opt/openssl@3
    if [ -f /opt/homebrew/opt/openssl@3/include/openssl/ssl.h ]; then DEFAULT_SSL=/opt/homebrew/opt/openssl@3; fi
    TLS_ROOT=${HAJIMI_OPENSSL_ROOT:-$DEFAULT_SSL}
    CRYPTO_LIB_NAME="ngtcp2_crypto_ossl"
fi

if [ -f "$BUILD/include/ngtcp2/ngtcp2.h" ] && [ -f "$BUILD/include/nghttp3/nghttp3.h" ] && \
   [ -f "$BUILD/lib/libngtcp2.a" ] && [ -f "$BUILD/lib/lib${CRYPTO_LIB_NAME}.a" ] && [ -f "$BUILD/lib/libnghttp3.a" ]; then
    OK_QUIC=1
    for ARCH in $ARCHS; do
        lipo "$BUILD/lib/libngtcp2.a" -verify_arch "$ARCH" >/dev/null 2>&1 || OK_QUIC=0
        lipo "$BUILD/lib/lib${CRYPTO_LIB_NAME}.a" -verify_arch "$ARCH" >/dev/null 2>&1 || OK_QUIC=0
        lipo "$BUILD/lib/libnghttp3.a" -verify_arch "$ARCH" >/dev/null 2>&1 || OK_QUIC=0
    done
    if [ "$OK_QUIC" = "1" ]; then
        echo "Reusing cached C QUIC/HTTP3 static libraries ($TLS_BACKEND, $ARCHS) at $BUILD"
        exit 0
    fi
fi

mkdir -p "$BUILD/downloads" "$BUILD/src" "$BUILD/include" "$BUILD/lib" 

fetch() {
    NAME=$1 VERSION=$2 HASH=$3
    ARCHIVE="$BUILD/downloads/$NAME-$VERSION.tar.xz"
    if [ ! -f "$ARCHIVE" ]; then
        curl --proto '=https' --tlsv1.2 --fail --location --retry 2 --max-time 120 \
            "https://github.com/ngtcp2/$NAME/releases/download/v$VERSION/$NAME-$VERSION.tar.xz" \
            -o "$ARCHIVE"
    fi
    ACTUAL=$(shasum -a 256 "$ARCHIVE" | cut -d ' ' -f 1)
    if [ "$ACTUAL" != "$HASH" ]; then
        echo "Checksum mismatch for $NAME-$VERSION; remove $ARCHIVE and retry" >&2
        exit 1
    fi
    if [ ! -d "$BUILD/src/$NAME-$VERSION" ]; then
        tar -xf "$ARCHIVE" -C "$BUILD/src"
    fi
}

fetch ngtcp2 1.18.0 aac91fbcb8af77216862cc1bf6e9ddcabfe42b4c373a438b7b1d36b763a4ac5f
fetch nghttp3 1.12.0 6ca1e523b7edd75c02502f2bcf961125c25577e29405479016589c5da48fc43d

GEN_ARGS=""
if command -v ninja >/dev/null 2>&1; then GEN_ARGS="-GNinja"; fi

for ARCH in $ARCHS; do
    case "$ARCH" in x86_64|arm64) ;; *) echo "Unsupported architecture: $ARCH" >&2; exit 1;; esac
    SSL_ROOT=$TLS_ROOT
    if [ -d "$TLS_ROOT/$ARCH" ]; then SSL_ROOT="$TLS_ROOT/$ARCH"; fi
    PREFIX="$BUILD/$ARCH"

    for NAME in ngtcp2 nghttp3; do
        case "$NAME" in ngtcp2) VERSION=1.18.0;; nghttp3) VERSION=1.12.0;; esac
        CMAKE_BUILD="$BUILD/build-$NAME-$ARCH"
        rm -rf "$CMAKE_BUILD"
        if [ "$TLS_BACKEND" = "awslc" ]; then
            # shellcheck disable=SC2086
            cmake -S "$BUILD/src/$NAME-$VERSION" -B "$CMAKE_BUILD" $GEN_ARGS \
                -DCMAKE_BUILD_TYPE=Release -DCMAKE_OSX_ARCHITECTURES="$ARCH" \
                -DCMAKE_OSX_DEPLOYMENT_TARGET=13.0 -DCMAKE_INSTALL_PREFIX="$PREFIX" \
                -DCMAKE_POSITION_INDEPENDENT_CODE=ON -DBUILD_TESTING=OFF \
                -DENABLE_LIB_ONLY=ON -DENABLE_STATIC_LIB=ON -DENABLE_SHARED_LIB=OFF \
                -DENABLE_OPENSSL=OFF -DENABLE_GNUTLS=OFF \
                -DENABLE_BORINGSSL=ON -DENABLE_PICOTLS=OFF -DENABLE_WOLFSSL=OFF \
                -DBORINGSSL_INCLUDE_DIR="$SSL_ROOT/include" \
                -DBORINGSSL_LIBRARIES="$SSL_ROOT/lib/libssl.a;$SSL_ROOT/lib/libcrypto.a"
        else
            # shellcheck disable=SC2086
            cmake -S "$BUILD/src/$NAME-$VERSION" -B "$CMAKE_BUILD" $GEN_ARGS \
                -DCMAKE_BUILD_TYPE=Release -DCMAKE_OSX_ARCHITECTURES="$ARCH" \
                -DCMAKE_OSX_DEPLOYMENT_TARGET=13.0 -DCMAKE_INSTALL_PREFIX="$PREFIX" \
                -DCMAKE_POSITION_INDEPENDENT_CODE=ON -DBUILD_TESTING=OFF \
                -DENABLE_LIB_ONLY=ON -DENABLE_STATIC_LIB=ON -DENABLE_SHARED_LIB=OFF \
                -DENABLE_OPENSSL=ON -DENABLE_GNUTLS=OFF \
                -DENABLE_BORINGSSL=OFF -DENABLE_PICOTLS=OFF -DENABLE_WOLFSSL=OFF \
                -DOPENSSL_ROOT_DIR="$SSL_ROOT" -DOPENSSL_USE_STATIC_LIBS=TRUE
        fi
        cmake --build "$CMAKE_BUILD" --parallel "$JOBS"
        cmake --install "$CMAKE_BUILD"
        rm -rf "$CMAKE_BUILD"
    done
done

FIRST_ARCH=$(printf '%s\n' "$ARCHS" | awk '{print $1}')
cp -pR "$BUILD/$FIRST_ARCH/include/" "$BUILD/include/"
for NAME in ngtcp2 "$CRYPTO_LIB_NAME" nghttp3; do
    set --
    for ARCH in $ARCHS; do
        FILE="$BUILD/$ARCH/lib/lib$NAME.a"
        if [ ! -f "$FILE" ]; then echo "Missing $FILE" >&2; exit 1; fi
        set -- "$@" "$FILE"
    done
    lipo -create "$@" -output "$BUILD/lib/lib$NAME.a"
done
echo "Built C QUIC dependencies ($TLS_BACKEND) for $ARCHS at $BUILD"
