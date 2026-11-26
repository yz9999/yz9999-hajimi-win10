#!/bin/sh
# Build locked libssh2 snapshot against AWS-LC (default) or OpenSSL inside workspace.
set -eu
export LC_ALL=C
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
BASE="$ROOT/.build/Vendor/HajimiSSH"
COMMIT=2e1717456b8dd4c980e8e48d6dbfec524c2e62d1
HASH=cffa24d90bf14a26154b1124e0dcdaab1fe4038000a8f5a127acb77631a8ebe5
ARCHIVE="$BASE/downloads/libssh2-$COMMIT.tar.gz"
SOURCE="$BASE/src/libssh2-$COMMIT"
TLS_BACKEND=${HAJIMI_TLS_BACKEND:-openssl}

if [ "$TLS_BACKEND" = "awslc" ]; then
    TLS_ROOT=${HAJIMI_AWSLC_ROOT:-$ROOT/.build/Vendor/AWSLC}
else
    DEFAULT_SSL=/usr/local/opt/openssl@3
    if [ -f /opt/homebrew/opt/openssl@3/include/openssl/ssl.h ]; then DEFAULT_SSL=/opt/homebrew/opt/openssl@3; fi
    TLS_ROOT=${HAJIMI_OPENSSL_ROOT:-${OPENSSL_ROOT_DIR:-$DEFAULT_SSL}}
fi

ARCHS=${HAJIMI_ARCHS:-$(uname -m)}
JOBS=${HAJIMI_BUILD_JOBS:-$(sysctl -n hw.ncpu 2>/dev/null || echo 4)}
if [ -f "$BASE/include/libssh2.h" ] && [ -f "$BASE/lib/libssh2.a" ]; then
    OK_SSH=1
    for ARCH in $ARCHS; do
        lipo "$BASE/lib/libssh2.a" -verify_arch "$ARCH" >/dev/null 2>&1 || OK_SSH=0
    done
    if [ "$OK_SSH" = "1" ]; then
        printf '%s\n' "Reusing cached native SSH static library ($TLS_BACKEND, $ARCHS) at $BASE"
        exit 0
    fi
fi

mkdir -p "$BASE/downloads" "$BASE/src" "$BASE/include" "$BASE/lib" 

if [ ! -f "$ARCHIVE" ]; then
    curl --proto '=https' --tlsv1.2 --fail --location --connect-timeout 10 --max-time 120 \
        "https://codeload.github.com/libssh2/libssh2/tar.gz/$COMMIT" -o "$ARCHIVE"
fi
ACTUAL=$(/usr/bin/shasum -a 256 "$ARCHIVE" | /usr/bin/awk '{print $1}')
if [ "$ACTUAL" != "$HASH" ]; then
    printf '%s\n' "libssh2 source checksum mismatch; refusing to extract or compile." >&2
    exit 1
fi
if [ ! -d "$SOURCE" ]; then tar -xzf "$ARCHIVE" -C "$BASE/src"; fi

GEN_ARGS=""
if command -v ninja >/dev/null 2>&1; then GEN_ARGS="-GNinja"; fi

for ARCH in $ARCHS; do
    case "$ARCH" in x86_64|arm64) ;; *) printf '%s\n' "Unsupported architecture: $ARCH" >&2; exit 1;; esac
    SSL_ROOT=$TLS_ROOT
    if [ -d "$TLS_ROOT/$ARCH" ]; then SSL_ROOT="$TLS_ROOT/$ARCH"; fi
    if [ ! -f "$SSL_ROOT/include/openssl/ssl.h" ] || [ ! -f "$SSL_ROOT/lib/libcrypto.a" ]; then
        printf '%s\n' "TLS static archive missing at $SSL_ROOT" >&2
        exit 1
    fi
    PREFIX="$BASE/$ARCH"
    CMAKE_BUILD="$BASE/build-$ARCH"
    rm -rf "$CMAKE_BUILD"
    # shellcheck disable=SC2086
    cmake -S "$SOURCE" -B "$CMAKE_BUILD" $GEN_ARGS \
        -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="$PREFIX" \
        -DCMAKE_OSX_ARCHITECTURES="$ARCH" -DCMAKE_OSX_DEPLOYMENT_TARGET=13.0 \
        -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
        -DCRYPTO_BACKEND=OpenSSL -DOPENSSL_ROOT_DIR="$SSL_ROOT" \
        -DOPENSSL_USE_STATIC_LIBS=ON -DBUILD_SHARED_LIBS=OFF -DBUILD_STATIC_LIBS=ON \
        -DBUILD_EXAMPLES=OFF -DBUILD_TESTING=OFF -DLIBSSH2_BUILD_DOCS=OFF \
        -DPICKY_COMPILER=OFF -DENABLE_ZLIB_COMPRESSION=OFF
    cmake --build "$CMAKE_BUILD" --parallel "$JOBS"
    cmake --install "$CMAKE_BUILD"
    rm -rf "$CMAKE_BUILD"
done

FIRST_ARCH=$(printf '%s\n' "$ARCHS" | awk '{print $1}')
cp -pR "$BASE/$FIRST_ARCH/include/" "$BASE/include/"
set --
for ARCH in $ARCHS; do
    FILE="$BASE/$ARCH/lib/libssh2.a"
    if [ ! -f "$FILE" ]; then printf '%s\n' "Missing native SSH archive for $ARCH" >&2; exit 1; fi
    set -- "$@" "$FILE"
done
TEMPORARY="$BASE/lib/.libssh2.a.$$.tmp"
lipo -create "$@" -output "$TEMPORARY"
mv -f "$TEMPORARY" "$BASE/lib/libssh2.a"
printf '%s\n' "Built native SSH ($TLS_BACKEND) for $ARCHS: $BASE/include, $BASE/lib/libssh2.a"
