#!/bin/bash
# Generate CMake toolchain file for dependencies

set -e

SCRIPTDIR="$(dirname "$0")"
BASEDIR="$SCRIPTDIR"
HOST="${HOST:-x86_64-linux-gnu}"
DISTDIR="$BASEDIR/dist"

# Create toolchain file
TOOLCHAIN_FILE="$BASEDIR/toolchainfile.cmake"

cat > "$TOOLCHAIN_FILE" << EOF
# CMake toolchain file for Pastella dependencies
# Generated for $HOST

set(CMAKE_SYSTEM_NAME $("$SCRIPTDIR/config.guess"))

# Cross-compilation settings
set(CMAKE_PREFIX_PATH "$DISTDIR/$HOST")

set(CMAKE_FIND_ROOT_PATH "$DISTDIR/$HOST")
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)

# Boost
set(BOOST_ROOT "$DISTDIR/$HOST")
set(Boost_INCLUDE_DIR "$DISTDIR/$HOST/include")
set(Boost_LIBRARY_DIR "$DISTDIR/$HOST/lib")

# OpenSSL
set(OPENSSL_ROOT_DIR "$DISTDIR/$HOST")
set(OPENSSL_INCLUDE_DIR "$DISTDIR/$HOST/include")
set(OPENSSL_CRYPTO_LIBRARY "$DISTDIR/$HOST/lib/libcrypto.a")
set(OPENSSL_SSL_LIBRARY "$DISTDIR/$HOST/lib/libssl.a")
EOF

echo "Toolchain file generated: $TOOLCHAIN_FILE"
echo ""
echo "Usage in CMake:"
echo "  cmake -DCMAKE_TOOLCHAIN_FILE=$TOOLCHAIN_FILE .."
