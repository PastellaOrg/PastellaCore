# Pastella Dependency Build System

This system automatically builds Boost and OpenSSL for cross-compilation.

## Quick Start

```bash
cd contrib/depends

# Build dependencies for current platform
make

# Build for Windows (cross-compile from Linux)
make HOST=x86_64-w64-mingw32

# Build for Windows 32-bit
make HOST=i686-w64-mingw32

# Clean build
make clean
```

## What It Does

1. **Downloads** Boost 1.68.0 and OpenSSL 1.1.1w
2. **Extracts** them to `work/` directory
3. **Compiles** them for the target platform
4. **Installs** them to `dist/<target>/`

## Output

After building, dependencies are in:
```
dist/
├── x86_64-linux-gnu/       # Linux native builds
│   ├── include/
│   ├── lib/
│   └── share/
├── x86_64-w64-mingw32/     # Windows 64-bit (cross-compiled)
│   ├── include/
│   ├── lib/
│   └── share/
└── i686-w64-mingw32/       # Windows 32-bit (cross-compiled)
    ├── include/
    ├── lib/
    └── share/
```

## Usage in Main Makefile

After building dependencies, the main Makefile can use them:

```bash
cd ../..

# Build with dependencies
make release-static-linux-x86_64
make release-static-win64
```

The main Makefile automatically detects and uses the built dependencies.

## Prerequisites

### Linux
```bash
sudo apt-get install build-essential cmake git wget g++-mingw-w64-x86-64
```

### For Cross-Compilation to Windows
```bash
sudo apt-get install g++-mingw-w64-x86-64 g++-mingw-w64-i686
```

## Manual Control

### Build specific package
```bash
cd contrib/depends
make boost      # Build only Boost
make openssl    # Build only OpenSSL
```

### Force rebuild
```bash
make clean
make all
```

## Troubleshooting

**Problem:** Build fails with MinGW errors
```bash
# Ensure MinGW is in POSIX mode
sudo update-alternatives --set x86_64-w64-mingw32-g++ x86_64-w64-mingw32-g++-posix
sudo update-alternatives --set x86_64-w64-mingw32-gcc x86_64-w64-mingw32-gcc-posix
```

**Problem:** Download fails
```bash
# Manually download to sources/ directory
cd contrib/depends/sources
wget https://archives.boost.io/release/1.68.0/source/boost_1_68_0.tar.gz
wget https://www.openssl.org/source/openssl-1.1.1w.tar.gz
```

**Problem:** Partial download
```bash
# Remove partial file and rebuild
rm -f sources/*.tar.gz
make clean
make all
```

## Structure

```
contrib/depends/
├── Makefile                 # Main build control
├── funcs.mk                # Common build functions
├── generate-toolchain.sh   # CMake toolchain generator
├── config.guess            # Host system detection
├── packages/
│   ├── boost.mk           # Boost build recipe
│   └── openssl.mk         # OpenSSL build recipe
├── built/                  # Temporary build files
├── dist/                   # Final installation directory
├── sources/                # Downloaded source tarballs
└── work/                   # Extracted sources
```

## Advanced

### Custom OpenSSL configuration
Edit `packages/openssl.mk` and modify the `openssl_build` function.

### Custom Boost libraries
Edit `packages/boost.mk` and modify the `--with-libraries=` option.

### Different versions
Update `boost_version` or `openssl_version` in the respective `.mk` files.

## Integration with Main Build

The main `Makefile` automatically detects dependencies:

1. If `contrib/depends/dist/<HOST>/` exists, uses those
2. Otherwise, tries system libraries
3. Falls back to bundled libraries in `/external/`

This ensures builds work everywhere - from developer machines to CI systems.
