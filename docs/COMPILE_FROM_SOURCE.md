# Compiling PastellaCore from Source

This guide provides detailed instructions for compiling PastellaCore on various platforms.

## Table of Contents

- [Quick Start](#quick-start)
- [Prerequisites](#prerequisites)
- [Linux](#linux)
- [Windows](#windows)
- [macOS](#macos)
- [FreeBSD](#freebsd)
- [Build Targets](#build-targets)

## Quick Start

### Linux (Native Build)
```bash
git clone https://github.com/PastellaOrg/PastellaCore.git
cd PastellaCore
make release
```

Binaries will be in `build/src/`

---

## Prerequisites

### Common Requirements

- **CMake** 3.8 or higher
- **Make** (GNU Make)
- **Git**
- **C++17 compatible compiler** (GCC 7.0+, Clang 6.0+)
- **Boost** 1.66 or higher
- **OpenSSL**

### Platform-Specific

| Platform | Additional Requirements |
|----------|-------------------------|
| Linux | build-essential, libzstd-dev |
| Windows | MinGW-w64, MSYS2 |
| macOS | XCode, Command Line Tools |
| FreeBSD | clang, libc++ |

---

## Linux

### Ubuntu/Debian

```bash
# Install dependencies
sudo apt-get update
sudo apt-get install -y \
    build-essential \
    cmake \
    git \
    libboost-all-dev \
    libzstd-dev \
    python3

# Clone repository
git clone https://github.com/PastellaOrg/PastellaCore.git
cd PastellaCore

# Build
make release

# Run
./build/src/Pastellad --version
```

### Arch Linux

```bash
# Install dependencies
sudo pacman -S cmake git boost python3 zstd

# Clone repository
git clone https://github.com/PastellaOrg/PastellaCore.git
cd PastellaCore

# Build
make release

# Run
./build/src/Pastellad --version
```

### Fedora/RHEL

```bash
# Install dependencies
sudo dnf install -y \
    cmake \
    git \
    boost-devel \
    boost-static \
    zlib-static \
    python3

# Clone repository
git clone https://github.com/PastellaOrg/PastellaCore.git
cd PastellaCore

# Build
make release

# Run
./build/src/Pastellad --version
```

### Static Linux Build (Fully Portable)

For a static build with all dependencies bundled:

```bash
# Build dependencies
make depends-linux

# Build static binary
make release-static-linux-x86_64
```

The static binary will be in `build/release/x86_64-linux-gnu/src/`

### Linux ARM64 (Raspberry Pi, ARM servers)

For static ARM64 build:

```bash
# Build dependencies
make depends-linux-arm64

# Build static binary
make release-static-linux-arm64
```

The static binary will be in `build/release/arm64-linux/src/`

---

## Windows

Windows builds are done via **cross-compilation from Linux**.

### Option 1: Using Make (Recommended)

```bash
# Install MinGW-w64 on Ubuntu/Debian
sudo apt-get install -y mingw-w64

# Build dependencies
make depends-win64

# Build Windows binary
make release-static-win64
```

The Windows binary will be in `build/release/x86_64-w64-mingw32/src/`

### Option 2: Using Visual Studio (Native)

1. Install [Visual Studio 2019 or later](https://visualstudio.microsoft.com/)
2. Install "Desktop development with C++" workload
3. Install [Boost](https://www.boost.org/users/download/) (1.66 or later)
4. Install [CMake](https://cmake.org/download/)
5. Clone repository and open Developer Command Prompt

```cmd
cd PastellaCore
mkdir build
cd build
cmake -G "Visual Studio 16 2019" -A x64 ..
```

6. Open `PastellaCore.sln` in Visual Studio
7. Build → Build Solution (Release configuration)

---

## macOS

### Option 1: Using Homebrew (x86_64)

```bash
# Install XCode and Command Line Tools
xcode-select --install

# Install Homebrew
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install dependencies
brew install cmake boost git

# Clone repository
git clone https://github.com/PastellaOrg/PastellaCore.git
cd PastellaCore

# Build
make release

# Run
./build/src/Pastellad --version
```

### Option 2: Static macOS Build

For a static build (more portable):

```bash
# Build dependencies
make depends-mac

# Build static binary
make release-static-mac-x86_64
```

### macOS ARM64 (Apple Silicon M1/M2/M3)

```bash
# Build dependencies
make depends-mac-arm64

# Build static binary
make release-static-mac-arm64
```

---

## FreeBSD

```bash
# Install dependencies
pkg install cmake git boost-python3 python3 zstd

# Clone repository
git clone https://github.com/PastellaOrg/PastellaCore.git
cd PastellaCore

# Build
make release

# Or for static build
make release-static-freebsd-x86_64
```

---

## Build Targets

### Quick Reference

| Target | Description | Command |
|--------|-------------|---------|
| `release` | Optimized build with system libraries | `make release` |
| `debug` | Debug build with symbols | `make debug` |
| `release-all` | Release with all components | `make release-all` |

### Static Build Targets (Portable Binaries)

| Target | Description | Command |
|--------|-------------|---------|
| `release-static-linux-x86_64` | Static Linux x86_64 | `make depends-linux && make release-static-linux-x86_64` |
| `release-static-linux-arm64` | Static Linux ARM64 | `make depends-linux-arm64 && make release-static-linux-arm64` |
| `release-static-win64` | Static Windows x64 (cross-compile) | `make depends-win64 && make release-static-win64` |
| `release-static-mac-x86_64` | Static macOS x86_64 | `make depends-mac && make release-static-mac-x86_64` |
| `release-static-mac-arm64` | Static macOS ARM64 | `make depends-mac-arm64 && make release-static-mac-arm64` |
| `release-static-freebsd-x86_64` | Static FreeBSD x86_64 | `make depends-freebsd && make release-static-freebsd-x86_64` |

### Dependency Management

| Target | Description | Command |
|--------|-------------|---------|
| `depends` | Auto-detect system and build dependencies | `make depends` |
| `depends-win64` | Build Windows x64 dependencies | `make depends-win64` |
| `depends-linux` | Build Linux x86_64 dependencies | `make depends-linux` |
| `depends-linux-arm64` | Build Linux ARM64 dependencies | `make depends-linux-arm64` |
| `depends-mac` | Build macOS x86_64 dependencies | `make depends-mac` |
| `depends-mac-arm64` | Build macOS ARM64 dependencies | `make depends-mac-arm64` |
| `depends-freebsd` | Build FreeBSD x86_64 dependencies | `make depends-freebsd` |

### Clean Targets

| Target | Description | Command |
|--------|-------------|---------|
| `clean` | Remove build directory | `make clean` |
| `clean-all` | Remove all build directories | `make clean-all` |
| `clean-depends` | Clean dependencies for current system | `make clean-depends` |
| `clean-depends-all` | Clean all dependency builds | `make clean-depends-all` |

---

## Getting Help

For a full list of build targets:

```bash
make help
```

For issues or questions:

- [GitHub Issues](https://github.com/PastellaOrg/PastellaCore/issues)
- [Discord](https://discord.gg/pastella)

---

## Build Output Locations

After building, binaries are located in:

| Build Type | Location |
|------------|----------|
| Debug | `build/debug/src/` |
| Release | `build/release/src/` |
| Static Linux x86_64 | `build/release/x86_64-linux-gnu/src/` |
| Static Linux ARM64 | `build/release/arm64-linux/src/` |
| Static Windows | `build/release/x86_64-w64-mingw32/src/` |
| Static macOS x86_64 | `build/release/x86_64-apple-darwin/src/` |
| Static macOS ARM64 | `build/release/arm64-apple-darwin/src/` |
| Static FreeBSD | `build/release/x86_64-unknown-freebsd/src/` |

Main binaries:
- `Pastellad` - Daemon/node
- `Pastella-Wallet` - CLI wallet
- `Pastella-Wallet-API` - Wallet API server
- `P2P` - P2P node (for testing)

---

## Troubleshooting

### Build Fails with "boost not found"

Ensure Boost is installed and its path is set correctly:

```bash
# Linux
export BOOST_ROOT=/usr
cmake -DBOOST_ROOT=$BOOST_ROOT ..
```

### Build Fails with "cmake version too old"

Install CMake 3.8+:

```bash
# Ubuntu/Debian
sudo pip3 install cmake

# Or
sudo apt-get install cmake
```

### Windows Build: "wine not found" or "gcc not found"

Ensure MinGW-w64 is properly installed and in your PATH:

```bash
sudo apt-get install mingw-w64
```

### macOS Build: "command not found: cmake"

Install CMake via Homebrew:

```bash
brew install cmake
```

### ARM Build: "aarch64-linux-gnu not found"

Build dependencies first:

```bash
make depends-linux-arm64
```

### Running Pastellad: "error while loading shared libraries"

For static builds, this shouldn't happen. For dynamic builds, ensure library paths are set:

```bash
export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH
```
