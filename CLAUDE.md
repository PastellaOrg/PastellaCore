# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Pastella Protocol is a next-generation blockchain platform featuring hybrid consensus (RandomX PoW + Staking), on-chain governance, and advanced economic mechanisms. The codebase inherits technology from CryptoNote/Bytecoin, Monero, and TurtleCoin, but has evolved significantly beyond the original CryptoNote specification with native staking, decentralized governance, and sophisticated tokenomics.

## Build Commands

### Standard Build
```bash
mkdir build && cd build
cmake ..               # Configure with default Release build type
make                   # Compile with make -j$(nproc) for faster compilation
```

### Build Variations
- `make -j4` - Compile with 4 threads (adjust as needed)
- `cmake -DCMAKE_BUILD_TYPE=Debug ..` - Debug build with symbols
- `cmake -DCMAKE_BUILD_TYPE=RelWithDebInfo ..` - Release with debug info

### Build Configuration Options
- `cmake -DWITH_LEVELDB=ON ..` - Use LevelDB instead of RocksDB
- `cmake -DNO_AES=ON ..` - Disable hardware AES (for ARM compatibility)
- `cmake -DARCH=native ..` - Optimize for host CPU (default)

## Build Outputs

The build system produces these binaries in `build/src/`:

- **Pastellad** - Main blockchain daemon
- **Pastella-Wallet** - CLI wallet (zedwallet++)
- **Pastella-Wallet-API** - Wallet API library

## Architecture Overview

### Core Components

**Daemon Architecture:**
- `/src/daemon/` - Main node implementation (Pastellad)
- `/src/cryptonotecore/` - Blockchain validation, transactions, consensus, staking, governance
- `/src/p2p/` - Peer-to-peer networking and discovery
- `/src/rpc/` - JSON-RPC API for daemon communication

**Wallet Architecture:**
- `/src/zedwallet++/` - CLI wallet interface
- `/src/walletbackend/` - Core wallet functionality
- `/src/walletservice/` - Wallet API service daemon
- `/src/walletapi/` - Wallet API library for external integration

**Supporting Systems:**
- `/src/crypto/` - Cryptographic primitives (Keccak, RandomX)
- `/src/miner/` - Mining software implementation
- `/src/config/` - Blockchain parameters and coin specifications
- `/src/cryptonotecore/StakingSystem.*` - Staking pool and validation
- `/src/cryptonotecore/GovernanceSystem.*` - On-chain governance manager

### Key Configuration

**Cryptocurrency Parameters** (`/src/config/CryptoNoteConfig.h`):
- Ticker: PAS, Total Supply: 80M PAS
- Block Time: 30 seconds, Algorithm: RandomX
- Yearly halving for 10 years
- Staking: 5-tier lock-up system (1, 30, 90, 180, 365 days) with variable rewards (5%-50%)
- Governance: On-chain proposals and voting with weighted voting based on stake duration

**Database Options:**
- **RocksDB** (default) - High-performance key-value storage
- **LevelDB** (alternative) - Configure with `cmake -DWITH_LEVELDB=ON`

### Dependencies Management

All third-party libraries are included in `/external/` and statically linked:
- Crypto++ - Cryptographic operations
- RocksDB/LevelDB - Blockchain storage
- Boost - System libraries (threading, networking)
- OpenSSL - TLS/HTTPS support (optional, auto-detected)
- ZSTD/LZ4 - Database compression
- MiniUPnPc - Automatic port forwarding

## Development Workflow

### Testing
No formal test suite is included in the codebase. Testing is typically done manually by:
1. Running `Pastellad --version` to verify build
2. Testing daemon operations with different configurations
3. Verifying wallet functionality
4. Testing staking operations and reward calculations
5. Testing governance proposals and voting

### Development Setup
- **C++17** is required (GCC 7.0+, Clang 6.0+, MSVC 2017+)
- All dependencies are statically linked by default
- Cross-platform support: Linux, Windows, macOS, ARM64

### Key Files to Understand

**Entry Points:**
- `/src/daemon/Daemon.cpp` - Main daemon entry point (Pastellad)
- `/src/zedwallet++/ZedWallet.cpp` - CLI wallet entry point
- `/src/walletservice/main.cpp` - Wallet service entry point

**Configuration:**
- `/src/config/CryptoNoteConfig.h` - Core blockchain parameters
- `/src/config/CryptoNoteConfig.h` - Network settings, ports, fees
- `CMakeLists.txt` - Build configuration and options

**New Systems:**
- `/src/cryptonotecore/StakingSystem.h` - Staking pool and validation
- `/src/cryptonotecore/GovernanceSystem.h` - On-chain governance manager
- `/src/common/TransactionExtra.h` - Transaction extra fields for staking/governance

## Platform-Specific Notes

### Linux/Unix
- Requires pthread linking
- Uses glibc-specific optimizations when available
- ccache automatically detected and used if available

### macOS
- Requires XCode and Developer Tools
- Links against libc++ instead of libstdc++
- Uses Homebrew OpenSSL if detected

### Windows
- Requires Visual Studio 2017+ with Desktop C++ development tools
- Uses static runtime linking (/MT)
- Requires Boost 1.68+ for Windows builds

### ARM64
- Set `NO_AES=ON` if hardware AES causes issues
- Set `ARCH=native` or target-specific architecture
- May need increased RAM or swap for compilation

## Network Configuration

- **P2P Port**: 21000
- **RPC Port**: 21001
- **Service Port**: 21002

Default configuration files are typically stored in platform-specific data directories.

## Unique Features

Pastella Protocol introduces several innovations beyond the original CryptoNote specification:

### Staking System
- Multi-tier lock-up periods: 1, 30, 90, 180, 365 days
- Variable annual rewards: 5%, 2%, 8%, 18%, 50% respectively
- Transparent address tracking for reward payouts
- Minimum stake: 1.0 PAS
- Integration with governance for voting power

### Governance System
- On-chain proposal creation and voting
- Proposal types: Parameter changes, Protocol upgrades, Treasury spending
- 7-day proposal duration (3360 blocks)
- Voting thresholds: 51% (simple), 67% (supermajority), 75% (consensus)
- Voting power multipliers: 1x, 2x, 3x, 4x based on stake lock duration
- Minimum proposal stake: 1.0 PAS
- Proposal fee: 0.1 PAS

### Hybrid Consensus
- RandomX Proof-of-Work algorithm
- Staking rewards distributed from transaction fees
- Governance voting power derived from staked tokens

- NEVER USE GIT!! NEVERRR!!!