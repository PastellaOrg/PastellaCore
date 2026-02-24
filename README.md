![image](https://raw.githubusercontent.com/PastellaProject/Pastella/main/src/config/logo-small.png)

```
LICENSES:

// Copyright (c) 2012-2017, The CryptoNote developers, The Bytecoin developers
// Copyright (c) 2014-2018, The Monero Project
// Copyright (c) 2018-2019, The TurtleCoin Developers
// Copyright (c) 2026, The Pastella Team
```

[Website](https://pastella.network) | [Official Pool](https://pool.pastella.network/) | [Official Block Explorer](https://explorer.pastella.network/) | [Discord](https://discord.gg/pastella) | [Twitter](https://twitter.com/PastellaProtocol)

![Download Count](https://img.shields.io/github/downloads/PastellaProject/Pastella/total.svg)
![Open Issue Count](https://img.shields.io/github/issues/PastellaProject/Pastella)
![Version](https://img.shields.io/github/v/release/PastellaProject/Pastella)

****

# Pastella Protocol

**Pastella Protocol** is a next-generation blockchain platform featuring hybrid consensus, on-chain governance, and advanced economic mechanisms. Building upon the foundations of CryptoNote, Pastella has evolved into a comprehensive protocol with native staking, decentralized governance, and sophisticated tokenomics.

## Key Features

- **Hybrid Consensus**: Combines RandomX Proof-of-Work with Simple Reward Staking
- **On-Chain Governance**: Decentralized proposal and voting system for protocol upgrades and parameter changes
- **Staking System**: Multi-tier staking with variable annual rewards (5%-50%) based on lock duration
- **Governance Integration**: Staking provides voting power with multipliers for longer lock periods
- **Advanced Tokenomics**: 80M total supply with yearly halving over 10 years
- **Privacy-Preserving**: Ring signatures and stealth addresses inherited from CryptoNote

### Coin specifications:

|Ticker|Decimals|Supply|Block Reward|Block Time|P2P Port|RPC Port|Service Port|Algo
|--|--|--|--|--|--|--|--|--|
|PAS|8|80,000,000 PAS|4 PAS|30 Seconds|21000|21001|21002|RandomX|

****

### Installing

You can download the latest binary images from here: https://github.com/PastellaProject/Pastella/releases
To compile the binaries yourself, scroll down to the next section.

****

### Ubuntu 64 bit Compiling

##### Prerequisites

You will need the following packages: boost, cmake (3.8 or higher), make, git and GCC/G++ (GCC-7.0 or higher).

##### Commands

- `sudo apt-get install software-properties-common -y`
- `sudo add-apt-repository ppa:ubuntu-toolchain-r/test -y`
- `sudo apt-get update`
- `sudo apt-get install aptitude libzstd-dev -y`
- `sudo aptitude install -y build-essential g++-8 gcc-8 git libboost-all-dev python3-pip`
- `sudo pip3 install cmake`
- `export CC=gcc`
- `export CXX=g++`
- `git clone -b master --single-branch https://github.com/PastellaProject/Pastella`
- `cd Pastella`
- `mkdir build`
- `cd build`
- `cmake ..`
- `make` *(To compile with a different amount of threads, use `make -j4` and replace the `4` with the your desired thread amount.)*

When the build process is complete. You can find the binary in `Pastella/build/src`.

- `cd src`
- `./Pastellad --version`

****
### Windows 64 bit Compiling

##### Prerequisites
- Install  [Visual Studio 2017 Community Edition](https://github.com/PastellaProject/Pastella/raw/main/downloads/vs_community.exe)
- When installing Visual Studio, it is  **required**  that you install  **Desktop development with C++**
- Install [Boost 1.68](https://sourceforge.net/projects/boost/files/boost-binaries/1.68.0/boost_1_68_0-msvc-14.1-64.exe/download)

##### Commands
- [Download](https://github.com/PastellaProject/Pastella/archive/master.zip) the GitHub repository and extract it somewhere.
- From the start menu, open 'Developer Command Prompt for VS 2017'.
- `cd <your_Pastella_location>`
- `mkdir build`
- `cd build`
- `set PATH="C:\Program Files (x86)\Microsoft Visual Studio\2017\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin";%PATH%`
- `cmake -G "Visual Studio 15 2017 Win64" .. -DBOOST_ROOT=C:/local/boost_1_68_0`

When it's done creating the cmake files you go ahead and open the `Pastella/build/Pastella.sln` file.
On the top right corner you see `Debug` and `x64` next to the `green play button`. Change `Debug` to `Releases`.  Then click on `Build` on the top menu and hit `Build Solution`. When the build process is complete. You can find the binary in `Pastella/build/src/Releases`.

****

### OSX/Apple 64 bit Compiling

##### Prerequisites

-   Install XCode and Developer Tools.

##### Commands

-   `which brew || /usr/bin/ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"`
-   `brew install --force cmake boost llvm gcc@8`
-   `export CC=gcc-8`
-   `export CXX=g++-8`
-   `git clone -b master --single-branch https://github.com/PastellaProject/Pastella`
-   `cd Pastella`
-   `mkdir build`
-   `cd build`
-   `cmake ..`
- `make` *(To compile with a different amount of threads, use `make -j4` and replace the 4 with the your desired thread amount.)*

When the build process is complete. You can find the binary in `Pastella/build/src`.

- `cd src`
- `./Pastellad --version`

****
### Raspberry Pi 3 B+ (AARCH64/ARM64) Compiling
The following images are known to work. Your operation system image  **MUST**  be 64 bit.

##### Known working images

-   [https://github.com/Crazyhead90/pi64/releases](https://github.com/Crazyhead90/pi64/releases)
-   [https://fedoraproject.org/wiki/Architectures/ARM/Raspberry_Pi#aarch64_supported_images_for_Raspberry_Pi_3](https://fedoraproject.org/wiki/Architectures/ARM/Raspberry_Pi#aarch64_supported_images_for_Raspberry_Pi_3)
-   [https://archlinuxarm.org/platforms/armv8/broadcom/raspberry-pi-3](https://archlinuxarm.org/platforms/armv8/broadcom/raspberry-pi-3)

Once you have a 64 bit image installed, setup proceeds the same as any Linux distribution. Ensure you have at least 2GB of ram, or the build is likely to fail. You may need to setup swap space.

##### Commands

-   `git clone -b master --single-branch https://github.com/PastellaProject/Pastella`
-   `cd Pastella`
-   `mkdir build`
-   `cd build`
-   `cmake ..`
-   `make`

When the build process is complete. You can find the binary in `Pastella/build/src`.

- `cd src`
- `./Pastellad --version`

****

### Thanks to these people to make Pastella happen
CryptoNote Developers, Bytecoin Developers, Monero Developers, Forknote Project, TurtleCoin Community, Pastella Team.

****
