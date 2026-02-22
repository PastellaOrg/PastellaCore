# Build statically
add_definitions(-DSTATICLIB)

# Add external libraries as include dirs, so we can do #include "httplib" for example
if (WITH_LEVELDB)
  include_directories(${CMAKE_SOURCE_DIR}/external/leveldb/include)
endif ()
include_directories(${CMAKE_SOURCE_DIR}/external/rocksdb/include)
include_directories(${CMAKE_SOURCE_DIR}/external/cpp-linenoise)
include_directories(${CMAKE_SOURCE_DIR}/external/cpp-httplib)
include_directories(${CMAKE_SOURCE_DIR}/external/nlohmann-json)
include_directories(${CMAKE_SOURCE_DIR}/external/rapidjson)
include_directories(${CMAKE_SOURCE_DIR}/external/cxxopts)
include_directories(${CMAKE_SOURCE_DIR}/external/cryptopp)
include_directories(${CMAKE_SOURCE_DIR}/external/zstd)
include_directories(${CMAKE_SOURCE_DIR}/external/lz4)
include_directories(${CMAKE_SOURCE_DIR}/external/snappy)

# Show cmake where the source files are
# Note, if you add remove a source file, you will need to re-run cmake so it
# can find the new file
file(GLOB_RECURSE Common common/*)
file(GLOB_RECURSE Config config/*)
file(GLOB_RECURSE Crypto crypto/*)
file(GLOB_RECURSE PastellaCore pastellacore/* PastellaConfig.h)
if (WITH_LEVELDB)
  message(STATUS "WITH_LEVELDB: Remove: RocksDBWrapper")
  list(FILTER PastellaCore EXCLUDE REGEX ".*RocksDBWrapper.*$")
else ()
  message(STATUS "WITH_LEVELDB: Remove: LevelDBWrapper")
  list(FILTER PastellaCore EXCLUDE REGEX ".*LevelDBWrapper.*$")
endif ()
  file(GLOB_RECURSE PastellaProtocol pastellaprotocol/*)
  file(GLOB_RECURSE CryptoTest cryptotest/*)
  file(GLOB_RECURSE Errors errors/*)
file(GLOB_RECURSE Http http/*)
file(GLOB_RECURSE JsonRpcServer jsonrpcserver/*)
file(GLOB_RECURSE Logging logging/*)
file(GLOB_RECURSE Logger logger/*)
file(GLOB_RECURSE Mnemonics mnemonics/*)
file(GLOB_RECURSE Nigel nigel/*)
file(GLOB_RECURSE NodeRpcProxy noderpcproxy/*)
file(GLOB_RECURSE P2p p2p/*)
file(GLOB_RECURSE Rpc rpc/*)
file(GLOB_RECURSE Serialization serialization/*)
file(GLOB_RECURSE SubWallets subwallets/*)
file(GLOB_RECURSE Transfers transfers/*)
file(GLOB_RECURSE Pastellad daemon/*)
file(GLOB_RECURSE Utilities utilities/*)
file(GLOB_RECURSE Wallet wallet/*)
file(GLOB_RECURSE WalletApi walletapi/*)
file(GLOB_RECURSE WalletBackend walletbackend/*)
file(GLOB_RECURSE pastellawallet pastellawallet/*)

if (MSVC)
    file(GLOB_RECURSE System system/* platform/windows/system/*)
elseif (MINGW OR MSYS)
    file(GLOB_RECURSE System system/* platform/windows/system/* platform/posix/system/*)
elseif (APPLE)
    file(GLOB_RECURSE System system/* platform/osx/system/* platform/posix/system/*)
else ()
    file(GLOB_RECURSE System system/* platform/linux/system/* platform/posix/system/*)
endif ()
else ()
    file(GLOB_RECURSE System system/* platform/linux/system/* platform/posix/system/*)
endif ()

# Group the files together in IDEs
source_group("" FILES $${Common} ${Config} ${Crypto} ${PastellaCore} ${PastellaProtocol} ${Pastellad} ${JsonRpcServer} ${Http} ${Logging} ${Logger} ${Mnemonics} ${Nigel} ${NodeRpcProxy} ${P2p} ${Rpc} ${Serialization} ${System} ${Transfers} ${Wallet} ${WalletApi} ${WalletBackend} ${WalletService} ${pastellawallet} ${CryptoTest} ${Errors} ${Utilities} ${SubWallets})

# Define a group of files as a library to link against
add_library(Common STATIC ${Common})
add_library(Config STATIC ${Config})
add_library(Crypto STATIC ${Crypto})
add_library(PastellaCore STATIC ${PastellaCore})
add_library(Errors STATIC ${Errors})
add_library(Http STATIC ${Http})
add_library(JsonRpcServer STATIC ${JsonRpcServer})
add_library(Logging STATIC ${Logging})
add_library(Logger STATIC ${Logger})
add_library(Mnemonics STATIC ${Mnemonics})
add_library(Nigel STATIC ${Nigel})
add_library(NodeRpcProxy STATIC ${NodeRpcProxy})
add_library(P2P STATIC ${PastellaProtocol} ${P2p})
add_library(Rpc STATIC ${Rpc})
add_library(Serialization STATIC ${Serialization})
add_library(SubWallets STATIC ${SubWallets})
add_library(System STATIC ${System})
add_library(Transfers STATIC ${Transfers})
add_library(Utilities STATIC ${Utilities})
add_library(Wallet STATIC ${Wallet})
add_library(WalletBackend STATIC ${WalletBackend})

if (MSVC)
    set(DAEMON_SOURCES_OS
            binaryinfo/daemon.rc
            )
    set(ZED_WALLET_SOURCES_OS
            binaryinfo/pastellawallet.rc
            )
    set(PG_SOURCES_OS
            binaryinfo/service.rc
            )
    set(CT_SOURCES_OS
            binaryinfo/cryptotest.rc
            )
    set(WALLET_API_SOURCES_OS
            binaryinfo/walletapi.rc
            )
    set(WALLET_UPGRADER_SOURCES_OS
            binaryinfo/walletupgrader.rc
            )
endif ()

add_executable(cryptotest ${CryptoTest} ${CT_SOURCES_OS})

# Staking system test executable (DISABLED - StakingPool not implemented yet)
# add_executable(StakingSystemTests cryptotest/StakingSystemTests.cpp)

add_executable(Pastellad ${Pastellad} ${DAEMON_SOURCES_OS})
add_executable(WalletApi ${WalletApi} ${WALLET_API_SOURCES_OS})
add_executable(pastellawallet ${pastellawallet} ${ZED_WALLET_SOURCES_OS})

if (MSVC)
    target_link_libraries(System ws2_32)
    target_link_libraries(Pastellad Rpcrt4 ws2_32 advapi32 crypt32 gdi32 user32)
    target_link_libraries(pastellawallet ws2_32 advapi32 crypt32 gdi32 user32)
    target_link_libraries(WalletApi ws2_32 advapi32 crypt32 gdi32 user32)
endif ()

# A bit of hackery so we don't have to do the if/else/ for every target that
# wants to use filesystem
add_library(__filesystem INTERFACE)

# Windows works out of the box
if (APPLE)
    # On macOS, filesystem is built into libc++ with modern Clang/LLVM
    # Only link Homebrew libc++fs if explicitly needed (older systems)
    if (EXISTS "/opt/homebrew/opt/llvm/lib/libc++fs.a")
        target_link_libraries(__filesystem INTERFACE /opt/homebrew/opt/llvm/lib/libc++fs.a)
    elseif (EXISTS "/usr/local/opt/llvm/lib/libc++fs.a")
        target_link_libraries(__filesystem INTERFACE /usr/local/opt/llvm/lib/libc++fs.a)
    endif ()
    # If Homebrew LLVM not found, libc++ has filesystem built-in (no link needed)
elseif (UNIX)
    target_link_libraries(__filesystem INTERFACE stdc++fs)
endif ()

if (MSVC)
    if (WITH_LEVELDB)
      target_link_libraries(Pastellad System PastellaCore leveldb snappy Errors ${Boost_LIBRARIES})
    else ()
      target_link_libraries(Pastellad System PastellaCore rocksdb zstd Errors ${Boost_LIBRARIES})
    endif ()
else ()
    if (WITH_LEVELDB)
      target_link_libraries(Pastellad System PastellaCore levellib snappy Errors ${Boost_LIBRARIES})
    else ()
      target_link_libraries(Pastellad System PastellaCore rocksdblib zstd Errors ${Boost_LIBRARIES})
    endif ()
endif ()

# Add the dependencies we need
target_link_libraries(Common __filesystem)
target_link_libraries(Crypto randomx)
target_link_libraries(PastellaCore Utilities Common Logging Crypto P2P Rpc Http Serialization System ${Boost_LIBRARIES})
target_link_libraries(cryptotest Crypto Common)
# target_link_libraries(StakingSystemTests Crypto Common PastellaCore Utilities WalletBackend)
target_link_libraries(Errors Crypto SubWallets Utilities)
target_link_libraries(Logging Common)
target_link_libraries(Nigel Errors PastellaCore)
target_link_libraries(NodeRpcProxy Rpc)
target_link_libraries(P2P upnpc-static Serialization System PastellaCore)
target_link_libraries(Rpc P2P Utilities PastellaCore)
target_link_libraries(Serialization Common Crypto ${Boost_LIBRARIES})
target_link_libraries(SubWallets Common Logger)
target_link_libraries(Transfers PastellaCore)
target_link_libraries(Utilities Common Errors)
target_link_libraries(Wallet NodeRpcProxy Transfers PastellaCore Common WalletBackend ${Boost_LIBRARIES} ${CURL_LIBRARIES})
target_link_libraries(WalletApi WalletBackend)
target_link_libraries(WalletBackend Serialization Mnemonics Nigel cryptopp-static __filesystem Utilities SubWallets Logger Config Wallet)
target_link_libraries(pastellawallet WalletBackend)

if (OPENSSL_FOUND)
    target_link_libraries(Nigel ${OPENSSL_LIBRARIES})
    target_link_libraries(WalletApi ${OPENSSL_LIBRARIES})
    target_link_libraries(pastellawallet ${OPENSSL_LIBRARIES})
    target_link_libraries(Pastellad ${OPENSSL_LIBRARIES})
endif ()

# Add dependencies means we have to build the latter before we build the former
# In this case it's because we need to have the current version name rather
# than a cached one
add_dependencies(cryptotest version)
# add_dependencies(StakingSystemTests version)
add_dependencies(JsonRpcServer version)
add_dependencies(P2P version)
add_dependencies(Rpc version)
add_dependencies(Pastellad version)
add_dependencies(WalletApi version)
add_dependencies(pastellawallet version)

# Finally build the binaries
set_property(TARGET Pastellad PROPERTY OUTPUT_NAME "Pastellad")
set_property(TARGET pastellawallet PROPERTY OUTPUT_NAME "Pastella-Wallet")
set_property(TARGET cryptotest PROPERTY OUTPUT_NAME "Cryptotest")
# set_property(TARGET StakingSystemTests PROPERTY OUTPUT_NAME "StakingSystemTests")
set_property(TARGET WalletApi PROPERTY OUTPUT_NAME "Pastella-Wallet-API")

# Additional make targets, can be used to build a subset of the targets
# e.g. make pool will build only Pastellad and service
add_custom_target(pool DEPENDS Pastellad)
add_custom_target(cli DEPENDS Pastellad pastellawallet)
add_custom_target(pastella-wallet DEPENDS pastellawallet)
