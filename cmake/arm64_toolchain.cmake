# ARM64 Linux cross-compilation toolchain file using musl

set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR aarch64)

# Check if musl-cross is available from depends system
if(DEFINED ENV{DEPS_LINUX_ARM64_PREFIX})
    set(DEPS_PREFIX $ENV{DEPS_LINUX_ARM64_PREFIX})
else()
    set(DEPS_PREFIX /root/git/PastellaCore/contrib/depends/aarch64-linux-gnu)
endif()

# Musl cross-compiler should be in DEPS_PREFIX/bin
set(MUSL_CROSS_BIN ${DEPS_PREFIX}/bin)

# Check if musl-cross toolchain exists
if(EXISTS ${MUSL_CROSS_BIN}/aarch64-linux-musl-gcc)
    message(STATUS "Using musl-cross toolchain: ${MUSL_CROSS_BIN}")

    # Cross-compiler paths - use musl cross-compiler
    set(CMAKE_C_COMPILER ${MUSL_CROSS_BIN}/aarch64-linux-musl-gcc)
    set(CMAKE_CXX_COMPILER ${MUSL_CROSS_BIN}/aarch64-linux-musl-g++)
    set(CMAKE_AR ${MUSL_CROSS_BIN}/aarch64-linux-musl-ar)
    set(CMAKE_RANLIB ${MUSL_CROSS_BIN}/aarch64-linux-musl-ranlib)
    set(CMAKE_STRIP ${MUSL_CROSS_BIN}/aarch64-linux-musl-strip)
else()
    message(FATAL_ERROR "musl-cross toolchain not found at ${MUSL_CROSS_BIN}. "
                        "Please run 'make depends-linux-arm64' first to build the toolchain.")
endif()

# Target environment - use depends for dependencies
set(CMAKE_FIND_ROOT_PATH ${DEPS_PREFIX})
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)

# Static linking - musl handles this natively
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static")

# Link libucontext for ucontext functions on musl
if(DEFINED ENV{UCONTEXT_LIBRARY})
    set(UCONTEXT_LIB $ENV{UCONTEXT_LIBRARY})
    if(EXISTS ${UCONTEXT_LIB})
        message(STATUS "Using libucontext: ${UCONTEXT_LIB}")
        set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${UCONTEXT_LIB}")
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -I${DEPS_PREFIX}/include")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -I${DEPS_PREFIX}/include")
    endif()
endif()
