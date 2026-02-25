# Copyright (c) 2014-2024, The Monero Project
# Copyright (c) 2021-2024, The Pastella Project
#
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification, are
# permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this list of
#    conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice, this list
#    of conditions and the following disclaimer in the documentation and/or other
#    materials provided with the distribution.
#
# 3. Neither the name of the copyright holder nor the names of its contributors may be
#    used to endorse or promote products derived from this software without specific
#    prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
# EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
# THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
# THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

# Build directory configuration
USE_SINGLE_BUILDDIR ?= 1
ifeq ($(USE_SINGLE_BUILDDIR),1)
  builddir := build
  topdir   := $(CURDIR)
  deldirs  := $(builddir)/debug $(builddir)/release $(builddir)/fuzz
else
  subbuilddir := $(shell echo `uname | sed -e 's|[:/\\ \(\)]|_|g'`/`git branch 2>/dev/null | grep '\* ' | cut -f2- -d' ' | sed -e 's|[:/\\ \(\)]|_|g'`)
  builddir   := build/"$(subbuilddir)"
  topdir     := $(CURDIR)
  deldirs    := $(builddir)
endif

# Dependency detection
# Check if contrib/depends are built
CONTRIB_DEPENDS_DIR := $(topdir)/contrib/depends

# Define dependency prefixes for cross-compilation (used by Windows targets)
DEPS_WIN64_HOST := x86_64-w64-mingw32
DEPS_WIN64_PREFIX := $(CONTRIB_DEPENDS_DIR)/$(DEPS_WIN64_HOST)

DEPS_LINUX_HOST := x86_64-linux-gnu
DEPS_LINUX_PREFIX := $(CONTRIB_DEPENDS_DIR)/$(DEPS_LINUX_HOST)

DEPS_LINUX_ARM64_HOST := aarch64-linux-musl
DEPS_LINUX_ARM64_PREFIX := $(CONTRIB_DEPENDS_DIR)/$(DEPS_LINUX_ARM64_HOST)

# Check if musl is available in depends (musl builds as libc.a, not libmusl.a)
MUSL_LIB := $(wildcard $(DEPS_LINUX_ARM64_PREFIX)/lib/libc.a)
ifneq ($(MUSL_LIB),)
    MUSL_AVAILABLE := 1
    MUSL_LIB_FILE := $(MUSL_LIB)
else
    MUSL_AVAILABLE := 0
endif

# SIMD flags for x86/x86_64 builds (AES-NI, PCLMUL, SSSE3, SSE4.1, SSE4.2)
X86_SIMD_FLAGS := -maes -mpclmul -mssse3 -msse4.1 -msse4.2

# Windows-specific defines for cross-compilation
WINDOWS_DEFINES := -Uinterface -DWIN32 -D_WIN32 -D_WINDOWS -D_WIN32_WINNT=0x0601 -DWIN32_LEAN_AND_MEAN -DLEVELDB_PLATFORM_WINDOWS

# Default target
all: release-all

# =============================================================================
# Dependency Management
# =============================================================================

# Auto-detect current system and build dependencies for it
depends:
	cd contrib/depends && $(MAKE) HOST=$(shell ./contrib/depends/config.guess)
	@echo ""
	@echo "Dependencies built successfully for current system!"
	@echo "Now you can run: make release-static"

# Explicit platform targets for cross-compilation
depends-win64:
	cd contrib/depends && $(MAKE) HOST=x86_64-w64-mingw32
	@echo ""
	@echo "Dependencies built successfully!"
	@echo "Now you can run: make release-static-win64"

depends-linux:
	cd contrib/depends && $(MAKE) HOST=x86_64-linux-gnu
	@echo ""
	@echo "Dependencies built successfully!"
	@echo "Now you can run: make release-static-linux-x86_64"

depends-mac:
	cd contrib/depends && $(MAKE) HOST=x86_64-apple-darwin
	@echo ""
	@echo "Dependencies built successfully!"
	@echo "Now you can run: make release-static-mac-x86_64"

depends-freebsd:
	cd contrib/depends && $(MAKE) HOST=x86_64-unknown-freebsd
	@echo ""
	@echo "Dependencies built successfully!"
	@echo "Now you can run: make release-static-freebsd-x86_64"

depends-linux-arm64:
	cd contrib/depends && $(MAKE) HOST=aarch64-linux-gnu
	@echo ""
	@echo "Dependencies built successfully!"
	@echo "Now you can run: make release-static-linux-arm64"

depends-mac-arm64:
	cd contrib/depends && $(MAKE) HOST=aarch64-apple-darwin
	@echo ""
	@echo "Dependencies built successfully!"
	@echo "Now you can run: make release-static-mac-arm64"

# Clean dependencies for current system
clean-depends:
	cd contrib/depends && $(MAKE) HOST=$(shell ./contrib/depends/config.guess) clean
	@echo ""
	@echo "Dependencies cleaned for current system"

# Clean dependencies for specific platforms
clean-depends-win64:
	cd contrib/depends && $(MAKE) HOST=x86_64-w64-mingw32 clean
	@echo ""
	@echo "Dependencies cleaned for Windows x64"

clean-depends-linux:
	cd contrib/depends && $(MAKE) HOST=x86_64-linux-gnu clean
	@echo ""
	@echo "Dependencies cleaned for Linux x86_64"

clean-depends-mac:
	cd contrib/depends && $(MAKE) HOST=x86_64-apple-darwin clean
	@echo ""
	@echo "Dependencies cleaned for macOS"

clean-depends-freebsd:
	cd contrib/depends && $(MAKE) HOST=x86_64-unknown-freebsd clean
	@echo ""
	@echo "Dependencies cleaned for FreeBSD"

clean-depends-linux-arm64:
	cd contrib/depends && $(MAKE) HOST=aarch64-linux-gnu clean
	@echo ""
	@echo "Dependencies cleaned for Linux ARM64"

clean-depends-mac-arm64:
	cd contrib/depends && $(MAKE) HOST=aarch64-apple-darwin clean
	@echo ""
	@echo "Dependencies cleaned for macOS ARM64"

clean-depends-all:
	cd contrib/depends && $(MAKE) clean-all
	@echo ""
	@echo "All dependencies cleaned!"

distclean-depends:
	cd contrib/depends && $(MAKE) distclean
	@echo ""
	@echo "All dependency sources and artifacts removed!"

# =============================================================================
# Development Builds
# =============================================================================

cmake-debug:
	(cd $(builddir)/debug && cmake -D CMAKE_BUILD_TYPE=Debug $(topdir)

debug: cmake-debug
	cd $(builddir)/debug && $(MAKE) --no-print-directory

debug-test:
	(cd $(builddir)/debug && cmake -D CMAKE_BUILD_TYPE=Debug $(topdir) && $(MAKE) --no-print-directory && $(MAKE) test)

debug-all:
	(cd $(builddir)/debug && cmake -D BUILD_SHARED_LIBS=OFF -D CMAKE_BUILD_TYPE=Debug $(topdir) && $(MAKE) --no-print-directory)

cmake-release:
	mkdir -p $(builddir)/release
	(cd $(builddir)/release && cmake -D CMAKE_BUILD_TYPE=Release -D CMAKE_CXX_FLAGS="$(X86_SIMD_FLAGS)" -D CMAKE_C_FLAGS="$(X86_SIMD_FLAGS)" $(topdir))

release: cmake-release
	cd $(builddir)/release && $(MAKE) --no-print-directory

release-test:
	(cd $(builddir)/release && cmake -D CMAKE_BUILD_TYPE=Release $(topdir) && $(MAKE) --no-print-directory && $(MAKE) test)

release-all:
	(cd $(builddir)/release && cmake -D CMAKE_BUILD_TYPE=Release $(topdir) && $(MAKE) --no-print-directory)

# =============================================================================
# Static Builds - Linux
# =============================================================================

release-static-linux-x86_64:
	mkdir -p $(builddir)/release/x86_64-linux-gnu
	(cd $(builddir)/release/x86_64-linux-gnu && cmake \
		-D CMAKE_BUILD_TYPE=Release \
		-D STATIC=ON \
		-D ARCH="x86-64" \
		-D BOOST_ROOT=$(DEPS_LINUX_PREFIX) \
		-D Boost_INCLUDE_DIR=$(DEPS_LINUX_PREFIX)/include \
		-D Boost_LIBRARY_DIR=$(DEPS_LINUX_PREFIX)/lib \
		-D Boost_NO_SYSTEM_PATHS=ON \
		-D Boost_USE_STATIC_LIBS=ON \
		-D Boost_FOUND=ON \
		-D OPENSSL_ROOT_DIR=$(DEPS_LINUX_PREFIX) \
		-D OPENSSL_INCLUDE_DIR=$(DEPS_LINUX_PREFIX)/include \
		-D OPENSSL_CRYPTO_LIBRARY=$(DEPS_LINUX_PREFIX)/lib/libcrypto.a \
		-D OPENSSL_SSL_LIBRARY=$(DEPS_LINUX_PREFIX)/lib/libssl.a \
		-D CMAKE_CXX_FLAGS="$(X86_SIMD_FLAGS)" \
		-D CMAKE_C_FLAGS="$(X86_SIMD_FLAGS)" \
		$(topdir) && $(MAKE) --no-print-directory)

release-static-linux-arm64:
	mkdir -p $(builddir)/release/arm64-linux
	(cd $(builddir)/release/arm64-linux && DEPS_LINUX_ARM64_PREFIX=$(DEPS_LINUX_ARM64_PREFIX) cmake -G "Unix Makefiles" \
		-D CMAKE_BUILD_TYPE=Release \
		-D STATIC=ON \
		-D ARCH="armv8-a" \
		-D CMAKE_TOOLCHAIN_FILE=$(topdir)/cmake/arm64_toolchain.cmake \
		-D WITH_LEVELDB=OFF \
		-D BOOST_ROOT=$(DEPS_LINUX_ARM64_PREFIX) \
		-D Boost_INCLUDE_DIR=$(DEPS_LINUX_ARM64_PREFIX)/include \
		-D Boost_LIBRARY_DIR=$(DEPS_LINUX_ARM64_PREFIX)/lib \
		-D Boost_NO_SYSTEM_PATHS=ON \
		-D Boost_USE_STATIC_LIBS=ON \
		-D Boost_FOUND=ON \
		-D OPENSSL_ROOT_DIR=$(DEPS_LINUX_ARM64_PREFIX) \
		-D OPENSSL_INCLUDE_DIR=$(DEPS_LINUX_ARM64_PREFIX)/include \
		-D OPENSSL_CRYPTO_LIBRARY=$(DEPS_LINUX_ARM64_PREFIX)/lib/libcrypto.a \
		-D OPENSSL_SSL_LIBRARY=$(DEPS_LINUX_ARM64_PREFIX)/lib/libssl.a \
		-D UCONTEXT_LIBRARY=$(DEPS_LINUX_ARM64_PREFIX)/lib/libucontext.a \
		$(topdir) && $(MAKE) --no-print-directory)

# =============================================================================
# Static Builds - Cross-Compilation (Linux → Windows)
# =============================================================================


release-static-win64:
	mkdir -p $(builddir)/release/x86_64-w64-mingw32
	(cd $(builddir)/release/x86_64-w64-mingw32 && cmake -G "Unix Makefiles" \
		-D CMAKE_BUILD_TYPE=Release \
		-D STATIC=ON \
		-D ARCH="x86-64" \
		-D CMAKE_TOOLCHAIN_FILE=$(topdir)/cmake/mingw_toolchain.cmake \
		-D WITH_LEVELDB=ON \
		-D BOOST_ROOT=$(DEPS_WIN64_PREFIX) \
		-D Boost_INCLUDE_DIR=$(DEPS_WIN64_PREFIX)/include \
		-D Boost_LIBRARY_DIR=$(DEPS_WIN64_PREFIX)/lib \
		-D Boost_NO_SYSTEM_PATHS=ON \
		-D Boost_USE_STATIC_LIBS=ON \
		-D Boost_FOUND=ON \
		-D Boost_SYSTEM_LIBRARY=$(DEPS_WIN64_PREFIX)/lib/libboost_system.a \
		-D Boost_SYSTEM_LIBRARY_RELEASE=$(DEPS_WIN64_PREFIX)/lib/libboost_system.a \
		-D Boost_THREAD_LIBRARY=$(DEPS_WIN64_PREFIX)/lib/libboost_thread.a \
		-D Boost_THREAD_LIBRARY_RELEASE=$(DEPS_WIN64_PREFIX)/lib/libboost_thread.a \
		-D Boost_DATE_TIME_LIBRARY=$(DEPS_WIN64_PREFIX)/lib/libboost_date_time.a \
		-D Boost_DATE_TIME_LIBRARY_RELEASE=$(DEPS_WIN64_PREFIX)/lib/libboost_date_time.a \
		-D Boost_CHRONO_LIBRARY=$(DEPS_WIN64_PREFIX)/lib/libboost_chrono.a \
		-D Boost_CHRONO_LIBRARY_RELEASE=$(DEPS_WIN64_PREFIX)/lib/libboost_chrono.a \
		-D Boost_SERIALIZATION_LIBRARY=$(DEPS_WIN64_PREFIX)/lib/libboost_serialization.a \
		-D Boost_SERIALIZATION_LIBRARY_RELEASE=$(DEPS_WIN64_PREFIX)/lib/libboost_serialization.a \
		-D Boost_LIBRARIES="$(DEPS_WIN64_PREFIX)/lib/libboost_system.a;$(DEPS_WIN64_PREFIX)/lib/libboost_thread.a;$(DEPS_WIN64_PREFIX)/lib/libboost_date_time.a;$(DEPS_WIN64_PREFIX)/lib/libboost_chrono.a;$(DEPS_WIN64_PREFIX)/lib/libboost_serialization.a" \
		-D OPENSSL_ROOT_DIR=$(DEPS_WIN64_PREFIX) \
		-D OPENSSL_INCLUDE_DIR=$(DEPS_WIN64_PREFIX)/include \
		-D OPENSSL_CRYPTO_LIBRARY=$(DEPS_WIN64_PREFIX)/lib/libcrypto.a \
		-D OPENSSL_SSL_LIBRARY=$(DEPS_WIN64_PREFIX)/lib/libssl.a \
		-D CMAKE_CXX_FLAGS="$(WINDOWS_DEFINES) $(X86_SIMD_FLAGS) -isystem $(topdir)/src/platform/windows -I$(topdir)/src -I/usr/x86_64-w64-mingw32/include" \
		-D CMAKE_C_FLAGS="$(WINDOWS_DEFINES) $(X86_SIMD_FLAGS) -isystem $(topdir)/src/platform/windows -I$(topdir)/src -I/usr/x86_64-w64-mingw32/include" \
		-D CMAKE_EXE_LINKER_FLAGS="-static -static-libgcc -static-libstdc++ -lws2_32 -lgdi32 -lcrypt32 -lbcrypt -liphlpapi -lshlwapi -lmswsock" \
		$(topdir) && $(MAKE) --no-print-directory)

debug-static-win64:
	mkdir -p $(builddir)/debug/x86_64-w64-mingw32
	(cd $(builddir)/debug/x86_64-w64-mingw32 && cmake -G "Unix Makefiles" \
		-D CMAKE_BUILD_TYPE=Debug \
		-D STATIC=ON \
		-D ARCH="x86-64" \
		-D CMAKE_TOOLCHAIN_FILE=$(topdir)/cmake/mingw_toolchain.cmake \
		-D WITH_LEVELDB=ON \
		-D BOOST_ROOT=$(DEPS_WIN64_PREFIX) \
		-D Boost_INCLUDE_DIR=$(DEPS_WIN64_PREFIX)/include \
		-D Boost_SYSTEM_LIBRARY_RELEASE=$(DEPS_WIN64_PREFIX)/lib/libboost_system.a \
		-D Boost_THREAD_LIBRARY_RELEASE=$(DEPS_WIN64_PREFIX)/lib/libboost_thread.a \
		-D Boost_DATE_TIME_LIBRARY_RELEASE=$(DEPS_WIN64_PREFIX)/lib/libboost_date_time.a \
		-D Boost_CHRONO_LIBRARY_RELEASE=$(DEPS_WIN64_PREFIX)/lib/libboost_chrono.a \
		-D Boost_SERIALIZATION_LIBRARY_RELEASE=$(DEPS_WIN64_PREFIX)/lib/libboost_serialization.a \
		-D OPENSSL_ROOT_DIR=$(DEPS_WIN64_PREFIX) \
		-D OPENSSL_INCLUDE_DIR=$(DEPS_WIN64_PREFIX)/include \
		-D OPENSSL_CRYPTO_LIBRARY=$(DEPS_WIN64_PREFIX)/lib/libcrypto.a \
		-D OPENSSL_SSL_LIBRARY=$(DEPS_WIN64_PREFIX)/lib/libssl.a \
		-D CMAKE_EXE_LINKER_FLAGS="-static -static-libgcc -static-libstdc++ -lws2_32 -lgdi32 -lcrypt32 -lbcrypt -liphlpapi -lshlwapi -lmswsock" \
		$(topdir) && $(MAKE) --no-print-directory)

# =============================================================================
# Static Builds - macOS
# =============================================================================

release-static-mac-x86_64:
	mkdir -p $(builddir)/release/x86_64-apple-darwin
	(cd $(builddir)/release/x86_64-apple-darwin && cmake -D STATIC=ON -D ARCH="x86-64" -D CMAKE_BUILD_TYPE=Release $(topdir) && $(MAKE) --no-print-directory)

release-static-mac-arm64:
	mkdir -p $(builddir)/release/arm64-apple-darwin
	(cd $(builddir)/release/arm64-apple-darwin && cmake -D STATIC=ON -D ARCH="arm64" -D CMAKE_BUILD_TYPE=Release $(topdir) && $(MAKE) --no-print-directory)

# =============================================================================
# Static Builds - FreeBSD
# =============================================================================

release-static-freebsd-x86_64:
	mkdir -p $(builddir)/release/x86_64-unknown-freebsd
	(cd $(builddir)/release/x86_64-unknown-freebsd && cmake -D STATIC=ON -D ARCH="x86-64" -D CMAKE_BUILD_TYPE=Release $(topdir) && $(MAKE) --no-print-directory)

# =============================================================================
# Static Builds - Generic
# =============================================================================

release-static:
	(cd $(builddir)/release && cmake -D STATIC=ON -D ARCH="default" -D CMAKE_BUILD_TYPE=Release $(topdir) && $(MAKE) --no-print-directory)

# =============================================================================
# Testing & Coverage
# =============================================================================

coverage:
	(cd $(builddir)/debug && cmake -D CMAKE_BUILD_TYPE=Debug -D COVERAGE=ON $(topdir) && $(MAKE) --no-print-directory && $(MAKE) test)

fuzz:
	(cd $(builddir)/fuzz && cmake -D STATIC=ON -D SANITIZE=ON -D USE_LTO=OFF -D CMAKE_C_COMPILER=afl-gcc -D CMAKE_CXX_COMPILER=afl-g++ -D ARCH="x86-64" -D CMAKE_BUILD_TYPE=fuzz $(topdir) && $(MAKE) --no-print-directory)

# =============================================================================
# Clean Targets
# =============================================================================

clean:
	@echo "WARNING: Back-up your wallet if it exists within ./"$(deldirs)"!" ; \
	read -r -p "This will destroy the build directory, continue (y/N)?: " CONTINUE; \
	[ $$CONTINUE = "y" ] || [ $$CONTINUE = "Y" ] || (echo "Exiting."; exit 1)
	rm -rf $(deldirs)

clean-all:
	@echo "WARNING: Back-up your wallet if it exists within ./build!" ; \
	read -r -p "This will destroy all build directories, continue (y/N)?: " CONTINUE; \
	[ $$CONTINUE = "y" ] || [ $$CONTINUE = "Y" ] || (echo "Exiting."; exit 1)
	rm -rf ./build

# =============================================================================
# Utility Targets
# =============================================================================

help:
	@echo "Pastella Build System"
	@echo ""
	@echo "Dependency targets:"
	@echo "  make depends                      - Auto-detect system and build dependencies"
	@echo "  make depends-win64                - Build dependencies for Windows x64"
	@echo "  make depends-linux                - Build dependencies for Linux x86_64"
	@echo "  make depends-linux-arm64          - Build dependencies for Linux ARM64"
	@echo "  make depends-mac                  - Build dependencies for macOS x86_64"
	@echo "  make depends-mac-arm64            - Build dependencies for macOS ARM64"
	@echo "  make depends-freebsd              - Build dependencies for FreeBSD x86_64"
	@echo ""
	@echo "Static build targets:"
	@echo "  make release-static-linux-x86_64  - Build static Linux x86_64 binary"
	@echo "  make release-static-linux-arm64   - Build static Linux ARM64 binary"
	@echo "  make release-static-win64         - Build static Windows x64 binary (cross-compile)"
	@echo "  make release-static-mac-x86_64    - Build static macOS x86_64 binary"
	@echo "  make release-static-mac-arm64     - Build static macOS ARM64 binary"
	@echo "  make release-static-freebsd-x86_64- Build static FreeBSD x86_64 binary"
	@echo ""
	@echo "Debug targets:"
	@echo "  make debug-static-win64           - Build debug Windows x64 binary (cross-compile)"
	@echo ""
	@echo "Quick start guides:"
	@echo "  Native Linux (fastest):    make release"
	@echo "  Static Linux x86_64:       make depends-linux && make release-static-linux-x86_64"
	@echo "  Windows (from Linux):      make depends-win64 && make release-static-win64"
	@echo ""
	@echo "Development targets:"
	@echo "  make debug                        - Build debug version"
	@echo "  make release                      - Build optimized release with system libraries"
	@echo "  make release-all                  - Build release with tests"
	@echo ""
	@echo "Clean targets:"
	@echo "  make clean                        - Remove build directory"
	@echo "  make clean-all                    - Remove all build directories"
	@echo "  make clean-depends                - Clean dependencies for current system"
	@echo "  make clean-depends-win64          - Clean Windows x64 dependencies"
	@echo "  make clean-depends-linux-arm64    - Clean Linux ARM64 dependencies"
	@echo "  make clean-depends-mac-arm64      - Clean macOS ARM64 dependencies"
	@echo ""
	@echo "For a full list of targets, see the Makefile"

.PHONY: all depends depends-win64 depends-linux depends-linux-arm64 depends-mac depends-mac-arm64 depends-freebsd cmake-debug debug debug-test debug-all cmake-release release release-test release-all \
	release-static-linux-x86_64 release-static-linux-arm64 \
	release-static-win64 debug-static-win64 \
	release-static-mac-x86_64 release-static-mac-arm64 release-static-freebsd-x86_64 \
	release-static coverage fuzz clean clean-all help \
	clean-depends clean-depends-win64 clean-depends-linux clean-depends-linux-arm64 clean-depends-mac clean-depends-mac-arm64 clean-depends-freebsd clean-depends-all distclean-depends
