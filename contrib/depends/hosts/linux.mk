linux_CFLAGS=-pipe -std=$(C_STANDARD)
linux_CXXFLAGS=-pipe -std=$(CXX_STANDARD)
linux_ARFLAGS=cr

linux_release_CFLAGS=-O2
linux_release_CXXFLAGS=$(linux_release_CFLAGS)

linux_debug_CFLAGS=-O1
linux_debug_CXXFLAGS=$(linux_debug_CFLAGS)

linux_debug_CPPFLAGS=-D_GLIBCXX_DEBUG -D_GLIBCXX_DEBUG_PEDANTIC

linux_cmake_system=Linux

# Use musl-cross toolchain for aarch64-linux-musl builds
aarch64_linux_CC=$(BASEDIR)/aarch64-linux-musl/bin/aarch64-linux-musl-gcc
aarch64_linux_CXX=$(BASEDIR)/aarch64-linux-musl/bin/aarch64-linux-musl-g++
aarch64_linux_AR=$(BASEDIR)/aarch64-linux-musl/bin/aarch64-linux-musl-ar
aarch64_linux_RANLIB=$(BASEDIR)/aarch64-linux-musl/bin/aarch64-linux-musl-ranlib
aarch64_linux_STRIP=$(BASEDIR)/aarch64-linux-musl/bin/aarch64-linux-musl-strip
aarch64_linux_NM=$(BASEDIR)/aarch64-linux-musl/bin/aarch64-linux-musl-nm
