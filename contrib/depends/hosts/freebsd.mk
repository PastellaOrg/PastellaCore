freebsd_CFLAGS=-pipe -std=$(C_STANDARD)
freebsd_CXXFLAGS=-pipe -std=$(CXX_STANDARD)
freebsd_ARFLAGS=cr

freebsd_release_CFLAGS=-O2
freebsd_release_CXXFLAGS=$(freebsd_release_CFLAGS)

freebsd_debug_CFLAGS=-O1
freebsd_debug_CXXFLAGS=$(freebsd_debug_CFLAGS)

freebsd_debug_CPPFLAGS=-D_GLIBCXX_DEBUG -D_GLIBCXX_DEBUG_PEDANTIC

freebsd_cmake_system=FreeBSD
