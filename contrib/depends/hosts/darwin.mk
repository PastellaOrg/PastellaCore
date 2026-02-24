darwin_CFLAGS=-pipe -std=$(C_STANDARD)
darwin_CXXFLAGS=-pipe -std=$(CXX_STANDARD) -stdlib=libc++
darwin_ARFLAGS=cr

darwin_release_CFLAGS=-O2
darwin_release_CXXFLAGS=$(darwin_release_CFLAGS)

darwin_debug_CFLAGS=-O1
darwin_debug_CXXFLAGS=$(darwin_debug_CFLAGS)

darwin_debug_CPPFLAGS=-D_GLIBCXX_DEBUG -D_GLIBCXX_DEBUG_PEDANTIC

darwin_cmake_system=Darwin
