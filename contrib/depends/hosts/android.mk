android_CFLAGS=-pipe -std=$(C_STANDARD)
android_CXXFLAGS=-pipe -std=$(CXX_STANDARD)
android_ARFLAGS=cr

android_release_CFLAGS=-O2
android_release_CXXFLAGS=$(android_release_CFLAGS)

android_debug_CFLAGS=-O1
android_debug_CXXFLAGS=$(android_debug_CFLAGS)

android_debug_CPPFLAGS=-D_GLIBCXX_DEBUG -D_GLIBCXX_DEBUG_PEDANTIC

android_cmake_system=Android
