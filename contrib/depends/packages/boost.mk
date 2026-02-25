package=boost
$(package)_version=1.68.0
$(package)_download_path=https://pastella.org/depends
$(package)_file_name=boost_1_68_0.tar.gz
$(package)_sha256_hash=da3411ea45622579d419bfda66f45cd0f8c32a181d84adfa936f5688388995cf

$(package)_config_opts_release=variant=release
$(package)_config_opts_debug=variant=debug
$(package)_config_opts+=--layout=system --user-config=user-config.jam
$(package)_config_opts+=threading=multi link=static -sNO_BZIP2=1 -sNO_ZLIB=1
$(package)_config_opts_linux=threadapi=pthread runtime-link=shared
$(package)_config_opts_mingw32=binary-format=pe target-os=windows threadapi=win32 runtime-link=static
$(package)_config_opts_x86_64_mingw32=address-model=64
$(package)_config_opts_i686_mingw32=address-model=32
$(package)_config_libraries_$(host_os)="system,thread,date_time,chrono,serialization"
$(package)_config_libraries_mingw32="system,thread,date_time,chrono,serialization,locale"
$(package)_cxxflags_linux+=-fPIC
$(package)_cxxflags_freebsd+=-fPIC

define $(package)_preprocess_cmds
  echo "using gcc : : $($(package)_cxx) : <cxxflags>\"$($(package)_cxxflags)\" <linkflags>\"$($(package)_ldflags)\" <archiver>\"$($(package)_ar)\" <ranlib>\"$(host_RANLIB)\" : ;" > user-config.jam
endef

define $(package)_config_cmds
  ./bootstrap.sh --without-icu --with-libraries=$(boost_config_libraries_$(host_os))
endef

define $(package)_build_cmds
  ./b2 -d0 -j4 --prefix=$($(package)_staging_prefix_dir) $($(package)_config_opts) stage
endef

define $(package)_stage_cmds
  ./b2 -d0 -j4 --prefix=$($(package)_staging_prefix_dir) $($(package)_config_opts) install
endef
