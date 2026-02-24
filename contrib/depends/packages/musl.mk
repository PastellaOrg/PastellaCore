package=musl
$(package)_version=1.2.5
$(package)_download_path=https://musl.libc.org/releases
$(package)_file_name=$(package)-$($(package)_version).tar.gz
$(package)_sha256_hash=a9a118bbe84d8764da0ea0d28b3ab3fae8477fc7e4085d90102b8596fc7c75e4

# Cross-compilation settings for musl
define $(package)_set_vars
$(package)_config_opts=--prefix=$(host_prefix) --exec-prefix=$(host_prefix) --libdir=$(host_prefix)/lib
$(package)_cc=$(host_CC)
$(package)_cxx=$(host_CXX)
$(package)_ar=$(host_AR)
$(package)_ranlib=$(host_RANLIB)
$(package)_ld=$(host_CC)
$(package)_cflags=$(CFLAGS)
$(package)_cxxflags=$(CXXFLAGS)
$(package)_ldflags=$(LDFLAGS)
endef

define $(package)_config_cmds
	./configure --host=$(host) --build=$(build) $($(package)_config_opts) CC=$($(package)_cc) AR=$($(package)_ar) RANLIB=$($(package)_ranlib)
endef

define $(package)_build_cmds
	$(MAKE)
endef

define $(package)_stage_cmds
	$(MAKE) DESTDIR=$($(package)_staging_dir) install
endef

define $(package)_postprocess_cmds
	rm -rf $($(package)_staging_dir)/$(host_prefix)/bin
	rm -rf $($(package)_staging_dir)/$(host_prefix)/share/man
endef
