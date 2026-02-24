package=libucontext
$(package)_version=1.2
$(package)_download_path=https://github.com/kaniini/libucontext/archive/refs/tags
$(package)_file_name=$(package)-$($(package)_version).tar.gz
$(package)_sha256_hash=937fba9d0beebd7cf957b79979b19fe3a29bb9c4bfd25e869477d7154bbf8fd3

define $(package)_build_cmds
	$(MAKE) ARCH=aarch64 CC=$($(package)_cc) AR=$($(package)_ar)
endef

define $(package)_stage_cmds
  mkdir -p $($(package)_staging_dir)/$(host_prefix)/lib $($(package)_staging_dir)/$(host_prefix)/include/libucontext && \
  cp libucontext.a libucontext_posix.a $($(package)_staging_dir)/$(host_prefix)/lib/ && \
  cp include/libucontext/libucontext.h arch/aarch64/include/libucontext/bits.h $($(package)_staging_dir)/$(host_prefix)/include/libucontext/
endef
