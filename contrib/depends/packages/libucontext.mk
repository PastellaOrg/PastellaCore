package=libucontext
$(package)_version=1.2
$(package)_download_path=https://pastella.org/depends
$(package)_file_name=$(package)-$($(package)_version).tar.gz
$(package)_sha256_hash=ac855dc04a55ce6551379cf892dabaa79dd5572316c27a77bc9ef9cc6ddf85c7

define $(package)_build_cmds
	$(MAKE) -s ARCH=aarch64 CC=$(host_CC) AR=$(host_AR)
endef

define $(package)_stage_cmds
  mkdir -p $($(package)_staging_dir)/$(host_prefix)/lib $($(package)_staging_dir)/$(host_prefix)/include/libucontext && \
  cp libucontext.a libucontext_posix.a $($(package)_staging_dir)/$(host_prefix)/lib/ && \
  cp include/libucontext/libucontext.h arch/aarch64/include/libucontext/bits.h $($(package)_staging_dir)/$(host_prefix)/include/libucontext/
endef
