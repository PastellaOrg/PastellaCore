package=musl-cross
$(package)_version=11.2.1
$(package)_download_path=https://musl.cc
$(package)_file_name=aarch64-linux-musl-cross.tgz
$(package)_sha256_hash=c909817856d6ceda86aa510894fa3527eac7989f0ef6e87b5721c58737a06c38

define $(package)_extract_cmds
	tar xf $($(package)_source_dir)/$($(package)_file_name) -C $($(package)_extract_dir)
endef

define $(package)_build_cmds
	touch $($(package)_build_dir)/.stamp_built
endef

define $(package)_stage_cmds
	mkdir -p $($(package)_staging_prefix_dir) && \
	cp -r aarch64-linux-musl-cross/* $($(package)_staging_prefix_dir)/ && \
	chmod +x $($(package)_staging_prefix_dir)/bin/* || true
endef
