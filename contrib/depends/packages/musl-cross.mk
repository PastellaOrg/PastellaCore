package=musl-cross
$(package)_version=11.2.1
$(package)_download_path=https://pastella.org/depends
$(package)_file_name=aarch64-linux-musl-cross.tgz
$(package)_sha256_hash=c909817856d6ceda86aa510894fa3527eac7989f0ef6e87b5721c58737a06c38

define $(package)_extract_cmds
	mkdir -p $($(package)_extract_dir) && \
	tar --no-same-owner --strip-components=1 -xf $($(package)_source)
endef

define $(package)_build_cmds
	# Stage binaries to a separate musl directory to avoid conflicts
	mkdir -p $(BASEDIR)/aarch64-linux-musl && \
	cp -r $($(package)_extract_dir)/* $(BASEDIR)/aarch64-linux-musl/ && \
	chmod +x $(BASEDIR)/aarch64-linux-musl/bin/* || true
	touch $($(package)_build_dir)/.stamp_built
endef

define $(package)_stage_cmds
	# Binaries already staged in build_cmds
	true
endef
