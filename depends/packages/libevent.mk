package=libevent
$(package)_version=fc9bfd210d289d1565cf03e3d9d2e85f50f5b144
$(package)_download_path=https://github.com/libevent/libevent/archive
$(package)_file_name=$($(package)_version).tar.gz
$(package)_sha256_hash=5457907404df32dd35436004f3b94e64b3cdf1320c274411803404933732788c

# When building for Windows, we set _WIN32_WINNT to target the same Windows
# version as we do in configure. Due to quirks in libevents build system, this
# is also required to enable support for ipv6. See #19375.
define $(package)_set_vars
  $(package)_config_opts=--disable-shared --disable-openssl --disable-libevent-regress --disable-samples
  $(package)_config_opts += --disable-dependency-tracking --enable-option-checking
  $(package)_config_opts_release=--disable-debug-mode
  $(package)_cppflags_mingw32=-D_WIN32_WINNT=0x0601

  ifeq ($(NO_HARDEN),)
  $(package)_cppflags+=-D_FORTIFY_SOURCE=3
  endif
endef

define $(package)_config_cmds
  ./autogen.sh && \
  $($(package)_autoconf)
endef

define $(package)_build_cmds
  $(MAKE)
endef

define $(package)_stage_cmds
  $(MAKE) DESTDIR=$($(package)_staging_dir) install
endef

define $(package)_postprocess_cmds
  rm lib/*.la && \
  rm include/ev*.h && \
  rm include/event2/*_compat.h
endef
