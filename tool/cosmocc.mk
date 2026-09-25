#########################################################################
# tool/cosmocc.mk - the pinned cosmocc toolchain
#
# Single source of truth for the toolchain version used by the Makefiles
# and CI. The APE build needs cosmocc because one output file then runs on
# Linux, macOS, Windows and the BSDs (x86-64 and AArch64) without a
# per-OS build - that portability is the reason the project uses it.
#
# The sha256 below is of the release asset
#   https://github.com/jart/cosmopolitan/releases/download/4.0.2/cosmocc-4.0.2.zip
# (441763966 bytes), verified 2026-09-25.
#
#   make -f Makefile.e9studio toolchain          # fetch + verify + unpack
#   make -f Makefile.e9studio COSMOCC=/opt/cosmocc-4.0.2   # use a copy you have
#########################################################################

COSMOCC_VERSION := 4.0.2
COSMOCC_SHA256  := 85b8c37a406d862e656ad4ec14be9f6ce474c1b436b9615e91a55208aced3f44
COSMOCC_URL     := https://github.com/jart/cosmopolitan/releases/download/$(COSMOCC_VERSION)/cosmocc-$(COSMOCC_VERSION).zip

# Install location; override to reuse an existing unpacked toolchain.
COSMOCC ?= $(CURDIR)/.cosmocc/$(COSMOCC_VERSION)

.PHONY: toolchain
toolchain:
	COSMOCC='$(COSMOCC)' COSMOCC_VERSION='$(COSMOCC_VERSION)' \
	COSMOCC_SHA256='$(COSMOCC_SHA256)' COSMOCC_URL='$(COSMOCC_URL)' \
	sh tool/fetch-cosmocc.sh
