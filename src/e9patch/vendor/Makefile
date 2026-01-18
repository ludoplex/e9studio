# E9Studio Vendor Library Makefile
#
# Builds self-contained analysis components:
# - Signature scanning (binwalk-inspired)
# - x86-64 disassembly
# - AArch64 disassembly
# - Binary analysis utilities
#
# Copyright (C) 2024 E9Patch Contributors

CC ?= cc
AR ?= ar
CFLAGS ?= -O2 -Wall -Wextra -Wpedantic -std=c11
CFLAGS += -fPIC

# For Cosmopolitan builds
ifdef COSMO
CC = cosmocc
AR = cosmoar
CFLAGS += -DCOSMOPOLITAN
endif

SRCS = e9signatures.c \
       e9disasm_x86.c \
       e9disasm_arm64.c \
       e9vendor.c

OBJS = $(SRCS:.c=.o)
HEADERS = e9signatures.h \
          e9disasm_x86.h \
          e9disasm_arm64.h \
          e9vendor.h

LIB = libe9vendor.a

.PHONY: all clean test

all: $(LIB)

$(LIB): $(OBJS)
	$(AR) rcs $@ $^

%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@

# Test program
test: test_vendor
	./test_vendor

test_vendor: test_vendor.c $(LIB)
	$(CC) $(CFLAGS) $< -L. -le9vendor -lm -o $@

clean:
	rm -f $(OBJS) $(LIB) test_vendor

# Install to parent directory
install: $(LIB)
	cp $(LIB) ../
	cp $(HEADERS) ../

# Dependency tracking
e9signatures.o: e9signatures.c e9signatures.h
e9disasm_x86.o: e9disasm_x86.c e9disasm_x86.h
e9disasm_arm64.o: e9disasm_arm64.c e9disasm_arm64.h
e9vendor.o: e9vendor.c e9vendor.h e9signatures.h e9disasm_x86.h e9disasm_arm64.h
