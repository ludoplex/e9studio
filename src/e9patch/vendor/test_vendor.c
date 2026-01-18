/*
 * test_vendor.c
 * Test program for E9Studio Vendor Library
 *
 * Copyright (C) 2024 E9Patch Contributors
 */

#include "e9vendor.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Sample x86-64 code (push rbp; mov rbp, rsp; xor eax, eax; ret) */
static const uint8_t X86_SAMPLE[] = {
    0x55,                       /* push rbp */
    0x48, 0x89, 0xe5,           /* mov rbp, rsp */
    0x31, 0xc0,                 /* xor eax, eax */
    0x5d,                       /* pop rbp */
    0xc3,                       /* ret */
};

/* Sample AArch64 code */
static const uint8_t ARM64_SAMPLE[] = {
    0xfd, 0x7b, 0xbf, 0xa9,     /* stp x29, x30, [sp, #-16]! */
    0xfd, 0x03, 0x00, 0x91,     /* mov x29, sp */
    0x00, 0x00, 0x80, 0xd2,     /* mov x0, #0 */
    0xfd, 0x7b, 0xc1, 0xa8,     /* ldp x29, x30, [sp], #16 */
    0xc0, 0x03, 0x5f, 0xd6,     /* ret */
};

/* Sample ELF header */
static const uint8_t ELF_SAMPLE[] = {
    0x7f, 'E', 'L', 'F',        /* Magic */
    0x02,                       /* 64-bit */
    0x01,                       /* Little endian */
    0x01,                       /* ELF version */
    0x00,                       /* System V ABI */
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x02, 0x00,                 /* ET_EXEC */
    0x3e, 0x00,                 /* x86-64 */
    0x01, 0x00, 0x00, 0x00,     /* ELF version */
    /* ... rest would follow */
};

static void test_version(void)
{
    printf("=== Version Test ===\n");
    printf("Version: %s\n", e9_vendor_version());
    printf("Build: %s\n", e9_vendor_build_info());
    printf("\n");
}

static void test_signatures(void)
{
    printf("=== Signature Test ===\n");

    E9SigScanner *scanner = e9_sig_scanner_create();
    if (!scanner) {
        printf("ERROR: Failed to create scanner\n");
        return;
    }

    /* Test ELF detection */
    uint32_t count;
    E9SigMatch *matches = e9_sig_scan(scanner, ELF_SAMPLE, sizeof(ELF_SAMPLE), &count);

    printf("ELF sample: found %u signatures\n", count);
    for (uint32_t i = 0; i < count; i++) {
        printf("  [0x%zx] %s (confidence: %d)\n",
               matches[i].offset,
               matches[i].description,
               matches[i].confidence);
    }

    e9_sig_matches_free(matches);
    e9_sig_scanner_free(scanner);
    printf("\n");
}

static void test_x86_disasm(void)
{
    printf("=== x86-64 Disassembly Test ===\n");

    E9Disasm *dis = e9_disasm_create(E9_ARCH_X86_64);
    if (!dis) {
        printf("ERROR: Failed to create disassembler\n");
        return;
    }

    E9Instruction *insns;
    size_t count = e9_disasm_many(dis, X86_SAMPLE, sizeof(X86_SAMPLE),
                                   0x1000, 10, &insns);

    printf("Decoded %zu instructions:\n", count);
    for (size_t i = 0; i < count; i++) {
        printf("  0x%08llx: %s\n",
               (unsigned long long)insns[i].address,
               insns[i].text);
    }

    e9_insns_free(insns, count);
    e9_disasm_free(dis);
    printf("\n");
}

static void test_arm64_disasm(void)
{
    printf("=== AArch64 Disassembly Test ===\n");

    E9Disasm *dis = e9_disasm_create(E9_ARCH_ARM64);
    if (!dis) {
        printf("ERROR: Failed to create disassembler\n");
        return;
    }

    E9Instruction *insns;
    size_t count = e9_disasm_many(dis, ARM64_SAMPLE, sizeof(ARM64_SAMPLE),
                                   0x1000, 10, &insns);

    printf("Decoded %zu instructions:\n", count);
    for (size_t i = 0; i < count; i++) {
        printf("  0x%08llx: %s\n",
               (unsigned long long)insns[i].address,
               insns[i].text);
    }

    e9_insns_free(insns, count);
    e9_disasm_free(dis);
    printf("\n");
}

static void test_entropy(void)
{
    printf("=== Entropy Test ===\n");

    /* Test with zeros (should be 0) */
    uint8_t zeros[256] = {0};
    double ent_zeros = e9_entropy(zeros, sizeof(zeros));
    printf("Entropy of all zeros: %.2f (expected: 0.00)\n", ent_zeros);

    /* Test with random-ish data */
    uint8_t random[256];
    for (int i = 0; i < 256; i++) random[i] = i;
    double ent_random = e9_entropy(random, sizeof(random));
    printf("Entropy of 0-255 bytes: %.2f (expected: 8.00)\n", ent_random);

    printf("\n");
}

static void test_identify(void)
{
    printf("=== Binary Identification Test ===\n");

    /* Pad ELF sample to make it valid enough */
    uint8_t elf_padded[64];
    memset(elf_padded, 0, sizeof(elf_padded));
    memcpy(elf_padded, ELF_SAMPLE, sizeof(ELF_SAMPLE));

    E9BinaryInfo *info = e9_identify(elf_padded, sizeof(elf_padded));
    if (info) {
        char report[1024];
        e9_info_print(info, report, sizeof(report));
        printf("%s", report);
        e9_identify_free(info);
    } else {
        printf("ERROR: Failed to identify binary\n");
    }

    printf("\n");
}

static void test_strings(void)
{
    printf("=== String Extraction Test ===\n");

    const char *sample = "Hello, World!\x00"
                         "/usr/bin/test\x00"
                         "https://example.com\x00"
                         "test@example.org\x00"
                         "\x00\x00\x00"
                         "short\x00";

    uint32_t count;
    E9String *strings = e9_strings_extract((const uint8_t*)sample, 80, 4, &count);

    printf("Found %u strings:\n", count);
    for (uint32_t i = 0; i < count; i++) {
        printf("  [0x%04llx] \"%s\"",
               (unsigned long long)strings[i].offset,
               strings[i].value);
        if (strings[i].is_path) printf(" [path]");
        if (strings[i].is_url) printf(" [url]");
        if (strings[i].is_email) printf(" [email]");
        printf("\n");
    }

    e9_strings_free(strings, count);
    printf("\n");
}

static void test_compression_detection(void)
{
    printf("=== Compression Detection Test ===\n");

    /* gzip */
    uint8_t gzip[] = { 0x1f, 0x8b, 0x08 };
    printf("gzip header: %s\n", e9_compress_name(e9_detect_compression(gzip, 3)));

    /* zlib */
    uint8_t zlib[] = { 0x78, 0x9c };
    printf("zlib header: %s\n", e9_compress_name(e9_detect_compression(zlib, 2)));

    /* zstd */
    uint8_t zstd[] = { 0x28, 0xb5, 0x2f, 0xfd };
    printf("zstd header: %s\n", e9_compress_name(e9_detect_compression(zstd, 4)));

    /* unknown */
    uint8_t unknown[] = { 0x00, 0x01, 0x02 };
    printf("unknown: %s\n", e9_compress_name(e9_detect_compression(unknown, 3)));

    printf("\n");
}

int main(void)
{
    printf("E9Studio Vendor Library Tests\n");
    printf("==============================\n\n");

    test_version();
    test_signatures();
    test_x86_disasm();
    test_arm64_disasm();
    test_entropy();
    test_identify();
    test_strings();
    test_compression_detection();

    printf("All tests completed!\n");
    return 0;
}
