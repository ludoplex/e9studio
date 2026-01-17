/*
 * e9polyglot.c
 * Polyglot and Schizophrenic File Detection Implementation
 *
 * Copyright (C) 2024 E9Patch Contributors
 * License: GPLv3+
 */

#include "e9polyglot.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <math.h>

/*
 * ============================================================================
 * Magic Signature Database (binwalk-inspired)
 * ============================================================================
 */

static const E9MagicSignature builtin_signatures[] = {
    /* Executables */
    { E9_FMT_ELF, "ELF", (const uint8_t*)"\x7f""ELF", 4, 0,
      "ELF executable" },
    { E9_FMT_PE, "PE", (const uint8_t*)"PE\0\0", 4, -1,
      "PE signature (at e_lfanew)" },
    { E9_FMT_DOS_MZ, "DOS MZ", (const uint8_t*)"MZ", 2, 0,
      "DOS MZ executable" },
    { E9_FMT_MACHO, "Mach-O 64", (const uint8_t*)"\xfe\xed\xfa\xcf", 4, 0,
      "Mach-O 64-bit" },
    { E9_FMT_MACHO, "Mach-O 64 (rev)", (const uint8_t*)"\xcf\xfa\xed\xfe", 4, 0,
      "Mach-O 64-bit (reverse)" },
    { E9_FMT_SHELL_SCRIPT, "Shell script", (const uint8_t*)"#!/", 3, 0,
      "Shell script shebang" },
    { E9_FMT_SHELL_SCRIPT, "Shell script 2", (const uint8_t*)"#!", 2, 0,
      "Shell script shebang (short)" },

    /* Archives - Compression */
    { E9_FMT_ZIP, "ZIP", (const uint8_t*)"PK\x03\x04", 4, -1,
      "ZIP local file header" },
    { E9_FMT_ZIP, "ZIP (empty)", (const uint8_t*)"PK\x05\x06", 4, -1,
      "ZIP end of central directory" },
    { E9_FMT_GZIP, "gzip", (const uint8_t*)"\x1f\x8b\x08", 3, -1,
      "gzip compressed data" },
    { E9_FMT_BZIP2, "bzip2", (const uint8_t*)"BZh", 3, -1,
      "bzip2 compressed data" },
    { E9_FMT_XZ, "XZ", (const uint8_t*)"\xfd""7zXZ\x00", 6, -1,
      "XZ compressed data" },
    { E9_FMT_ZSTD, "Zstandard", (const uint8_t*)"\x28\xb5\x2f\xfd", 4, -1,
      "Zstandard compressed data" },
    { E9_FMT_LZ4, "LZ4", (const uint8_t*)"\x04\x22\x4d\x18", 4, -1,
      "LZ4 compressed data" },
    { E9_FMT_7Z, "7-Zip", (const uint8_t*)"7z\xbc\xaf\x27\x1c", 6, -1,
      "7-Zip archive" },
    { E9_FMT_RAR, "RAR", (const uint8_t*)"Rar!\x1a\x07", 6, -1,
      "RAR archive" },

    /* Archives - Tape/AR */
    { E9_FMT_TAR, "tar (ustar)", (const uint8_t*)"ustar", 5, 257,
      "POSIX tar archive" },
    { E9_FMT_AR, "ar", (const uint8_t*)"!<arch>\n", 8, 0,
      "ar archive" },
    { E9_FMT_CPIO, "cpio (new)", (const uint8_t*)"070701", 6, -1,
      "cpio newc archive" },
    { E9_FMT_CPIO, "cpio (old)", (const uint8_t*)"070707", 6, -1,
      "cpio odc archive" },

    /* Filesystems */
    { E9_FMT_SQUASHFS, "SquashFS", (const uint8_t*)"hsqs", 4, -1,
      "SquashFS filesystem" },
    { E9_FMT_SQUASHFS, "SquashFS (BE)", (const uint8_t*)"sqsh", 4, -1,
      "SquashFS filesystem (big-endian)" },
    { E9_FMT_CRAMFS, "CramFS", (const uint8_t*)"\x45\x3d\xcd\x28", 4, -1,
      "CramFS filesystem" },
    { E9_FMT_JFFS2, "JFFS2", (const uint8_t*)"\x85\x19", 2, -1,
      "JFFS2 filesystem" },
    { E9_FMT_EXT4, "ext2/3/4", (const uint8_t*)"\x53\xef", 2, 0x438,
      "ext2/3/4 filesystem" },
    { E9_FMT_ISO9660, "ISO 9660", (const uint8_t*)"CD001", 5, 0x8001,
      "ISO 9660 filesystem" },

    /* Images */
    { E9_FMT_PNG, "PNG", (const uint8_t*)"\x89PNG\r\n\x1a\n", 8, 0,
      "PNG image" },
    { E9_FMT_JPEG, "JPEG", (const uint8_t*)"\xff\xd8\xff", 3, 0,
      "JPEG image" },
    { E9_FMT_GIF, "GIF87a", (const uint8_t*)"GIF87a", 6, 0,
      "GIF image (87a)" },
    { E9_FMT_GIF, "GIF89a", (const uint8_t*)"GIF89a", 6, 0,
      "GIF image (89a)" },
    { E9_FMT_BMP, "BMP", (const uint8_t*)"BM", 2, 0,
      "BMP image" },
    { E9_FMT_PDF, "PDF", (const uint8_t*)"%PDF-", 5, 0,
      "PDF document" },

    /* Documents */
    { E9_FMT_XML, "XML", (const uint8_t*)"<?xml", 5, 0,
      "XML document" },
    { E9_FMT_HTML, "HTML", (const uint8_t*)"<!DOCTYPE html", 14, -1,
      "HTML document" },
    { E9_FMT_HTML, "HTML (tag)", (const uint8_t*)"<html", 5, -1,
      "HTML document" },

    /* Bytecode */
    { E9_FMT_WASM, "WebAssembly", (const uint8_t*)"\x00""asm", 4, 0,
      "WebAssembly binary" },
    { E9_FMT_JAVA_CLASS, "Java class", (const uint8_t*)"\xca\xfe\xba\xbe", 4, 0,
      "Java class file" },
    { E9_FMT_DEX, "Dalvik DEX", (const uint8_t*)"dex\n", 4, 0,
      "Android DEX file" },
    { E9_FMT_LLVM_BC, "LLVM bitcode", (const uint8_t*)"BC\xc0\xde", 4, 0,
      "LLVM bitcode" },

    /* Crypto */
    { E9_FMT_PEM, "PEM", (const uint8_t*)"-----BEGIN ", 11, -1,
      "PEM encoded data" },
    { E9_FMT_PGP, "PGP", (const uint8_t*)"\x95\x01", 2, -1,
      "PGP message" },
    { E9_FMT_PGP, "PGP (armor)", (const uint8_t*)"-----BEGIN PGP", 14, -1,
      "PGP armored message" },

    /* End marker */
    { E9_FMT_UNKNOWN, NULL, NULL, 0, 0, NULL }
};

static E9MagicSignature *custom_signatures = NULL;
static size_t num_custom_signatures = 0;

/*
 * Format name strings
 */
static const char *format_names[] = {
    [E9_FMT_UNKNOWN] = "unknown",
    [E9_FMT_ELF] = "ELF",
    [E9_FMT_PE] = "PE",
    [E9_FMT_MACHO] = "Mach-O",
    [E9_FMT_DOS_MZ] = "DOS MZ",
    [E9_FMT_DOS_COM] = "DOS COM",
    [E9_FMT_SHELL_SCRIPT] = "Shell script",
    [E9_FMT_APE] = "APE",
    [E9_FMT_ZIP] = "ZIP",
    [E9_FMT_GZIP] = "gzip",
    [E9_FMT_BZIP2] = "bzip2",
    [E9_FMT_XZ] = "XZ",
    [E9_FMT_ZSTD] = "Zstandard",
    [E9_FMT_LZ4] = "LZ4",
    [E9_FMT_TAR] = "tar",
    [E9_FMT_CPIO] = "cpio",
    [E9_FMT_AR] = "ar",
    [E9_FMT_7Z] = "7-Zip",
    [E9_FMT_RAR] = "RAR",
    [E9_FMT_SQUASHFS] = "SquashFS",
    [E9_FMT_CRAMFS] = "CramFS",
    [E9_FMT_JFFS2] = "JFFS2",
    [E9_FMT_UBIFS] = "UBIFS",
    [E9_FMT_EXT4] = "ext2/3/4",
    [E9_FMT_FAT] = "FAT",
    [E9_FMT_ISO9660] = "ISO 9660",
    [E9_FMT_PNG] = "PNG",
    [E9_FMT_JPEG] = "JPEG",
    [E9_FMT_GIF] = "GIF",
    [E9_FMT_BMP] = "BMP",
    [E9_FMT_PDF] = "PDF",
    [E9_FMT_XML] = "XML",
    [E9_FMT_HTML] = "HTML",
    [E9_FMT_JSON] = "JSON",
    [E9_FMT_WASM] = "WebAssembly",
    [E9_FMT_JAVA_CLASS] = "Java class",
    [E9_FMT_DEX] = "DEX",
    [E9_FMT_LLVM_BC] = "LLVM bitcode",
    [E9_FMT_PEM] = "PEM",
    [E9_FMT_DER] = "DER",
    [E9_FMT_PGP] = "PGP",
    [E9_FMT_ZIPOS] = "ZipOS",
    [E9_FMT_APPIMAGE] = "AppImage",
    [E9_FMT_FLATPAK] = "Flatpak",
    [E9_FMT_SNAP] = "Snap",
};

const char *e9_format_name(E9FormatType fmt)
{
    if (fmt >= E9_FMT_COUNT) return "unknown";
    return format_names[fmt];
}

/*
 * ============================================================================
 * Helper Functions
 * ============================================================================
 */

static void *e9_alloc(size_t size)
{
    void *p = calloc(1, size);
    return p;
}

static char *e9_strdup(const char *s)
{
    if (!s) return NULL;
    size_t len = strlen(s) + 1;
    char *p = (char *)malloc(len);
    if (p) memcpy(p, s, len);
    return p;
}

/*
 * Check if data matches signature at offset
 */
static bool match_signature(const uint8_t *data, size_t size,
                           const E9MagicSignature *sig, int64_t at_offset)
{
    int64_t offset = at_offset;

    /* Handle relative offsets */
    if (sig->offset >= 0 && at_offset < 0) {
        offset = sig->offset;
    }

    if (offset < 0 || (size_t)offset + sig->magic_len > size) {
        return false;
    }

    return memcmp(data + offset, sig->magic, sig->magic_len) == 0;
}

/*
 * ============================================================================
 * Entropy Analysis
 * ============================================================================
 */

E9EntropyResult e9_entropy_analyze(const uint8_t *data, size_t size)
{
    E9EntropyResult result = {0};

    if (!data || size == 0) return result;

    /* Count byte frequencies */
    uint64_t freq[256] = {0};
    for (size_t i = 0; i < size; i++) {
        freq[data[i]]++;
    }

    /* Calculate Shannon entropy */
    double entropy = 0.0;
    for (int i = 0; i < 256; i++) {
        if (freq[i] > 0) {
            double p = (double)freq[i] / size;
            entropy -= p * log2(p);
        }
    }
    result.entropy = entropy;

    /* Calculate chi-square */
    double expected = (double)size / 256.0;
    double chi_sq = 0.0;
    for (int i = 0; i < 256; i++) {
        double diff = freq[i] - expected;
        chi_sq += (diff * diff) / expected;
    }
    result.chi_square = chi_sq;

    /* Classify */
    result.likely_compressed = (entropy > 7.5);
    result.likely_encrypted = (entropy > 7.9 && chi_sq < 300);
    result.likely_text = (entropy < 5.0);

    /* Check for text by looking at printable ratio */
    size_t printable = 0;
    for (size_t i = 0; i < size; i++) {
        if ((data[i] >= 32 && data[i] < 127) ||
            data[i] == '\n' || data[i] == '\r' || data[i] == '\t') {
            printable++;
        }
    }
    if ((double)printable / size > 0.9) {
        result.likely_text = true;
    }

    return result;
}

double *e9_entropy_map(const uint8_t *data, size_t size,
                       size_t block_size, size_t *num_blocks)
{
    if (!data || size == 0 || block_size == 0) return NULL;

    size_t count = (size + block_size - 1) / block_size;
    double *map = (double *)malloc(count * sizeof(double));
    if (!map) return NULL;

    for (size_t i = 0; i < count; i++) {
        size_t offset = i * block_size;
        size_t len = block_size;
        if (offset + len > size) len = size - offset;

        E9EntropyResult r = e9_entropy_analyze(data + offset, len);
        map[i] = r.entropy;
    }

    if (num_blocks) *num_blocks = count;
    return map;
}

E9FormatRegion *e9_entropy_find_high(const uint8_t *data, size_t size,
                                      double threshold)
{
    E9FormatRegion *head = NULL;
    E9FormatRegion *tail = NULL;

    size_t block_size = 256;
    size_t num_blocks;
    double *map = e9_entropy_map(data, size, block_size, &num_blocks);
    if (!map) return NULL;

    bool in_region = false;
    size_t region_start = 0;

    for (size_t i = 0; i < num_blocks; i++) {
        if (map[i] >= threshold && !in_region) {
            in_region = true;
            region_start = i * block_size;
        } else if (map[i] < threshold && in_region) {
            in_region = false;

            E9FormatRegion *r = (E9FormatRegion *)e9_alloc(sizeof(E9FormatRegion));
            if (r) {
                r->format = E9_FMT_UNKNOWN;
                r->offset = region_start;
                r->size = i * block_size - region_start;
                r->confidence = map[i - 1] / 8.0;
                snprintf(r->description, sizeof(r->description),
                         "High entropy region (%.2f bits/byte)", map[i - 1]);

                if (!head) head = r;
                else tail->next = r;
                tail = r;
            }
        }
    }

    /* Handle region at end */
    if (in_region) {
        E9FormatRegion *r = (E9FormatRegion *)e9_alloc(sizeof(E9FormatRegion));
        if (r) {
            r->format = E9_FMT_UNKNOWN;
            r->offset = region_start;
            r->size = size - region_start;
            r->confidence = map[num_blocks - 1] / 8.0;
            snprintf(r->description, sizeof(r->description),
                     "High entropy region (%.2f bits/byte)", map[num_blocks - 1]);

            if (!head) head = r;
            else tail->next = r;
        }
    }

    free(map);
    return head;
}

/*
 * ============================================================================
 * Signature Scanning
 * ============================================================================
 */

const E9MagicSignature *e9_signature_database(size_t *count)
{
    if (count) {
        size_t n = 0;
        while (builtin_signatures[n].magic) n++;
        *count = n;
    }
    return builtin_signatures;
}

int e9_signature_add(const E9MagicSignature *sig)
{
    if (!sig || !sig->magic) return -1;

    custom_signatures = realloc(custom_signatures,
                                (num_custom_signatures + 1) * sizeof(E9MagicSignature));
    if (!custom_signatures) return -1;

    memcpy(&custom_signatures[num_custom_signatures], sig, sizeof(E9MagicSignature));
    num_custom_signatures++;
    return 0;
}

E9FormatRegion *e9_signature_scan(const uint8_t *data, size_t size)
{
    E9FormatRegion *head = NULL;
    E9FormatRegion *tail = NULL;

    /* Scan all offsets */
    for (size_t offset = 0; offset < size; offset++) {
        /* Check builtin signatures */
        for (size_t i = 0; builtin_signatures[i].magic; i++) {
            const E9MagicSignature *sig = &builtin_signatures[i];

            /* Skip signatures with fixed offsets unless we're at that offset */
            if (sig->offset >= 0 && (size_t)sig->offset != offset) {
                continue;
            }

            if (offset + sig->magic_len <= size &&
                memcmp(data + offset, sig->magic, sig->magic_len) == 0) {

                E9FormatRegion *r = (E9FormatRegion *)e9_alloc(sizeof(E9FormatRegion));
                if (r) {
                    r->format = sig->format;
                    r->offset = offset;
                    r->size = 0;  /* Size determined later by format parser */
                    r->confidence = 0.9;
                    strncpy(r->description, sig->description,
                            sizeof(r->description) - 1);

                    if (!head) head = r;
                    else tail->next = r;
                    tail = r;
                }
            }
        }

        /* Check custom signatures */
        for (size_t i = 0; i < num_custom_signatures; i++) {
            const E9MagicSignature *sig = &custom_signatures[i];

            if (sig->offset >= 0 && (size_t)sig->offset != offset) {
                continue;
            }

            if (offset + sig->magic_len <= size &&
                memcmp(data + offset, sig->magic, sig->magic_len) == 0) {

                E9FormatRegion *r = (E9FormatRegion *)e9_alloc(sizeof(E9FormatRegion));
                if (r) {
                    r->format = sig->format;
                    r->offset = offset;
                    r->confidence = 0.8;
                    strncpy(r->description, sig->description,
                            sizeof(r->description) - 1);

                    if (!head) head = r;
                    else tail->next = r;
                    tail = r;
                }
            }
        }
    }

    return head;
}

E9FormatRegion *e9_signature_scan_format(const uint8_t *data, size_t size,
                                          E9FormatType format)
{
    E9FormatRegion *all = e9_signature_scan(data, size);
    E9FormatRegion *filtered = NULL;
    E9FormatRegion *tail = NULL;

    E9FormatRegion *r = all;
    while (r) {
        E9FormatRegion *next = r->next;
        if (r->format == format) {
            r->next = NULL;
            if (!filtered) filtered = r;
            else tail->next = r;
            tail = r;
        } else {
            free(r);
        }
        r = next;
    }

    return filtered;
}

/*
 * ============================================================================
 * APE Detection and Parsing
 * ============================================================================
 */

bool e9_is_ape(const uint8_t *data, size_t size)
{
    if (size < 64) return false;

    /* APE files start with MZ (DOS) but also have:
     * 1. A shell script somewhere in the header
     * 2. ELF signature at a specific offset
     * 3. PE signature pointed to by e_lfanew
     * 4. ZIP central directory at the end
     */

    /* Check for MZ */
    if (data[0] != 'M' || data[1] != 'Z') {
        return false;
    }

    /* Look for shell script in first 512 bytes */
    bool has_shell = false;
    for (size_t i = 0; i < 512 && i + 2 < size; i++) {
        if (data[i] == '#' && data[i+1] == '!') {
            has_shell = true;
            break;
        }
    }

    /* Look for ELF signature */
    bool has_elf = false;
    for (size_t i = 0; i < size - 4; i += 4) {
        if (data[i] == 0x7f && data[i+1] == 'E' &&
            data[i+2] == 'L' && data[i+3] == 'F') {
            has_elf = true;
            break;
        }
    }

    /* Check for ZIP end of central directory at end */
    bool has_zip = false;
    if (size > 22) {
        for (size_t i = size - 22; i > 0 && i > size - 65536; i--) {
            if (data[i] == 'P' && data[i+1] == 'K' &&
                data[i+2] == 0x05 && data[i+3] == 0x06) {
                has_zip = true;
                break;
            }
        }
    }

    /* APE needs at least shell script + ELF or PE */
    return has_shell && (has_elf || has_zip);
}

int e9_ape_parse(const uint8_t *data, size_t size, E9APELayout *layout)
{
    if (!data || !layout || size < 64) return -1;

    memset(layout, 0, sizeof(E9APELayout));

    /* Check MZ header */
    if (data[0] != 'M' || data[1] != 'Z') {
        return -1;
    }
    layout->dos_header = 0;

    /* Get e_lfanew (PE header offset) */
    uint32_t e_lfanew = *(uint32_t *)(data + 0x3C);
    if (e_lfanew < size && e_lfanew + 4 <= size) {
        if (memcmp(data + e_lfanew, "PE\0\0", 4) == 0) {
            layout->pe_offset = e_lfanew;
            /* Parse PE to get size */
            uint16_t num_sections = *(uint16_t *)(data + e_lfanew + 6);
            uint16_t opt_hdr_size = *(uint16_t *)(data + e_lfanew + 20);
            uint64_t sections_start = e_lfanew + 24 + opt_hdr_size;

            /* Find last section to determine PE size */
            for (uint16_t i = 0; i < num_sections && sections_start + 40 <= size; i++) {
                const uint8_t *shdr = data + sections_start + i * 40;
                uint32_t raw_ptr = *(uint32_t *)(shdr + 20);
                uint32_t raw_size = *(uint32_t *)(shdr + 16);
                if (raw_ptr + raw_size > layout->pe_size) {
                    layout->pe_size = raw_ptr + raw_size;
                }
            }
        }
    }

    /* Find shell script */
    for (size_t i = 0; i < 512 && i + 2 < size; i++) {
        if (data[i] == '#' && data[i+1] == '!') {
            layout->shell_offset = i;
            /* Find end of line */
            size_t end = i;
            while (end < size && data[end] != '\n') end++;
            layout->shell_size = end - i;
            break;
        }
    }

    /* Find ELF header */
    for (size_t i = 0; i < size - 4; i++) {
        if (data[i] == 0x7f && data[i+1] == 'E' &&
            data[i+2] == 'L' && data[i+3] == 'F') {
            layout->elf_offset = i;

            /* Parse ELF to get size and entry */
            if (i + 64 <= size && data[i + 4] == 2) {  /* 64-bit */
                layout->elf_entry = *(uint64_t *)(data + i + 24);
                layout->elf_phdr = *(uint64_t *)(data + i + 32);
                layout->elf_shdr = *(uint64_t *)(data + i + 40);

                uint16_t phnum = *(uint16_t *)(data + i + 56);
                uint64_t phoff = layout->elf_phdr;
                uint64_t max_end = 0;

                for (uint16_t j = 0; j < phnum && i + phoff + 56 <= size; j++) {
                    uint64_t p_offset = *(uint64_t *)(data + i + phoff + j * 56 + 8);
                    uint64_t p_filesz = *(uint64_t *)(data + i + phoff + j * 56 + 32);
                    if (p_offset + p_filesz > max_end) {
                        max_end = p_offset + p_filesz;
                    }
                }
                layout->elf_size = max_end;
            }
            break;
        }
    }

    /* Find Mach-O header */
    for (size_t i = 0; i < size - 4; i++) {
        if ((data[i] == 0xfe && data[i+1] == 0xed &&
             data[i+2] == 0xfa && data[i+3] == 0xcf) ||
            (data[i] == 0xcf && data[i+1] == 0xfa &&
             data[i+2] == 0xed && data[i+3] == 0xfe)) {
            layout->macho_offset = i;
            break;
        }
    }

    /* Find ZIP end of central directory */
    for (size_t i = size - 22; i > 0 && i > size - 65536; i--) {
        if (data[i] == 'P' && data[i+1] == 'K' &&
            data[i+2] == 0x05 && data[i+3] == 0x06) {
            layout->zipos_end = i + 22;
            layout->zipos_num_entries = *(uint16_t *)(data + i + 10);

            /* Get central directory offset */
            uint32_t cd_offset = *(uint32_t *)(data + i + 16);
            layout->zipos_central_dir = cd_offset;

            /* Find first local file header */
            for (size_t j = 0; j < cd_offset && j + 4 < size; j++) {
                if (data[j] == 'P' && data[j+1] == 'K' &&
                    data[j+2] == 0x03 && data[j+3] == 0x04) {
                    layout->zipos_start = j;
                    break;
                }
            }
            break;
        }
    }

    return 0;
}

/*
 * ============================================================================
 * Polyglot Analysis
 * ============================================================================
 */

E9PolyglotAnalysis *e9_polyglot_analyze(const uint8_t *data, size_t size)
{
    if (!data || size < 4) return NULL;

    E9PolyglotAnalysis *analysis = (E9PolyglotAnalysis *)e9_alloc(
        sizeof(E9PolyglotAnalysis));
    if (!analysis) return NULL;

    /* Scan for all signatures */
    analysis->interpretations = e9_signature_scan(data, size);

    /* Count interpretations */
    E9FormatRegion *r = analysis->interpretations;
    while (r) {
        analysis->num_interpretations++;
        r = r->next;
    }

    /* Check for APE */
    if (e9_is_ape(data, size)) {
        analysis->is_ape = true;
        analysis->is_polyglot = true;

        E9APELayout layout;
        if (e9_ape_parse(data, size, &layout) == 0) {
            analysis->ape_layout.mz_header = layout.dos_header;
            analysis->ape_layout.elf_header = layout.elf_offset;
            analysis->ape_layout.pe_header = layout.pe_offset;
            analysis->ape_layout.shell_shebang = layout.shell_offset;
            analysis->ape_layout.zipos_start = layout.zipos_start;
            analysis->ape_layout.zipos_end = layout.zipos_end;
        }
    }

    /* Check for other polyglot types */
    if (!analysis->is_polyglot) {
        /* PDF polyglot (PDF + something else) */
        if (memcmp(data, "%PDF-", 5) == 0) {
            /* Check for ZIP at end */
            for (size_t i = size - 22; i > size/2; i--) {
                if (memcmp(data + i, "PK\x05\x06", 4) == 0) {
                    analysis->is_polyglot = true;
                    break;
                }
            }
        }
    }

    /* Count unique formats at offset 0 */
    uint32_t formats_at_zero = 0;
    r = analysis->interpretations;
    while (r) {
        if (r->offset == 0) formats_at_zero++;
        r = r->next;
    }

    /* Multiple valid formats at same offset = schizophrenic */
    if (formats_at_zero > 1) {
        analysis->is_schizophrenic = true;
    }

    /* Calculate attack surface */
    analysis->attack_surface.num_parsers = analysis->num_interpretations;

    /* Find ambiguous regions (overlapping interpretations) */
    r = analysis->interpretations;
    while (r) {
        E9FormatRegion *r2 = r->next;
        while (r2) {
            if ((r->offset < r2->offset + r2->size) &&
                (r2->offset < r->offset + r->size)) {
                analysis->attack_surface.ambiguous_regions++;
            }
            r2 = r2->next;
        }
        r = r->next;
    }

    return analysis;
}

void e9_polyglot_free(E9PolyglotAnalysis *analysis)
{
    if (!analysis) return;

    /* Free interpretations */
    E9FormatRegion *r = analysis->interpretations;
    while (r) {
        E9FormatRegion *next = r->next;
        free(r);
        r = next;
    }

    /* Free embedded */
    r = analysis->embedded;
    while (r) {
        E9FormatRegion *next = r->next;
        free(r);
        r = next;
    }

    free(analysis);
}

E9FormatRegion *e9_polyglot_at_offset(E9PolyglotAnalysis *analysis, uint64_t offset)
{
    if (!analysis) return NULL;

    E9FormatRegion *result = NULL;
    E9FormatRegion *tail = NULL;

    E9FormatRegion *r = analysis->interpretations;
    while (r) {
        if (r->offset <= offset && (r->size == 0 || offset < r->offset + r->size)) {
            /* Clone the region */
            E9FormatRegion *clone = (E9FormatRegion *)e9_alloc(sizeof(E9FormatRegion));
            if (clone) {
                memcpy(clone, r, sizeof(E9FormatRegion));
                clone->next = NULL;
                clone->children = NULL;
                clone->conflicts = NULL;

                if (!result) result = clone;
                else tail->next = clone;
                tail = clone;
            }
        }
        r = r->next;
    }

    return result;
}

/*
 * ============================================================================
 * Specific Polyglot Checks
 * ============================================================================
 */

bool e9_is_polyglot_pdf(const uint8_t *data, size_t size)
{
    if (size < 10 || memcmp(data, "%PDF-", 5) != 0) return false;

    /* Check for embedded ZIP */
    for (size_t i = 0; i < size - 4; i++) {
        if (memcmp(data + i, "PK\x03\x04", 4) == 0) {
            return true;
        }
    }

    /* Check for embedded script */
    for (size_t i = 0; i < size - 10; i++) {
        if (memcmp(data + i, "<script", 7) == 0) {
            return true;
        }
    }

    return false;
}

bool e9_is_polyglot_zip(const uint8_t *data, size_t size)
{
    if (size < 30) return false;

    /* Valid ZIP but has non-ZIP prefix */
    bool has_prefix = (memcmp(data, "PK\x03\x04", 4) != 0);

    /* Find ZIP signature */
    bool has_zip = false;
    for (size_t i = 0; i < size - 4; i++) {
        if (memcmp(data + i, "PK\x03\x04", 4) == 0) {
            has_zip = true;
            break;
        }
    }

    return has_prefix && has_zip;
}

/*
 * ============================================================================
 * Hidden Data Detection
 * ============================================================================
 */

E9HiddenRegion *e9_find_hidden(const uint8_t *data, size_t size,
                                E9PolyglotAnalysis *analysis,
                                uint32_t *num_regions)
{
    if (!data || !analysis || !num_regions) return NULL;

    /* Create coverage bitmap */
    uint8_t *covered = (uint8_t *)calloc((size + 7) / 8, 1);
    if (!covered) return NULL;

    /* Mark covered regions */
    E9FormatRegion *r = analysis->interpretations;
    while (r) {
        if (r->size > 0) {
            for (uint64_t i = r->offset; i < r->offset + r->size && i < size; i++) {
                covered[i / 8] |= (1 << (i % 8));
            }
        }
        r = r->next;
    }

    /* Find uncovered regions */
    E9HiddenRegion *regions = NULL;
    uint32_t count = 0;
    uint32_t capacity = 0;

    bool in_gap = false;
    size_t gap_start = 0;

    for (size_t i = 0; i < size; i++) {
        bool is_covered = (covered[i / 8] & (1 << (i % 8))) != 0;

        if (!is_covered && !in_gap) {
            in_gap = true;
            gap_start = i;
        } else if (is_covered && in_gap) {
            in_gap = false;

            /* Record gap */
            if (count >= capacity) {
                capacity = capacity ? capacity * 2 : 16;
                regions = realloc(regions, capacity * sizeof(E9HiddenRegion));
            }

            E9HiddenRegion *h = &regions[count++];
            h->offset = gap_start;
            h->size = i - gap_start;
            h->entropy = e9_entropy_analyze(data + gap_start, h->size);
            snprintf(h->description, sizeof(h->description),
                     "Uncovered region (%s)",
                     h->entropy.likely_encrypted ? "encrypted" :
                     h->entropy.likely_compressed ? "compressed" : "data");
        }
    }

    /* Handle gap at end */
    if (in_gap) {
        if (count >= capacity) {
            capacity = capacity ? capacity * 2 : 16;
            regions = realloc(regions, capacity * sizeof(E9HiddenRegion));
        }

        E9HiddenRegion *h = &regions[count++];
        h->offset = gap_start;
        h->size = size - gap_start;
        h->entropy = e9_entropy_analyze(data + gap_start, h->size);
        snprintf(h->description, sizeof(h->description),
                 "Trailing data (%s)",
                 h->entropy.likely_encrypted ? "encrypted" :
                 h->entropy.likely_compressed ? "compressed" : "data");
    }

    free(covered);
    *num_regions = count;
    return regions;
}

E9HiddenRegion *e9_find_appended(const uint8_t *data, size_t size,
                                  E9FormatType primary_format,
                                  uint32_t *num_regions)
{
    if (!data || !num_regions) return NULL;

    uint64_t format_end = 0;

    switch (primary_format) {
        case E9_FMT_ELF:
            if (size >= 64 && memcmp(data, "\x7f""ELF", 4) == 0) {
                /* Find last section/segment */
                uint64_t shoff = *(uint64_t *)(data + 40);
                uint16_t shnum = *(uint16_t *)(data + 60);
                uint16_t shentsize = *(uint16_t *)(data + 58);
                format_end = shoff + shnum * shentsize;
            }
            break;

        case E9_FMT_PE:
            /* Use PE section table to find end */
            break;

        case E9_FMT_ZIP:
            /* Find end of central directory */
            for (size_t i = size - 22; i > 0; i--) {
                if (memcmp(data + i, "PK\x05\x06", 4) == 0) {
                    format_end = i + 22;
                    uint16_t comment_len = *(uint16_t *)(data + i + 20);
                    format_end += comment_len;
                    break;
                }
            }
            break;

        default:
            *num_regions = 0;
            return NULL;
    }

    if (format_end == 0 || format_end >= size) {
        *num_regions = 0;
        return NULL;
    }

    E9HiddenRegion *regions = (E9HiddenRegion *)malloc(sizeof(E9HiddenRegion));
    if (!regions) {
        *num_regions = 0;
        return NULL;
    }

    regions[0].offset = format_end;
    regions[0].size = size - format_end;
    regions[0].entropy = e9_entropy_analyze(data + format_end, regions[0].size);
    snprintf(regions[0].description, sizeof(regions[0].description),
             "Appended data after %s", e9_format_name(primary_format));

    *num_regions = 1;
    return regions;
}
