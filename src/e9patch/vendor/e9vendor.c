/*
 * e9vendor.c
 * Unified E9Studio Vendor Library Implementation
 *
 * Copyright (C) 2024 E9Patch Contributors
 * License: GPLv3+
 */

#include "e9vendor.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <math.h>
#include <ctype.h>

/*
 * Version info
 */
const char *e9_vendor_version(void)
{
    static char version[32];
    snprintf(version, sizeof(version), "%d.%d.%d",
             E9VENDOR_VERSION_MAJOR,
             E9VENDOR_VERSION_MINOR,
             E9VENDOR_VERSION_PATCH);
    return version;
}

const char *e9_vendor_build_info(void)
{
    return "E9Studio Vendor Library - Self-contained binary analysis";
}

/*
 * ============================================================================
 * Binary Identification
 * ============================================================================
 */

E9BinaryInfo *e9_identify(const uint8_t *data, size_t size)
{
    if (!data || size < 4) return NULL;

    E9BinaryInfo *info = calloc(1, sizeof(E9BinaryInfo));
    if (!info) return NULL;

    info->format = E9_FMT_UNKNOWN;
    info->arch = E9_ARCH_UNKNOWN;

    /* Check for ELF */
    if (size >= 52 && memcmp(data, "\x7F" "ELF", 4) == 0) {
        info->format = E9_FMT_ELF;
        info->is_64bit = (data[4] == 2);
        info->is_little_endian = (data[5] == 1);

        uint16_t e_type, e_machine;
        if (info->is_little_endian) {
            e_type = data[16] | (data[17] << 8);
            e_machine = data[18] | (data[19] << 8);
        } else {
            e_type = (data[16] << 8) | data[17];
            e_machine = (data[18] << 8) | data[19];
        }

        info->is_executable = (e_type == 2);
        info->is_shared_lib = (e_type == 3);
        info->is_relocatable = (e_type == 1);

        switch (e_machine) {
            case 0x03: info->arch = E9_ARCH_X86; break;
            case 0x3E: info->arch = E9_ARCH_X86_64; break;
            case 0x28: info->arch = E9_ARCH_ARM; break;
            case 0xB7: info->arch = E9_ARCH_ARM64; break;
            case 0x08: info->arch = E9_ARCH_MIPS; break;
            case 0xF3: info->arch = E9_ARCH_RISCV; break;
        }

        /* Get entry point */
        if (info->is_64bit && size >= 32) {
            if (info->is_little_endian) {
                info->entry_point = *(uint64_t*)(data + 24);
            }
        } else if (size >= 28) {
            if (info->is_little_endian) {
                info->entry_point = *(uint32_t*)(data + 24);
            }
        }

        snprintf(info->description, sizeof(info->description),
                 "ELF %s %s %s",
                 info->is_64bit ? "64-bit" : "32-bit",
                 info->is_little_endian ? "LSB" : "MSB",
                 info->is_executable ? "executable" :
                 info->is_shared_lib ? "shared object" : "relocatable");
    }
    /* Check for PE/MZ */
    else if (size >= 64 && data[0] == 'M' && data[1] == 'Z') {
        /* Check for APE first */
        if (size >= 8 && memcmp(data, "MZqFpD=", 7) == 0) {
            info->format = E9_FMT_APE;
            info->is_polyglot = true;
            snprintf(info->description, sizeof(info->description),
                     "Actually Portable Executable (APE polyglot)");
        } else {
            info->format = E9_FMT_PE;
            uint32_t pe_offset = *(uint32_t*)(data + 60);

            if (pe_offset + 6 <= size && memcmp(data + pe_offset, "PE\x00\x00", 4) == 0) {
                uint16_t machine = *(uint16_t*)(data + pe_offset + 4);

                switch (machine) {
                    case 0x014C: info->arch = E9_ARCH_X86; info->is_64bit = false; break;
                    case 0x8664: info->arch = E9_ARCH_X86_64; info->is_64bit = true; break;
                    case 0x01C4: info->arch = E9_ARCH_ARM; info->is_64bit = false; break;
                    case 0xAA64: info->arch = E9_ARCH_ARM64; info->is_64bit = true; break;
                }

                info->is_little_endian = true;
                info->is_executable = true;

                snprintf(info->description, sizeof(info->description),
                         "PE %s executable",
                         info->is_64bit ? "64-bit" : "32-bit");
            }
        }
    }
    /* Check for Mach-O */
    else if (size >= 4) {
        uint32_t magic = *(uint32_t*)data;

        if (magic == 0xFEEDFACE || magic == 0xCEFAEDFE) {
            info->format = E9_FMT_MACHO;
            info->is_64bit = false;
            info->is_little_endian = (magic == 0xFEEDFACE);
            snprintf(info->description, sizeof(info->description),
                     "Mach-O 32-bit");
        }
        else if (magic == 0xFEEDFACF || magic == 0xCFFAEDFE) {
            info->format = E9_FMT_MACHO;
            info->is_64bit = true;
            info->is_little_endian = (magic == 0xFEEDFACF);
            snprintf(info->description, sizeof(info->description),
                     "Mach-O 64-bit");
        }
        else if (magic == 0xCAFEBABE || magic == 0xBEBAFECA) {
            info->format = E9_FMT_MACHO;
            snprintf(info->description, sizeof(info->description),
                     "Mach-O Universal Binary");
        }
    }
    /* Check for WebAssembly */
    if (size >= 8 && memcmp(data, "\x00" "asm\x01\x00\x00\x00", 8) == 0) {
        info->format = E9_FMT_WASM;
        info->arch = E9_ARCH_WASM;
        snprintf(info->description, sizeof(info->description),
                 "WebAssembly module");
    }

    /* Scan for embedded signatures */
    E9SigScanner *scanner = e9_sig_scanner_create();
    if (scanner) {
        info->signatures = e9_sig_scan(scanner, data, size, &info->num_signatures);
        e9_sig_scanner_free(scanner);

        /* Check for polyglot */
        if (info->num_signatures > 1) {
            for (uint32_t i = 0; i < info->num_signatures; i++) {
                if (info->signatures[i].offset == 0 &&
                    info->signatures[i].sig->category == E9_SIG_CAT_EXECUTABLE) {
                    info->is_polyglot = true;
                    break;
                }
            }
        }
    }

    if (info->format == E9_FMT_UNKNOWN) {
        snprintf(info->description, sizeof(info->description),
                 "Unknown binary format");
    }

    return info;
}

void e9_identify_free(E9BinaryInfo *info)
{
    if (!info) return;
    e9_sig_matches_free(info->signatures);
    free(info);
}

/*
 * ============================================================================
 * Multi-Architecture Disassembly
 * ============================================================================
 */

struct E9Disasm {
    E9Arch arch;
    union {
        E9X86Disasm *x86;
        E9A64Disasm *a64;
    } ctx;
};

E9Disasm *e9_disasm_create(E9Arch arch)
{
    E9Disasm *dis = calloc(1, sizeof(E9Disasm));
    if (!dis) return NULL;

    dis->arch = arch;

    switch (arch) {
        case E9_ARCH_X86:
            dis->ctx.x86 = e9_x86_disasm_create(32);
            break;
        case E9_ARCH_X86_64:
            dis->ctx.x86 = e9_x86_disasm_create(64);
            break;
        case E9_ARCH_ARM64:
            dis->ctx.a64 = e9_a64_disasm_create();
            break;
        default:
            free(dis);
            return NULL;
    }

    return dis;
}

void e9_disasm_free(E9Disasm *dis)
{
    if (!dis) return;

    switch (dis->arch) {
        case E9_ARCH_X86:
        case E9_ARCH_X86_64:
            e9_x86_disasm_free(dis->ctx.x86);
            break;
        case E9_ARCH_ARM64:
            e9_a64_disasm_free(dis->ctx.a64);
            break;
        default:
            break;
    }

    free(dis);
}

int e9_disasm_one(E9Disasm *dis, const uint8_t *code, size_t size,
                  uint64_t address, E9Instruction *insn)
{
    if (!dis || !code || !insn) return 0;

    memset(insn, 0, sizeof(*insn));

    switch (dis->arch) {
        case E9_ARCH_X86:
        case E9_ARCH_X86_64: {
            E9X86Insn x86_insn;
            int len = e9_x86_disasm_one(dis->ctx.x86, code, size, address, &x86_insn);
            if (len <= 0) return 0;

            insn->address = x86_insn.address;
            insn->length = x86_insn.length;
            memcpy(insn->bytes, x86_insn.bytes, x86_insn.length);
            strncpy(insn->mnemonic, x86_insn.mnemonic, sizeof(insn->mnemonic) - 1);
            strncpy(insn->text, x86_insn.text, sizeof(insn->text) - 1);
            insn->is_branch = x86_insn.is_branch;
            insn->is_call = x86_insn.is_call;
            insn->is_ret = x86_insn.is_ret;
            insn->is_conditional = x86_insn.is_conditional;
            insn->branch_target = x86_insn.branch_target;
            insn->reads_memory = x86_insn.reads_memory;
            insn->writes_memory = x86_insn.writes_memory;
            return len;
        }

        case E9_ARCH_ARM64: {
            E9A64Insn a64_insn;
            int len = e9_a64_disasm_one(dis->ctx.a64, code, size, address, &a64_insn);
            if (len != 4) return 0;

            insn->address = a64_insn.address;
            insn->length = 4;
            memcpy(insn->bytes, &a64_insn.encoding, 4);
            strncpy(insn->mnemonic, a64_insn.mnemonic, sizeof(insn->mnemonic) - 1);
            strncpy(insn->text, a64_insn.text, sizeof(insn->text) - 1);
            insn->is_branch = a64_insn.is_branch;
            insn->is_call = a64_insn.is_call;
            insn->is_ret = a64_insn.is_ret;
            insn->is_conditional = a64_insn.is_conditional;
            insn->branch_target = a64_insn.branch_target;
            insn->reads_memory = a64_insn.reads_memory;
            insn->writes_memory = a64_insn.writes_memory;
            return 4;
        }

        default:
            return 0;
    }
}

size_t e9_disasm_many(E9Disasm *dis, const uint8_t *code, size_t size,
                      uint64_t address, size_t count, E9Instruction **insns)
{
    if (!dis || !code || !insns) return 0;

    *insns = calloc(count, sizeof(E9Instruction));
    if (!*insns) return 0;

    size_t decoded = 0;
    size_t offset = 0;

    while (decoded < count && offset < size) {
        int len = e9_disasm_one(dis, code + offset, size - offset,
                                 address + offset, &(*insns)[decoded]);
        if (len <= 0) break;

        offset += len;
        decoded++;
    }

    return decoded;
}

void e9_insns_free(E9Instruction *insns, size_t count)
{
    (void)count;
    free(insns);
}

/*
 * ============================================================================
 * Entropy Analysis
 * ============================================================================
 */

double e9_entropy(const uint8_t *data, size_t size)
{
    if (!data || size == 0) return 0.0;

    size_t freq[256] = {0};
    for (size_t i = 0; i < size; i++) {
        freq[data[i]]++;
    }

    double entropy = 0.0;
    for (int i = 0; i < 256; i++) {
        if (freq[i] > 0) {
            double p = (double)freq[i] / size;
            entropy -= p * log2(p);
        }
    }

    return entropy;
}

E9EntropyResult *e9_entropy_analyze(const uint8_t *data, size_t size,
                                     size_t block_size)
{
    if (!data || size == 0 || block_size == 0) return NULL;

    E9EntropyResult *result = calloc(1, sizeof(E9EntropyResult));
    if (!result) return NULL;

    result->block_size = block_size;
    result->num_blocks = (size + block_size - 1) / block_size;
    result->values = calloc(result->num_blocks, sizeof(double));

    if (!result->values) {
        free(result);
        return NULL;
    }

    result->min_entropy = 8.0;
    result->max_entropy = 0.0;
    double sum = 0.0;

    size_t low_entropy_blocks = 0;
    size_t high_entropy_blocks = 0;

    for (size_t i = 0; i < result->num_blocks; i++) {
        size_t offset = i * block_size;
        size_t len = (offset + block_size > size) ? (size - offset) : block_size;

        double ent = e9_entropy(data + offset, len);
        result->values[i] = ent;

        if (ent < result->min_entropy) result->min_entropy = ent;
        if (ent > result->max_entropy) result->max_entropy = ent;
        sum += ent;

        if (ent < 1.0) low_entropy_blocks++;
        if (ent > 7.5) high_entropy_blocks++;
    }

    result->avg_entropy = sum / result->num_blocks;

    /* Detection heuristics */
    result->likely_compressed = (result->avg_entropy > 7.0);
    result->likely_encrypted = (result->avg_entropy > 7.9 &&
                                result->max_entropy - result->min_entropy < 0.2);
    result->has_padding = (low_entropy_blocks > 0);

    return result;
}

void e9_entropy_free(E9EntropyResult *result)
{
    if (!result) return;
    free(result->values);
    free(result);
}

/*
 * ============================================================================
 * String Extraction
 * ============================================================================
 */

static bool is_printable_ascii(uint8_t c)
{
    return c >= 0x20 && c < 0x7F;
}

static void classify_string(E9String *str)
{
    if (!str || !str->value) return;

    /* Path detection */
    if (str->value[0] == '/' ||
        (str->length > 2 && str->value[1] == ':' && str->value[2] == '\\')) {
        str->is_path = true;
    }

    /* URL detection */
    if (strncmp(str->value, "http://", 7) == 0 ||
        strncmp(str->value, "https://", 8) == 0 ||
        strncmp(str->value, "ftp://", 6) == 0) {
        str->is_url = true;
    }

    /* Simple IP detection */
    int dots = 0;
    bool all_digits_dots = true;
    for (size_t i = 0; i < str->length && all_digits_dots; i++) {
        char c = str->value[i];
        if (c == '.') dots++;
        else if (!isdigit(c)) all_digits_dots = false;
    }
    if (all_digits_dots && dots == 3) {
        str->is_ip_addr = true;
    }

    /* Email detection */
    if (strchr(str->value, '@') != NULL && strchr(str->value, '.') != NULL) {
        str->is_email = true;
    }

    /* Function name heuristic */
    if (str->length > 2 && str->length < 64) {
        bool looks_like_func = true;
        for (size_t i = 0; i < str->length && looks_like_func; i++) {
            char c = str->value[i];
            if (!isalnum(c) && c != '_') {
                looks_like_func = false;
            }
        }
        if (looks_like_func) {
            str->is_function_name = true;
        }
    }
}

E9String *e9_strings_extract(const uint8_t *data, size_t size,
                              size_t min_len, uint32_t *count)
{
    if (!data || size == 0 || !count) {
        if (count) *count = 0;
        return NULL;
    }

    if (min_len < 4) min_len = 4;

    /* First pass: count strings */
    size_t num_strings = 0;
    size_t run_start = 0;
    size_t run_len = 0;

    for (size_t i = 0; i < size; i++) {
        if (is_printable_ascii(data[i])) {
            if (run_len == 0) run_start = i;
            run_len++;
        } else {
            if (run_len >= min_len) num_strings++;
            run_len = 0;
        }
    }
    if (run_len >= min_len) num_strings++;

    if (num_strings == 0) {
        *count = 0;
        return NULL;
    }

    /* Allocate */
    E9String *strings = calloc(num_strings, sizeof(E9String));
    if (!strings) {
        *count = 0;
        return NULL;
    }

    /* Second pass: extract */
    size_t idx = 0;
    run_len = 0;

    for (size_t i = 0; i < size; i++) {
        if (is_printable_ascii(data[i])) {
            if (run_len == 0) run_start = i;
            run_len++;
        } else {
            if (run_len >= min_len && idx < num_strings) {
                strings[idx].offset = run_start;
                strings[idx].length = run_len;
                strings[idx].value = malloc(run_len + 1);
                if (strings[idx].value) {
                    memcpy(strings[idx].value, data + run_start, run_len);
                    strings[idx].value[run_len] = '\0';
                    strings[idx].encoding = E9_STR_ASCII;
                    classify_string(&strings[idx]);
                }
                idx++;
            }
            run_len = 0;
        }
    }
    if (run_len >= min_len && idx < num_strings) {
        strings[idx].offset = run_start;
        strings[idx].length = run_len;
        strings[idx].value = malloc(run_len + 1);
        if (strings[idx].value) {
            memcpy(strings[idx].value, data + run_start, run_len);
            strings[idx].value[run_len] = '\0';
            strings[idx].encoding = E9_STR_ASCII;
            classify_string(&strings[idx]);
        }
        idx++;
    }

    *count = idx;
    return strings;
}

void e9_strings_free(E9String *strings, uint32_t count)
{
    if (!strings) return;
    for (uint32_t i = 0; i < count; i++) {
        free(strings[i].value);
    }
    free(strings);
}

/*
 * ============================================================================
 * Compression Detection
 * ============================================================================
 */

E9CompressType e9_detect_compression(const uint8_t *data, size_t size)
{
    if (!data || size < 2) return E9_COMPRESS_NONE;

    /* gzip */
    if (size >= 3 && data[0] == 0x1F && data[1] == 0x8B && data[2] == 0x08) {
        return E9_COMPRESS_GZIP;
    }

    /* zlib */
    if (size >= 2 && data[0] == 0x78 &&
        (data[1] == 0x01 || data[1] == 0x5E || data[1] == 0x9C || data[1] == 0xDA)) {
        return E9_COMPRESS_ZLIB;
    }

    /* bzip2 */
    if (size >= 3 && data[0] == 'B' && data[1] == 'Z' && data[2] == 'h') {
        return E9_COMPRESS_BZIP2;
    }

    /* XZ */
    if (size >= 6 && memcmp(data, "\xFD" "7zXZ\x00", 6) == 0) {
        return E9_COMPRESS_XZ;
    }

    /* LZMA */
    if (size >= 3 && data[0] == 0x5D && data[1] == 0x00 && data[2] == 0x00) {
        return E9_COMPRESS_LZMA;
    }

    /* Zstandard */
    if (size >= 4 && memcmp(data, "\x28\xB5\x2F\xFD", 4) == 0) {
        return E9_COMPRESS_ZSTD;
    }

    /* LZ4 */
    if (size >= 4 && memcmp(data, "\x04\x22\x4D\x18", 4) == 0) {
        return E9_COMPRESS_LZ4;
    }

    return E9_COMPRESS_NONE;
}

const char *e9_compress_name(E9CompressType type)
{
    switch (type) {
        case E9_COMPRESS_NONE: return "none";
        case E9_COMPRESS_ZLIB: return "zlib";
        case E9_COMPRESS_GZIP: return "gzip";
        case E9_COMPRESS_DEFLATE: return "deflate";
        case E9_COMPRESS_BZIP2: return "bzip2";
        case E9_COMPRESS_LZMA: return "lzma";
        case E9_COMPRESS_XZ: return "xz";
        case E9_COMPRESS_ZSTD: return "zstd";
        case E9_COMPRESS_LZ4: return "lz4";
        case E9_COMPRESS_LZO: return "lzo";
        default: return "unknown";
    }
}

/*
 * ============================================================================
 * CRC32 (IEEE polynomial)
 * ============================================================================
 */

static uint32_t crc32_table[256];
static bool crc32_table_init = false;

static void crc32_init_table(void)
{
    if (crc32_table_init) return;

    for (uint32_t i = 0; i < 256; i++) {
        uint32_t crc = i;
        for (int j = 0; j < 8; j++) {
            if (crc & 1) {
                crc = (crc >> 1) ^ 0xEDB88320;
            } else {
                crc >>= 1;
            }
        }
        crc32_table[i] = crc;
    }
    crc32_table_init = true;
}

uint32_t e9_crc32(const uint8_t *data, size_t size)
{
    return e9_crc32_update(0, data, size);
}

uint32_t e9_crc32_update(uint32_t crc, const uint8_t *data, size_t size)
{
    if (!data) return crc;

    crc32_init_table();

    crc = ~crc;
    for (size_t i = 0; i < size; i++) {
        crc = crc32_table[(crc ^ data[i]) & 0xFF] ^ (crc >> 8);
    }
    return ~crc;
}

/*
 * ============================================================================
 * Hash Utilities
 * ============================================================================
 */

void e9_hash_to_hex(const uint8_t *hash, size_t len, char *out)
{
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[i * 2] = hex[hash[i] >> 4];
        out[i * 2 + 1] = hex[hash[i] & 0x0F];
    }
    out[len * 2] = '\0';
}

/* Minimal MD5 and SHA256 implementations would go here */
/* For now, provide stubs */

void e9_md5(const uint8_t *data, size_t size, uint8_t out[16])
{
    /* Stub - TODO: implement */
    (void)data;
    (void)size;
    memset(out, 0, 16);
}

void e9_sha256(const uint8_t *data, size_t size, uint8_t out[32])
{
    /* Stub - TODO: implement */
    (void)data;
    (void)size;
    memset(out, 0, 32);
}

/*
 * ============================================================================
 * Hex Dump
 * ============================================================================
 */

void e9_hexdump(const uint8_t *data, size_t size, uint64_t base_addr,
                char *out, size_t out_size)
{
    if (!data || !out || out_size == 0) return;

    char *p = out;
    char *end = out + out_size - 1;

    for (size_t i = 0; i < size && p < end - 80; i += 16) {
        /* Address */
        p += snprintf(p, end - p, "%08llx  ",
                      (unsigned long long)(base_addr + i));

        /* Hex bytes */
        for (size_t j = 0; j < 16; j++) {
            if (i + j < size) {
                p += snprintf(p, end - p, "%02x ", data[i + j]);
            } else {
                p += snprintf(p, end - p, "   ");
            }
            if (j == 7) p += snprintf(p, end - p, " ");
        }

        /* ASCII */
        p += snprintf(p, end - p, " |");
        for (size_t j = 0; j < 16 && i + j < size; j++) {
            char c = data[i + j];
            p += snprintf(p, end - p, "%c", (c >= 0x20 && c < 0x7F) ? c : '.');
        }
        p += snprintf(p, end - p, "|\n");
    }

    *p = '\0';
}

/*
 * ============================================================================
 * Disassembly Dump
 * ============================================================================
 */

void e9_disasm_dump(E9Disasm *dis, const uint8_t *code, size_t size,
                    uint64_t address, char *out, size_t out_size)
{
    if (!dis || !code || !out || out_size == 0) return;

    char *p = out;
    char *end = out + out_size - 1;
    size_t offset = 0;

    while (offset < size && p < end - 100) {
        E9Instruction insn;
        int len = e9_disasm_one(dis, code + offset, size - offset,
                                 address + offset, &insn);
        if (len <= 0) break;

        /* Address */
        p += snprintf(p, end - p, "%08llx:  ",
                      (unsigned long long)(address + offset));

        /* Hex bytes */
        for (int i = 0; i < len && i < 8; i++) {
            p += snprintf(p, end - p, "%02x ", code[offset + i]);
        }
        for (int i = len; i < 8; i++) {
            p += snprintf(p, end - p, "   ");
        }

        /* Disassembly */
        p += snprintf(p, end - p, " %s\n", insn.text);

        offset += len;
    }

    *p = '\0';
}

/*
 * ============================================================================
 * Info Printing
 * ============================================================================
 */

void e9_info_print(const E9BinaryInfo *info, char *out, size_t out_size)
{
    if (!info || !out || out_size == 0) return;

    char *p = out;
    char *end = out + out_size - 1;

    p += snprintf(p, end - p, "Binary Analysis Report\n");
    p += snprintf(p, end - p, "======================\n\n");
    p += snprintf(p, end - p, "Format: %s\n", info->description);

    const char *arch_names[] = {
        "Unknown", "x86", "x86-64", "ARM", "ARM64", "MIPS", "RISC-V", "WebAssembly"
    };
    p += snprintf(p, end - p, "Architecture: %s\n",
                  arch_names[info->arch < 8 ? info->arch : 0]);

    p += snprintf(p, end - p, "Bits: %d\n", info->is_64bit ? 64 : 32);
    p += snprintf(p, end - p, "Endianness: %s\n",
                  info->is_little_endian ? "little" : "big");

    if (info->entry_point) {
        p += snprintf(p, end - p, "Entry point: 0x%llx\n",
                      (unsigned long long)info->entry_point);
    }

    if (info->is_polyglot) {
        p += snprintf(p, end - p, "\n*** POLYGLOT FILE DETECTED ***\n");
    }

    if (info->num_signatures > 0) {
        p += snprintf(p, end - p, "\nEmbedded signatures found: %u\n",
                      info->num_signatures);
        for (uint32_t i = 0; i < info->num_signatures && i < 10; i++) {
            p += snprintf(p, end - p, "  [0x%zx] %s\n",
                          info->signatures[i].offset,
                          info->signatures[i].description);
        }
    }

    *p = '\0';
}
