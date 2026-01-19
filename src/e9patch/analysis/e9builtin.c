/*
 * e9builtin.c
 * Self-Contained Analysis Engine Implementation
 *
 * Zero external dependencies - everything runs standalone in e9studio.com
 *
 * Copyright (C) 2024 E9Patch Contributors
 * License: GPLv3+
 */

#include "e9builtin.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <math.h>

/*
 * ============================================================================
 * SIGNATURE DATABASE
 * ============================================================================
 */

static const E9Signature g_signatures[] = {
    /* Executables */
    {"ELF", "ELF executable", (const uint8_t*)"\x7f""ELF", 4, 0, 1},
    {"PE", "PE executable", (const uint8_t*)"MZ", 2, 0, 2},
    {"Mach-O 64 LE", "Mach-O 64-bit", (const uint8_t*)"\xcf\xfa\xed\xfe", 4, 0, 3},
    {"Mach-O 64 BE", "Mach-O 64-bit BE", (const uint8_t*)"\xfe\xed\xfa\xcf", 4, 0, 3},
    {"Shell", "Shell script", (const uint8_t*)"#!/", 3, 0, 4},

    /* Archives */
    {"ZIP", "ZIP archive", (const uint8_t*)"PK\x03\x04", 4, -1, 10},
    {"ZIP empty", "ZIP (empty)", (const uint8_t*)"PK\x05\x06", 4, -1, 10},
    {"gzip", "gzip compressed", (const uint8_t*)"\x1f\x8b", 2, -1, 11},
    {"bzip2", "bzip2 compressed", (const uint8_t*)"BZh", 3, -1, 12},
    {"XZ", "XZ compressed", (const uint8_t*)"\xfd""7zXZ\x00", 6, -1, 13},
    {"Zstd", "Zstandard", (const uint8_t*)"\x28\xb5\x2f\xfd", 4, -1, 14},
    {"LZ4", "LZ4 compressed", (const uint8_t*)"\x04\x22\x4d\x18", 4, -1, 15},
    {"7z", "7-Zip archive", (const uint8_t*)"7z\xbc\xaf\x27\x1c", 6, -1, 16},
    {"RAR", "RAR archive", (const uint8_t*)"Rar!\x1a\x07", 6, -1, 17},
    {"tar", "tar archive", (const uint8_t*)"ustar", 5, 257, 18},
    {"ar", "ar archive", (const uint8_t*)"!<arch>\n", 8, 0, 19},
    {"cpio", "cpio archive", (const uint8_t*)"070701", 6, -1, 20},

    /* Filesystems */
    {"SquashFS", "SquashFS", (const uint8_t*)"hsqs", 4, -1, 30},
    {"CramFS", "CramFS", (const uint8_t*)"\x45\x3d\xcd\x28", 4, -1, 31},
    {"ext", "ext2/3/4", (const uint8_t*)"\x53\xef", 2, 0x438, 32},

    /* Images */
    {"PNG", "PNG image", (const uint8_t*)"\x89PNG\r\n\x1a\n", 8, 0, 40},
    {"JPEG", "JPEG image", (const uint8_t*)"\xff\xd8\xff", 3, 0, 41},
    {"GIF", "GIF image", (const uint8_t*)"GIF8", 4, 0, 42},
    {"BMP", "BMP image", (const uint8_t*)"BM", 2, 0, 43},
    {"PDF", "PDF document", (const uint8_t*)"%PDF-", 5, 0, 44},

    /* Bytecode */
    {"WASM", "WebAssembly", (const uint8_t*)"\x00""asm", 4, 0, 50},
    {"Java", "Java class", (const uint8_t*)"\xca\xfe\xba\xbe", 4, 0, 51},
    {"DEX", "Android DEX", (const uint8_t*)"dex\n", 4, 0, 52},

    /* Crypto */
    {"PEM", "PEM encoded", (const uint8_t*)"-----BEGIN ", 11, -1, 60},

    /* Packers (common signatures) */
    {"UPX", "UPX packed", (const uint8_t*)"UPX!", 4, -1, 70},

    {NULL, NULL, NULL, 0, 0, 0}  /* End marker */
};

const E9Signature *e9_builtin_signatures(size_t *count)
{
    if (count) {
        size_t n = 0;
        while (g_signatures[n].magic) n++;
        *count = n;
    }
    return g_signatures;
}

E9SignatureHit *e9_builtin_scan(const uint8_t *data, size_t size, size_t *count)
{
    if (!data || !count) return NULL;
    *count = 0;

    size_t capacity = 64;
    E9SignatureHit *hits = malloc(capacity * sizeof(E9SignatureHit));
    if (!hits) return NULL;

    for (size_t i = 0; g_signatures[i].magic; i++) {
        const E9Signature *sig = &g_signatures[i];

        if (sig->offset >= 0) {
            /* Fixed offset */
            if ((size_t)sig->offset + sig->magic_len <= size &&
                memcmp(data + sig->offset, sig->magic, sig->magic_len) == 0) {

                if (*count >= capacity) {
                    capacity *= 2;
                    hits = realloc(hits, capacity * sizeof(E9SignatureHit));
                }
                hits[*count].offset = sig->offset;
                hits[*count].format_id = sig->format_id;
                hits[*count].name = sig->name;
                hits[*count].description = sig->description;
                (*count)++;
            }
        } else {
            /* Scan for signature */
            for (size_t off = 0; off + sig->magic_len <= size; off++) {
                if (memcmp(data + off, sig->magic, sig->magic_len) == 0) {
                    if (*count >= capacity) {
                        capacity *= 2;
                        hits = realloc(hits, capacity * sizeof(E9SignatureHit));
                    }
                    hits[*count].offset = off;
                    hits[*count].format_id = sig->format_id;
                    hits[*count].name = sig->name;
                    hits[*count].description = sig->description;
                    (*count)++;

                    /* Don't scan for more of same sig */
                    break;
                }
            }
        }
    }

    return hits;
}

void e9_builtin_scan_free(E9SignatureHit *hits)
{
    free(hits);
}

/*
 * ============================================================================
 * DISASSEMBLY (x86-64)
 * ============================================================================
 */

/* Minimal x86-64 instruction length decoder */
static int x64_insn_len(const uint8_t *code, size_t max)
{
    if (max == 0) return 0;

    size_t pos = 0;

    /* Prefixes */
    while (pos < max) {
        uint8_t b = code[pos];
        if ((b >= 0x40 && b <= 0x4f) ||  /* REX */
            b == 0x66 || b == 0x67 || b == 0xf0 ||
            b == 0xf2 || b == 0xf3 ||
            b == 0x2e || b == 0x36 || b == 0x3e ||
            b == 0x26 || b == 0x64 || b == 0x65) {
            pos++;
        } else {
            break;
        }
    }
    if (pos >= max) return (int)pos;

    uint8_t op = code[pos++];

    /* Two-byte opcode */
    if (op == 0x0f && pos < max) {
        op = code[pos++];
        /* Most 0F opcodes have ModRM */
        if (pos < max) {
            uint8_t modrm = code[pos++];
            uint8_t mod = modrm >> 6;
            uint8_t rm = modrm & 7;

            if (mod != 3 && rm == 4 && pos < max) pos++;  /* SIB */
            if (mod == 1) pos++;
            else if (mod == 2 || (mod == 0 && rm == 5)) pos += 4;
        }

        /* Jcc near: 4-byte displacement */
        if (op >= 0x80 && op <= 0x8f) pos += 4;

        return (int)(pos > max ? max : pos);
    }

    /* Single-byte opcodes */
    switch (op) {
        case 0x90: case 0xc3: case 0xcb: case 0xcc:
        case 0xf4: case 0xf5: case 0xfc: case 0xfd:
            return (int)pos;

        case 0xc2: case 0xca:
            return (int)(pos + 2);

        case 0xe8: case 0xe9:
            return (int)(pos + 4);

        case 0xeb:
        case 0x70: case 0x71: case 0x72: case 0x73:
        case 0x74: case 0x75: case 0x76: case 0x77:
        case 0x78: case 0x79: case 0x7a: case 0x7b:
        case 0x7c: case 0x7d: case 0x7e: case 0x7f:
            return (int)(pos + 1);

        case 0xb8: case 0xb9: case 0xba: case 0xbb:
        case 0xbc: case 0xbd: case 0xbe: case 0xbf:
            return (int)(pos + (code[0] >= 0x48 ? 8 : 4));

        default:
            break;
    }

    /* Instructions with ModRM */
    if (pos < max) {
        uint8_t modrm = code[pos++];
        uint8_t mod = modrm >> 6;
        uint8_t rm = modrm & 7;

        if (mod != 3 && rm == 4 && pos < max) pos++;  /* SIB */
        if (mod == 1) pos++;
        else if (mod == 2 || (mod == 0 && rm == 5)) pos += 4;

        /* Immediate */
        if ((op >= 0x80 && op <= 0x83) || op == 0xc7 || op == 0xc6) {
            if (op == 0x81 || op == 0xc7) pos += 4;
            else pos++;
        }
    }

    return (int)(pos > max ? max : pos);
}

/* Simple x86-64 mnemonic decoder */
static void x64_decode(const uint8_t *code, int len, uint64_t addr,
                       E9DisasmInsn *out)
{
    out->address = addr;
    out->size = len;
    if (len > 15) len = 15;
    memcpy(out->bytes, code, len);

    out->is_branch = false;
    out->is_call = false;
    out->is_ret = false;
    out->branch_target = 0;

    /* Skip prefixes */
    int pos = 0;
    while (pos < len && ((code[pos] >= 0x40 && code[pos] <= 0x4f) ||
           code[pos] == 0x66 || code[pos] == 0x67 ||
           code[pos] == 0xf2 || code[pos] == 0xf3)) {
        pos++;
    }
    if (pos >= len) {
        strcpy(out->mnemonic, "???");
        out->operands[0] = '\0';
        return;
    }

    uint8_t op = code[pos];

    switch (op) {
        case 0xc3:
            strcpy(out->mnemonic, "ret");
            out->operands[0] = '\0';
            out->is_ret = true;
            break;

        case 0xe8:
            strcpy(out->mnemonic, "call");
            out->is_call = true;
            if (pos + 5 <= len) {
                int32_t rel = *(int32_t *)(code + pos + 1);
                out->branch_target = addr + len + rel;
                snprintf(out->operands, sizeof(out->operands),
                         "0x%lx", out->branch_target);
            }
            break;

        case 0xe9:
            strcpy(out->mnemonic, "jmp");
            out->is_branch = true;
            if (pos + 5 <= len) {
                int32_t rel = *(int32_t *)(code + pos + 1);
                out->branch_target = addr + len + rel;
                snprintf(out->operands, sizeof(out->operands),
                         "0x%lx", out->branch_target);
            }
            break;

        case 0xeb:
            strcpy(out->mnemonic, "jmp");
            out->is_branch = true;
            if (pos + 2 <= len) {
                int8_t rel = (int8_t)code[pos + 1];
                out->branch_target = addr + len + rel;
                snprintf(out->operands, sizeof(out->operands),
                         "0x%lx", out->branch_target);
            }
            break;

        case 0x90:
            strcpy(out->mnemonic, "nop");
            out->operands[0] = '\0';
            break;

        case 0xcc:
            strcpy(out->mnemonic, "int3");
            out->operands[0] = '\0';
            break;

        case 0x55:
            strcpy(out->mnemonic, "push");
            strcpy(out->operands, "rbp");
            break;

        case 0x5d:
            strcpy(out->mnemonic, "pop");
            strcpy(out->operands, "rbp");
            break;

        case 0x74:
            strcpy(out->mnemonic, "jz");
            out->is_branch = true;
            if (pos + 2 <= len) {
                int8_t rel = (int8_t)code[pos + 1];
                out->branch_target = addr + len + rel;
                snprintf(out->operands, sizeof(out->operands),
                         "0x%lx", out->branch_target);
            }
            break;

        case 0x75:
            strcpy(out->mnemonic, "jnz");
            out->is_branch = true;
            if (pos + 2 <= len) {
                int8_t rel = (int8_t)code[pos + 1];
                out->branch_target = addr + len + rel;
                snprintf(out->operands, sizeof(out->operands),
                         "0x%lx", out->branch_target);
            }
            break;

        default:
            snprintf(out->mnemonic, sizeof(out->mnemonic), "op%02x", op);
            out->operands[0] = '\0';
            break;
    }
}

int e9_builtin_disasm_one(const uint8_t *code, size_t max_len,
                          uint64_t addr, int arch, E9DisasmInsn *out)
{
    if (!code || !out || max_len == 0) return -1;

    memset(out, 0, sizeof(*out));

    if (arch == E9_ARCH_X86_64) {
        int len = x64_insn_len(code, max_len);
        if (len <= 0) return -1;
        x64_decode(code, len, addr, out);
        return len;
    }
    else if (arch == E9_ARCH_AARCH64) {
        if (max_len < 4) return -1;
        out->address = addr;
        out->size = 4;
        memcpy(out->bytes, code, 4);

        uint32_t insn = *(uint32_t *)code;

        /* BL */
        if ((insn & 0xfc000000) == 0x94000000) {
            strcpy(out->mnemonic, "bl");
            out->is_call = true;
            int32_t imm = insn & 0x03ffffff;
            if (imm & 0x02000000) imm |= 0xfc000000;
            out->branch_target = addr + (imm << 2);
            snprintf(out->operands, sizeof(out->operands),
                     "0x%lx", out->branch_target);
        }
        /* B */
        else if ((insn & 0xfc000000) == 0x14000000) {
            strcpy(out->mnemonic, "b");
            out->is_branch = true;
            int32_t imm = insn & 0x03ffffff;
            if (imm & 0x02000000) imm |= 0xfc000000;
            out->branch_target = addr + (imm << 2);
            snprintf(out->operands, sizeof(out->operands),
                     "0x%lx", out->branch_target);
        }
        /* RET */
        else if ((insn & 0xfffffc1f) == 0xd65f0000) {
            strcpy(out->mnemonic, "ret");
            out->is_ret = true;
            out->operands[0] = '\0';
        }
        /* NOP */
        else if (insn == 0xd503201f) {
            strcpy(out->mnemonic, "nop");
            out->operands[0] = '\0';
        }
        else {
            snprintf(out->mnemonic, sizeof(out->mnemonic), ".word");
            snprintf(out->operands, sizeof(out->operands), "0x%08x", insn);
        }

        return 4;
    }

    return -1;
}

E9DisasmInsn *e9_builtin_disasm(const uint8_t *code, size_t size,
                                 uint64_t addr, int arch, size_t max_insns,
                                 size_t *out_count)
{
    if (!code || !out_count) return NULL;
    *out_count = 0;

    size_t capacity = max_insns ? max_insns : 256;
    E9DisasmInsn *insns = malloc(capacity * sizeof(E9DisasmInsn));
    if (!insns) return NULL;

    size_t off = 0;
    while (off < size && (max_insns == 0 || *out_count < max_insns)) {
        E9DisasmInsn *insn = &insns[*out_count];
        int len = e9_builtin_disasm_one(code + off, size - off,
                                         addr + off, arch, insn);
        if (len <= 0) break;

        (*out_count)++;
        off += len;

        if (*out_count >= capacity) {
            capacity *= 2;
            insns = realloc(insns, capacity * sizeof(E9DisasmInsn));
        }
    }

    return insns;
}

void e9_builtin_disasm_free(E9DisasmInsn *insns)
{
    free(insns);
}

int e9_builtin_disasm_fmt(E9DisasmInsn *insn, char *buf, size_t buf_size)
{
    if (!insn || !buf) return -1;

    char bytes[48];
    size_t pos = 0;
    for (int i = 0; i < insn->size && i < 8; i++) {
        pos += snprintf(bytes + pos, sizeof(bytes) - pos, "%02x ", insn->bytes[i]);
    }

    return snprintf(buf, buf_size, "%016lx: %-24s %-8s %s",
                    insn->address, bytes, insn->mnemonic, insn->operands);
}

/*
 * ============================================================================
 * ENTROPY ANALYSIS
 * ============================================================================
 */

E9EntropyInfo e9_builtin_entropy(const uint8_t *data, size_t size)
{
    E9EntropyInfo info = {0};
    if (!data || size == 0) return info;

    uint64_t freq[256] = {0};
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
    info.entropy = entropy;

    double expected = (double)size / 256.0;
    double chi = 0.0;
    for (int i = 0; i < 256; i++) {
        double d = freq[i] - expected;
        chi += (d * d) / expected;
    }
    info.chi_square = chi;

    info.likely_compressed = (entropy > 7.5);
    info.likely_encrypted = (entropy > 7.9 && chi < 300);
    info.likely_random = (entropy > 7.95);

    size_t printable = 0;
    for (size_t i = 0; i < size; i++) {
        if ((data[i] >= 32 && data[i] < 127) ||
            data[i] == '\n' || data[i] == '\r' || data[i] == '\t') {
            printable++;
        }
    }
    info.likely_text = ((double)printable / size > 0.85);

    return info;
}

double *e9_builtin_entropy_map(const uint8_t *data, size_t size,
                                size_t block_size, size_t *num_blocks)
{
    if (!data || !num_blocks || block_size == 0) return NULL;

    size_t count = (size + block_size - 1) / block_size;
    double *map = malloc(count * sizeof(double));
    if (!map) return NULL;

    for (size_t i = 0; i < count; i++) {
        size_t off = i * block_size;
        size_t len = (off + block_size <= size) ? block_size : size - off;
        E9EntropyInfo e = e9_builtin_entropy(data + off, len);
        map[i] = e.entropy;
    }

    *num_blocks = count;
    return map;
}

/*
 * ============================================================================
 * POLYGLOT DETECTION
 * ============================================================================
 */

E9PolyglotInfo e9_builtin_polyglot(const uint8_t *data, size_t size)
{
    E9PolyglotInfo info = {0};
    if (!data || size < 4) return info;

    /* Check ELF */
    for (size_t i = 0; i + 4 <= size; i++) {
        if (data[i] == 0x7f && data[i+1] == 'E' &&
            data[i+2] == 'L' && data[i+3] == 'F') {
            info.has_elf = true;
            info.elf_offset = i;
            break;
        }
    }

    /* Check PE (MZ at 0) */
    if (data[0] == 'M' && data[1] == 'Z') {
        info.has_pe = true;
        info.pe_offset = 0;
    }

    /* Check Mach-O */
    for (size_t i = 0; i + 4 <= size; i += 4) {
        uint32_t magic = *(uint32_t *)(data + i);
        if (magic == 0xfeedfacf || magic == 0xcffaedfe) {
            info.has_macho = true;
            info.macho_offset = i;
            break;
        }
    }

    /* Check ZIP */
    for (size_t i = 0; i + 4 <= size; i++) {
        if (data[i] == 'P' && data[i+1] == 'K' &&
            (data[i+2] == 0x03 || data[i+2] == 0x05)) {
            info.has_zip = true;
            info.zip_offset = i;
            break;
        }
    }

    /* Check shell script */
    for (size_t i = 0; i + 2 <= size && i < 512; i++) {
        if (data[i] == '#' && data[i+1] == '!') {
            info.has_shell = true;
            info.shell_offset = i;
            break;
        }
    }

    /* Determine if polyglot */
    int formats = info.has_elf + info.has_pe + info.has_macho +
                  info.has_zip + info.has_shell;
    info.is_polyglot = (formats > 1);

    /* APE detection: has MZ + (ELF or shell) + ZIP at end */
    if (info.has_pe && (info.has_elf || info.has_shell) && info.has_zip) {
        info.is_ape = true;
    }

    return info;
}

/*
 * ============================================================================
 * PACKER DETECTION
 * ============================================================================
 */

E9PackerInfo e9_builtin_packer_detect(const uint8_t *data, size_t size)
{
    E9PackerInfo info = {0};
    if (!data || size < 64) return info;

    /* UPX detection */
    for (size_t i = 0; i + 4 <= size; i++) {
        if (memcmp(data + i, "UPX!", 4) == 0) {
            info.name = "UPX";
            info.is_packed = true;
            info.confidence = 0.95;

            /* Try to find version */
            if (i >= 4 && data[i-4] >= '0' && data[i-4] <= '9') {
                static char ver[8];
                snprintf(ver, sizeof(ver), "%c.%c%c",
                         data[i-4], data[i-3], data[i-2]);
                info.version = ver;
            }
            return info;
        }
    }

    /* ASPack detection */
    for (size_t i = 0; i + 6 <= size; i++) {
        if (memcmp(data + i, "ASPack", 6) == 0) {
            info.name = "ASPack";
            info.is_packed = true;
            info.confidence = 0.9;
            return info;
        }
    }

    /* Check for high entropy sections (generic packer indicator) */
    if (data[0] == 'M' && data[1] == 'Z' && size > 0x200) {
        E9EntropyInfo ent = e9_builtin_entropy(data + 0x200,
                                                size > 0x1000 ? 0xe00 : size - 0x200);
        if (ent.entropy > 7.5) {
            info.name = "Unknown packer";
            info.is_packed = true;
            info.confidence = 0.6;
        }
    }

    return info;
}

/*
 * ============================================================================
 * STRING EXTRACTION
 * ============================================================================
 */

E9String *e9_builtin_strings(const uint8_t *data, size_t size,
                              size_t min_len, size_t *count)
{
    if (!data || !count) return NULL;
    *count = 0;

    if (min_len == 0) min_len = 4;

    size_t capacity = 256;
    E9String *strings = malloc(capacity * sizeof(E9String));
    if (!strings) return NULL;

    size_t start = 0;
    bool in_string = false;

    for (size_t i = 0; i <= size; i++) {
        bool is_printable = (i < size) &&
            ((data[i] >= 32 && data[i] < 127) ||
             data[i] == '\t');

        if (is_printable && !in_string) {
            start = i;
            in_string = true;
        }
        else if (!is_printable && in_string) {
            size_t len = i - start;
            if (len >= min_len) {
                if (*count >= capacity) {
                    capacity *= 2;
                    strings = realloc(strings, capacity * sizeof(E9String));
                }

                E9String *s = &strings[*count];
                s->offset = start;
                s->length = len;
                s->value = malloc(len + 1);
                memcpy(s->value, data + start, len);
                s->value[len] = '\0';
                s->is_wide = false;
                s->is_encrypted = false;

                (*count)++;
            }
            in_string = false;
        }
    }

    return strings;
}

void e9_builtin_strings_free(E9String *strings, size_t count)
{
    if (strings) {
        for (size_t i = 0; i < count; i++) {
            free(strings[i].value);
        }
        free(strings);
    }
}

/*
 * ============================================================================
 * ELF PARSING
 * ============================================================================
 */

int e9_builtin_elf_parse(const uint8_t *data, size_t size, E9ElfHeader *hdr)
{
    if (!data || !hdr || size < 64) return -1;
    if (memcmp(data, "\x7f""ELF", 4) != 0) return -1;

    hdr->elf_class = data[4];
    hdr->endian = data[5];
    hdr->machine = *(uint16_t *)(data + 18);

    if (hdr->elf_class == 2) {  /* 64-bit */
        hdr->entry = *(uint64_t *)(data + 24);
        hdr->phoff = *(uint64_t *)(data + 32);
        hdr->shoff = *(uint64_t *)(data + 40);
        hdr->phnum = *(uint16_t *)(data + 56);
        hdr->shnum = *(uint16_t *)(data + 60);
        hdr->shstrndx = *(uint16_t *)(data + 62);
    } else {
        hdr->entry = *(uint32_t *)(data + 24);
        hdr->phoff = *(uint32_t *)(data + 28);
        hdr->shoff = *(uint32_t *)(data + 32);
        hdr->phnum = *(uint16_t *)(data + 44);
        hdr->shnum = *(uint16_t *)(data + 48);
        hdr->shstrndx = *(uint16_t *)(data + 50);
    }

    return 0;
}

/*
 * ============================================================================
 * ZIP PARSING (for ZipOS)
 * ============================================================================
 */

E9ZipArchive *e9_builtin_zip_open(const uint8_t *data, size_t size)
{
    if (!data || size < 22) return NULL;

    /* Find end of central directory */
    uint64_t eocd = 0;
    for (size_t i = size - 22; i > 0 && i > size - 65536; i--) {
        if (data[i] == 'P' && data[i+1] == 'K' &&
            data[i+2] == 0x05 && data[i+3] == 0x06) {
            eocd = i;
            break;
        }
    }
    if (eocd == 0) return NULL;

    E9ZipArchive *zip = calloc(1, sizeof(E9ZipArchive));
    if (!zip) return NULL;

    uint16_t num_entries = *(uint16_t *)(data + eocd + 10);
    uint32_t cd_size = *(uint32_t *)(data + eocd + 12);
    uint32_t cd_offset = *(uint32_t *)(data + eocd + 16);

    zip->central_dir_offset = cd_offset;
    zip->central_dir_size = cd_size;
    zip->num_entries = num_entries;

    if (num_entries > 0) {
        zip->entries = calloc(num_entries, sizeof(E9ZipEntry));

        uint64_t pos = cd_offset;
        for (size_t i = 0; i < num_entries && pos + 46 <= size; i++) {
            if (data[pos] != 'P' || data[pos+1] != 'K' ||
                data[pos+2] != 0x01 || data[pos+3] != 0x02) break;

            E9ZipEntry *e = &zip->entries[i];
            e->method = *(uint16_t *)(data + pos + 10);
            e->crc32 = *(uint32_t *)(data + pos + 16);
            e->comp_size = *(uint32_t *)(data + pos + 20);
            e->uncomp_size = *(uint32_t *)(data + pos + 24);
            uint16_t name_len = *(uint16_t *)(data + pos + 28);
            uint16_t extra_len = *(uint16_t *)(data + pos + 30);
            uint16_t comment_len = *(uint16_t *)(data + pos + 32);
            e->offset = *(uint32_t *)(data + pos + 42);

            if (name_len > 0 && pos + 46 + name_len <= size) {
                size_t copy_len = name_len < 255 ? name_len : 255;
                memcpy(e->name, data + pos + 46, copy_len);
            }

            pos += 46 + name_len + extra_len + comment_len;
        }
    }

    return zip;
}

void e9_builtin_zip_close(E9ZipArchive *zip)
{
    if (zip) {
        free(zip->entries);
        free(zip);
    }
}

/*
 * ============================================================================
 * FULL ANALYSIS
 * ============================================================================
 */

E9AnalysisResult *e9_builtin_analyze(const uint8_t *data, size_t size)
{
    if (!data) return NULL;

    E9AnalysisResult *result = calloc(1, sizeof(E9AnalysisResult));
    if (!result) return NULL;

    result->size = size;

    /* Signature scan */
    result->signatures = e9_builtin_scan(data, size, &result->num_signatures);

    /* Polyglot detection */
    result->polyglot = e9_builtin_polyglot(data, size);

    /* Packer detection */
    result->packer = e9_builtin_packer_detect(data, size);

    /* Entropy */
    result->entropy = e9_builtin_entropy(data, size);

    /* String extraction */
    result->strings = e9_builtin_strings(data, size, 6, &result->num_strings);

    /* Format-specific parsing */
    if (result->polyglot.has_elf) {
        e9_builtin_elf_parse(data + result->polyglot.elf_offset,
                             size - result->polyglot.elf_offset,
                             &result->parsed.elf.header);
    }

    return result;
}

void e9_builtin_analyze_free(E9AnalysisResult *result)
{
    if (result) {
        e9_builtin_scan_free(result->signatures);
        e9_builtin_strings_free(result->strings, result->num_strings);
        free(result->parsed.elf.sections);
        free(result->parsed.elf.symbols);
        free(result);
    }
}
