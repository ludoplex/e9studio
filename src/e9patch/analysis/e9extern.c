/*
 * e9extern.c
 * External Tool Integration Implementation
 *
 * Copyright (C) 2024 E9Patch Contributors
 * License: GPLv3+
 */

#include "e9extern.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <errno.h>

/* Note: When building with cosmocc, cosmopolitan libc is automatically provided. */

/* Optional library headers - conditionally included */
#ifdef HAVE_CAPSTONE
#include <capstone/capstone.h>
#endif

#ifdef HAVE_KEYSTONE
#include <keystone/keystone.h>
#endif

#ifdef HAVE_ZLIB
#include <zlib.h>
#endif

#ifdef HAVE_LZMA
#include <lzma.h>
#endif

#ifdef HAVE_ZSTD
#include <zstd.h>
#endif

/*
 * Global tool detection cache
 */
static E9ExternTools g_tools = {0};
static bool g_tools_detected = false;

/*
 * ============================================================================
 * Utility Functions
 * ============================================================================
 */

bool e9_extern_exists(const char *cmd)
{
    char *path = e9_extern_which(cmd);
    bool exists = (path != NULL);
    free(path);
    return exists;
}

char *e9_extern_which(const char *cmd)
{
    if (!cmd) return NULL;

    /* Try 'which' command */
    char buf[512];
    snprintf(buf, sizeof(buf), "which %s 2>/dev/null", cmd);

    FILE *fp = popen(buf, "r");
    if (!fp) return NULL;

    char *result = NULL;
    if (fgets(buf, sizeof(buf), fp)) {
        /* Remove trailing newline */
        size_t len = strlen(buf);
        if (len > 0 && buf[len-1] == '\n') buf[len-1] = '\0';
        if (buf[0] != '\0') {
            result = strdup(buf);
        }
    }
    pclose(fp);
    return result;
}

char *e9_extern_run(const char *cmd, int *exit_code)
{
    if (!cmd) return NULL;

    FILE *fp = popen(cmd, "r");
    if (!fp) {
        if (exit_code) *exit_code = -1;
        return NULL;
    }

    /* Read all output */
    size_t capacity = 4096;
    size_t len = 0;
    char *output = malloc(capacity);
    if (!output) {
        pclose(fp);
        return NULL;
    }

    char buf[1024];
    while (fgets(buf, sizeof(buf), fp)) {
        size_t chunk = strlen(buf);
        if (len + chunk + 1 > capacity) {
            capacity *= 2;
            char *new_output = realloc(output, capacity);
            if (!new_output) {
                free(output);
                pclose(fp);
                return NULL;
            }
            output = new_output;
        }
        memcpy(output + len, buf, chunk);
        len += chunk;
    }
    output[len] = '\0';

    int status = pclose(fp);
    if (exit_code) {
        *exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    }

    return output;
}

char *e9_extern_tempfile(const uint8_t *data, size_t size, const char *suffix)
{
    char template[256];
    snprintf(template, sizeof(template), "/tmp/e9ext_XXXXXX%s",
             suffix ? suffix : "");

    int fd = mkstemps(template, suffix ? strlen(suffix) : 0);
    if (fd < 0) return NULL;

    if (write(fd, data, size) != (ssize_t)size) {
        close(fd);
        unlink(template);
        return NULL;
    }
    close(fd);

    return strdup(template);
}

void e9_extern_tempfile_free(char *path)
{
    if (path) {
        unlink(path);
        free(path);
    }
}

/*
 * ============================================================================
 * Tool Detection
 * ============================================================================
 */

E9ExternTools *e9_extern_detect(void)
{
    if (g_tools_detected) return &g_tools;

    memset(&g_tools, 0, sizeof(g_tools));

    /* Python tools */
    g_tools.has_binwalk = e9_extern_exists("binwalk");
    if (g_tools.has_binwalk) {
        char *path = e9_extern_which("binwalk");
        if (path) {
            strncpy(g_tools.binwalk_path, path, sizeof(g_tools.binwalk_path)-1);
            free(path);
        }
    }

    g_tools.has_polyfile = e9_extern_exists("polyfile");
    if (g_tools.has_polyfile) {
        char *path = e9_extern_which("polyfile");
        if (path) {
            strncpy(g_tools.polyfile_path, path, sizeof(g_tools.polyfile_path)-1);
            free(path);
        }
    }

    /* Check for polytracker (more complex setup) */
    g_tools.has_polytracker = e9_extern_exists("polytracker");

    /* System tools */
    g_tools.has_objdump = e9_extern_exists("objdump");
    if (g_tools.has_objdump) {
        char *path = e9_extern_which("objdump");
        if (path) {
            strncpy(g_tools.objdump_path, path, sizeof(g_tools.objdump_path)-1);
            free(path);
        }
    }

    g_tools.has_readelf = e9_extern_exists("readelf");
    if (g_tools.has_readelf) {
        char *path = e9_extern_which("readelf");
        if (path) {
            strncpy(g_tools.readelf_path, path, sizeof(g_tools.readelf_path)-1);
            free(path);
        }
    }

    g_tools.has_nm = e9_extern_exists("nm");
    g_tools.has_strings = e9_extern_exists("strings");
    g_tools.has_file = e9_extern_exists("file");

    /* C libraries - check at compile time */
#ifdef HAVE_CAPSTONE
    g_tools.has_capstone = true;
#endif
#ifdef HAVE_KEYSTONE
    g_tools.has_keystone = true;
#endif
#ifdef HAVE_ZLIB
    g_tools.has_zlib = true;
#endif
#ifdef HAVE_LZMA
    g_tools.has_lzma = true;
#endif
#ifdef HAVE_ZSTD
    g_tools.has_zstd = true;
#endif

    /* Try to detect via pkg-config if not compile-time */
    if (!g_tools.has_capstone) {
        int rc;
        char *out = e9_extern_run("pkg-config --exists capstone && echo yes", &rc);
        if (out && strstr(out, "yes")) g_tools.has_capstone = true;
        free(out);
    }

    g_tools_detected = true;
    return &g_tools;
}

const E9ExternTools *e9_extern_tools(void)
{
    if (!g_tools_detected) e9_extern_detect();
    return &g_tools;
}

/*
 * ============================================================================
 * binwalk Integration
 * ============================================================================
 */

E9BinwalkResult *e9_binwalk_scan(const char *filepath, uint32_t *count)
{
    if (!filepath || !count) return NULL;
    *count = 0;

    const E9ExternTools *tools = e9_extern_tools();
    if (!tools->has_binwalk) return NULL;

    /* Run binwalk with CSV output */
    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "binwalk -B --csv '%s' 2>/dev/null", filepath);

    int rc;
    char *output = e9_extern_run(cmd, &rc);
    if (!output || rc != 0) {
        free(output);
        return NULL;
    }

    /* Parse CSV output: DECIMAL,HEXADECIMAL,DESCRIPTION */
    E9BinwalkResult *results = NULL;
    uint32_t capacity = 0;

    char *line = strtok(output, "\n");
    while (line) {
        /* Skip header */
        if (strncmp(line, "DECIMAL", 7) == 0) {
            line = strtok(NULL, "\n");
            continue;
        }

        uint64_t offset;
        char desc[256] = {0};

        if (sscanf(line, "%lu,%*x,%255[^\n]", &offset, desc) >= 1) {
            if (*count >= capacity) {
                capacity = capacity ? capacity * 2 : 32;
                results = realloc(results, capacity * sizeof(E9BinwalkResult));
            }

            E9BinwalkResult *r = &results[*count];
            r->offset = offset;
            strncpy(r->description, desc, sizeof(r->description)-1);
            r->size = 0;

            /* Extract type from description */
            if (strstr(desc, "gzip")) strncpy(r->type, "gzip", sizeof(r->type));
            else if (strstr(desc, "Zip")) strncpy(r->type, "zip", sizeof(r->type));
            else if (strstr(desc, "ELF")) strncpy(r->type, "elf", sizeof(r->type));
            else if (strstr(desc, "PNG")) strncpy(r->type, "png", sizeof(r->type));
            else strncpy(r->type, "unknown", sizeof(r->type));

            (*count)++;
        }

        line = strtok(NULL, "\n");
    }

    free(output);
    return results;
}

E9BinwalkResult *e9_binwalk_scan_mem(const uint8_t *data, size_t size, uint32_t *count)
{
    if (!data || !count) return NULL;

    /* Write to temp file, scan, cleanup */
    char *tmpfile = e9_extern_tempfile(data, size, ".bin");
    if (!tmpfile) return NULL;

    E9BinwalkResult *results = e9_binwalk_scan(tmpfile, count);

    e9_extern_tempfile_free(tmpfile);
    return results;
}

int e9_binwalk_extract(const char *filepath, const char *outdir)
{
    if (!filepath || !outdir) return -1;

    const E9ExternTools *tools = e9_extern_tools();
    if (!tools->has_binwalk) return -1;

    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "binwalk -e -C '%s' '%s' 2>/dev/null",
             outdir, filepath);

    int rc;
    char *output = e9_extern_run(cmd, &rc);
    free(output);
    return rc;
}

E9BinwalkEntropy *e9_binwalk_entropy(const char *filepath)
{
    if (!filepath) return NULL;

    const E9ExternTools *tools = e9_extern_tools();
    if (!tools->has_binwalk) return NULL;

    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "binwalk -E --csv '%s' 2>/dev/null", filepath);

    int rc;
    char *output = e9_extern_run(cmd, &rc);
    if (!output || rc != 0) {
        free(output);
        return NULL;
    }

    E9BinwalkEntropy *ent = calloc(1, sizeof(E9BinwalkEntropy));
    if (!ent) {
        free(output);
        return NULL;
    }

    /* Count lines for allocation */
    size_t lines = 0;
    for (char *p = output; *p; p++) {
        if (*p == '\n') lines++;
    }

    ent->entropy = malloc(lines * sizeof(double));
    if (!ent->entropy) {
        free(ent);
        free(output);
        return NULL;
    }

    /* Parse: OFFSET,ENTROPY */
    char *line = strtok(output, "\n");
    while (line) {
        if (strncmp(line, "OFFSET", 6) == 0) {
            line = strtok(NULL, "\n");
            continue;
        }

        uint64_t offset;
        double entropy;
        if (sscanf(line, "%lu,%lf", &offset, &entropy) == 2) {
            ent->entropy[ent->num_blocks++] = entropy;
        }

        line = strtok(NULL, "\n");
    }

    free(output);
    return ent;
}

void e9_binwalk_entropy_free(E9BinwalkEntropy *ent)
{
    if (ent) {
        free(ent->entropy);
        free(ent);
    }
}

/*
 * ============================================================================
 * polyfile Integration
 * ============================================================================
 */

E9PolyfileMatch *e9_polyfile_scan(const char *filepath, uint32_t *count)
{
    if (!filepath || !count) return NULL;
    *count = 0;

    const E9ExternTools *tools = e9_extern_tools();
    if (!tools->has_polyfile) return NULL;

    /* Run polyfile - it outputs JSON */
    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "polyfile '%s' 2>/dev/null", filepath);

    int rc;
    char *output = e9_extern_run(cmd, &rc);
    if (!output) return NULL;

    /* Simple JSON parsing for format matches */
    /* polyfile output format varies, this is simplified */
    E9PolyfileMatch *results = NULL;
    uint32_t capacity = 0;

    /* Look for "match" entries in JSON */
    char *p = output;
    while ((p = strstr(p, "\"filetype\"")) != NULL) {
        if (*count >= capacity) {
            capacity = capacity ? capacity * 2 : 16;
            results = realloc(results, capacity * sizeof(E9PolyfileMatch));
        }

        E9PolyfileMatch *m = &results[*count];
        memset(m, 0, sizeof(*m));

        /* Extract filetype */
        char *start = strchr(p, ':');
        if (start) {
            start = strchr(start, '"');
            if (start) {
                start++;
                char *end = strchr(start, '"');
                if (end) {
                    size_t len = end - start;
                    if (len >= sizeof(m->format)) len = sizeof(m->format) - 1;
                    memcpy(m->format, start, len);
                }
            }
        }

        m->confidence = 1.0;
        (*count)++;
        p++;
    }

    free(output);
    return results;
}

char *e9_polyfile_json(const char *filepath)
{
    if (!filepath) return NULL;

    const E9ExternTools *tools = e9_extern_tools();
    if (!tools->has_polyfile) return NULL;

    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "polyfile --json '%s' 2>/dev/null", filepath);

    int rc;
    return e9_extern_run(cmd, &rc);
}

bool e9_polyfile_is_polyglot(const char *filepath)
{
    uint32_t count = 0;
    E9PolyfileMatch *matches = e9_polyfile_scan(filepath, &count);
    bool is_polyglot = (count > 1);
    free(matches);
    return is_polyglot;
}

/*
 * ============================================================================
 * Capstone Integration
 * ============================================================================
 */

#ifdef HAVE_CAPSTONE

void *e9_capstone_open(int arch, int mode)
{
    csh *handle = malloc(sizeof(csh));
    if (!handle) return NULL;

    cs_arch cs_a = (arch == E9_CS_ARCH_X86) ? CS_ARCH_X86 :
                   (arch == E9_CS_ARCH_ARM64) ? CS_ARCH_ARM64 : CS_ARCH_X86;
    cs_mode cs_m = (mode & E9_CS_MODE_64) ? CS_MODE_64 : CS_MODE_32;

    if (cs_open(cs_a, cs_m, handle) != CS_ERR_OK) {
        free(handle);
        return NULL;
    }

    cs_option(*handle, CS_OPT_DETAIL, CS_OPT_ON);
    return handle;
}

void e9_capstone_close(void *handle)
{
    if (handle) {
        cs_close((csh *)handle);
        free(handle);
    }
}

size_t e9_capstone_disasm(void *handle, const uint8_t *code, size_t size,
                          uint64_t addr, size_t count, E9CapstoneInsn **insns)
{
    if (!handle || !code || !insns) return 0;

    cs_insn *cs_insns;
    size_t num = cs_disasm(*(csh *)handle, code, size, addr, count, &cs_insns);

    if (num == 0) {
        *insns = NULL;
        return 0;
    }

    *insns = calloc(num, sizeof(E9CapstoneInsn));
    if (!*insns) {
        cs_free(cs_insns, num);
        return 0;
    }

    for (size_t i = 0; i < num; i++) {
        E9CapstoneInsn *dst = &(*insns)[i];
        cs_insn *src = &cs_insns[i];

        dst->address = src->address;
        dst->size = src->size;
        memcpy(dst->bytes, src->bytes, src->size);
        strncpy(dst->mnemonic, src->mnemonic, sizeof(dst->mnemonic)-1);
        strncpy(dst->op_str, src->op_str, sizeof(dst->op_str)-1);
    }

    cs_free(cs_insns, num);
    return num;
}

void e9_capstone_free(E9CapstoneInsn *insns, size_t count)
{
    free(insns);
}

#else /* No Capstone - use objdump fallback */

void *e9_capstone_open(int arch, int mode)
{
    /* Return dummy handle, we'll use objdump */
    int *h = malloc(sizeof(int));
    if (h) *h = arch;
    return h;
}

void e9_capstone_close(void *handle)
{
    free(handle);
}

size_t e9_capstone_disasm(void *handle, const uint8_t *code, size_t size,
                          uint64_t addr, size_t count, E9CapstoneInsn **insns)
{
    /* Fallback: write code to temp file, run objdump */
    *insns = NULL;

    const E9ExternTools *tools = e9_extern_tools();
    if (!tools->has_objdump) return 0;

    char *tmpfile = e9_extern_tempfile(code, size, ".bin");
    if (!tmpfile) return 0;

    char cmd[1024];
    snprintf(cmd, sizeof(cmd),
             "objdump -D -b binary -m i386:x86-64 '%s' 2>/dev/null | "
             "grep '^ *[0-9a-f]*:'",
             tmpfile);

    int rc;
    char *output = e9_extern_run(cmd, &rc);
    e9_extern_tempfile_free(tmpfile);

    if (!output) return 0;

    /* Parse objdump output */
    size_t capacity = 64;
    size_t num = 0;
    *insns = calloc(capacity, sizeof(E9CapstoneInsn));
    if (!*insns) {
        free(output);
        return 0;
    }

    char *line = strtok(output, "\n");
    while (line && (count == 0 || num < count)) {
        uint64_t off;
        char bytes_str[64], mnemonic[32], operands[128];

        if (sscanf(line, " %lx: %63s %31s %127[^\n]",
                   &off, bytes_str, mnemonic, operands) >= 2) {
            if (num >= capacity) {
                capacity *= 2;
                *insns = realloc(*insns, capacity * sizeof(E9CapstoneInsn));
            }

            E9CapstoneInsn *insn = &(*insns)[num];
            insn->address = addr + off;
            strncpy(insn->mnemonic, mnemonic, sizeof(insn->mnemonic)-1);
            strncpy(insn->op_str, operands, sizeof(insn->op_str)-1);

            /* Parse bytes */
            insn->size = 0;
            char *bp = bytes_str;
            while (*bp && insn->size < 24) {
                unsigned int b;
                if (sscanf(bp, "%02x", &b) == 1) {
                    insn->bytes[insn->size++] = b;
                    bp += 2;
                } else {
                    break;
                }
            }

            num++;
        }

        line = strtok(NULL, "\n");
    }

    free(output);
    return num;
}

void e9_capstone_free(E9CapstoneInsn *insns, size_t count)
{
    free(insns);
}

#endif /* HAVE_CAPSTONE */

/*
 * ============================================================================
 * Compression Library Wrappers
 * ============================================================================
 */

#ifdef HAVE_ZLIB

uint8_t *e9_zlib_compress(const uint8_t *data, size_t size, int level, size_t *out_size)
{
    uLongf bound = compressBound(size);
    uint8_t *output = malloc(bound);
    if (!output) return NULL;

    if (compress2(output, &bound, data, size, level) != Z_OK) {
        free(output);
        return NULL;
    }

    *out_size = bound;
    return output;
}

uint8_t *e9_zlib_decompress(const uint8_t *data, size_t size, size_t max_out, size_t *out_size)
{
    if (max_out == 0) max_out = size * 10;  /* Guess */

    uint8_t *output = malloc(max_out);
    if (!output) return NULL;

    uLongf out_len = max_out;
    if (uncompress(output, &out_len, data, size) != Z_OK) {
        free(output);
        return NULL;
    }

    *out_size = out_len;
    return output;
}

#else /* No zlib */

uint8_t *e9_zlib_compress(const uint8_t *data, size_t size, int level, size_t *out_size)
{
    /* Use gzip command as fallback */
    char *tmpfile = e9_extern_tempfile(data, size, ".raw");
    if (!tmpfile) return NULL;

    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "gzip -%d -c '%s'", level, tmpfile);

    FILE *fp = popen(cmd, "r");
    e9_extern_tempfile_free(tmpfile);
    if (!fp) return NULL;

    size_t capacity = size;
    uint8_t *output = malloc(capacity);
    size_t len = 0;

    size_t n;
    uint8_t buf[4096];
    while ((n = fread(buf, 1, sizeof(buf), fp)) > 0) {
        if (len + n > capacity) {
            capacity *= 2;
            output = realloc(output, capacity);
        }
        memcpy(output + len, buf, n);
        len += n;
    }

    pclose(fp);
    *out_size = len;
    return output;
}

uint8_t *e9_zlib_decompress(const uint8_t *data, size_t size, size_t max_out, size_t *out_size)
{
    char *tmpfile = e9_extern_tempfile(data, size, ".gz");
    if (!tmpfile) return NULL;

    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "gzip -d -c '%s'", tmpfile);

    FILE *fp = popen(cmd, "r");
    e9_extern_tempfile_free(tmpfile);
    if (!fp) return NULL;

    size_t capacity = max_out ? max_out : size * 10;
    uint8_t *output = malloc(capacity);
    size_t len = 0;

    size_t n;
    uint8_t buf[4096];
    while ((n = fread(buf, 1, sizeof(buf), fp)) > 0) {
        if (len + n > capacity) {
            capacity *= 2;
            output = realloc(output, capacity);
        }
        memcpy(output + len, buf, n);
        len += n;
    }

    pclose(fp);
    *out_size = len;
    return output;
}

#endif /* HAVE_ZLIB */

/*
 * ============================================================================
 * System Tool Wrappers
 * ============================================================================
 */

char *e9_file_type(const char *filepath)
{
    if (!filepath) return NULL;

    const E9ExternTools *tools = e9_extern_tools();
    if (!tools->has_file) return NULL;

    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "file -b '%s' 2>/dev/null", filepath);

    int rc;
    char *output = e9_extern_run(cmd, &rc);
    if (output) {
        /* Remove trailing newline */
        size_t len = strlen(output);
        if (len > 0 && output[len-1] == '\n') output[len-1] = '\0';
    }
    return output;
}

char **e9_strings_extract(const char *filepath, size_t min_len, uint32_t *count)
{
    if (!filepath || !count) return NULL;
    *count = 0;

    const E9ExternTools *tools = e9_extern_tools();
    if (!tools->has_strings) return NULL;

    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "strings -n %zu '%s' 2>/dev/null",
             min_len > 0 ? min_len : 4, filepath);

    int rc;
    char *output = e9_extern_run(cmd, &rc);
    if (!output) return NULL;

    /* Count lines */
    uint32_t num_lines = 0;
    for (char *p = output; *p; p++) {
        if (*p == '\n') num_lines++;
    }

    char **strings = calloc(num_lines + 1, sizeof(char *));
    if (!strings) {
        free(output);
        return NULL;
    }

    char *line = strtok(output, "\n");
    while (line) {
        strings[*count] = strdup(line);
        (*count)++;
        line = strtok(NULL, "\n");
    }

    free(output);
    return strings;
}

char *e9_objdump_disasm(const char *filepath, uint64_t start, uint64_t end)
{
    if (!filepath) return NULL;

    const E9ExternTools *tools = e9_extern_tools();
    if (!tools->has_objdump) return NULL;

    char cmd[1024];
    if (start || end) {
        snprintf(cmd, sizeof(cmd),
                 "objdump -d --start-address=0x%lx --stop-address=0x%lx '%s' 2>/dev/null",
                 start, end, filepath);
    } else {
        snprintf(cmd, sizeof(cmd), "objdump -d '%s' 2>/dev/null", filepath);
    }

    int rc;
    return e9_extern_run(cmd, &rc);
}

char *e9_readelf_headers(const char *filepath)
{
    if (!filepath) return NULL;

    const E9ExternTools *tools = e9_extern_tools();
    if (!tools->has_readelf) return NULL;

    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "readelf -h '%s' 2>/dev/null", filepath);

    int rc;
    return e9_extern_run(cmd, &rc);
}

char *e9_readelf_symbols(const char *filepath)
{
    if (!filepath) return NULL;

    const E9ExternTools *tools = e9_extern_tools();
    if (!tools->has_readelf) return NULL;

    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "readelf -s '%s' 2>/dev/null", filepath);

    int rc;
    return e9_extern_run(cmd, &rc);
}

char *e9_readelf_sections(const char *filepath)
{
    if (!filepath) return NULL;

    const E9ExternTools *tools = e9_extern_tools();
    if (!tools->has_readelf) return NULL;

    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "readelf -S '%s' 2>/dev/null", filepath);

    int rc;
    return e9_extern_run(cmd, &rc);
}

E9LiefSymbol *e9_nm_symbols(const char *filepath, uint32_t *count)
{
    if (!filepath || !count) return NULL;
    *count = 0;

    const E9ExternTools *tools = e9_extern_tools();
    if (!tools->has_nm) return NULL;

    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "nm -C '%s' 2>/dev/null", filepath);

    int rc;
    char *output = e9_extern_run(cmd, &rc);
    if (!output) return NULL;

    /* Count lines */
    uint32_t num_lines = 0;
    for (char *p = output; *p; p++) {
        if (*p == '\n') num_lines++;
    }

    E9LiefSymbol *syms = calloc(num_lines, sizeof(E9LiefSymbol));
    if (!syms) {
        free(output);
        return NULL;
    }

    char *line = strtok(output, "\n");
    while (line) {
        uint64_t addr;
        char type;
        char name[256];

        if (sscanf(line, "%lx %c %255s", &addr, &type, name) == 3) {
            E9LiefSymbol *s = &syms[*count];
            s->address = addr;
            strncpy(s->name, name, sizeof(s->name)-1);
            s->is_exported = (type == 'T' || type == 'D' || type == 'B');
            s->is_imported = (type == 'U');
            (*count)++;
        }

        line = strtok(NULL, "\n");
    }

    free(output);
    return syms;
}
