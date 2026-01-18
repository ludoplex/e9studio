/*
 * e9signatures.c
 * Signature Scanner Implementation
 *
 * Multi-pattern search for file format identification.
 * Uses a simple but efficient algorithm suitable for embedded use.
 *
 * Copyright (C) 2024 E9Patch Contributors
 * License: GPLv3+
 */

#include "e9signatures.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

/*
 * Simple signature scanner
 * For production use, this could be replaced with Aho-Corasick
 * but for our purposes (typically small files or streaming), this is sufficient.
 */
struct E9SigScanner {
    /* Grouped by first byte for quick rejection */
    struct {
        const E9Signature **sigs;
        size_t count;
    } first_byte[256];

    /* Short signatures (only match at start) */
    const E9Signature **short_sigs;
    size_t num_short;

    /* Offset-based signatures */
    struct {
        const E9Signature *sig;
        size_t offset;
    } *offset_sigs;
    size_t num_offset;
};

/*
 * Create signature scanner
 */
E9SigScanner *e9_sig_scanner_create(void)
{
    E9SigScanner *scanner = calloc(1, sizeof(E9SigScanner));
    if (!scanner) return NULL;

    /* Count signatures per first byte */
    size_t counts[256] = {0};
    size_t num_short = 0;
    size_t num_offset = 0;

    for (size_t i = 0; i < E9_NUM_SIGNATURES; i++) {
        const E9Signature *sig = &E9_SIGNATURE_DB[i];
        if (!sig->magic || sig->magic_len == 0) continue;

        if (sig->magic_offset > 0) {
            num_offset++;
        } else if (sig->short_sig) {
            num_short++;
        } else {
            counts[sig->magic[0]]++;
        }
    }

    /* Allocate arrays */
    for (int i = 0; i < 256; i++) {
        if (counts[i] > 0) {
            scanner->first_byte[i].sigs = calloc(counts[i] + 1, sizeof(E9Signature*));
            scanner->first_byte[i].count = 0;
        }
    }

    if (num_short > 0) {
        scanner->short_sigs = calloc(num_short + 1, sizeof(E9Signature*));
        scanner->num_short = 0;
    }

    if (num_offset > 0) {
        scanner->offset_sigs = calloc(num_offset, sizeof(*scanner->offset_sigs));
        scanner->num_offset = 0;
    }

    /* Populate arrays */
    for (size_t i = 0; i < E9_NUM_SIGNATURES; i++) {
        const E9Signature *sig = &E9_SIGNATURE_DB[i];
        if (!sig->magic || sig->magic_len == 0) continue;

        if (sig->magic_offset > 0) {
            scanner->offset_sigs[scanner->num_offset].sig = sig;
            scanner->offset_sigs[scanner->num_offset].offset = sig->magic_offset;
            scanner->num_offset++;
        } else if (sig->short_sig) {
            scanner->short_sigs[scanner->num_short++] = sig;
        } else {
            uint8_t first = sig->magic[0];
            scanner->first_byte[first].sigs[scanner->first_byte[first].count++] = sig;
        }
    }

    return scanner;
}

/*
 * Free scanner
 */
void e9_sig_scanner_free(E9SigScanner *scanner)
{
    if (!scanner) return;

    for (int i = 0; i < 256; i++) {
        free(scanner->first_byte[i].sigs);
    }
    free(scanner->short_sigs);
    free(scanner->offset_sigs);
    free(scanner);
}

/*
 * Check if signature matches at position
 */
static bool check_sig_at(const uint8_t *data, size_t size, size_t pos,
                         const E9Signature *sig)
{
    if (pos + sig->magic_len > size) return false;
    return memcmp(data + pos, sig->magic, sig->magic_len) == 0;
}

/*
 * Estimate size of matched format (where possible)
 */
static size_t estimate_size(const uint8_t *data, size_t size, size_t offset,
                            const E9Signature *sig)
{
    /* For now, return 0 (unknown) */
    /* This could be expanded with format-specific parsers */
    (void)data;
    (void)size;
    (void)offset;
    (void)sig;
    return 0;
}

/*
 * Scan data for signatures
 */
E9SigMatch *e9_sig_scan(E9SigScanner *scanner, const uint8_t *data, size_t size,
                        uint32_t *count)
{
    if (!scanner || !data || size == 0 || !count) {
        if (count) *count = 0;
        return NULL;
    }

    /* Allocate result array (grow as needed) */
    size_t capacity = 64;
    size_t num_matches = 0;
    E9SigMatch *matches = calloc(capacity, sizeof(E9SigMatch));
    if (!matches) {
        *count = 0;
        return NULL;
    }

    /* Check short signatures at offset 0 */
    for (size_t i = 0; i < scanner->num_short; i++) {
        const E9Signature *sig = scanner->short_sigs[i];
        if (check_sig_at(data, size, 0, sig)) {
            if (num_matches >= capacity) {
                capacity *= 2;
                E9SigMatch *new_matches = realloc(matches, capacity * sizeof(E9SigMatch));
                if (!new_matches) break;
                matches = new_matches;
            }

            matches[num_matches].sig = sig;
            matches[num_matches].offset = 0;
            matches[num_matches].size = estimate_size(data, size, 0, sig);
            matches[num_matches].confidence = sig->confidence;
            snprintf(matches[num_matches].description, sizeof(matches[num_matches].description),
                     "%s", sig->description);
            num_matches++;
        }
    }

    /* Check offset-based signatures */
    for (size_t i = 0; i < scanner->num_offset; i++) {
        const E9Signature *sig = scanner->offset_sigs[i].sig;
        size_t offset = scanner->offset_sigs[i].offset;

        if (offset < size && check_sig_at(data, size, offset, sig)) {
            if (num_matches >= capacity) {
                capacity *= 2;
                E9SigMatch *new_matches = realloc(matches, capacity * sizeof(E9SigMatch));
                if (!new_matches) break;
                matches = new_matches;
            }

            matches[num_matches].sig = sig;
            matches[num_matches].offset = 0; /* Report file start */
            matches[num_matches].size = estimate_size(data, size, 0, sig);
            matches[num_matches].confidence = sig->confidence;
            snprintf(matches[num_matches].description, sizeof(matches[num_matches].description),
                     "%s", sig->description);
            num_matches++;
        }
    }

    /* Scan for normal signatures */
    for (size_t pos = 0; pos < size; pos++) {
        uint8_t byte = data[pos];
        struct { const E9Signature **sigs; size_t count; } *bucket = &scanner->first_byte[byte];

        for (size_t i = 0; i < bucket->count; i++) {
            const E9Signature *sig = bucket->sigs[i];
            if (check_sig_at(data, size, pos, sig)) {
                if (num_matches >= capacity) {
                    capacity *= 2;
                    E9SigMatch *new_matches = realloc(matches, capacity * sizeof(E9SigMatch));
                    if (!new_matches) goto done;
                    matches = new_matches;
                }

                matches[num_matches].sig = sig;
                matches[num_matches].offset = pos;
                matches[num_matches].size = estimate_size(data, size, pos, sig);
                matches[num_matches].confidence = sig->confidence;
                snprintf(matches[num_matches].description, sizeof(matches[num_matches].description),
                         "%s at offset 0x%zx", sig->description, pos);
                num_matches++;
            }
        }
    }

done:
    *count = (uint32_t)num_matches;
    return matches;
}

/*
 * Free scan results
 */
void e9_sig_matches_free(E9SigMatch *matches)
{
    free(matches);
}

/*
 * Simple single-signature check
 */
bool e9_sig_check(const uint8_t *data, size_t size, const char *sig_name)
{
    const E9Signature *sig = e9_sig_lookup(sig_name);
    if (!sig) return false;

    if (sig->magic_offset > 0) {
        return check_sig_at(data, size, sig->magic_offset, sig);
    }
    return check_sig_at(data, size, 0, sig);
}

/*
 * Get signature by name
 */
const E9Signature *e9_sig_lookup(const char *name)
{
    if (!name) return NULL;

    for (size_t i = 0; i < E9_NUM_SIGNATURES; i++) {
        if (E9_SIGNATURE_DB[i].name && strcmp(E9_SIGNATURE_DB[i].name, name) == 0) {
            return &E9_SIGNATURE_DB[i];
        }
    }
    return NULL;
}

/*
 * Iterate over all signatures
 */
const E9Signature *e9_sig_iter(size_t *index)
{
    if (!index || *index >= E9_NUM_SIGNATURES) return NULL;
    return &E9_SIGNATURE_DB[(*index)++];
}

/*
 * ============================================================================
 * Format-specific validation helpers
 * ============================================================================
 */

/*
 * Validate ELF header
 */
bool e9_sig_validate_elf(const uint8_t *data, size_t size)
{
    if (size < 52) return false;  /* Minimum ELF header size */
    if (memcmp(data, "\x7F" "ELF", 4) != 0) return false;

    uint8_t ei_class = data[4];  /* 32-bit or 64-bit */
    uint8_t ei_data = data[5];   /* Endianness */
    uint8_t ei_version = data[6];

    if (ei_class != 1 && ei_class != 2) return false;  /* ELFCLASS32/64 */
    if (ei_data != 1 && ei_data != 2) return false;    /* ELFDATA2LSB/MSB */
    if (ei_version != 1) return false;                  /* EV_CURRENT */

    return true;
}

/*
 * Validate PE header
 */
bool e9_sig_validate_pe(const uint8_t *data, size_t size)
{
    if (size < 64) return false;
    if (data[0] != 'M' || data[1] != 'Z') return false;

    /* Get PE header offset from e_lfanew */
    uint32_t pe_offset = data[60] | (data[61] << 8) |
                         (data[62] << 16) | (data[63] << 24);

    if (pe_offset + 4 > size) return false;

    /* Check PE signature */
    if (memcmp(data + pe_offset, "PE\x00\x00", 4) != 0) return false;

    return true;
}

/*
 * Validate ZIP archive
 */
bool e9_sig_validate_zip(const uint8_t *data, size_t size)
{
    if (size < 30) return false;
    if (memcmp(data, "PK\x03\x04", 4) != 0) return false;

    /* Basic header validation */
    uint16_t version = data[4] | (data[5] << 8);
    uint16_t flags = data[6] | (data[7] << 8);
    uint16_t compression = data[8] | (data[9] << 8);

    (void)version;
    (void)flags;

    /* Check compression method is valid */
    if (compression > 99) return false;

    return true;
}

/*
 * Get format description based on signature analysis
 */
void e9_sig_describe(const uint8_t *data, size_t size, const E9Signature *sig,
                     char *desc, size_t desc_size)
{
    if (!data || !sig || !desc || desc_size == 0) return;

    desc[0] = '\0';

    if (strcmp(sig->name, "elf") == 0 && e9_sig_validate_elf(data, size)) {
        const char *class_str = (data[4] == 2) ? "64-bit" : "32-bit";
        const char *endian_str = (data[5] == 1) ? "little-endian" : "big-endian";

        uint16_t e_type = (data[5] == 1) ?
            (data[16] | (data[17] << 8)) :
            ((data[16] << 8) | data[17]);

        const char *type_str;
        switch (e_type) {
            case 1: type_str = "relocatable"; break;
            case 2: type_str = "executable"; break;
            case 3: type_str = "shared object"; break;
            case 4: type_str = "core dump"; break;
            default: type_str = "unknown type"; break;
        }

        snprintf(desc, desc_size, "ELF %s %s %s", class_str, endian_str, type_str);
    }
    else if (strcmp(sig->name, "pe") == 0 && e9_sig_validate_pe(data, size)) {
        uint32_t pe_offset = data[60] | (data[61] << 8) |
                             (data[62] << 16) | (data[63] << 24);

        if (pe_offset + 6 <= size) {
            uint16_t machine = data[pe_offset + 4] | (data[pe_offset + 5] << 8);

            const char *arch_str;
            switch (machine) {
                case 0x8664: arch_str = "x86-64"; break;
                case 0x014c: arch_str = "i386"; break;
                case 0xaa64: arch_str = "ARM64"; break;
                case 0x01c4: arch_str = "ARM"; break;
                default: arch_str = "unknown arch"; break;
            }

            snprintf(desc, desc_size, "PE %s executable", arch_str);
        } else {
            snprintf(desc, desc_size, "PE executable");
        }
    }
    else {
        snprintf(desc, desc_size, "%s", sig->description);
    }
}
