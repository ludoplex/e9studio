/*
 * e9signatures.h
 * Comprehensive File Signature Database
 *
 * Extracted and converted from:
 * - binwalk (https://github.com/ReFirmLabs/binwalk) - GPLv2
 * - file(1) magic database - BSD license
 *
 * This is a self-contained C header that can be compiled directly into
 * e9studio.com without any external dependencies.
 *
 * Copyright (C) 2024 E9Patch Contributors
 * License: GPLv3+
 */

#ifndef E9SIGNATURES_H
#define E9SIGNATURES_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Signature confidence levels
 */
#define E9_SIG_CONFIDENCE_LOW     0
#define E9_SIG_CONFIDENCE_MEDIUM  128
#define E9_SIG_CONFIDENCE_HIGH    250

/*
 * Signature categories
 */
typedef enum {
    E9_SIG_CAT_EXECUTABLE = 0,      /* ELF, PE, Mach-O */
    E9_SIG_CAT_ARCHIVE,             /* ZIP, TAR, RAR, etc. */
    E9_SIG_CAT_COMPRESSED,          /* gzip, bzip2, xz, zstd, etc. */
    E9_SIG_CAT_FILESYSTEM,          /* ext4, squashfs, cramfs, etc. */
    E9_SIG_CAT_FIRMWARE,            /* UEFI, u-boot, etc. */
    E9_SIG_CAT_IMAGE,               /* PNG, JPEG, GIF, BMP */
    E9_SIG_CAT_DOCUMENT,            /* PDF, Office */
    E9_SIG_CAT_MEDIA,               /* Audio/Video */
    E9_SIG_CAT_CRYPTO,              /* Keys, certificates, encrypted */
    E9_SIG_CAT_DATA,                /* Generic data formats */
    E9_SIG_CAT_OTHER,
} E9SigCategory;

/*
 * Signature definition
 */
typedef struct {
    const char *name;               /* Short identifier (e.g., "elf") */
    const char *description;        /* Human-readable description */
    E9SigCategory category;         /* Category */
    uint8_t confidence;             /* Default confidence level */
    bool short_sig;                 /* Only match at file start */
    size_t magic_offset;            /* Offset of magic from file start */

    /* Magic bytes (may have multiple patterns) */
    const uint8_t *magic;
    size_t magic_len;

    /* Additional patterns (NULL-terminated array) */
    const uint8_t **alt_magic;
    const size_t *alt_magic_len;
    size_t num_alt;

} E9Signature;

/*
 * ============================================================================
 * Magic Bytes Database
 * ============================================================================
 */

/* ELF Binary */
static const uint8_t SIG_ELF[] = { 0x7F, 'E', 'L', 'F' };

/* PE/DOS Executable */
static const uint8_t SIG_PE_1[] = { 0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00,
                                    0x04, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00 };
static const uint8_t SIG_PE_2[] = { 0x4D, 0x5A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
static const uint8_t SIG_MZ[] = { 'M', 'Z' };

/* Mach-O */
static const uint8_t SIG_MACHO_32[] = { 0xFE, 0xED, 0xFA, 0xCE };
static const uint8_t SIG_MACHO_64[] = { 0xFE, 0xED, 0xFA, 0xCF };
static const uint8_t SIG_MACHO_32_REV[] = { 0xCE, 0xFA, 0xED, 0xFE };
static const uint8_t SIG_MACHO_64_REV[] = { 0xCF, 0xFA, 0xED, 0xFE };
static const uint8_t SIG_MACHO_FAT[] = { 0xCA, 0xFE, 0xBA, 0xBE };
static const uint8_t SIG_MACHO_FAT_REV[] = { 0xBE, 0xBA, 0xFE, 0xCA };

/* ZIP Archive */
static const uint8_t SIG_ZIP[] = { 'P', 'K', 0x03, 0x04 };
static const uint8_t SIG_ZIP_EMPTY[] = { 'P', 'K', 0x05, 0x06 };
static const uint8_t SIG_ZIP_SPAN[] = { 'P', 'K', 0x07, 0x08 };

/* gzip */
static const uint8_t SIG_GZIP[] = { 0x1F, 0x8B, 0x08 };

/* bzip2 */
static const uint8_t SIG_BZIP2_9[] = { 'B', 'Z', 'h', '9', '1', 'A', 'Y', '&', 'S', 'Y' };
static const uint8_t SIG_BZIP2_8[] = { 'B', 'Z', 'h', '8', '1', 'A', 'Y', '&', 'S', 'Y' };
static const uint8_t SIG_BZIP2_7[] = { 'B', 'Z', 'h', '7', '1', 'A', 'Y', '&', 'S', 'Y' };
static const uint8_t SIG_BZIP2_6[] = { 'B', 'Z', 'h', '6', '1', 'A', 'Y', '&', 'S', 'Y' };
static const uint8_t SIG_BZIP2_5[] = { 'B', 'Z', 'h', '5', '1', 'A', 'Y', '&', 'S', 'Y' };
static const uint8_t SIG_BZIP2_4[] = { 'B', 'Z', 'h', '4', '1', 'A', 'Y', '&', 'S', 'Y' };
static const uint8_t SIG_BZIP2_3[] = { 'B', 'Z', 'h', '3', '1', 'A', 'Y', '&', 'S', 'Y' };
static const uint8_t SIG_BZIP2_2[] = { 'B', 'Z', 'h', '2', '1', 'A', 'Y', '&', 'S', 'Y' };
static const uint8_t SIG_BZIP2_1[] = { 'B', 'Z', 'h', '1', '1', 'A', 'Y', '&', 'S', 'Y' };

/* XZ */
static const uint8_t SIG_XZ[] = { 0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00 };

/* LZMA */
static const uint8_t SIG_LZMA[] = { 0x5D, 0x00, 0x00 };

/* Zstandard */
static const uint8_t SIG_ZSTD[] = { 0x28, 0xB5, 0x2F, 0xFD };

/* LZ4 */
static const uint8_t SIG_LZ4[] = { 0x04, 0x22, 0x4D, 0x18 };

/* 7-Zip */
static const uint8_t SIG_7ZIP[] = { '7', 'z', 0xBC, 0xAF, 0x27, 0x1C };

/* RAR */
static const uint8_t SIG_RAR[] = { 'R', 'a', 'r', '!', 0x1A, 0x07 };
static const uint8_t SIG_RAR5[] = { 'R', 'a', 'r', '!', 0x1A, 0x07, 0x01, 0x00 };

/* TAR (ustar) */
static const uint8_t SIG_USTAR[] = { 'u', 's', 't', 'a', 'r', 0x00 };
static const uint8_t SIG_USTAR_GNU[] = { 'u', 's', 't', 'a', 'r', ' ', ' ', 0x00 };

/* CPIO */
static const uint8_t SIG_CPIO_NEWC[] = { '0', '7', '0', '7', '0', '1' };
static const uint8_t SIG_CPIO_CRC[] = { '0', '7', '0', '7', '0', '2' };
static const uint8_t SIG_CPIO_BIN_LE[] = { 0xC7, 0x71 };
static const uint8_t SIG_CPIO_BIN_BE[] = { 0x71, 0xC7 };

/* SquashFS */
static const uint8_t SIG_SQUASHFS_LE[] = { 'h', 's', 'q', 's' };
static const uint8_t SIG_SQUASHFS_BE[] = { 's', 'q', 's', 'h' };
static const uint8_t SIG_SQUASHFS_LZMA[] = { 's', 'q', 'l', 'z' };
static const uint8_t SIG_SQUASHFS_ALT1[] = { 'q', 's', 'h', 's' };
static const uint8_t SIG_SQUASHFS_ALT2[] = { 't', 'q', 's', 'h' };
static const uint8_t SIG_SQUASHFS_ALT3[] = { 'h', 's', 'q', 't' };
static const uint8_t SIG_SQUASHFS_ALT4[] = { 's', 'h', 's', 'q' };

/* CramFS */
static const uint8_t SIG_CRAMFS[] = { 'C', 'o', 'm', 'p', 'r', 'e', 's', 's', 'e', 'd',
                                      ' ', 'R', 'O', 'M', 'F', 'S' };
static const uint8_t SIG_CRAMFS_ALT[] = { 0x45, 0x3D, 0xCD, 0x28 };

/* JFFS2 */
static const uint8_t SIG_JFFS2_LE_1[] = { 0x85, 0x19, 0x01, 0xE0 };
static const uint8_t SIG_JFFS2_LE_2[] = { 0x85, 0x19, 0x02, 0xE0 };
static const uint8_t SIG_JFFS2_LE_3[] = { 0x85, 0x19, 0x03, 0x20 };
static const uint8_t SIG_JFFS2_BE_1[] = { 0x19, 0x85, 0xE0, 0x01 };
static const uint8_t SIG_JFFS2_BE_2[] = { 0x19, 0x85, 0xE0, 0x02 };
static const uint8_t SIG_JFFS2_BE_3[] = { 0x19, 0x85, 0x20, 0x03 };

/* UBI/UBIFS */
static const uint8_t SIG_UBI[] = { 'U', 'B', 'I', '#', 0x01 };
static const uint8_t SIG_UBIFS[] = { 0x31, 0x18, 0x10, 0x06 };

/* ext2/3/4 */
static const uint8_t SIG_EXT_MAGIC[] = { 0x53, 0xEF };  /* At offset 0x438 */

/* NTFS */
static const uint8_t SIG_NTFS[] = { 0xEB, 0x52, 0x90, 'N', 'T', 'F', 'S', ' ', ' ', ' ', ' ' };

/* FAT */
static const uint8_t SIG_FAT_BOOT[] = { 0x55, 0xAA };  /* At offset 510 */

/* BTRFS */
static const uint8_t SIG_BTRFS[] = { '_', 'B', 'H', 'R', 'f', 'S', '_', 'M' };

/* ISO9660 */
static const uint8_t SIG_ISO9660[] = { 0x01, 'C', 'D', '0', '0', '1', 0x01, 0x00 };

/* UEFI */
static const uint8_t SIG_UEFI_FV[] = { '_', 'F', 'V', 'H' };
static const uint8_t SIG_UEFI_CAPSULE[] = { 0xBD, 0x86, 0x66, 0x3B, 0x76, 0x0D, 0x30, 0x40,
                                            0xB7, 0x0E, 0xB5, 0x51, 0x9E, 0x2F, 0xC5, 0xA0 };

/* Android */
static const uint8_t SIG_ANDROID_BOOT[] = { 'A', 'N', 'D', 'R', 'O', 'I', 'D', '!' };
static const uint8_t SIG_ANDROID_SPARSE[] = { 0x3A, 0xFF, 0x26, 0xED };

/* PNG */
static const uint8_t SIG_PNG[] = { 0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A };

/* JPEG */
static const uint8_t SIG_JPEG_JFIF[] = { 0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 'J', 'F', 'I', 'F', 0x00 };
static const uint8_t SIG_JPEG_EXIF[] = { 0xFF, 0xD8, 0xFF, 0xE1 };
static const uint8_t SIG_JPEG_RAW[] = { 0xFF, 0xD8, 0xFF, 0xDB };

/* GIF */
static const uint8_t SIG_GIF87[] = { 'G', 'I', 'F', '8', '7', 'a' };
static const uint8_t SIG_GIF89[] = { 'G', 'I', 'F', '8', '9', 'a' };

/* BMP */
static const uint8_t SIG_BMP[] = { 'B', 'M' };

/* PDF */
static const uint8_t SIG_PDF[] = { '%', 'P', 'D', 'F', '-', '1', '.' };

/* Microsoft Office */
static const uint8_t SIG_OLE2[] = { 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1 };

/* OpenDocument */
static const uint8_t SIG_ODF[] = { 'P', 'K', 0x03, 0x04 }; /* Actually ZIP, check mimetype */

/* SQLite */
static const uint8_t SIG_SQLITE[] = { 'S', 'Q', 'L', 'i', 't', 'e', ' ', 'f', 'o', 'r',
                                      'm', 'a', 't', ' ', '3', 0x00 };

/* GPG/PGP */
static const uint8_t SIG_GPG_PUB[] = { 0x99, 0x01 };
static const uint8_t SIG_GPG_SEC[] = { 0x95, 0x01 };
static const uint8_t SIG_GPG_SIG[] = { 0x89 };
static const uint8_t SIG_PGP_ARMOR[] = { '-', '-', '-', '-', '-', 'B', 'E', 'G', 'I', 'N',
                                         ' ', 'P', 'G', 'P' };

/* SSH */
static const uint8_t SIG_SSH_PRIVKEY[] = { '-', '-', '-', '-', '-', 'B', 'E', 'G', 'I', 'N',
                                           ' ', 'O', 'P', 'E', 'N', 'S', 'S', 'H' };

/* X.509 Certificate */
static const uint8_t SIG_X509_DER[] = { 0x30, 0x82 };
static const uint8_t SIG_X509_PEM[] = { '-', '-', '-', '-', '-', 'B', 'E', 'G', 'I', 'N',
                                        ' ', 'C', 'E', 'R', 'T' };

/* U-Boot */
static const uint8_t SIG_UBOOT_IMAGE[] = { 0x27, 0x05, 0x19, 0x56 };

/* Device Tree Blob */
static const uint8_t SIG_DTB[] = { 0xD0, 0x0D, 0xFE, 0xED };

/* RIFF (WAV, AVI, etc.) */
static const uint8_t SIG_RIFF[] = { 'R', 'I', 'F', 'F' };

/* Ogg */
static const uint8_t SIG_OGG[] = { 'O', 'g', 'g', 'S' };

/* FLAC */
static const uint8_t SIG_FLAC[] = { 'f', 'L', 'a', 'C' };

/* MP3 ID3 */
static const uint8_t SIG_ID3[] = { 'I', 'D', '3' };

/* MP4/MOV */
static const uint8_t SIG_MP4_FTYP[] = { 'f', 't', 'y', 'p' }; /* At offset 4 */

/* WebM/Matroska */
static const uint8_t SIG_EBML[] = { 0x1A, 0x45, 0xDF, 0xA3 };

/* Java Class */
static const uint8_t SIG_JAVA_CLASS[] = { 0xCA, 0xFE, 0xBA, 0xBE };

/* Python Bytecode (varies by version) */
static const uint8_t SIG_PYC_38[] = { 0x55, 0x0D, 0x0D, 0x0A };
static const uint8_t SIG_PYC_39[] = { 0x61, 0x0D, 0x0D, 0x0A };
static const uint8_t SIG_PYC_310[] = { 0x6F, 0x0D, 0x0D, 0x0A };
static const uint8_t SIG_PYC_311[] = { 0xA7, 0x0D, 0x0D, 0x0A };

/* WebAssembly */
static const uint8_t SIG_WASM[] = { 0x00, 'a', 's', 'm', 0x01, 0x00, 0x00, 0x00 };

/* LLVM Bitcode */
static const uint8_t SIG_LLVM_BC[] = { 'B', 'C', 0xC0, 0xDE };

/* Git Pack */
static const uint8_t SIG_GIT_PACK[] = { 'P', 'A', 'C', 'K' };

/* Debian Package */
static const uint8_t SIG_DEB[] = { '!', '<', 'a', 'r', 'c', 'h', '>' };

/* RPM */
static const uint8_t SIG_RPM[] = { 0xED, 0xAB, 0xEE, 0xDB };

/* ar archive */
static const uint8_t SIG_AR[] = { '!', '<', 'a', 'r', 'c', 'h', '>', 0x0A };

/* Actually Portable Executable (APE) */
static const uint8_t SIG_APE[] = { 'M', 'Z', 'q', 'F', 'p', 'D', '=' };

/* AES S-Box (potential crypto) */
static const uint8_t SIG_AES_SBOX[] = { 0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
                                        0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76 };

/*
 * ============================================================================
 * Signature Database Table
 * ============================================================================
 */

/* Helper macro for simple signatures */
#define E9_SIG_ENTRY(name, desc, cat, conf, magic_arr) \
    { name, desc, cat, conf, false, 0, magic_arr, sizeof(magic_arr), NULL, NULL, 0 }

#define E9_SIG_ENTRY_OFFSET(name, desc, cat, conf, magic_arr, offset) \
    { name, desc, cat, conf, false, offset, magic_arr, sizeof(magic_arr), NULL, NULL, 0 }

#define E9_SIG_ENTRY_SHORT(name, desc, cat, conf, magic_arr) \
    { name, desc, cat, conf, true, 0, magic_arr, sizeof(magic_arr), NULL, NULL, 0 }

static const E9Signature E9_SIGNATURE_DB[] = {
    /* Executables */
    E9_SIG_ENTRY("elf", "ELF executable", E9_SIG_CAT_EXECUTABLE, E9_SIG_CONFIDENCE_HIGH, SIG_ELF),
    E9_SIG_ENTRY("pe", "Windows PE executable", E9_SIG_CAT_EXECUTABLE, E9_SIG_CONFIDENCE_MEDIUM, SIG_MZ),
    E9_SIG_ENTRY("macho32", "Mach-O 32-bit executable", E9_SIG_CAT_EXECUTABLE, E9_SIG_CONFIDENCE_HIGH, SIG_MACHO_32),
    E9_SIG_ENTRY("macho64", "Mach-O 64-bit executable", E9_SIG_CAT_EXECUTABLE, E9_SIG_CONFIDENCE_HIGH, SIG_MACHO_64),
    E9_SIG_ENTRY("macho32r", "Mach-O 32-bit (reversed)", E9_SIG_CAT_EXECUTABLE, E9_SIG_CONFIDENCE_HIGH, SIG_MACHO_32_REV),
    E9_SIG_ENTRY("macho64r", "Mach-O 64-bit (reversed)", E9_SIG_CAT_EXECUTABLE, E9_SIG_CONFIDENCE_HIGH, SIG_MACHO_64_REV),
    E9_SIG_ENTRY("machofat", "Mach-O Universal Binary", E9_SIG_CAT_EXECUTABLE, E9_SIG_CONFIDENCE_HIGH, SIG_MACHO_FAT),
    E9_SIG_ENTRY("ape", "Actually Portable Executable", E9_SIG_CAT_EXECUTABLE, E9_SIG_CONFIDENCE_HIGH, SIG_APE),
    E9_SIG_ENTRY("wasm", "WebAssembly module", E9_SIG_CAT_EXECUTABLE, E9_SIG_CONFIDENCE_HIGH, SIG_WASM),
    E9_SIG_ENTRY("javaclass", "Java class file", E9_SIG_CAT_EXECUTABLE, E9_SIG_CONFIDENCE_HIGH, SIG_JAVA_CLASS),
    E9_SIG_ENTRY("llvmbc", "LLVM bitcode", E9_SIG_CAT_EXECUTABLE, E9_SIG_CONFIDENCE_HIGH, SIG_LLVM_BC),

    /* Archives */
    E9_SIG_ENTRY("zip", "ZIP archive", E9_SIG_CAT_ARCHIVE, E9_SIG_CONFIDENCE_HIGH, SIG_ZIP),
    E9_SIG_ENTRY("7zip", "7-Zip archive", E9_SIG_CAT_ARCHIVE, E9_SIG_CONFIDENCE_HIGH, SIG_7ZIP),
    E9_SIG_ENTRY("rar", "RAR archive", E9_SIG_CAT_ARCHIVE, E9_SIG_CONFIDENCE_HIGH, SIG_RAR),
    E9_SIG_ENTRY("rar5", "RAR5 archive", E9_SIG_CAT_ARCHIVE, E9_SIG_CONFIDENCE_HIGH, SIG_RAR5),
    E9_SIG_ENTRY_OFFSET("ustar", "TAR archive (ustar)", E9_SIG_CAT_ARCHIVE, E9_SIG_CONFIDENCE_HIGH, SIG_USTAR, 257),
    E9_SIG_ENTRY("cpio", "CPIO archive (newc)", E9_SIG_CAT_ARCHIVE, E9_SIG_CONFIDENCE_HIGH, SIG_CPIO_NEWC),
    E9_SIG_ENTRY("cpiocrc", "CPIO archive (crc)", E9_SIG_CAT_ARCHIVE, E9_SIG_CONFIDENCE_HIGH, SIG_CPIO_CRC),
    E9_SIG_ENTRY("ar", "ar archive", E9_SIG_CAT_ARCHIVE, E9_SIG_CONFIDENCE_HIGH, SIG_AR),
    E9_SIG_ENTRY("deb", "Debian package", E9_SIG_CAT_ARCHIVE, E9_SIG_CONFIDENCE_HIGH, SIG_DEB),
    E9_SIG_ENTRY("rpm", "RPM package", E9_SIG_CAT_ARCHIVE, E9_SIG_CONFIDENCE_HIGH, SIG_RPM),
    E9_SIG_ENTRY("gitpack", "Git pack file", E9_SIG_CAT_ARCHIVE, E9_SIG_CONFIDENCE_HIGH, SIG_GIT_PACK),

    /* Compressed */
    E9_SIG_ENTRY("gzip", "gzip compressed data", E9_SIG_CAT_COMPRESSED, E9_SIG_CONFIDENCE_HIGH, SIG_GZIP),
    E9_SIG_ENTRY("bzip2", "bzip2 compressed data", E9_SIG_CAT_COMPRESSED, E9_SIG_CONFIDENCE_HIGH, SIG_BZIP2_9),
    E9_SIG_ENTRY("xz", "XZ compressed data", E9_SIG_CAT_COMPRESSED, E9_SIG_CONFIDENCE_HIGH, SIG_XZ),
    E9_SIG_ENTRY("lzma", "LZMA compressed data", E9_SIG_CAT_COMPRESSED, E9_SIG_CONFIDENCE_LOW, SIG_LZMA),
    E9_SIG_ENTRY("zstd", "Zstandard compressed data", E9_SIG_CAT_COMPRESSED, E9_SIG_CONFIDENCE_HIGH, SIG_ZSTD),
    E9_SIG_ENTRY("lz4", "LZ4 compressed data", E9_SIG_CAT_COMPRESSED, E9_SIG_CONFIDENCE_HIGH, SIG_LZ4),

    /* Filesystems */
    E9_SIG_ENTRY("squashfs", "SquashFS filesystem (LE)", E9_SIG_CAT_FILESYSTEM, E9_SIG_CONFIDENCE_HIGH, SIG_SQUASHFS_LE),
    E9_SIG_ENTRY("squashfsbe", "SquashFS filesystem (BE)", E9_SIG_CAT_FILESYSTEM, E9_SIG_CONFIDENCE_HIGH, SIG_SQUASHFS_BE),
    E9_SIG_ENTRY("cramfs", "CramFS filesystem", E9_SIG_CAT_FILESYSTEM, E9_SIG_CONFIDENCE_HIGH, SIG_CRAMFS),
    E9_SIG_ENTRY("jffs2le", "JFFS2 filesystem (LE)", E9_SIG_CAT_FILESYSTEM, E9_SIG_CONFIDENCE_HIGH, SIG_JFFS2_LE_1),
    E9_SIG_ENTRY("jffs2be", "JFFS2 filesystem (BE)", E9_SIG_CAT_FILESYSTEM, E9_SIG_CONFIDENCE_HIGH, SIG_JFFS2_BE_1),
    E9_SIG_ENTRY("ubi", "UBI image", E9_SIG_CAT_FILESYSTEM, E9_SIG_CONFIDENCE_HIGH, SIG_UBI),
    E9_SIG_ENTRY("ubifs", "UBIFS filesystem", E9_SIG_CAT_FILESYSTEM, E9_SIG_CONFIDENCE_HIGH, SIG_UBIFS),
    E9_SIG_ENTRY_OFFSET("ext", "ext2/3/4 filesystem", E9_SIG_CAT_FILESYSTEM, E9_SIG_CONFIDENCE_HIGH, SIG_EXT_MAGIC, 0x438),
    E9_SIG_ENTRY("ntfs", "NTFS filesystem", E9_SIG_CAT_FILESYSTEM, E9_SIG_CONFIDENCE_HIGH, SIG_NTFS),
    E9_SIG_ENTRY("btrfs", "BTRFS filesystem", E9_SIG_CAT_FILESYSTEM, E9_SIG_CONFIDENCE_HIGH, SIG_BTRFS),
    E9_SIG_ENTRY("iso9660", "ISO 9660 CD-ROM", E9_SIG_CAT_FILESYSTEM, E9_SIG_CONFIDENCE_HIGH, SIG_ISO9660),

    /* Firmware */
    E9_SIG_ENTRY("uefifv", "UEFI Firmware Volume", E9_SIG_CAT_FIRMWARE, E9_SIG_CONFIDENCE_HIGH, SIG_UEFI_FV),
    E9_SIG_ENTRY("ueficap", "UEFI Capsule", E9_SIG_CAT_FIRMWARE, E9_SIG_CONFIDENCE_HIGH, SIG_UEFI_CAPSULE),
    E9_SIG_ENTRY("uboot", "U-Boot image", E9_SIG_CAT_FIRMWARE, E9_SIG_CONFIDENCE_HIGH, SIG_UBOOT_IMAGE),
    E9_SIG_ENTRY("dtb", "Device Tree Blob", E9_SIG_CAT_FIRMWARE, E9_SIG_CONFIDENCE_HIGH, SIG_DTB),
    E9_SIG_ENTRY("androidboot", "Android boot image", E9_SIG_CAT_FIRMWARE, E9_SIG_CONFIDENCE_HIGH, SIG_ANDROID_BOOT),
    E9_SIG_ENTRY("androidsparse", "Android sparse image", E9_SIG_CAT_FIRMWARE, E9_SIG_CONFIDENCE_HIGH, SIG_ANDROID_SPARSE),

    /* Images */
    E9_SIG_ENTRY("png", "PNG image", E9_SIG_CAT_IMAGE, E9_SIG_CONFIDENCE_HIGH, SIG_PNG),
    E9_SIG_ENTRY("jpeg", "JPEG image (JFIF)", E9_SIG_CAT_IMAGE, E9_SIG_CONFIDENCE_HIGH, SIG_JPEG_JFIF),
    E9_SIG_ENTRY("jpegexif", "JPEG image (EXIF)", E9_SIG_CAT_IMAGE, E9_SIG_CONFIDENCE_MEDIUM, SIG_JPEG_EXIF),
    E9_SIG_ENTRY("gif87", "GIF image (87a)", E9_SIG_CAT_IMAGE, E9_SIG_CONFIDENCE_HIGH, SIG_GIF87),
    E9_SIG_ENTRY("gif89", "GIF image (89a)", E9_SIG_CAT_IMAGE, E9_SIG_CONFIDENCE_HIGH, SIG_GIF89),
    E9_SIG_ENTRY_SHORT("bmp", "BMP image", E9_SIG_CAT_IMAGE, E9_SIG_CONFIDENCE_MEDIUM, SIG_BMP),

    /* Documents */
    E9_SIG_ENTRY("pdf", "PDF document", E9_SIG_CAT_DOCUMENT, E9_SIG_CONFIDENCE_HIGH, SIG_PDF),
    E9_SIG_ENTRY("ole2", "OLE2 Compound Document", E9_SIG_CAT_DOCUMENT, E9_SIG_CONFIDENCE_HIGH, SIG_OLE2),

    /* Databases */
    E9_SIG_ENTRY("sqlite", "SQLite database", E9_SIG_CAT_DATA, E9_SIG_CONFIDENCE_HIGH, SIG_SQLITE),

    /* Media */
    E9_SIG_ENTRY("riff", "RIFF container (WAV/AVI)", E9_SIG_CAT_MEDIA, E9_SIG_CONFIDENCE_MEDIUM, SIG_RIFF),
    E9_SIG_ENTRY("ogg", "Ogg container", E9_SIG_CAT_MEDIA, E9_SIG_CONFIDENCE_HIGH, SIG_OGG),
    E9_SIG_ENTRY("flac", "FLAC audio", E9_SIG_CAT_MEDIA, E9_SIG_CONFIDENCE_HIGH, SIG_FLAC),
    E9_SIG_ENTRY("id3", "MP3 with ID3 tag", E9_SIG_CAT_MEDIA, E9_SIG_CONFIDENCE_MEDIUM, SIG_ID3),
    E9_SIG_ENTRY("ebml", "EBML container (WebM/MKV)", E9_SIG_CAT_MEDIA, E9_SIG_CONFIDENCE_HIGH, SIG_EBML),

    /* Crypto */
    E9_SIG_ENTRY("pgparmor", "PGP armored data", E9_SIG_CAT_CRYPTO, E9_SIG_CONFIDENCE_HIGH, SIG_PGP_ARMOR),
    E9_SIG_ENTRY("sshkey", "OpenSSH private key", E9_SIG_CAT_CRYPTO, E9_SIG_CONFIDENCE_HIGH, SIG_SSH_PRIVKEY),
    E9_SIG_ENTRY("x509pem", "X.509 certificate (PEM)", E9_SIG_CAT_CRYPTO, E9_SIG_CONFIDENCE_HIGH, SIG_X509_PEM),
    E9_SIG_ENTRY("aessbox", "AES S-Box (potential crypto)", E9_SIG_CAT_CRYPTO, E9_SIG_CONFIDENCE_LOW, SIG_AES_SBOX),

    /* End marker */
    { NULL, NULL, 0, 0, false, 0, NULL, 0, NULL, NULL, 0 }
};

#define E9_NUM_SIGNATURES (sizeof(E9_SIGNATURE_DB) / sizeof(E9_SIGNATURE_DB[0]) - 1)

/*
 * ============================================================================
 * Signature Scanning API
 * ============================================================================
 */

typedef struct {
    const E9Signature *sig;         /* Which signature matched */
    size_t offset;                  /* Where in the data */
    size_t size;                    /* Estimated size (0 if unknown) */
    uint8_t confidence;             /* Adjusted confidence */
    char description[256];          /* Human-readable description */
} E9SigMatch;

/*
 * Initialize signature scanner (builds search automaton)
 */
typedef struct E9SigScanner E9SigScanner;
E9SigScanner *e9_sig_scanner_create(void);
void e9_sig_scanner_free(E9SigScanner *scanner);

/*
 * Scan data for signatures
 */
E9SigMatch *e9_sig_scan(E9SigScanner *scanner, const uint8_t *data, size_t size,
                        uint32_t *count);

/*
 * Free scan results
 */
void e9_sig_matches_free(E9SigMatch *matches);

/*
 * Simple single-signature check
 */
bool e9_sig_check(const uint8_t *data, size_t size, const char *sig_name);

/*
 * Get signature by name
 */
const E9Signature *e9_sig_lookup(const char *name);

/*
 * Iterate over all signatures
 */
const E9Signature *e9_sig_iter(size_t *index);

#ifdef __cplusplus
}
#endif

#endif /* E9SIGNATURES_H */
