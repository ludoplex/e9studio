/*
 * procmem_test.c - tests for the unified process memory API (e9procmem.c)
 *
 * Run as an APE, the same binary exercises whichever backend the host OS
 * selects at run time: /proc/PID/mem on Linux, NT handles on Windows, and
 * the "not implemented" path on macOS / BSD.
 *
 * Copyright (C) 2026 E9Studio Contributors
 * License: GPLv3+
 */

#if defined(__COSMOPOLITAN__) && !defined(_COSMO_SOURCE)
#define _COSMO_SOURCE
#endif

#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

#ifdef __COSMOPOLITAN__
#include <cosmo.h>
#endif

#include "e9procmem.h"
#include "testlib.h"

/* Lives at the same address in a fork()ed child. */
static volatile uint64_t g_shared_word = 0x1122334455667788ull;

TEST(procmem, platform_info_matches_host)
{
    E9PlatformInfo info;
    e9_procmem_get_platform(&info);
    EXPECT_EQ(sysconf(_SC_PAGESIZE), info.page_size);
    EXPECT_EQ(1, info.can_self);
#ifdef __COSMOPOLITAN__
    if (IsLinux()) {
        EXPECT_EQ(PROCMEM_OS_LINUX, info.os);
        EXPECT_EQ(1, info.can_remote);
        EXPECT_STREQ("procfs", info.backend);
    } else if (IsWindows()) {
        EXPECT_EQ(PROCMEM_OS_WINDOWS, info.os);
        EXPECT_EQ(1, info.can_remote);
        EXPECT_STREQ("nt", info.backend);
    } else if (IsXnu()) {
        EXPECT_EQ(PROCMEM_OS_MACOS, info.os);
        EXPECT_EQ(0, info.can_remote);   /* must not claim a backend it lacks */
        EXPECT_STREQ("self", info.backend);
    }
#endif
    printf("  os=%s arch=%s backend=%s page=%u\n", procmem_os_str(info.os),
           procmem_arch_str(info.arch), info.backend, (unsigned)info.page_size);
}

TEST(procmem, self_read)
{
    static const char text[] = "e9procmem";
    char buf[sizeof(text)];
    E9ProcHandle h;
    ASSERT_EQ(PROCMEM_OK, e9_procmem_open(&h, 0, PROCMEM_READ));
    EXPECT_EQ(PROCMEM_OK, e9_procmem_read(&h, (uintptr_t)text, buf, sizeof(buf)));
    EXPECT_STREQ(text, buf);
    e9_procmem_close(&h);
}

TEST(procmem, self_write_spanning_two_pages)
{
    size_t pg = (size_t)sysconf(_SC_PAGESIZE);
    unsigned char *m = mmap(NULL, 2 * pg, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    ASSERT_TRUE(m != MAP_FAILED);
    ASSERT_EQ(0, mprotect(m, 2 * pg, PROT_READ));      /* start read-only */

    const unsigned char patch[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    uint64_t addr = (uintptr_t)(m + pg - 4);           /* straddles the boundary */
    E9ProcHandle h;
    ASSERT_EQ(PROCMEM_OK, e9_procmem_open(&h, 0, PROCMEM_READ | PROCMEM_WRITE));
    int rc = e9_procmem_write(&h, addr, patch, sizeof(patch));
    if (rc == PROCMEM_ERR_PERM) {
        /* W^X hosts (e.g. Apple silicon) refuse RWX pages: must be reported */
        printf("  RWX refused by host: %s\n", e9_procmem_error(&h));
        EXPECT_TRUE(strstr(e9_procmem_error(&h), "mprotect") != NULL);
    } else {
        EXPECT_EQ(PROCMEM_OK, rc);
        EXPECT_EQ(0, memcmp(m + pg - 4, patch, sizeof(patch)));
    }
    e9_procmem_close(&h);
    munmap(m, 2 * pg);
}

TEST(procmem, protect_uses_real_page_size)
{
    size_t pg = (size_t)sysconf(_SC_PAGESIZE);
    unsigned char *m = mmap(NULL, 2 * pg, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    ASSERT_TRUE(m != MAP_FAILED);
    E9ProcHandle h;
    ASSERT_EQ(PROCMEM_OK, e9_procmem_open(&h, 0, PROCMEM_READ));
    /* unaligned start inside the 2nd page: must align down by the host page
     * size (16 KiB on Apple silicon), not by a hard-coded 4 KiB mask */
    EXPECT_EQ(PROCMEM_OK, e9_procmem_protect(&h, (uintptr_t)(m + pg + 100), 10,
                                             PROCMEM_READ));
    EXPECT_EQ(PROCMEM_OK, e9_procmem_protect(&h, (uintptr_t)(m + pg + 100), 10,
                                             PROCMEM_READ | PROCMEM_WRITE));
    m[pg + 100] = 42;
    EXPECT_EQ(42, m[pg + 100]);
    e9_procmem_close(&h);
    munmap(m, 2 * pg);
}

TEST(procmem, closed_handle_is_rejected)
{
    E9ProcHandle h;
    char c;
    memset(&h, 0, sizeof(h));
    EXPECT_EQ(PROCMEM_ERR_PLATFORM, e9_procmem_read(&h, (uintptr_t)&c, &c, 1));
}

TEST(procmem, remote_child_read_write)
{
    int ready[2], release[2];
    ASSERT_EQ(0, pipe(ready));
    ASSERT_EQ(0, pipe(release));
    pid_t pid = fork();
    ASSERT_TRUE(pid >= 0);
    if (pid == 0) {
        char c = 0;
        close(ready[0]);
        close(release[1]);
        ssize_t ignored = write(ready[1], "r", 1);   /* child is up */
        (void)ignored;
        ignored = read(release[0], &c, 1);          /* wait for the parent */
        _exit(g_shared_word == 0xCAFEF00DDEADBEEFull ? 0 : 7);
    }
    char c;
    close(ready[1]);
    close(release[0]);
    ASSERT_EQ(1, read(ready[0], &c, 1));

    E9PlatformInfo info;
    e9_procmem_get_platform(&info);
    E9ProcHandle h;
    int rc = e9_procmem_open(&h, pid, PROCMEM_READ | PROCMEM_WRITE);
    int expect_child = 7;
    if (!info.can_remote) {
        EXPECT_EQ(PROCMEM_ERR_PLATFORM, rc);
        printf("  remote access unsupported here, as reported: %s\n", e9_procmem_error(&h));
    } else if (rc != PROCMEM_OK) {
        E9TEST_FAIL("open(child %d): %s", (int)pid, e9_procmem_error(&h));
    } else {
        uint64_t v = 0, nv = 0xCAFEF00DDEADBEEFull;
        EXPECT_EQ(PROCMEM_OK, e9_procmem_read(&h, (uintptr_t)&g_shared_word, &v, sizeof(v)));
        EXPECT_EQ(0x1122334455667788ull, v);
        EXPECT_EQ(PROCMEM_OK, e9_procmem_write(&h, (uintptr_t)&g_shared_word, &nv, sizeof(nv)));
        EXPECT_EQ(PROCMEM_OK, e9_procmem_read(&h, (uintptr_t)&g_shared_word, &v, sizeof(v)));
        EXPECT_EQ(nv, v);
        EXPECT_EQ(0x1122334455667788ull, g_shared_word);   /* parent untouched */
        expect_child = 0;                                  /* child sees the write */
    }
    e9_procmem_close(&h);

    ssize_t ignored = write(release[1], "g", 1);
    (void)ignored;
    int status = 0;
    ASSERT_EQ(pid, waitpid(pid, &status, 0));
    EXPECT_TRUE(WIFEXITED(status));
    EXPECT_EQ(expect_child, WEXITSTATUS(status));
    close(ready[0]);
    close(release[1]);
}
