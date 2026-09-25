/*
 * livereload_test.c - tests for the live-reload file watcher, the
 * shell-free compiler invocation, and APE self-location
 *
 * Copyright (C) 2026 E9Studio Contributors
 * License: GPLv3+
 */

#if defined(__COSMOPOLITAN__) && !defined(_COSMO_SOURCE)
#define _COSMO_SOURCE
#endif

#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/stat.h>
#include <unistd.h>

#include "e9ape.h"
#include "e9livereload.h"
#include "testlib.h"

static int write_text(const char *path, const char *text)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return -1;
    ssize_t n = write(fd, text, strlen(text));
    close(fd);
    return n == (ssize_t)strlen(text) ? 0 : -1;
}

static int copy_file(const char *from, const char *to)
{
    char buf[65536];
    int in = open(from, O_RDONLY), out = open(to, O_WRONLY | O_CREAT | O_TRUNC, 0755);
    ssize_t n = 0;
    while (in >= 0 && out >= 0 && (n = read(in, buf, sizeof(buf))) > 0)
        if (write(out, buf, (size_t)n) != n) { n = -1; break; }
    if (in >= 0) close(in);
    if (out >= 0) close(out);
    return (in < 0 || out < 0 || n < 0) ? -1 : 0;
}

TEST(ape, self_path_is_found)
{
    const char *self = e9_ape_get_self_path();
    ASSERT_TRUE(self != NULL);
    struct stat st;
    EXPECT_EQ(0, stat(self, &st));
    printf("  self=%s\n", self);
}

TEST(ape, parses_own_fat_binary)
{
#ifndef __COSMOPOLITAN__
    SKIP_TEST("the test binary is only an APE when built with cosmocc");
#else
    int fd = open(e9_ape_get_self_path(), O_RDONLY);
    ASSERT_TRUE(fd >= 0);
    struct stat st;
    ASSERT_EQ(0, fstat(fd, &st));
    uint8_t *data = malloc((size_t)st.st_size);
    ASSERT_TRUE(data != NULL);
    ssize_t got = 0, n;
    while (got < st.st_size && (n = read(fd, data + got, (size_t)(st.st_size - got))) > 0)
        got += n;
    close(fd);
    ASSERT_EQ(st.st_size, got);

    E9_APEInfo info;
    EXPECT_TRUE(e9_ape_detect(data, (size_t)got));
    EXPECT_EQ(0, e9_ape_parse(data, (size_t)got, &info));
    EXPECT_TRUE(info.is_cosmopolitan);
    /* cosmocc links x86-64 and AArch64 into one file; the AArch64 image is
     * an ELF whose magic ("\x7f" "ELF") must be found */
    EXPECT_TRUE(info.has_arm64_elf);
    free(data);
#endif
}

TEST(livereload, watcher_reports_changes_without_a_shell)
{
#ifndef __COSMOPOLITAN__
    SKIP_TEST("needs an APE target; build with cosmocc");
#else
    char dir[] = "/tmp/e9lrtest.XXXXXX";
    ASSERT_TRUE(mkdtemp(dir) != NULL);
    char target[512], src[512], cache[512], evil[512], pwned[512];
    snprintf(target, sizeof(target), "%s/target.com", dir);
    snprintf(src, sizeof(src), "%s/src", dir);
    snprintf(cache, sizeof(cache), "%s/cache", dir);
    snprintf(pwned, sizeof(pwned), "%s/src/PWNED", dir);
    ASSERT_EQ(0, mkdir(src, 0755));

    /* the running APE is locked on some hosts; watch a copy of it */
    ASSERT_EQ(0, copy_file(e9_ape_get_self_path(), target));

    E9LiveReloadConfig cfg = E9_LIVERELOAD_CONFIG_DEFAULT;
    cfg.source_dir = src;
    cfg.cache_dir = cache;
    cfg.compiler = "e9-no-such-compiler";   /* spawn fails fast, no shell */
    cfg.enable_hot_patch = false;
    ASSERT_EQ(0, e9_livereload_init(target, &cfg));
    ASSERT_EQ(0, e9_livereload_watch());

    E9LiveReloadStats stats;
    EXPECT_EQ(0, e9_livereload_poll());               /* empty baseline */

    char a[600];
    snprintf(a, sizeof(a), "%s/a.c", src);
    ASSERT_EQ(0, write_text(a, "int f(void){return 1;}\n"));
    EXPECT_EQ(1, e9_livereload_poll());               /* new file */
    EXPECT_EQ(0, e9_livereload_poll());               /* unchanged */
    ASSERT_EQ(0, write_text(a, "int f(void){return 22;}\n"));
    EXPECT_EQ(1, e9_livereload_poll());               /* edited */

    char readme[600];
    snprintf(readme, sizeof(readme), "%s/notes.txt", src);
    ASSERT_EQ(0, write_text(readme, "not a source file\n"));
    EXPECT_EQ(0, e9_livereload_poll());               /* ignored */

    /* a hostile file name must reach the compiler as one argv element */
    snprintf(evil, sizeof(evil), "%s/x;touch PWNED;.c", src);
    ASSERT_EQ(0, write_text(evil, "int g;\n"));
    ASSERT_EQ(0, chdir(src));
    EXPECT_EQ(1, e9_livereload_poll());
    struct stat st;
    EXPECT_TRUE(stat(pwned, &st) != 0);

    e9_livereload_get_stats(&stats);
    EXPECT_EQ(3, stats.changes_detected);

    e9_livereload_unwatch();
    e9_livereload_shutdown();
    unlink(evil);
    unlink(readme);
    unlink(a);
    rmdir(cache);
    rmdir(src);
    unlink(target);
    rmdir(dir);
#endif
}
