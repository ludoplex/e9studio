/*
 * livereload_test.c - tests for the live-reload file watcher, the
 * shell-free compiler invocation, and APE self-location/parsing
 *
 * The binary doubles as a fake compiler: with E9_FAKE_CC=1 in its
 * environment it answers `--version` and `... -c SRC -o OUT` (copying SRC
 * to OUT) instead of running the tests. That lets the tests spawn a real
 * "compiler" on every OS without depending on one being installed.
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
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "e9ape.h"
#include "e9livereload.h"

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

/* Fake compiler mode (see file comment). Exits; never returns when active. */
static void fake_cc(int argc, char **argv)
{
    if (!getenv("E9_FAKE_CC"))
        return;
    if (argc == 2 && strcmp(argv[1], "--version") == 0) {
        puts("e9-fake-cc 1.0");
        exit(0);
    }
    const char *src = NULL, *out = NULL;
    for (int i = 1; i + 1 < argc; i++) {
        if (strcmp(argv[i], "-c") == 0) src = argv[i + 1];
        if (strcmp(argv[i], "-o") == 0) out = argv[i + 1];
    }
    exit(src && out && copy_file(src, out) == 0 ? 0 : 3);
}
#define E9TEST_PRE_MAIN(argc, argv) fake_cc(argc, argv)
#include "testlib.h"

static int write_text(const char *path, const char *text)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return -1;
    ssize_t n = write(fd, text, strlen(text));
    close(fd);
    return n == (ssize_t)strlen(text) ? 0 : -1;
}

static bool exists(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0;
}

TEST(ape, self_path_is_found)
{
    const char *self = e9_ape_get_self_path();
    ASSERT_TRUE(self != NULL);
    EXPECT_TRUE(exists(self));
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

/* Temporary layout shared by the live-reload tests */
typedef struct {
    char dir[64], target[512], src[512], cache[512];
} Scratch;

static int scratch_init(Scratch *s)
{
    snprintf(s->dir, sizeof(s->dir), "/tmp/e9lrtest.XXXXXX");
    if (!mkdtemp(s->dir)) return -1;
    snprintf(s->target, sizeof(s->target), "%s/target.com", s->dir);
    snprintf(s->src, sizeof(s->src), "%s/src", s->dir);
    snprintf(s->cache, sizeof(s->cache), "%s/cache", s->dir);
    if (mkdir(s->src, 0755) != 0) return -1;
    /* the running APE is locked on some hosts; watch a copy of it */
    return copy_file(e9_ape_get_self_path(), s->target);
}

static void scratch_remove(Scratch *s, const char *const *files)
{
    char path[1024];
    for (; *files; files++) {
        snprintf(path, sizeof(path), "%s/%s", s->src, *files);
        unlink(path);
        snprintf(path, sizeof(path), "%s/%s.o", s->cache, *files);
        unlink(path);
        snprintf(path, sizeof(path), "%s/%s.new.o", s->cache, *files);
        unlink(path);
    }
    rmdir(s->cache);
    rmdir(s->src);
    unlink(s->target);
    rmdir(s->dir);
}

TEST(livereload, watcher_reports_new_and_edited_sources_only)
{
#ifndef __COSMOPOLITAN__
    SKIP_TEST("needs an APE target; build with cosmocc");
#else
    Scratch s;
    ASSERT_EQ(0, scratch_init(&s));
    E9LiveReloadConfig cfg = E9_LIVERELOAD_CONFIG_DEFAULT;
    cfg.source_dir = s.src;
    cfg.cache_dir = s.cache;
    cfg.compiler = "e9-no-such-compiler";   /* spawn fails fast, no shell */
    cfg.enable_hot_patch = false;
    ASSERT_EQ(0, e9_livereload_init(s.target, &cfg));
    ASSERT_EQ(0, e9_livereload_watch());
    EXPECT_EQ(0, e9_livereload_poll());               /* empty baseline */

    char a[600], notes[600];
    snprintf(a, sizeof(a), "%s/a.c", s.src);
    snprintf(notes, sizeof(notes), "%s/notes.txt", s.src);
    ASSERT_EQ(0, write_text(a, "int f(void){return 1;}\n"));
    EXPECT_EQ(1, e9_livereload_poll());               /* new file */
    EXPECT_EQ(0, e9_livereload_poll());               /* unchanged */
    ASSERT_EQ(0, write_text(a, "int f(void){return 22;}\n"));
    EXPECT_EQ(1, e9_livereload_poll());               /* edited (size differs) */
    ASSERT_EQ(0, write_text(notes, "not a source file\n"));
    EXPECT_EQ(0, e9_livereload_poll());               /* ignored */

    E9LiveReloadStats stats;
    e9_livereload_get_stats(&stats);
    EXPECT_EQ(2, stats.changes_detected);
    e9_livereload_shutdown();
    static const char *const files[] = {"a.c", "notes.txt", NULL};
    scratch_remove(&s, files);
#endif
}

TEST(livereload, compiler_gets_file_names_as_argv_not_via_a_shell)
{
#ifndef __COSMOPOLITAN__
    SKIP_TEST("needs an APE target; build with cosmocc");
#else
    Scratch s;
    ASSERT_EQ(0, scratch_init(&s));
    ASSERT_EQ(0, setenv("E9_FAKE_CC", "1", 1));      /* children act as the compiler */
    E9LiveReloadConfig cfg = E9_LIVERELOAD_CONFIG_DEFAULT;
    cfg.source_dir = s.src;
    cfg.cache_dir = s.cache;
    cfg.compiler = e9_ape_get_self_path();
    cfg.enable_hot_patch = false;
    ASSERT_EQ(0, e9_livereload_init(s.target, &cfg));

    EXPECT_TRUE(e9_livereload_compiler_available());   /* spawn + /dev/null */
    EXPECT_STREQ("e9-fake-cc 1.0", e9_livereload_compiler_version());  /* spawn + pipe */

    ASSERT_EQ(0, e9_livereload_watch());
    static const char evil_name[] = "y;touch PWNED;.c";
    char evil[600], cached[600], pwned[600];
    snprintf(evil, sizeof(evil), "%s/%s", s.src, evil_name);
    snprintf(cached, sizeof(cached), "%s/%s.o", s.cache, evil_name);
    snprintf(pwned, sizeof(pwned), "%s/PWNED", s.src);
    ASSERT_EQ(0, write_text(evil, "int g;\n"));
    ASSERT_EQ(0, chdir(s.src));
    EXPECT_EQ(1, e9_livereload_poll());
    /* the fake compiler received the whole name as one argument and
     * produced the object the watcher then cached under that name */
    EXPECT_TRUE(exists(cached));
    EXPECT_TRUE(!exists(pwned));
    EXPECT_TRUE(!exists("PWNED"));

    e9_livereload_shutdown();
    unsetenv("E9_FAKE_CC");
    ASSERT_EQ(0, chdir("/tmp"));   /* leave the directory before removing it */
    static const char *const files[] = {"y;touch PWNED;.c", NULL};
    scratch_remove(&s, files);
#endif
}
