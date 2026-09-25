/*
 * testlib.h - minimal TEST()/EXPECT_*() harness
 *
 * Mirrors the shape of Cosmopolitan's libc/testlib (TEST(suite, name)
 * blocks, EXPECT_EQ / EXPECT_STREQ / ASSERT_* macros, one program per test
 * file). The cosmocc release does not ship libtestlib, so this header keeps
 * the tests self-contained and buildable with cosmocc or a host cc.
 *
 * Copyright (C) 2026 E9Studio Contributors
 * License: GPLv3+
 */

#ifndef E9_TESTLIB_H
#define E9_TESTLIB_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct e9test {
    const char *suite;
    const char *name;
    void (*fn)(void);
    struct e9test *next;
} e9test;

static e9test *e9test_head;
static e9test **e9test_tail = &e9test_head;
static int e9test_failures;
static int e9test_skipped;

#define TEST(SUITE, NAME)                                                   \
    static void SUITE##_##NAME(void);                                       \
    __attribute__((constructor)) static void SUITE##_##NAME##_register(void) \
    {                                                                       \
        static e9test t = {#SUITE, #NAME, SUITE##_##NAME, NULL};            \
        *e9test_tail = &t;                                                  \
        e9test_tail = &t.next;                                              \
    }                                                                       \
    static void SUITE##_##NAME(void)

#define E9TEST_FAIL(...)                                                    \
    do {                                                                    \
        fprintf(stderr, "%s:%d: ", __FILE__, __LINE__);                     \
        fprintf(stderr, __VA_ARGS__);                                       \
        fputc('\n', stderr);                                                \
        e9test_failures++;                                                  \
    } while (0)

#define EXPECT_EQ(WANT, GOT)                                                \
    do {                                                                    \
        long long w_ = (long long)(WANT), g_ = (long long)(GOT);            \
        if (w_ != g_)                                                       \
            E9TEST_FAIL("EXPECT_EQ(%s, %s): want %lld, got %lld",           \
                        #WANT, #GOT, w_, g_);                               \
    } while (0)

#define EXPECT_NE(A, B)                                                     \
    do {                                                                    \
        long long a_ = (long long)(A), b_ = (long long)(B);                 \
        if (a_ == b_)                                                       \
            E9TEST_FAIL("EXPECT_NE(%s, %s): both %lld", #A, #B, a_);        \
    } while (0)

#define EXPECT_TRUE(X)                                                      \
    do {                                                                    \
        if (!(X)) E9TEST_FAIL("EXPECT_TRUE(%s)", #X);                       \
    } while (0)

#define EXPECT_STREQ(WANT, GOT)                                             \
    do {                                                                    \
        const char *w_ = (WANT), *g_ = (GOT);                               \
        if (!w_ || !g_ || strcmp(w_, g_) != 0)                              \
            E9TEST_FAIL("EXPECT_STREQ(%s, %s): want \"%s\", got \"%s\"",    \
                        #WANT, #GOT, w_ ? w_ : "(null)", g_ ? g_ : "(null)"); \
    } while (0)

/* ASSERT_* stop the current test on failure */
#define ASSERT_TRUE(X)                                                      \
    do {                                                                    \
        if (!(X)) { E9TEST_FAIL("ASSERT_TRUE(%s)", #X); return; }           \
    } while (0)

#define ASSERT_EQ(WANT, GOT)                                                \
    do {                                                                    \
        long long w_ = (long long)(WANT), g_ = (long long)(GOT);            \
        if (w_ != g_) {                                                     \
            E9TEST_FAIL("ASSERT_EQ(%s, %s): want %lld, got %lld",           \
                        #WANT, #GOT, w_, g_);                               \
            return;                                                         \
        }                                                                   \
    } while (0)

#define SKIP_TEST(WHY)                                                      \
    do {                                                                    \
        printf("  skipped: %s\n", WHY);                                     \
        e9test_skipped++;                                                   \
        return;                                                             \
    } while (0)

/* A test file may define E9TEST_PRE_MAIN(argc, argv) before including this
 * header, e.g. to let the test binary double as a helper program it spawns. */
#ifndef E9TEST_PRE_MAIN
#define E9TEST_PRE_MAIN(argc, argv) ((void)(argc), (void)(argv))
#endif

int main(int argc, char **argv)
{
    E9TEST_PRE_MAIN(argc, argv);
    int n = 0;
    for (e9test *t = e9test_head; t; t = t->next, n++) {
        int before = e9test_failures;
        printf("TEST %s.%s\n", t->suite, t->name);
        t->fn();
        if (e9test_failures != before) printf("  FAILED\n");
    }
    printf("%d tests, %d failures, %d skipped\n", n, e9test_failures, e9test_skipped);
    return e9test_failures ? 1 : 0;
}

#endif /* E9_TESTLIB_H */
