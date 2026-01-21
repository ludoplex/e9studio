/*
 * e9studio_gui_main.c
 * E9Studio GUI/TUI Unified Entry Point
 *
 * Provides automatic GUI/TUI selection based on environment.
 * Falls back to TUI mode when GUI is not available.
 *
 * Copyright (C) 2024 E9Patch Contributors
 * License: GPLv3+
 */

#include "e9studio_tedit.h"
#include "e9studio_gui.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Forward declaration - original TUI main from e9studio.c */
/* Weak symbol allows standalone GUI build without TUI */
__attribute__((weak))
int e9studio_tui_main(int argc, char **argv)
{
    (void)argc; (void)argv;
    fprintf(stderr, "[e9studio] TUI mode not available in this build.\n");
    fprintf(stderr, "[e9studio] Use --cli for command-line interface.\n");
    return 1;
}

/*
 * ============================================================================
 * Command Line Parsing
 * ============================================================================
 */

static void print_usage(const char *prog)
{
    printf("E9Studio - Binary Analysis and Patching Tool\n\n");
    printf("Usage: %s [options] [binary]\n\n", prog);
    printf("Options:\n");
    printf("  -h, --help              Show this help\n");
    printf("  -v, --version           Show version\n");
    printf("  -t, --tui               Force TUI mode\n");
    printf("  -g, --gui               Force GUI mode (if available)\n");
    printf("  --cli                   Force CLI mode (text commands)\n");
    printf("  -c, --config <file>     Load configuration file\n");
    printf("  -m, --menu <file>       Load menu from INI file\n");
    printf("  -s, --script <file>     Run script file\n");
    printf("  --self-test             Run self-test diagnostics\n");
    printf("\n");
    printf("Environment:\n");
    printf("  E9STUDIO_TUI=1          Force TUI mode\n");
    printf("  E9STUDIO_BACKEND=<x>    Force backend (tui|win32|x11|cocoa)\n");
    printf("\n");
    printf("Examples:\n");
    printf("  %s /bin/ls              Analyze /bin/ls\n", prog);
    printf("  %s --tui program.elf    Analyze in TUI mode\n", prog);
    printf("  %s --cli                Start CLI interface\n", prog);
    printf("\n");
}

static void print_version(void)
{
    printf("e9studio %s\n", "0.1.0");
    printf("GUI Framework: %s\n", e9gui_version());
    printf("Platform: %s\n", e9gui_platform_name(e9gui_get_platform()));
    printf("Backend: %s (auto-detected)\n", e9gui_backend_name(e9gui_detect_backend()));
    printf("\n");
    printf("Built with Cosmopolitan Libc for cross-platform portability.\n");
    printf("License: GPLv3+\n");
}

typedef enum {
    MODE_AUTO,
    MODE_TUI,
    MODE_GUI,
    MODE_CLI
} E9StartMode;

typedef struct {
    E9StartMode mode;
    const char *binary_path;
    const char *config_path;
    const char *menu_path;
    const char *script_path;
    int self_test;
} E9StartupOptions;

static int parse_args(int argc, char **argv, E9StartupOptions *opts)
{
    memset(opts, 0, sizeof(E9StartupOptions));
    opts->mode = MODE_AUTO;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return -1;  /* Signal to exit */
        }
        if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--version") == 0) {
            print_version();
            return -1;
        }
        if (strcmp(argv[i], "-t") == 0 || strcmp(argv[i], "--tui") == 0) {
            opts->mode = MODE_TUI;
        }
        else if (strcmp(argv[i], "-g") == 0 || strcmp(argv[i], "--gui") == 0) {
            opts->mode = MODE_GUI;
        }
        else if (strcmp(argv[i], "--cli") == 0) {
            opts->mode = MODE_CLI;
        }
        else if (strcmp(argv[i], "--self-test") == 0) {
            opts->self_test = 1;
        }
        else if ((strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--config") == 0) && i + 1 < argc) {
            opts->config_path = argv[++i];
        }
        else if ((strcmp(argv[i], "-m") == 0 || strcmp(argv[i], "--menu") == 0) && i + 1 < argc) {
            opts->menu_path = argv[++i];
        }
        else if ((strcmp(argv[i], "-s") == 0 || strcmp(argv[i], "--script") == 0) && i + 1 < argc) {
            opts->script_path = argv[++i];
        }
        else if (argv[i][0] != '-' && !opts->binary_path) {
            opts->binary_path = argv[i];
        }
    }

    return 0;
}

/*
 * ============================================================================
 * Self-Test
 * ============================================================================
 */

static int run_self_test(void)
{
    printf("=== E9Studio Self-Test ===\n\n");

    int passed = 0;
    int failed = 0;

    /* Test 1: Platform detection */
    printf("1. Platform detection: ");
    E9Platform platform = e9gui_get_platform();
    if (platform != E9_PLATFORM_UNKNOWN) {
        printf("PASS (%s)\n", e9gui_platform_name(platform));
        passed++;
    } else {
        printf("FAIL (unknown platform)\n");
        failed++;
    }

    /* Test 2: Backend detection */
    printf("2. Backend detection: ");
    E9Backend backend = e9gui_detect_backend();
    printf("PASS (%s)\n", e9gui_backend_name(backend));
    passed++;

    /* Test 3: Editor creation */
    printf("3. Editor creation: ");
    E9EditorState *ed = e9editor_create();
    if (ed) {
        printf("PASS\n");
        passed++;
    } else {
        printf("FAIL\n");
        failed++;
    }

    /* Test 4: Buffer operations */
    printf("4. Buffer operations: ");
    if (ed) {
        e9editor_set_text(ed, "Hello, World!", 13);
        char buf[64];
        size_t len = e9editor_get_text(ed, buf, sizeof(buf));
        if (len == 13 && strcmp(buf, "Hello, World!") == 0) {
            printf("PASS\n");
            passed++;
        } else {
            printf("FAIL (got '%s', len=%zu)\n", buf, len);
            failed++;
        }
    } else {
        printf("SKIP\n");
    }

    /* Test 5: Insert operation */
    printf("5. Insert operation: ");
    if (ed) {
        e9editor_insert(ed, 7, "Beautiful ", 10);
        char buf[64];
        e9editor_get_text(ed, buf, sizeof(buf));
        if (strstr(buf, "Beautiful")) {
            printf("PASS\n");
            passed++;
        } else {
            printf("FAIL (got '%s')\n", buf);
            failed++;
        }
    } else {
        printf("SKIP\n");
    }

    /* Test 6: Language detection */
    printf("6. Language detection: ");
    E9Language lang = e9editor_detect_language("test.c");
    if (lang == E9_LANG_C) {
        printf("PASS (.c -> C)\n");
        passed++;
    } else {
        printf("FAIL\n");
        failed++;
    }

    /* Test 7: App state */
    printf("7. App state: ");
    E9AppState app;
    if (e9app_init(&app) == 0) {
        printf("PASS\n");
        passed++;
        e9app_shutdown(&app);
    } else {
        printf("FAIL\n");
        failed++;
    }

    /* Cleanup */
    if (ed) e9editor_destroy(ed);

    printf("\n=== Results: %d passed, %d failed ===\n", passed, failed);
    return failed > 0 ? 1 : 0;
}

/*
 * ============================================================================
 * Main Entry Point
 * ============================================================================
 */

int e9studio_gui_main(int argc, char **argv)
{
    E9StartupOptions opts;

    /* Parse command line */
    if (parse_args(argc, argv, &opts) < 0) {
        return 0;  /* Help or version printed */
    }

    /* Run self-test if requested */
    if (opts.self_test) {
        return run_self_test();
    }

    /* Determine mode */
    E9StartMode mode = opts.mode;
    if (mode == MODE_AUTO) {
        /* Auto-detect: use CLI by default, TUI if e9gui_should_use_tui returns true */
        if (e9gui_should_use_tui(argc, argv)) {
            mode = MODE_TUI;
        } else {
            /* Check if GUI backend is available */
            E9Backend backend = e9gui_detect_backend();
            if (backend == E9_BACKEND_TUI) {
                mode = MODE_CLI;  /* Fall back to CLI mode */
            } else {
                mode = MODE_GUI;
            }
        }
    }

    /* Route to appropriate interface */
    switch (mode) {
        case MODE_TUI:
            /* Use original TUI implementation */
            printf("[e9studio] Starting TUI mode...\n");
            return e9studio_tui_main(argc, argv);

        case MODE_GUI: {
            /* GUI mode - create window */
            printf("[e9studio] Starting GUI mode...\n");
            E9WindowConfig config = {
                .title = "E9Studio",
                .width = 1280,
                .height = 800,
                .resizable = true,
                .fullscreen = false,
                .backend = 0  /* Auto-detect */
            };

            E9Window *win = e9gui_create_window(&config);
            if (!win) {
                fprintf(stderr, "[e9studio] Failed to create window, falling back to CLI\n");
                mode = MODE_CLI;
                /* Fall through to CLI */
            } else {
                /* Check if we got TUI fallback */
                if (e9gui_window_get_backend(win) == E9_BACKEND_TUI) {
                    e9gui_destroy_window(win);
                    mode = MODE_CLI;
                    /* Fall through to CLI */
                } else {
                    /* TODO: Run GUI main loop with analysis panels */
                    e9gui_destroy_window(win);
                    return 0;
                }
            }
        }
        /* Fall through if GUI failed */
        __attribute__((fallthrough));

        case MODE_CLI:
        default: {
            /* CLI mode - text-based interface */
            E9AppState app;

            if (e9app_init(&app) != 0) {
                fprintf(stderr, "[e9studio] Failed to initialize application\n");
                return 1;
            }

            /* Load config if specified */
            if (opts.config_path) {
                e9build_load_config(&app.build, opts.config_path);
            }

            /* Load menu if specified */
            if (opts.menu_path) {
                e9menu_load_ini(&app.menus, opts.menu_path);
            }

            /* Open binary if specified */
            if (opts.binary_path) {
                e9app_load_binary(&app, opts.binary_path);
            }

            /* Initialize CLI platform */
            if (e9platform_init(&app) != 0) {
                fprintf(stderr, "[e9studio] Failed to initialize platform\n");
                e9app_shutdown(&app);
                return 1;
            }

            /* Run CLI event loop */
            int result = e9platform_run(&app);

            /* Cleanup */
            e9platform_shutdown(&app);
            e9app_shutdown(&app);

            return result;
        }
    }

    return 0;
}

/*
 * If compiled as standalone, use this as main()
 */
#ifdef E9STUDIO_GUI_STANDALONE
int main(int argc, char **argv)
{
    return e9studio_gui_main(argc, argv);
}
#endif
