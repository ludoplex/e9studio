/*
 * e9studio.c
 * Self-contained e9patch studio
 *
 * A single APE file that provides:
 * - Embedded WASM VM (wasm3)
 * - e9patch core (as WASM module in ZipOS)
 * - Embedded compiler (cosmocc as WASM in ZipOS)
 * - Terminal UI for editing
 * - File watcher for hot-reload
 * - Self-modification capability (save patches to own ZipOS)
 *
 * No browser or external tools required.
 *
 * Usage:
 *   ./e9studio.com target.elf          # Edit and patch target.elf
 *   ./e9studio.com --daemon             # Run as background service
 *   ./e9studio.com --self-test          # Run internal tests
 *
 * Copyright (C) 2024 E9Patch Contributors
 * License: GPLv3+
 */

/* Central config must be included first for feature test macros */
#include "e9studio_config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdbool.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/select.h>
#include <time.h>
#include <errno.h>

#include "e9wasm_host.h"

#ifdef __linux__
#include <sys/inotify.h>
#endif

/*
 * Execution mode for WASM runtime
 */
typedef enum {
    EXEC_MODE_DEFAULT = 0,   /* Use best available (Fast JIT if supported) */
    EXEC_MODE_INTERP = 1,    /* Fast interpreter */
    EXEC_MODE_JIT = 2,       /* Fast JIT compilation */
    EXEC_MODE_AOT = 3        /* Ahead-of-time compiled modules */
} ExecMode;

/*
 * Studio Configuration
 */
typedef struct {
    const char *target_path;        /* Path to target binary */
    const char *source_dir;         /* Directory containing source files */
    int port;                       /* Port for remote connections (0 = disabled) */
    bool daemon_mode;               /* Run as background service */
    bool verbose;                   /* Verbose output */
    bool tui_mode;                  /* Terminal UI mode */
    bool self_test;                 /* Run self-tests */
    ExecMode exec_mode;             /* WASM execution mode */
} StudioConfig;

static StudioConfig g_config = {
    .target_path = NULL,
    .source_dir = ".",
    .port = 0,
    .daemon_mode = false,
    .verbose = false,
    .tui_mode = true,
    .self_test = false,
    .exec_mode = EXEC_MODE_DEFAULT,
};

/*
 * State
 */
static volatile bool g_running = true;
static void *g_target_binary = NULL;
static size_t g_target_size = 0;

/*
 * Signal handler
 */
static void signal_handler(int sig) {
    (void)sig;
    g_running = false;
}

/*
 * Print usage
 */
static void print_usage(const char *prog) {
    printf("E9Patch Studio - Self-contained binary rewriting environment\n\n");
    printf("Usage: %s [options] [target.elf]\n\n", prog);
    printf("Options:\n");
    printf("  --source-dir DIR     Source files directory (default: .)\n");
    printf("  --port PORT          Enable remote connections on PORT\n");
    printf("  --daemon             Run as background service\n");
    printf("  --no-tui             Disable terminal UI\n");
    printf("  --verbose, -v        Verbose output\n");
    printf("  --self-test          Run internal tests\n");
    printf("  --help, -h           Show this help\n");
    printf("\n");
    printf("Execution Mode (WAMR runtime):\n");
    printf("  --jit                Use Fast JIT compilation (default if available)\n");
    printf("  --interp             Use fast interpreter (slower but more portable)\n");
    printf("  --aot                Use ahead-of-time compiled modules\n");
    printf("\n");
    printf("Interactive mode:\n");
    printf("  'e' - Edit source file\n");
    printf("  'r' - Force reload and patch\n");
    printf("  'b' - Set breakpoint\n");
    printf("  's' - Save patched binary\n");
    printf("  'q' - Quit\n");
    printf("\n");
    printf("ZipOS contents:\n");
    printf("  /zip/e9patch.wasm    - Patching engine\n");
    printf("  /zip/cosmocc.wasm    - Embedded C compiler\n");
    printf("  /zip/target.elf      - Target binary (if embedded)\n");
    printf("  /zip/src/*           - Source files (if embedded)\n");
}

/*
 * Parse command line arguments
 */
static int parse_args(int argc, char **argv) {
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            print_usage(argv[0]);
            exit(0);
        } else if (strcmp(argv[i], "--source-dir") == 0 && i + 1 < argc) {
            g_config.source_dir = argv[++i];
        } else if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
            g_config.port = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--daemon") == 0) {
            g_config.daemon_mode = true;
            g_config.tui_mode = false;
        } else if (strcmp(argv[i], "--no-tui") == 0) {
            g_config.tui_mode = false;
        } else if (strcmp(argv[i], "--verbose") == 0 || strcmp(argv[i], "-v") == 0) {
            g_config.verbose = true;
        } else if (strcmp(argv[i], "--self-test") == 0) {
            g_config.self_test = true;
        } else if (strcmp(argv[i], "--jit") == 0) {
            g_config.exec_mode = EXEC_MODE_JIT;
        } else if (strcmp(argv[i], "--interp") == 0) {
            g_config.exec_mode = EXEC_MODE_INTERP;
        } else if (strcmp(argv[i], "--aot") == 0) {
            g_config.exec_mode = EXEC_MODE_AOT;
        } else if (argv[i][0] != '-') {
            g_config.target_path = argv[i];
        } else {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            return -1;
        }
    }

    return 0;
}

/*
 * Log message
 */
static void studio_log(const char *fmt, ...) {
    if (!g_config.verbose && !g_config.tui_mode) return;

    time_t now = time(NULL);
    struct tm *tm = localtime(&now);

    fprintf(stderr, "[%02d:%02d:%02d] ", tm->tm_hour, tm->tm_min, tm->tm_sec);

    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);

    fprintf(stderr, "\n");
}

/*
 * Load target binary
 */
static int load_target(void) {
    const char *path = g_config.target_path;
    if (!path) {
        /* Try loading from ZipOS */
        path = "/zip/target.elf";
    }

    studio_log("Loading target: %s", path);

    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "Failed to open target: %s: %s\n", path, strerror(errno));
        return -1;
    }

    struct stat st;
    fstat(fd, &st);
    g_target_size = (size_t)st.st_size;

    /* mmap with MAP_PRIVATE for copy-on-write */
    g_target_binary = mmap(NULL, g_target_size,
                           PROT_READ | PROT_WRITE,
                           MAP_PRIVATE, fd, 0);
    close(fd);

    if (g_target_binary == MAP_FAILED) {
        fprintf(stderr, "Failed to mmap target: %s\n", strerror(errno));
        return -1;
    }

    studio_log("Loaded %zu bytes", g_target_size);

    /* Verify ELF magic */
    uint8_t *data = g_target_binary;
    if (g_target_size < 4 || data[0] != 0x7f ||
        data[1] != 'E' || data[2] != 'L' || data[3] != 'F') {
        fprintf(stderr, "Warning: target may not be a valid ELF file\n");
    }

    return 0;
}

/*
 * Initialize WASM runtime and load modules
 */
static int init_wasm(void) {
    studio_log("Initializing WASM runtime...");

    /* Set execution mode before init */
    int wasm_mode;
    const char *mode_name;
    switch (g_config.exec_mode) {
        case EXEC_MODE_INTERP:
            wasm_mode = 0;  /* E9_WASM_MODE_INTERP */
            mode_name = "Fast Interpreter";
            break;
        case EXEC_MODE_JIT:
            wasm_mode = 1;  /* E9_WASM_MODE_FAST_JIT */
            mode_name = "Fast JIT";
            break;
        case EXEC_MODE_AOT:
            wasm_mode = 2;  /* E9_WASM_MODE_AOT */
            mode_name = "AOT";
            break;
        case EXEC_MODE_DEFAULT:
        default:
            wasm_mode = 1;  /* Default to Fast JIT */
            mode_name = "Fast JIT (default)";
            break;
    }
    e9wasm_set_exec_mode(wasm_mode);
    studio_log("WAMR execution mode: %s", mode_name);

    E9WasmConfig config = {
        .stack_size = 64 * 1024,
        .heap_size = 32 * 1024 * 1024,
        .shared_buffer_size = 128 * 1024 * 1024,
        .enable_wasi = true,
        .enable_debug = g_config.verbose,
        .module_path = "/zip/e9patch.wasm",
    };

    if (e9wasm_init(&config) < 0) {
        fprintf(stderr, "Failed to initialize WASM runtime\n");
        return -1;
    }

    /* Load e9patch module from ZipOS */
    void *module = e9wasm_load_module("/zip/e9patch.wasm");
    if (!module) {
        /* Not fatal - might be running in native-only mode */
        studio_log("Note: e9patch.wasm not found in ZipOS, running in native mode");
    } else {
        studio_log("Loaded e9patch.wasm");
    }

    return 0;
}

/*
 * File watcher (inotify on Linux)
 */
#ifdef __linux__
static int g_inotify_fd = -1;
static int g_watch_fd = -1;

static int init_file_watcher(void) {
    g_inotify_fd = inotify_init1(IN_NONBLOCK);
    if (g_inotify_fd < 0) {
        studio_log("Warning: inotify not available");
        return -1;
    }

    g_watch_fd = inotify_add_watch(g_inotify_fd, g_config.source_dir,
                                    IN_MODIFY | IN_CLOSE_WRITE);
    if (g_watch_fd < 0) {
        studio_log("Warning: cannot watch directory: %s", g_config.source_dir);
        return -1;
    }

    studio_log("Watching directory: %s", g_config.source_dir);
    return 0;
}

static void check_file_changes(void) {
    char buf[4096];
    ssize_t len = read(g_inotify_fd, buf, sizeof(buf));
    if (len <= 0) return;

    size_t offset = 0;
    while (offset < (size_t)len) {
        struct inotify_event *event = (struct inotify_event *)(buf + offset);

        if (event->len > 0) {
            const char *name = event->name;
            /* Check if it's a C source file */
            size_t name_len = strlen(name);
            if ((name_len > 2 && strcmp(name + name_len - 2, ".c") == 0) ||
                (name_len > 2 && strcmp(name + name_len - 2, ".h") == 0) ||
                (name_len > 4 && strcmp(name + name_len - 4, ".cpp") == 0)) {

                studio_log("File changed: %s", name);
                /* TODO: trigger recompile and patch */
            }
        }

        offset += sizeof(struct inotify_event) + event->len;
    }
}
#else
static int init_file_watcher(void) { return -1; }
static void check_file_changes(void) {}
#endif

/*
 * TUI rendering
 */
static void render_tui(void) {
    e9wasm_tui_clear();

    /* Header */
    e9wasm_tui_print(0, 0, "╔══════════════════════════════════════════════════════════════════════╗");
    e9wasm_tui_print(1, 0, "║              E9Patch Studio - Dynamic Binary Rewriting               ║");
    e9wasm_tui_print(2, 0, "╠══════════════════════════════════════════════════════════════════════╣");

    /* Status */
    char status[80];
    snprintf(status, sizeof(status), "║ Target: %-60s ║",
             g_config.target_path ? g_config.target_path : "(none)");
    e9wasm_tui_print(3, 0, status);

    snprintf(status, sizeof(status), "║ Size: %-62zu ║", g_target_size);
    e9wasm_tui_print(4, 0, status);

    snprintf(status, sizeof(status), "║ Source: %-59s ║", g_config.source_dir);
    e9wasm_tui_print(5, 0, status);

    e9wasm_tui_print(6, 0, "╠══════════════════════════════════════════════════════════════════════╣");

    /* Help */
    e9wasm_tui_print(7, 0, "║ Commands: [e]dit [r]eload [b]reakpoint [s]ave [q]uit                 ║");
    e9wasm_tui_print(8, 0, "╚══════════════════════════════════════════════════════════════════════╝");

    /* Log area */
    e9wasm_tui_print(10, 0, "Log:");

    e9wasm_tui_refresh();
}

/*
 * Handle TUI input
 */
static void handle_input(void) {
    /* Non-blocking read */
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(STDIN_FILENO, &fds);

    struct timeval tv = {0, 100000};  /* 100ms */
    if (select(STDIN_FILENO + 1, &fds, NULL, NULL, &tv) <= 0) {
        return;
    }

    char c;
    if (read(STDIN_FILENO, &c, 1) != 1) return;

    switch (c) {
        case 'q':
        case 'Q':
            g_running = false;
            break;

        case 'r':
        case 'R':
            studio_log("Reloading and patching...");
            /* TODO: trigger full reload */
            break;

        case 'b':
        case 'B':
            studio_log("Setting breakpoint...");
            /* TODO: breakpoint UI */
            break;

        case 's':
        case 'S':
            studio_log("Saving patched binary...");
            if (g_target_binary && g_target_size > 0) {
                const char *output = g_config.target_path ?
                    g_config.target_path : "patched.elf";
                char outpath[256];
                snprintf(outpath, sizeof(outpath), "%s.patched", output);

                int fd = open(outpath, O_WRONLY | O_CREAT | O_TRUNC, 0755);
                if (fd >= 0) {
                    ssize_t written = write(fd, g_target_binary, g_target_size);
                    close(fd);
                    if (written == (ssize_t)g_target_size) {
                        studio_log("Saved to %s", outpath);
                    } else {
                        studio_log("Write incomplete: %zd of %zu bytes", written, g_target_size);
                    }
                } else {
                    studio_log("Failed to save: %s", strerror(errno));
                }
            }
            break;

        case 'e':
        case 'E':
            studio_log("Opening editor...");
            /* TODO: embedded editor or spawn $EDITOR */
            break;
    }
}

/*
 * Run self-tests
 */
static int run_self_tests(void) {
    printf("Running e9studio self-tests...\n\n");

    int passed = 0, failed = 0;

    #define TEST(name, cond) do { \
        printf("  %-40s ", name); \
        if (cond) { printf("[PASS]\n"); passed++; } \
        else { printf("[FAIL]\n"); failed++; } \
    } while(0)

    /* WARN doesn't count as failure - used for optional features */
    #define WARN(name, cond) do { \
        printf("  %-40s ", name); \
        if (cond) { printf("[PASS]\n"); passed++; } \
        else { printf("[WARN]\n"); /* not a failure */ } \
    } while(0)

    /* Test WASM runtime */
    E9WasmConfig config = {
        .stack_size = 64 * 1024,
        .heap_size = 16 * 1024 * 1024,
        .shared_buffer_size = 64 * 1024 * 1024,
        .enable_wasi = true,
        .enable_debug = true,
    };
    TEST("WASM runtime initialization", e9wasm_init(&config) == 0);

    /* Test shared buffer */
    size_t buf_size;
    uint8_t *buf = e9wasm_get_shared_buffer(&buf_size);
    TEST("Shared buffer allocation", buf != NULL && buf_size > 0);

    /* Test ZipOS access (embedded ZIP in executable) */
    /* This is optional - only available after resources.zip is appended */
    int zipos_ok = e9wasm_zipos_available();
    WARN("Embedded ZipOS available", zipos_ok);

    /* Try reading a file from embedded ZIP */
    if (zipos_ok) {
        size_t size;
        uint8_t *data = e9wasm_zipos_read(".cosmo/VERSION", &size);
        TEST("ZipOS file read", data != NULL && size > 0);
        if (data) free(data);
    } else {
        TEST("ZipOS file read (skipped)", true);
    }

    /* Test mmap */
    void *mem = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    TEST("Anonymous mmap", mem != MAP_FAILED);
    if (mem != MAP_FAILED) munmap(mem, 4096);

    /* Test executable path */
    const char *exe = e9wasm_get_exe_path();
    TEST("Executable path detection", exe != NULL && strlen(exe) > 0);

    e9wasm_shutdown();

    printf("\n  Results: %d passed, %d failed\n", passed, failed);
    return failed > 0 ? 1 : 0;
}

/*
 * Main entry point
 */
int main(int argc, char **argv) {
    /* Parse arguments */
    if (parse_args(argc, argv) < 0) {
        print_usage(argv[0]);
        return 1;
    }

    /* Run self-tests if requested */
    if (g_config.self_test) {
        return run_self_tests();
    }

    /* Setup signal handlers */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    /* Initialize WASM runtime */
    if (init_wasm() < 0) {
        return 1;
    }

    /* Load target binary if specified */
    if (g_config.target_path || access("/zip/target.elf", F_OK) == 0) {
        if (load_target() < 0) {
            /* Not fatal - might add target later */
            studio_log("No target binary loaded");
        }
    }

    /* Initialize file watcher */
    init_file_watcher();

    /* Initialize TUI if enabled */
    if (g_config.tui_mode) {
        e9wasm_tui_init();
        render_tui();
    } else {
        studio_log("E9Patch Studio started");
        if (g_config.daemon_mode) {
            studio_log("Running in daemon mode...");
        }
    }

    /* Main loop */
    while (g_running) {
        /* Check for file changes */
        check_file_changes();

        /* Handle TUI input */
        if (g_config.tui_mode) {
            handle_input();

            /* Periodic TUI refresh */
            static time_t last_render = 0;
            time_t now = time(NULL);
            if (now != last_render) {
                render_tui();
                last_render = now;
            }
        }

        /* Small sleep to avoid busy-waiting */
        usleep(50000);  /* 50ms */
    }

    /* Cleanup */
    if (g_config.tui_mode) {
        e9wasm_tui_shutdown();
    }

    if (g_target_binary) {
        munmap(g_target_binary, g_target_size);
    }

    e9wasm_shutdown();

    studio_log("E9Patch Studio exited");
    return 0;
}
