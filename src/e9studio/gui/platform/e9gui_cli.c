/*
 * e9gui_cli.c - E9Studio CLI platform backend
 *
 * Command-line interface for e9studio that provides text-based
 * access to binary analysis features. Based on tedit-cosmo's
 * extensibility philosophy.
 *
 * Copyright (C) 2024 E9Patch Contributors
 * License: GPLv3+
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "../e9studio_tedit.h"
#include "../e9studio_gui.h"

/* Link to analysis engine (weak reference to allow standalone build) */
#ifdef E9STUDIO_WITH_ANALYSIS
#include "../../analysis/e9studio_analysis.h"
#endif

static E9AppState *g_app = NULL;

/*
 * ============================================================================
 * Utility Functions
 * ============================================================================
 */

char *e9util_str_trim(char *str)
{
    if (!str) return NULL;

    /* Trim leading whitespace */
    while (isspace((unsigned char)*str)) str++;

    if (*str == 0) return str;

    /* Trim trailing whitespace */
    char *end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) end--;
    end[1] = '\0';

    return str;
}

/*
 * ============================================================================
 * Help and Version
 * ============================================================================
 */

static void print_help(void)
{
    printf("E9Studio CLI Commands:\n");
    printf("\n");
    printf("File Operations:\n");
    printf("  new                  - Create new buffer\n");
    printf("  open <path>          - Open file (binary or text)\n");
    printf("  save [path]          - Save current file\n");
    printf("  close                - Close current buffer\n");
    printf("\n");
    printf("Binary Analysis:\n");
    printf("  load <binary>        - Load binary for analysis\n");
    printf("  info                 - Show binary info\n");
    printf("  symbols              - List symbols\n");
    printf("  functions            - List functions\n");
    printf("  disasm <addr|func>   - Disassemble at address or function\n");
    printf("  decompile <func>     - Decompile function\n");
    printf("  hex <addr> [size]    - Hex dump at address\n");
    printf("  strings [min_len]    - Extract strings\n");
    printf("  entropy              - Show entropy analysis\n");
    printf("  xrefs <addr>         - Show cross-references\n");
    printf("  goto <addr>          - Navigate to address\n");
    printf("\n");
    printf("Patching:\n");
    printf("  patch <addr> <bytes> - Patch bytes at address\n");
    printf("  nop <addr> <len>     - NOP out bytes\n");
    printf("  inject <addr> <asm>  - Inject assembly\n");
    printf("  export <path>        - Export patched binary\n");
    printf("\n");
    printf("Editor:\n");
    printf("  edit                 - Edit patch script\n");
    printf("  show                 - Show buffer contents\n");
    printf("  undo                 - Undo last edit\n");
    printf("  redo                 - Redo last undone edit\n");
    printf("\n");
    printf("Build (cosmocc):\n");
    printf("  build                - Build current file\n");
    printf("  run                  - Run built executable\n");
    printf("  buildrun             - Build and run\n");
    printf("\n");
    printf("Other:\n");
    printf("  menu <ini_path>      - Load menu from INI\n");
    printf("  script <path>        - Run script file\n");
    printf("  help                 - Show this help\n");
    printf("  version              - Show version\n");
    printf("  quit                 - Exit\n");
}

static void print_version(void)
{
    printf("e9studio %s (GUI framework %s)\n", "0.1.0", e9gui_version());
    printf("Binary analysis and patching tool\n");
    printf("Built with Cosmopolitan C\n");
    printf("Platform: %s\n", e9gui_platform_name(e9gui_get_platform()));
}

/*
 * ============================================================================
 * Status Display
 * ============================================================================
 */

static void print_status(void)
{
    E9EditorState *ed = e9app_get_active_editor(g_app);

    if (g_app->binary) {
        printf("[Binary: loaded] ");
    }

    if (ed) {
        size_t line, col;
        e9editor_get_cursor_pos(ed, &line, &col);
        printf("[%s%s] %s | L%zu C%zu | %zu bytes",
               ed->file_path[0] ? ed->file_path : "Untitled",
               ed->dirty ? " *" : "",
               e9editor_language_name(ed->language),
               line, col, e9editor_get_length(ed));
    } else {
        printf("[No file]");
    }
    printf("\n");
}

/*
 * ============================================================================
 * Binary Analysis Commands
 * ============================================================================
 */

#ifdef E9STUDIO_WITH_ANALYSIS

static void cmd_load_binary(const char *path)
{
    if (!path || !path[0]) {
        printf("Usage: load <binary_path>\n");
        return;
    }

    if (e9app_load_binary(g_app, path) == 0) {
        printf("Loaded: %s\n", path);
        e9app_show_symbols(g_app);
    } else {
        printf("Failed to load: %s\n", path);
    }
}

static void cmd_info(void)
{
    if (!g_app->binary) {
        printf("No binary loaded. Use 'load <path>' first.\n");
        return;
    }

    e9analysis_print_info(g_app->binary);
}

static void cmd_symbols(void)
{
    if (!g_app->binary) {
        printf("No binary loaded.\n");
        return;
    }

    e9app_show_symbols(g_app);
}

static void cmd_functions(void)
{
    if (!g_app->binary) {
        printf("No binary loaded.\n");
        return;
    }

    e9app_show_functions(g_app);
}

static void cmd_disasm(const char *arg)
{
    if (!g_app->binary) {
        printf("No binary loaded.\n");
        return;
    }

    if (!arg || !arg[0]) {
        printf("Usage: disasm <address|function_name>\n");
        return;
    }

    /* Try as hex address first */
    uint64_t addr = strtoull(arg, NULL, 16);
    if (addr != 0) {
        /* TODO: Disassemble at address */
        printf("Disassembly at 0x%llx:\n", (unsigned long long)addr);
        e9analysis_disasm_at(g_app->binary, addr, 32);
    } else {
        /* Try as function name */
        E9Function *func = e9analysis_find_function(g_app->binary, arg);
        if (func) {
            e9app_show_function(g_app, func);
        } else {
            printf("Function not found: %s\n", arg);
        }
    }
}

static void cmd_decompile(const char *arg)
{
    if (!g_app->binary) {
        printf("No binary loaded.\n");
        return;
    }

    if (!arg || !arg[0]) {
        printf("Usage: decompile <function_name>\n");
        return;
    }

    E9Function *func = e9analysis_find_function(g_app->binary, arg);
    if (func) {
        e9app_show_decompile(g_app, func);
    } else {
        printf("Function not found: %s\n", arg);
    }
}

static void cmd_hex(const char *args)
{
    if (!g_app->binary) {
        printf("No binary loaded.\n");
        return;
    }

    uint64_t addr = 0;
    size_t size = 256;

    if (sscanf(args, "%llx %zu", (unsigned long long *)&addr, &size) < 1) {
        printf("Usage: hex <address> [size]\n");
        return;
    }

    e9app_show_hex(g_app, addr, size);
}

static void cmd_strings(const char *arg)
{
    if (!g_app->binary) {
        printf("No binary loaded.\n");
        return;
    }

    int min_len = arg && arg[0] ? atoi(arg) : 4;
    if (min_len < 1) min_len = 4;

    e9analysis_extract_strings(g_app->binary, min_len);
}

static void cmd_entropy(void)
{
    if (!g_app->binary) {
        printf("No binary loaded.\n");
        return;
    }

    e9analysis_entropy(g_app->binary);
}

static void cmd_xrefs(const char *arg)
{
    if (!g_app->binary) {
        printf("No binary loaded.\n");
        return;
    }

    if (!arg || !arg[0]) {
        printf("Usage: xrefs <address>\n");
        return;
    }

    uint64_t addr = strtoull(arg, NULL, 16);
    e9analysis_show_xrefs(g_app->binary, addr);
}

static void cmd_goto(const char *arg)
{
    if (!g_app->binary) {
        printf("No binary loaded.\n");
        return;
    }

    if (!arg || !arg[0]) {
        printf("Usage: goto <address>\n");
        return;
    }

    uint64_t addr = strtoull(arg, NULL, 16);
    e9app_goto_address(g_app, addr);
    printf("Navigated to 0x%llx\n", (unsigned long long)addr);
}

#else /* !E9STUDIO_WITH_ANALYSIS */

/* Stub implementations when analysis engine is not linked */
static void cmd_load_binary(const char *path) {
    printf("Analysis engine not available. Rebuild with E9STUDIO_WITH_ANALYSIS.\n");
    (void)path;
}
static void cmd_info(void) { printf("Analysis engine not available.\n"); }
static void cmd_symbols(void) { printf("Analysis engine not available.\n"); }
static void cmd_functions(void) { printf("Analysis engine not available.\n"); }
static void cmd_disasm(const char *arg) { (void)arg; printf("Analysis engine not available.\n"); }
static void cmd_decompile(const char *arg) { (void)arg; printf("Analysis engine not available.\n"); }
static void cmd_hex(const char *args) { (void)args; printf("Analysis engine not available.\n"); }
static void cmd_strings(const char *arg) { (void)arg; printf("Analysis engine not available.\n"); }
static void cmd_entropy(void) { printf("Analysis engine not available.\n"); }
static void cmd_xrefs(const char *arg) { (void)arg; printf("Analysis engine not available.\n"); }
static void cmd_goto(const char *arg) { (void)arg; printf("Analysis engine not available.\n"); }

#endif /* E9STUDIO_WITH_ANALYSIS */

/*
 * ============================================================================
 * Build Commands
 * ============================================================================
 */

static void cmd_build(void)
{
    E9EditorState *ed = e9app_get_active_editor(g_app);
    if (!ed || !ed->file_path[0]) {
        printf("No file to build. Save first.\n");
        return;
    }

    char cmd[1024];
    e9menu_substitute_vars(cmd, sizeof(cmd), g_app->build.build_cmd,
                           ed->file_path, g_app->exe_dir);
    printf("Building: %s\n", cmd);
    e9build_run_command(cmd);
}

static void cmd_run(void)
{
    E9EditorState *ed = e9app_get_active_editor(g_app);
    if (!ed || !ed->file_path[0]) {
        printf("No file. Save first.\n");
        return;
    }

    char cmd[1024];
    e9menu_substitute_vars(cmd, sizeof(cmd), g_app->build.run_cmd,
                           ed->file_path, g_app->exe_dir);
    printf("Running: %s\n", cmd);
    e9build_run_command(cmd);
}

/*
 * ============================================================================
 * Command Handler
 * ============================================================================
 */

static void handle_command(const char *line)
{
    char cmd[64] = {0};
    char arg[512] = {0};

    sscanf(line, "%63s %511[^\n]", cmd, arg);
    e9util_str_trim(arg);

    E9EditorState *ed = e9app_get_active_editor(g_app);

    /* Help commands */
    if (strcmp(cmd, "help") == 0 || strcmp(cmd, "?") == 0) {
        print_help();
    }
    else if (strcmp(cmd, "version") == 0) {
        print_version();
    }
    /* Exit commands */
    else if (strcmp(cmd, "quit") == 0 || strcmp(cmd, "exit") == 0 || strcmp(cmd, "q") == 0) {
        if (ed && ed->dirty) {
            printf("Unsaved changes. Save first or use 'quit!' to discard.\n");
        } else {
            g_app->running = 0;
        }
    }
    else if (strcmp(cmd, "quit!") == 0) {
        g_app->running = 0;
    }
    /* File operations */
    else if (strcmp(cmd, "new") == 0) {
        e9app_new_editor(g_app);
        printf("Created new buffer.\n");
    }
    else if (strcmp(cmd, "open") == 0) {
        if (arg[0]) {
            if (e9app_open_file(g_app, arg) == 0) {
                printf("Opened: %s\n", arg);
            } else {
                printf("Failed to open: %s\n", arg);
            }
        } else {
            printf("Usage: open <path>\n");
        }
    }
    else if (strcmp(cmd, "save") == 0) {
        if (arg[0]) {
            if (e9app_save_file(g_app, arg) == 0) {
                printf("Saved: %s\n", arg);
            }
        } else if (ed && ed->file_path[0]) {
            if (e9app_save_file(g_app, ed->file_path) == 0) {
                printf("Saved: %s\n", ed->file_path);
            }
        } else {
            printf("Usage: save <path>\n");
        }
    }
    else if (strcmp(cmd, "close") == 0) {
        if (g_app->editor_count > 0) {
            e9app_close_editor(g_app, g_app->active_editor);
            printf("Closed buffer.\n");
        }
    }
    /* Binary analysis commands */
    else if (strcmp(cmd, "load") == 0) {
        cmd_load_binary(arg);
    }
    else if (strcmp(cmd, "info") == 0) {
        cmd_info();
    }
    else if (strcmp(cmd, "symbols") == 0 || strcmp(cmd, "sym") == 0) {
        cmd_symbols();
    }
    else if (strcmp(cmd, "functions") == 0 || strcmp(cmd, "funcs") == 0) {
        cmd_functions();
    }
    else if (strcmp(cmd, "disasm") == 0 || strcmp(cmd, "d") == 0) {
        cmd_disasm(arg);
    }
    else if (strcmp(cmd, "decompile") == 0 || strcmp(cmd, "dec") == 0) {
        cmd_decompile(arg);
    }
    else if (strcmp(cmd, "hex") == 0 || strcmp(cmd, "x") == 0) {
        cmd_hex(arg);
    }
    else if (strcmp(cmd, "strings") == 0) {
        cmd_strings(arg);
    }
    else if (strcmp(cmd, "entropy") == 0) {
        cmd_entropy();
    }
    else if (strcmp(cmd, "xrefs") == 0) {
        cmd_xrefs(arg);
    }
    else if (strcmp(cmd, "goto") == 0 || strcmp(cmd, "g") == 0) {
        cmd_goto(arg);
    }
    /* Build commands */
    else if (strcmp(cmd, "build") == 0) {
        cmd_build();
    }
    else if (strcmp(cmd, "run") == 0) {
        cmd_run();
    }
    else if (strcmp(cmd, "buildrun") == 0 || strcmp(cmd, "br") == 0) {
        cmd_build();
        cmd_run();
    }
    /* Editor commands */
    else if (strcmp(cmd, "show") == 0) {
        if (ed) {
            size_t len = e9editor_get_length(ed);
            char *buf = malloc(len + 1);
            if (buf) {
                e9editor_get_text(ed, buf, len + 1);
                printf("--- Buffer contents ---\n%s\n--- End ---\n", buf);
                free(buf);
            }
        } else {
            printf("No active editor.\n");
        }
    }
    else if (strcmp(cmd, "undo") == 0 || strcmp(cmd, "u") == 0) {
        if (ed) {
            e9editor_undo(ed);
            printf("Undo.\n");
        }
    }
    else if (strcmp(cmd, "redo") == 0) {
        if (ed) {
            e9editor_redo(ed);
            printf("Redo.\n");
        }
    }
    /* Menu loading */
    else if (strcmp(cmd, "menu") == 0) {
        if (arg[0]) {
            if (e9menu_load_ini(&g_app->menus, arg) == 0) {
                printf("Loaded menu: %s\n", arg);
            } else {
                printf("Failed to load menu: %s\n", arg);
            }
        } else {
            printf("Usage: menu <ini_path>\n");
        }
    }
    /* Unknown command */
    else if (cmd[0]) {
        printf("Unknown command: %s (type 'help' for commands)\n", cmd);
    }
}

/*
 * ============================================================================
 * Platform Interface Implementation
 * ============================================================================
 */

int e9platform_init(E9AppState *app)
{
    g_app = app;
    printf("\n");
    printf("  ╔═══════════════════════════════════════════════╗\n");
    printf("  ║           E9Studio CLI Interface              ║\n");
    printf("  ║     Binary Analysis and Patching Tool         ║\n");
    printf("  ╚═══════════════════════════════════════════════╝\n");
    printf("\n");
    printf("Type 'help' for commands, 'quit' to exit.\n\n");
    return 0;
}

int e9platform_run(E9AppState *app)
{
    char line[1024];

    while (app->running) {
        print_status();
        printf("e9> ");
        fflush(stdout);

        if (!fgets(line, sizeof(line), stdin)) {
            break;
        }

        e9util_str_trim(line);
        if (line[0]) {
            handle_command(line);
        }
    }

    return 0;
}

void e9platform_shutdown(E9AppState *app)
{
    (void)app;
    printf("Goodbye.\n");
}

/* Stub implementations for platform functions */
int e9platform_open_file_dialog(char *path, size_t max, const char *filter)
{
    (void)filter;
    printf("Enter file path: ");
    if (fgets(path, max, stdin)) {
        e9util_str_trim(path);
        return 0;
    }
    return -1;
}

int e9platform_save_file_dialog(char *path, size_t max, const char *filter)
{
    return e9platform_open_file_dialog(path, max, filter);
}

int e9platform_folder_dialog(char *path, size_t max, const char *title)
{
    (void)title;
    printf("Enter folder path: ");
    if (fgets(path, max, stdin)) {
        e9util_str_trim(path);
        return 0;
    }
    return -1;
}

int e9platform_message_box(const char *title, const char *msg, int type)
{
    (void)type;
    printf("[%s] %s\n", title, msg);
    return 0;
}

int e9platform_clipboard_set(const char *text)
{
    (void)text;
    return -1; /* Not supported in CLI */
}

char *e9platform_clipboard_get(void)
{
    return NULL;
}

int e9platform_open_url(const char *url)
{
    printf("URL: %s\n", url);
    return 0;
}

int e9platform_run_external(const char *cmd)
{
    return system(cmd);
}
