/*
 * e9studio_tedit.h
 * Integration layer between tedit-cosmo and e9studio analysis engine
 *
 * This provides the bridge between the text editor UI and the binary
 * analysis capabilities of e9studio.
 *
 * Copyright (C) 2024 E9Patch Contributors
 * License: GPLv3+
 */

#ifndef E9STUDIO_TEDIT_H
#define E9STUDIO_TEDIT_H

#include <stddef.h>
#include <stdbool.h>
#include "e9studio_gui.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ============================================================================
 * Application State (tedit-cosmo compatible)
 * ============================================================================
 */

/* Forward declarations from analysis engine */
struct E9BinaryContext;
struct E9Function;
struct E9Instruction;

/* Editor buffer for text content */
typedef struct E9Buffer {
    char *data;
    size_t size;
    size_t capacity;
    size_t gap_start;
    size_t gap_end;
} E9Buffer;

/* Syntax highlighting modes */
typedef enum {
    E9_LANG_NONE = 0,
    E9_LANG_C,              /* C/C++ */
    E9_LANG_ASM_X86,        /* x86/x64 assembly */
    E9_LANG_ASM_ARM,        /* ARM/AArch64 assembly */
    E9_LANG_PATCH,          /* E9Patch DSL */
    E9_LANG_HEX,            /* Hex dump */
    E9_LANG_INI             /* INI config files */
} E9Language;

/* Edit history entry */
typedef struct E9HistoryEntry {
    enum { E9_HIST_INSERT, E9_HIST_DELETE } type;
    size_t position;
    char *text;
    size_t length;
    struct E9HistoryEntry *next;
    struct E9HistoryEntry *prev;
} E9HistoryEntry;

/* Editor state (single buffer/file) */
typedef struct E9EditorState {
    E9Buffer *buffer;
    E9HistoryEntry *history;
    E9HistoryEntry *history_pos;
    char file_path[260];
    size_t cursor_line;
    size_t cursor_col;
    size_t selection_start;
    size_t selection_end;
    E9Language language;
    int dirty;
    int readonly;
    int history_enabled;
} E9EditorState;

/* Build configuration */
typedef struct E9BuildConfig {
    char build_cmd[512];
    char run_cmd[512];
    char clean_cmd[512];
    char compiler[128];
    char flags[256];
} E9BuildConfig;

/* Menu item */
typedef struct E9GuiMenuItem {
    char label[64];
    char command[256];
    char shortcut[16];
    bool enabled;
    bool checked;
    void (*callback)(void *);
    void *userdata;
} E9GuiMenuItem;

/* Menu */
typedef struct E9GuiMenu {
    char label[64];
    E9GuiMenuItem *items;
    size_t item_count;
    size_t item_capacity;
} E9GuiMenu;

/* Menu set */
typedef struct E9MenuSet {
    E9GuiMenu *menus;
    size_t menu_count;
    size_t menu_capacity;
} E9MenuSet;

/* Main application state */
typedef struct E9AppState {
    /* Editor tabs */
    E9EditorState **editors;
    size_t editor_count;
    size_t editor_capacity;
    size_t active_editor;

    /* Build config */
    E9BuildConfig build;

    /* Menu system */
    E9MenuSet menus;

    /* Paths */
    char exe_dir[260];
    char config_dir[260];

    /* State */
    int running;
    int gui_mode;

    /* Analysis context (from e9studio_analysis.h) */
    struct E9BinaryContext *binary;
    struct E9Function *current_function;

    /* GUI panels */
    E9Panel *panel_editor;
    E9Panel *panel_disasm;
    E9Panel *panel_decompile;
    E9Panel *panel_hex;
    E9Panel *panel_console;
    E9Panel *panel_symbols;
    E9Panel *panel_functions;
} E9AppState;

/*
 * ============================================================================
 * Application Lifecycle
 * ============================================================================
 */

int e9app_init(E9AppState *app);
void e9app_shutdown(E9AppState *app);

/*
 * ============================================================================
 * Editor Management
 * ============================================================================
 */

E9EditorState *e9editor_create(void);
void e9editor_destroy(E9EditorState *ed);

int e9editor_set_text(E9EditorState *ed, const char *text, size_t len);
size_t e9editor_get_text(E9EditorState *ed, char *buf, size_t max);
size_t e9editor_get_length(E9EditorState *ed);

void e9editor_set_language(E9EditorState *ed, E9Language lang);
E9Language e9editor_detect_language(const char *filename);
const char *e9editor_language_name(E9Language lang);

/* Edit operations */
int e9editor_insert(E9EditorState *ed, size_t pos, const char *text, size_t len);
void e9editor_delete(E9EditorState *ed, size_t pos, size_t len);
void e9editor_undo(E9EditorState *ed);
void e9editor_redo(E9EditorState *ed);

/* Selection */
void e9editor_select_all(E9EditorState *ed);
char *e9editor_get_selection(E9EditorState *ed, size_t *len);

/* Cursor */
void e9editor_goto_line(E9EditorState *ed, size_t line);
void e9editor_get_cursor_pos(E9EditorState *ed, size_t *line, size_t *col);

/* File operations */
int e9editor_load_file(E9EditorState *ed, const char *path);
int e9editor_save_file(E9EditorState *ed, const char *path);

/*
 * ============================================================================
 * Application File Management
 * ============================================================================
 */

E9EditorState *e9app_new_editor(E9AppState *app);
E9EditorState *e9app_get_active_editor(E9AppState *app);
int e9app_close_editor(E9AppState *app, size_t index);
int e9app_open_file(E9AppState *app, const char *path);
int e9app_save_file(E9AppState *app, const char *path);

/*
 * ============================================================================
 * Binary Analysis Integration
 * ============================================================================
 */

/* Load binary for analysis */
int e9app_load_binary(E9AppState *app, const char *path);

/* Update disassembly panel with function */
void e9app_show_function(E9AppState *app, struct E9Function *func);

/* Update decompilation panel */
void e9app_show_decompile(E9AppState *app, struct E9Function *func);

/* Update hex view at address */
void e9app_show_hex(E9AppState *app, uint64_t addr, size_t size);

/* Show symbols in symbol panel */
void e9app_show_symbols(E9AppState *app);

/* Show function list */
void e9app_show_functions(E9AppState *app);

/* Navigate to address */
void e9app_goto_address(E9AppState *app, uint64_t addr);

/* Console output */
void e9app_console_print(E9AppState *app, const char *fmt, ...);
void e9app_console_clear(E9AppState *app);

/*
 * ============================================================================
 * Menu System
 * ============================================================================
 */

int e9menu_load_ini(E9MenuSet *menus, const char *path);
void e9menu_free(E9MenuSet *menus);
int e9menu_substitute_vars(char *out, size_t out_size, const char *cmd,
                           const char *file_path, const char *exe_dir);

/*
 * ============================================================================
 * Build System
 * ============================================================================
 */

int e9build_load_config(E9BuildConfig *build, const char *path);
int e9build_run_command(const char *cmd);

/*
 * ============================================================================
 * Platform Interface (implemented per-platform)
 * ============================================================================
 */

int e9platform_init(E9AppState *app);
int e9platform_run(E9AppState *app);
void e9platform_shutdown(E9AppState *app);

/* File dialogs */
int e9platform_open_file_dialog(char *path, size_t max, const char *filter);
int e9platform_save_file_dialog(char *path, size_t max, const char *filter);
int e9platform_folder_dialog(char *path, size_t max, const char *title);

/* Message boxes */
int e9platform_message_box(const char *title, const char *msg, int type);

/* Clipboard */
int e9platform_clipboard_set(const char *text);
char *e9platform_clipboard_get(void);

/* Shell */
int e9platform_open_url(const char *url);
int e9platform_run_external(const char *cmd);

/*
 * ============================================================================
 * Utility Functions
 * ============================================================================
 */

char *e9util_str_trim(char *str);
char *e9util_file_read_all(const char *path, size_t *out_size);
int e9util_file_write_all(const char *path, const char *data, size_t size);
char *e9util_path_dirname(const char *path, char *buf, size_t buf_size);
char *e9util_path_basename(const char *path);
char *e9util_path_extension(const char *path);

#ifdef __cplusplus
}
#endif

#endif /* E9STUDIO_TEDIT_H */
