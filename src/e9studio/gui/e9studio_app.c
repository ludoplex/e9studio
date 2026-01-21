/*
 * e9studio_app.c
 * E9Studio Application Core
 *
 * Provides editor management, build system, and analysis integration.
 * Based on tedit-cosmo architecture with e9studio extensions.
 *
 * Copyright (C) 2024 E9Patch Contributors
 * License: GPLv3+
 */

#include "e9studio_tedit.h"
#include "e9studio_gui.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <ctype.h>

/*
 * Analysis engine integration is optional.
 * When E9STUDIO_WITH_ANALYSIS is defined, link with the analysis library.
 * Otherwise, stubs are used for standalone GUI builds.
 */
#ifdef E9STUDIO_WITH_ANALYSIS
#include "e9studio_analysis.h"
#define ANALYSIS_AVAILABLE 1
#else
#define ANALYSIS_AVAILABLE 0
#endif

/*
 * ============================================================================
 * Buffer Implementation (Gap Buffer)
 * ============================================================================
 */

#define GAP_SIZE 1024

static E9Buffer *buffer_create(void)
{
    E9Buffer *buf = calloc(1, sizeof(E9Buffer));
    if (!buf) return NULL;

    buf->capacity = GAP_SIZE;
    buf->data = malloc(buf->capacity);
    if (!buf->data) {
        free(buf);
        return NULL;
    }

    buf->gap_start = 0;
    buf->gap_end = GAP_SIZE;
    buf->size = 0;

    return buf;
}

static void buffer_destroy(E9Buffer *buf)
{
    if (buf) {
        free(buf->data);
        free(buf);
    }
}

/* Returns 0 on success, -1 on allocation failure */
static int buffer_ensure_gap(E9Buffer *buf, size_t required)
{
    size_t gap_size = buf->gap_end - buf->gap_start;
    if (gap_size >= required) return 0;

    /* Resize buffer */
    size_t new_capacity = buf->capacity + required + GAP_SIZE;
    char *new_data = malloc(new_capacity);
    if (!new_data) return -1;  /* Signal allocation failure */

    /* Copy data before gap */
    memcpy(new_data, buf->data, buf->gap_start);

    /* Copy data after gap to new location */
    size_t after_gap = buf->capacity - buf->gap_end;
    memcpy(new_data + new_capacity - after_gap, buf->data + buf->gap_end, after_gap);

    free(buf->data);
    buf->data = new_data;
    buf->gap_end = new_capacity - after_gap;
    buf->capacity = new_capacity;
    return 0;
}

static void buffer_move_gap(E9Buffer *buf, size_t pos)
{
    if (pos == buf->gap_start) return;

    (void)(buf->gap_end - buf->gap_start);  /* gap_size available if needed */

    if (pos < buf->gap_start) {
        /* Move gap left */
        size_t move = buf->gap_start - pos;
        memmove(buf->data + buf->gap_end - move, buf->data + pos, move);
        buf->gap_start = pos;
        buf->gap_end -= move;
    } else {
        /* Move gap right */
        size_t move = pos - buf->gap_start;
        memmove(buf->data + buf->gap_start, buf->data + buf->gap_end, move);
        buf->gap_start += move;
        buf->gap_end += move;
    }
}

/* Returns 0 on success, -1 on allocation failure */
static int buffer_insert(E9Buffer *buf, size_t pos, const char *text, size_t len)
{
    if (pos > buf->size) pos = buf->size;

    if (buffer_ensure_gap(buf, len) != 0) return -1;
    buffer_move_gap(buf, pos);

    memcpy(buf->data + buf->gap_start, text, len);
    buf->gap_start += len;
    buf->size += len;
    return 0;
}

static void buffer_delete(E9Buffer *buf, size_t pos, size_t len)
{
    if (pos >= buf->size) return;
    if (pos + len > buf->size) len = buf->size - pos;

    buffer_move_gap(buf, pos);
    buf->gap_end += len;
    buf->size -= len;
}

static size_t buffer_get_text(E9Buffer *buf, char *out, size_t max)
{
    if (max == 0) return buf->size;

    size_t before = buf->gap_start;
    size_t after = buf->capacity - buf->gap_end;
    size_t total = before + after;

    if (total >= max) total = max - 1;

    size_t copied = 0;
    if (before > 0) {
        size_t n = (before < max - 1) ? before : max - 1;
        memcpy(out, buf->data, n);
        copied = n;
    }
    if (after > 0 && copied < max - 1) {
        size_t n = (after < max - 1 - copied) ? after : max - 1 - copied;
        memcpy(out + copied, buf->data + buf->gap_end, n);
        copied += n;
    }
    out[copied] = '\0';
    return copied;
}

/*
 * ============================================================================
 * Editor Implementation
 * ============================================================================
 */

E9EditorState *e9editor_create(void)
{
    E9EditorState *ed = calloc(1, sizeof(E9EditorState));
    if (!ed) return NULL;

    ed->buffer = buffer_create();
    if (!ed->buffer) {
        free(ed);
        return NULL;
    }

    ed->cursor_line = 1;
    ed->cursor_col = 1;
    ed->language = E9_LANG_NONE;
    ed->history_enabled = 1;

    return ed;
}

void e9editor_destroy(E9EditorState *ed)
{
    if (!ed) return;

    buffer_destroy(ed->buffer);

    /* Free history */
    E9HistoryEntry *h = ed->history;
    while (h) {
        E9HistoryEntry *next = h->next;
        free(h->text);
        free(h);
        h = next;
    }

    free(ed);
}

int e9editor_set_text(E9EditorState *ed, const char *text, size_t len)
{
    if (!ed || !ed->buffer) return -1;

    /* Clear buffer */
    ed->buffer->gap_start = 0;
    ed->buffer->gap_end = ed->buffer->capacity;
    ed->buffer->size = 0;

    /* Insert new text */
    buffer_insert(ed->buffer, 0, text, len);
    ed->dirty = 0;

    return 0;
}

size_t e9editor_get_text(E9EditorState *ed, char *buf, size_t max)
{
    if (!ed || !ed->buffer) return 0;
    return buffer_get_text(ed->buffer, buf, max);
}

size_t e9editor_get_length(E9EditorState *ed)
{
    return ed && ed->buffer ? ed->buffer->size : 0;
}

const char *e9editor_language_name(E9Language lang)
{
    switch (lang) {
        case E9_LANG_C:       return "C";
        case E9_LANG_ASM_X86: return "x86 ASM";
        case E9_LANG_ASM_ARM: return "ARM ASM";
        case E9_LANG_PATCH:   return "E9Patch";
        case E9_LANG_HEX:     return "Hex";
        case E9_LANG_INI:     return "INI";
        default:              return "Text";
    }
}

E9Language e9editor_detect_language(const char *filename)
{
    if (!filename) return E9_LANG_NONE;

    const char *ext = strrchr(filename, '.');
    if (!ext) return E9_LANG_NONE;

    if (strcmp(ext, ".c") == 0 || strcmp(ext, ".h") == 0 ||
        strcmp(ext, ".cpp") == 0 || strcmp(ext, ".hpp") == 0) {
        return E9_LANG_C;
    }
    if (strcmp(ext, ".s") == 0 || strcmp(ext, ".S") == 0 ||
        strcmp(ext, ".asm") == 0) {
        return E9_LANG_ASM_X86;
    }
    if (strcmp(ext, ".e9") == 0 || strcmp(ext, ".patch") == 0) {
        return E9_LANG_PATCH;
    }
    if (strcmp(ext, ".ini") == 0 || strcmp(ext, ".cfg") == 0) {
        return E9_LANG_INI;
    }

    return E9_LANG_NONE;
}

void e9editor_set_language(E9EditorState *ed, E9Language lang)
{
    if (ed) ed->language = lang;
}

void e9editor_insert(E9EditorState *ed, size_t pos, const char *text, size_t len)
{
    if (!ed || !ed->buffer || !text || len == 0) return;

    buffer_insert(ed->buffer, pos, text, len);
    ed->dirty = 1;

    /* TODO: Add to history */
}

void e9editor_delete(E9EditorState *ed, size_t pos, size_t len)
{
    if (!ed || !ed->buffer || len == 0) return;

    /* TODO: Save to history before deleting */
    buffer_delete(ed->buffer, pos, len);
    ed->dirty = 1;
}

void e9editor_undo(E9EditorState *ed)
{
    if (!ed) return;
    /* TODO: Implement undo with history */
    printf("Undo not yet implemented.\n");
}

void e9editor_redo(E9EditorState *ed)
{
    if (!ed) return;
    /* TODO: Implement redo with history */
    printf("Redo not yet implemented.\n");
}

void e9editor_select_all(E9EditorState *ed)
{
    if (!ed) return;
    ed->selection_start = 0;
    ed->selection_end = e9editor_get_length(ed);
}

char *e9editor_get_selection(E9EditorState *ed, size_t *len)
{
    if (!ed || ed->selection_start == ed->selection_end) {
        if (len) *len = 0;
        return NULL;
    }

    size_t start = ed->selection_start < ed->selection_end ?
                   ed->selection_start : ed->selection_end;
    size_t end = ed->selection_start > ed->selection_end ?
                 ed->selection_start : ed->selection_end;
    size_t sel_len = end - start;

    char *buf = malloc(sel_len + 1);
    if (!buf) {
        if (len) *len = 0;
        return NULL;
    }

    /* TODO: Extract selection from buffer - for now return empty string */
    /* This is a stub implementation; full implementation would extract
     * text from the gap buffer between start and end positions */
    buf[0] = '\0';
    if (len) *len = 0;  /* Return 0 until properly implemented */
    return buf;
}

void e9editor_goto_line(E9EditorState *ed, size_t line)
{
    if (!ed) return;
    ed->cursor_line = line > 0 ? line : 1;
    ed->cursor_col = 1;
}

void e9editor_get_cursor_pos(E9EditorState *ed, size_t *line, size_t *col)
{
    if (!ed) return;
    if (line) *line = ed->cursor_line;
    if (col) *col = ed->cursor_col;
}

int e9editor_load_file(E9EditorState *ed, const char *path)
{
    if (!ed || !path) return -1;

    FILE *f = fopen(path, "rb");
    if (!f) return -1;

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (size < 0) {
        fclose(f);
        return -1;
    }

    char *data = malloc(size + 1);
    if (!data) {
        fclose(f);
        return -1;
    }

    size_t read = fread(data, 1, size, f);
    fclose(f);

    data[read] = '\0';
    e9editor_set_text(ed, data, read);
    free(data);

    strncpy(ed->file_path, path, sizeof(ed->file_path) - 1);
    ed->file_path[sizeof(ed->file_path) - 1] = '\0';
    ed->language = e9editor_detect_language(path);
    ed->dirty = 0;

    return 0;
}

int e9editor_save_file(E9EditorState *ed, const char *path)
{
    if (!ed || !path) return -1;

    size_t len = e9editor_get_length(ed);
    char *data = malloc(len + 1);
    if (!data) return -1;

    e9editor_get_text(ed, data, len + 1);

    FILE *f = fopen(path, "wb");
    if (!f) {
        free(data);
        return -1;
    }

    fwrite(data, 1, len, f);
    fclose(f);
    free(data);

    strncpy(ed->file_path, path, sizeof(ed->file_path) - 1);
    ed->file_path[sizeof(ed->file_path) - 1] = '\0';
    ed->dirty = 0;

    return 0;
}

/*
 * ============================================================================
 * Application Implementation
 * ============================================================================
 */

int e9app_init(E9AppState *app)
{
    if (!app) return -1;

    memset(app, 0, sizeof(E9AppState));
    app->running = 1;
    app->gui_mode = 0;  /* CLI by default */

    /* Set default build commands - memset already zeroed, but ensure null-termination */
    strncpy(app->build.build_cmd, "cosmocc -O2 -o {n}.com {e}",
            sizeof(app->build.build_cmd) - 1);
    app->build.build_cmd[sizeof(app->build.build_cmd) - 1] = '\0';
    strncpy(app->build.run_cmd, "./{n}.com",
            sizeof(app->build.run_cmd) - 1);
    app->build.run_cmd[sizeof(app->build.run_cmd) - 1] = '\0';
    strncpy(app->build.clean_cmd, "rm -f {n}.com",
            sizeof(app->build.clean_cmd) - 1);
    app->build.clean_cmd[sizeof(app->build.clean_cmd) - 1] = '\0';
    strncpy(app->build.compiler, "cosmocc",
            sizeof(app->build.compiler) - 1);
    app->build.compiler[sizeof(app->build.compiler) - 1] = '\0';

    /* Create initial editor */
    e9app_new_editor(app);

    return 0;
}

void e9app_shutdown(E9AppState *app)
{
    if (!app) return;

    /* Free editors */
    for (size_t i = 0; i < app->editor_count; i++) {
        e9editor_destroy(app->editors[i]);
    }
    free(app->editors);

    /* Free menus */
    e9menu_free(&app->menus);

#if ANALYSIS_AVAILABLE
    /* Free binary context */
    if (app->binary) {
        e9analysis_close(app->binary);
    }
#endif
}

E9EditorState *e9app_new_editor(E9AppState *app)
{
    if (!app) return NULL;

    E9EditorState *ed = e9editor_create();
    if (!ed) return NULL;

    /* Add to editor list */
    if (app->editor_count >= app->editor_capacity) {
        size_t new_capacity = app->editor_capacity ? app->editor_capacity * 2 : 4;
        E9EditorState **new_editors = realloc(app->editors,
                                              new_capacity * sizeof(E9EditorState *));
        if (!new_editors) {
            e9editor_destroy(ed);
            return NULL;
        }
        app->editors = new_editors;
        app->editor_capacity = new_capacity;
    }
    app->editors[app->editor_count++] = ed;
    app->active_editor = app->editor_count - 1;

    return ed;
}

E9EditorState *e9app_get_active_editor(E9AppState *app)
{
    if (!app || app->editor_count == 0) return NULL;
    if (app->active_editor >= app->editor_count) {
        app->active_editor = app->editor_count - 1;
    }
    return app->editors[app->active_editor];
}

int e9app_close_editor(E9AppState *app, size_t index)
{
    if (!app || index >= app->editor_count) return -1;

    e9editor_destroy(app->editors[index]);

    /* Shift remaining editors */
    for (size_t i = index; i < app->editor_count - 1; i++) {
        app->editors[i] = app->editors[i + 1];
    }
    app->editor_count--;

    if (app->active_editor >= app->editor_count && app->editor_count > 0) {
        app->active_editor = app->editor_count - 1;
    }

    return 0;
}

int e9app_open_file(E9AppState *app, const char *path)
{
    if (!app || !path) return -1;

    E9EditorState *ed = e9app_get_active_editor(app);
    if (!ed || ed->file_path[0] || ed->dirty || e9editor_get_length(ed) > 0) {
        /* Create new editor if current one is in use */
        ed = e9app_new_editor(app);
        if (!ed) return -1;
    }

    return e9editor_load_file(ed, path);
}

int e9app_save_file(E9AppState *app, const char *path)
{
    if (!app) return -1;

    E9EditorState *ed = e9app_get_active_editor(app);
    if (!ed) return -1;

    return e9editor_save_file(ed, path);
}

/*
 * ============================================================================
 * Binary Analysis Integration
 * ============================================================================
 */

int e9app_load_binary(E9AppState *app, const char *path)
{
#if ANALYSIS_AVAILABLE
    if (!app || !path) return -1;

    if (app->binary) {
        e9analysis_close(app->binary);
        app->binary = NULL;
    }

    app->binary = e9analysis_open(path);
    return app->binary ? 0 : -1;
#else
    (void)app; (void)path;
    return -1;
#endif
}

void e9app_show_function(E9AppState *app, struct E9Function *func)
{
#if ANALYSIS_AVAILABLE
    if (!app || !func || !app->binary) return;

    app->current_function = func;

    /* Get disassembly and display */
    char *disasm = e9analysis_disasm_function(app->binary, func);
    if (disasm) {
        printf("\n=== Function: %s ===\n%s\n", func->name, disasm);
        free(disasm);
    }
#else
    (void)app; (void)func;
#endif
}

void e9app_show_decompile(E9AppState *app, struct E9Function *func)
{
#if ANALYSIS_AVAILABLE
    if (!app || !func || !app->binary) return;

    char *code = e9analysis_decompile_function(app->binary, func);
    if (code) {
        printf("\n=== Decompiled: %s ===\n%s\n", func->name, code);
        free(code);
    }
#else
    (void)app; (void)func;
#endif
}

void e9app_show_hex(E9AppState *app, uint64_t addr, size_t size)
{
#if ANALYSIS_AVAILABLE
    if (!app || !app->binary) return;

    e9analysis_hexdump(app->binary, addr, size);
#else
    (void)app; (void)addr; (void)size;
#endif
}

void e9app_show_symbols(E9AppState *app)
{
#if ANALYSIS_AVAILABLE
    if (!app || !app->binary) return;

    e9analysis_list_symbols(app->binary);
#else
    (void)app;
#endif
}

void e9app_show_functions(E9AppState *app)
{
#if ANALYSIS_AVAILABLE
    if (!app || !app->binary) return;

    e9analysis_list_functions(app->binary);
#else
    (void)app;
#endif
}

void e9app_goto_address(E9AppState *app, uint64_t addr)
{
    (void)app; (void)addr;
    /* TODO: Navigate to address in hex/disasm view */
}

void e9app_console_print(E9AppState *app, const char *fmt, ...)
{
    (void)app;
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
}

void e9app_console_clear(E9AppState *app)
{
    (void)app;
    /* Clear console - platform specific */
    printf("\033[2J\033[H");  /* ANSI escape to clear */
}

/*
 * ============================================================================
 * Menu System
 * ============================================================================
 */

int e9menu_load_ini(E9MenuSet *menus, const char *path)
{
    if (!menus || !path) return -1;

    FILE *f = fopen(path, "r");
    if (!f) return -1;

    char line[512];
    E9GuiMenu *current_menu = NULL;

    while (fgets(line, sizeof(line), f)) {
        char *s = e9util_str_trim(line);
        if (!s[0] || s[0] == ';') continue;  /* Empty or comment */

        if (s[0] == '[') {
            /* New menu section */
            char *end = strchr(s, ']');
            if (end) {
                *end = '\0';
                s++;  /* Skip '[' */

                /* Allocate new menu */
                if (menus->menu_count >= menus->menu_capacity) {
                    size_t new_capacity = menus->menu_capacity ? menus->menu_capacity * 2 : 8;
                    E9GuiMenu *new_menus = realloc(menus->menus,
                                                   new_capacity * sizeof(E9GuiMenu));
                    if (!new_menus) {
                        fclose(f);
                        return -1;
                    }
                    menus->menus = new_menus;
                    menus->menu_capacity = new_capacity;
                }
                current_menu = &menus->menus[menus->menu_count++];
                memset(current_menu, 0, sizeof(E9GuiMenu));
                strncpy(current_menu->label, s, sizeof(current_menu->label) - 1);
                current_menu->label[sizeof(current_menu->label) - 1] = '\0';
            }
        } else if (current_menu) {
            /* Menu item */
            char *comma = strchr(s, ',');
            if (comma) {
                *comma = '\0';
                char *label = e9util_str_trim(s);
                char *command = e9util_str_trim(comma + 1);

                /* Add item to menu */
                if (current_menu->item_count >= current_menu->item_capacity) {
                    size_t new_capacity = current_menu->item_capacity ?
                                          current_menu->item_capacity * 2 : 16;
                    E9GuiMenuItem *new_items = realloc(current_menu->items,
                                                       new_capacity * sizeof(E9GuiMenuItem));
                    if (!new_items) continue;  /* Skip this item on failure */
                    current_menu->items = new_items;
                    current_menu->item_capacity = new_capacity;
                }
                E9GuiMenuItem *item = &current_menu->items[current_menu->item_count++];
                memset(item, 0, sizeof(E9GuiMenuItem));
                strncpy(item->label, label, sizeof(item->label) - 1);
                item->label[sizeof(item->label) - 1] = '\0';
                strncpy(item->command, command, sizeof(item->command) - 1);
                item->command[sizeof(item->command) - 1] = '\0';
                item->enabled = true;
            } else if (s[0] == '-') {
                /* Separator */
                if (current_menu->item_count >= current_menu->item_capacity) {
                    size_t new_capacity = current_menu->item_capacity ?
                                          current_menu->item_capacity * 2 : 16;
                    E9GuiMenuItem *new_items = realloc(current_menu->items,
                                                       new_capacity * sizeof(E9GuiMenuItem));
                    if (!new_items) continue;  /* Skip this item on failure */
                    current_menu->items = new_items;
                    current_menu->item_capacity = new_capacity;
                }
                E9GuiMenuItem *item = &current_menu->items[current_menu->item_count++];
                memset(item, 0, sizeof(E9GuiMenuItem));
                strncpy(item->label, "-", sizeof(item->label) - 1);
                item->label[sizeof(item->label) - 1] = '\0';
            }
        }
    }

    fclose(f);
    return 0;
}

void e9menu_free(E9MenuSet *menus)
{
    if (!menus) return;

    for (size_t i = 0; i < menus->menu_count; i++) {
        free(menus->menus[i].items);
    }
    free(menus->menus);
    memset(menus, 0, sizeof(E9MenuSet));
}

int e9menu_substitute_vars(char *out, size_t out_size, const char *cmd,
                           const char *file_path, const char *exe_dir)
{
    if (!out || !cmd) return -1;

    size_t out_pos = 0;
    const char *p = cmd;

    while (*p && out_pos < out_size - 1) {
        if (*p == '{') {
            p++;
            if (*p == 'e' && p[1] == '}') {
                /* {e} = full file path */
                if (file_path) {
                    size_t len = strlen(file_path);
                    if (out_pos + len < out_size - 1) {
                        strcpy(out + out_pos, file_path);
                        out_pos += len;
                    }
                }
                p += 2;
            } else if (*p == 'n' && p[1] == '}') {
                /* {n} = file name without extension */
                if (file_path) {
                    const char *base = strrchr(file_path, '/');
                    if (!base) base = strrchr(file_path, '\\');
                    base = base ? base + 1 : file_path;

                    const char *dot = strrchr(base, '.');
                    size_t len = dot ? (size_t)(dot - base) : strlen(base);
                    if (out_pos + len < out_size - 1) {
                        memcpy(out + out_pos, base, len);
                        out_pos += len;
                    }
                }
                p += 2;
            } else if (*p == 'b' && p[1] == '}') {
                /* {b} = binary/exe directory */
                if (exe_dir) {
                    size_t len = strlen(exe_dir);
                    if (out_pos + len < out_size - 1) {
                        strcpy(out + out_pos, exe_dir);
                        out_pos += len;
                    }
                }
                p += 2;
            } else if (*p == 'p' && p[1] == '}') {
                /* {p} = project directory (same as file dir) */
                if (file_path) {
                    const char *last = strrchr(file_path, '/');
                    if (!last) last = strrchr(file_path, '\\');
                    size_t len = last ? (size_t)(last - file_path) : 1;
                    if (out_pos + len < out_size - 1) {
                        if (len > 0) {
                            memcpy(out + out_pos, file_path, len);
                            out_pos += len;
                        } else {
                            out[out_pos++] = '.';
                        }
                    }
                }
                p += 2;
            } else {
                /* Unknown variable, copy literally */
                out[out_pos++] = '{';
            }
        } else {
            out[out_pos++] = *p++;
        }
    }

    out[out_pos] = '\0';
    return 0;
}

/*
 * ============================================================================
 * Build System
 * ============================================================================
 */

int e9build_load_config(E9BuildConfig *build, const char *path)
{
    if (!build || !path) return -1;

    FILE *f = fopen(path, "r");
    if (!f) return -1;

    char line[512];
    while (fgets(line, sizeof(line), f)) {
        char *s = e9util_str_trim(line);
        if (!s[0] || s[0] == ';' || s[0] == '[') continue;

        char *eq = strchr(s, '=');
        if (!eq) continue;

        *eq = '\0';
        char *key = e9util_str_trim(s);
        char *value = e9util_str_trim(eq + 1);

        if (strcmp(key, "build_cmd") == 0) {
            strncpy(build->build_cmd, value, sizeof(build->build_cmd) - 1);
            build->build_cmd[sizeof(build->build_cmd) - 1] = '\0';
        } else if (strcmp(key, "run_cmd") == 0) {
            strncpy(build->run_cmd, value, sizeof(build->run_cmd) - 1);
            build->run_cmd[sizeof(build->run_cmd) - 1] = '\0';
        } else if (strcmp(key, "clean_cmd") == 0) {
            strncpy(build->clean_cmd, value, sizeof(build->clean_cmd) - 1);
            build->clean_cmd[sizeof(build->clean_cmd) - 1] = '\0';
        } else if (strcmp(key, "compiler") == 0) {
            strncpy(build->compiler, value, sizeof(build->compiler) - 1);
            build->compiler[sizeof(build->compiler) - 1] = '\0';
        } else if (strcmp(key, "flags") == 0) {
            strncpy(build->flags, value, sizeof(build->flags) - 1);
            build->flags[sizeof(build->flags) - 1] = '\0';
        }
    }

    fclose(f);
    return 0;
}

int e9build_run_command(const char *cmd)
{
    if (!cmd) return -1;
    return system(cmd);
}

/*
 * ============================================================================
 * Utility Functions
 * ============================================================================
 */

char *e9util_file_read_all(const char *path, size_t *out_size)
{
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (size < 0) {
        fclose(f);
        return NULL;
    }

    char *data = malloc(size + 1);
    if (!data) {
        fclose(f);
        return NULL;
    }

    size_t read = fread(data, 1, size, f);
    fclose(f);

    data[read] = '\0';
    if (out_size) *out_size = read;

    return data;
}

int e9util_file_write_all(const char *path, const char *data, size_t size)
{
    FILE *f = fopen(path, "wb");
    if (!f) return -1;

    fwrite(data, 1, size, f);
    fclose(f);
    return 0;
}
