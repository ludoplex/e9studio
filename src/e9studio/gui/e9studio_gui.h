/*
 * e9studio_gui.h
 * E9Studio GUI Framework (cosmo-teditor inspired)
 *
 * Portable GUI for binary analysis and rewriting.
 * Falls back to TUI when GUI is unavailable.
 *
 * Copyright (C) 2024 E9Patch Contributors
 * License: GPLv3+
 */

#ifndef E9STUDIO_GUI_H
#define E9STUDIO_GUI_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ============================================================================
 * Platform Detection
 * ============================================================================
 */

typedef enum {
    E9_PLATFORM_UNKNOWN = 0,
    E9_PLATFORM_WINDOWS,
    E9_PLATFORM_LINUX,
    E9_PLATFORM_MACOS,
    E9_PLATFORM_FREEBSD,
    E9_PLATFORM_OPENBSD,
    E9_PLATFORM_NETBSD
} E9Platform;

typedef enum {
    E9_BACKEND_NONE = 0,
    E9_BACKEND_WIN32,       /* Windows GDI/User32 */
    E9_BACKEND_X11,         /* X11 (Linux/BSD) */
    E9_BACKEND_COCOA,       /* macOS Cocoa */
    E9_BACKEND_FRAMEBUFFER, /* Direct framebuffer */
    E9_BACKEND_TUI          /* Terminal fallback */
} E9Backend;

E9Platform e9gui_get_platform(void);
E9Backend e9gui_detect_backend(void);
const char *e9gui_platform_name(E9Platform platform);
const char *e9gui_backend_name(E9Backend backend);

/*
 * ============================================================================
 * Core Types
 * ============================================================================
 */

/* Forward declarations */
typedef struct E9Window E9Window;
typedef struct E9Panel E9Panel;
typedef struct E9Editor E9Editor;
typedef struct E9Plugin E9Plugin;
typedef struct E9Menu E9Menu;
typedef struct E9MenuItem E9MenuItem;

/* Colors */
typedef struct {
    uint8_t r, g, b, a;
} E9Color;

#define E9_RGB(r, g, b)    ((E9Color){(r), (g), (b), 255})
#define E9_RGBA(r, g, b, a) ((E9Color){(r), (g), (b), (a)})

/* Common colors */
#define E9_COLOR_BLACK      E9_RGB(0, 0, 0)
#define E9_COLOR_WHITE      E9_RGB(255, 255, 255)
#define E9_COLOR_RED        E9_RGB(255, 0, 0)
#define E9_COLOR_GREEN      E9_RGB(0, 255, 0)
#define E9_COLOR_BLUE       E9_RGB(0, 0, 255)
#define E9_COLOR_YELLOW     E9_RGB(255, 255, 0)
#define E9_COLOR_CYAN       E9_RGB(0, 255, 255)
#define E9_COLOR_MAGENTA    E9_RGB(255, 0, 255)

/* Rectangle */
typedef struct {
    int x, y, width, height;
} E9Rect;

/* Point */
typedef struct {
    int x, y;
} E9Point;

/*
 * ============================================================================
 * Panel System
 * ============================================================================
 */

typedef enum {
    E9_DOCK_NONE = 0,
    E9_DOCK_LEFT,
    E9_DOCK_RIGHT,
    E9_DOCK_TOP,
    E9_DOCK_BOTTOM,
    E9_DOCK_CENTER,
    E9_DOCK_FLOATING
} E9DockPosition;

typedef enum {
    E9_PANEL_EDITOR = 0,    /* Text editor */
    E9_PANEL_DISASM,        /* Disassembly view */
    E9_PANEL_DECOMPILE,     /* Decompiled C view */
    E9_PANEL_HEX,           /* Hex dump */
    E9_PANEL_CONSOLE,       /* Command console */
    E9_PANEL_PROJECTS,      /* File browser */
    E9_PANEL_SYMBOLS,       /* Symbol table */
    E9_PANEL_FUNCTIONS,     /* Function list */
    E9_PANEL_XREFS,         /* Cross-references */
    E9_PANEL_SCANNER,       /* Memory scanner */
    E9_PANEL_CUSTOM         /* Plugin-defined */
} E9PanelType;

/*
 * ============================================================================
 * Event System
 * ============================================================================
 */

typedef enum {
    E9_EVENT_NONE = 0,
    E9_EVENT_KEY_DOWN,
    E9_EVENT_KEY_UP,
    E9_EVENT_MOUSE_DOWN,
    E9_EVENT_MOUSE_UP,
    E9_EVENT_MOUSE_MOVE,
    E9_EVENT_MOUSE_WHEEL,
    E9_EVENT_RESIZE,
    E9_EVENT_CLOSE,
    E9_EVENT_FOCUS,
    E9_EVENT_BLUR,
    E9_EVENT_CUSTOM
} E9EventType;

typedef struct {
    E9EventType type;
    union {
        struct {
            int keycode;
            int modifiers;
            char text[8];  /* UTF-8 */
        } key;
        struct {
            int x, y;
            int button;
            int clicks;
        } mouse;
        struct {
            int delta;
        } wheel;
        struct {
            int width, height;
        } resize;
        void *custom_data;
    };
} E9Event;

/* Key modifiers */
#define E9_MOD_SHIFT    (1 << 0)
#define E9_MOD_CTRL     (1 << 1)
#define E9_MOD_ALT      (1 << 2)
#define E9_MOD_SUPER    (1 << 3)  /* Windows/Command key */

/*
 * ============================================================================
 * Window API
 * ============================================================================
 */

typedef struct {
    const char *title;
    int width;
    int height;
    bool resizable;
    bool fullscreen;
    E9Backend backend;      /* 0 = auto-detect */
} E9WindowConfig;

E9Window *e9gui_create_window(const E9WindowConfig *config);
void e9gui_destroy_window(E9Window *win);
bool e9gui_window_should_close(E9Window *win);
void e9gui_window_set_title(E9Window *win, const char *title);
void e9gui_window_get_size(E9Window *win, int *width, int *height);
E9Backend e9gui_window_get_backend(E9Window *win);

/*
 * ============================================================================
 * Main Loop
 * ============================================================================
 */

/* Poll events, returns true if event available */
bool e9gui_poll_event(E9Window *win, E9Event *event);

/* Begin frame (call before drawing) */
void e9gui_begin_frame(E9Window *win);

/* End frame (call after drawing, swaps buffers) */
void e9gui_end_frame(E9Window *win);

/* Run main loop with callback */
typedef void (*E9FrameCallback)(E9Window *win, void *userdata);
int e9gui_main_loop(E9Window *win, E9FrameCallback callback, void *userdata);

/*
 * ============================================================================
 * Panel API
 * ============================================================================
 */

E9Panel *e9gui_create_panel(E9Window *win, const char *id, E9PanelType type);
void e9gui_destroy_panel(E9Panel *panel);
void e9gui_panel_set_title(E9Panel *panel, const char *title);
void e9gui_panel_set_dock(E9Panel *panel, E9DockPosition dock);
void e9gui_panel_set_visible(E9Panel *panel, bool visible);
E9Rect e9gui_panel_get_rect(E9Panel *panel);

/* Panel content */
void e9gui_panel_set_text(E9Panel *panel, const char *text);
const char *e9gui_panel_get_text(E9Panel *panel);

/*
 * ============================================================================
 * Drawing API (Immediate Mode)
 * ============================================================================
 */

void e9gui_set_color(E9Window *win, E9Color color);
void e9gui_draw_rect(E9Window *win, E9Rect rect, bool filled);
void e9gui_draw_line(E9Window *win, E9Point p1, E9Point p2);
void e9gui_draw_text(E9Window *win, int x, int y, const char *text);
void e9gui_set_font(E9Window *win, const char *name, int size);
void e9gui_get_text_size(E9Window *win, const char *text, int *width, int *height);

/*
 * ============================================================================
 * Plugin System
 * ============================================================================
 */

#define E9_PLUGIN_API_VERSION 1

typedef struct {
    int api_version;
    const char *name;
    const char *version;
    const char *author;
    const char *description;

    /* Lifecycle */
    int (*init)(void);
    void (*shutdown)(void);

    /* UI hooks */
    void (*on_menu_build)(E9Menu *menu);
    void (*on_panel_create)(E9Panel *panel);
    void (*on_frame)(E9Window *win);

    /* Analysis hooks (from e9studio_analysis.h) */
    void (*on_binary_load)(void *binary);
    void (*on_function_select)(void *func);

    /* Editor hooks */
    void (*on_text_change)(E9Editor *ed, int line, const char *text);
} E9PluginInfo;

int e9gui_register_plugin(E9PluginInfo *plugin);
int e9gui_load_plugin_file(const char *path);
void e9gui_unload_plugin(const char *name);
E9PluginInfo *e9gui_get_plugin(const char *name);

/* Plugin export macro */
#define E9_PLUGIN_EXPORT(info_var) \
    __attribute__((visibility("default"))) \
    E9PluginInfo *e9_plugin_get_info(void) { return &(info_var); }

/*
 * ============================================================================
 * Menu System
 * ============================================================================
 */

E9Menu *e9gui_create_menu(const char *label);
E9MenuItem *e9gui_menu_add_item(E9Menu *menu, const char *label, const char *shortcut);
E9Menu *e9gui_menu_add_submenu(E9Menu *menu, const char *label);
void e9gui_menu_add_separator(E9Menu *menu);
void e9gui_menuitem_set_callback(E9MenuItem *item, void (*callback)(void *), void *userdata);
void e9gui_menuitem_set_enabled(E9MenuItem *item, bool enabled);
void e9gui_menuitem_set_checked(E9MenuItem *item, bool checked);

/*
 * ============================================================================
 * Dialogs
 * ============================================================================
 */

/* File dialog flags */
#define E9_DIALOG_OPEN          (1 << 0)
#define E9_DIALOG_SAVE          (1 << 1)
#define E9_DIALOG_DIRECTORY     (1 << 2)
#define E9_DIALOG_MULTI_SELECT  (1 << 3)

char *e9gui_file_dialog(E9Window *win, int flags, const char *filter, const char *default_path);
int e9gui_message_box(E9Window *win, const char *title, const char *message, int type);

/* Message box types */
#define E9_MSGBOX_INFO      0
#define E9_MSGBOX_WARNING   1
#define E9_MSGBOX_ERROR     2
#define E9_MSGBOX_QUESTION  3

/*
 * ============================================================================
 * Configuration
 * ============================================================================
 */

typedef struct E9Config E9Config;

E9Config *e9gui_config_load(const char *path);
void e9gui_config_save(E9Config *config, const char *path);
void e9gui_config_free(E9Config *config);

const char *e9gui_config_get_string(E9Config *config, const char *section, const char *key, const char *default_val);
int e9gui_config_get_int(E9Config *config, const char *section, const char *key, int default_val);
bool e9gui_config_get_bool(E9Config *config, const char *section, const char *key, bool default_val);

void e9gui_config_set_string(E9Config *config, const char *section, const char *key, const char *value);
void e9gui_config_set_int(E9Config *config, const char *section, const char *key, int value);
void e9gui_config_set_bool(E9Config *config, const char *section, const char *key, bool value);

/*
 * ============================================================================
 * TUI Fallback Integration
 * ============================================================================
 */

/* Check if TUI should be used instead of GUI */
bool e9gui_should_use_tui(int argc, char **argv);

/* Get the TUI main function (from e9studio.c) */
extern int e9studio_tui_main(int argc, char **argv);

/*
 * ============================================================================
 * Utility Functions
 * ============================================================================
 */

/* Version info */
const char *e9gui_version(void);

/* Error handling */
const char *e9gui_get_error(void);
void e9gui_clear_error(void);

#ifdef __cplusplus
}
#endif

#endif /* E9STUDIO_GUI_H */
