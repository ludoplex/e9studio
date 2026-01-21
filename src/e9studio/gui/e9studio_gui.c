/*
 * e9studio_gui.c
 * E9Studio GUI Framework Implementation
 *
 * Portable GUI with automatic TUI fallback.
 *
 * Copyright (C) 2024 E9Patch Contributors
 * License: GPLv3+
 */

#include "e9studio_gui.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdarg.h>

#ifdef __COSMOPOLITAN__
#include <cosmo.h>
#endif

/*
 * ============================================================================
 * Version
 * ============================================================================
 */

#define E9GUI_VERSION "0.1.0"

const char *e9gui_version(void)
{
    return E9GUI_VERSION;
}

/*
 * ============================================================================
 * Error Handling
 * ============================================================================
 */

static char g_error_msg[256] = {0};

const char *e9gui_get_error(void)
{
    return g_error_msg;
}

void e9gui_clear_error(void)
{
    g_error_msg[0] = '\0';
}

static void set_error(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    vsnprintf(g_error_msg, sizeof(g_error_msg), fmt, args);
    va_end(args);
}

/*
 * ============================================================================
 * Platform Detection
 * ============================================================================
 */

E9Platform e9gui_get_platform(void)
{
#ifdef __COSMOPOLITAN__
    if (IsWindows()) return E9_PLATFORM_WINDOWS;
    if (IsLinux()) return E9_PLATFORM_LINUX;
    if (IsXnu()) return E9_PLATFORM_MACOS;
    if (IsFreebsd()) return E9_PLATFORM_FREEBSD;
    if (IsOpenbsd()) return E9_PLATFORM_OPENBSD;
    if (IsNetbsd()) return E9_PLATFORM_NETBSD;
#else
    #if defined(_WIN32) || defined(_WIN64)
        return E9_PLATFORM_WINDOWS;
    #elif defined(__APPLE__) && defined(__MACH__)
        return E9_PLATFORM_MACOS;
    #elif defined(__linux__)
        return E9_PLATFORM_LINUX;
    #elif defined(__FreeBSD__)
        return E9_PLATFORM_FREEBSD;
    #elif defined(__OpenBSD__)
        return E9_PLATFORM_OPENBSD;
    #elif defined(__NetBSD__)
        return E9_PLATFORM_NETBSD;
    #endif
#endif
    return E9_PLATFORM_UNKNOWN;
}

const char *e9gui_platform_name(E9Platform platform)
{
    switch (platform) {
        case E9_PLATFORM_WINDOWS: return "Windows";
        case E9_PLATFORM_LINUX:   return "Linux";
        case E9_PLATFORM_MACOS:   return "macOS";
        case E9_PLATFORM_FREEBSD: return "FreeBSD";
        case E9_PLATFORM_OPENBSD: return "OpenBSD";
        case E9_PLATFORM_NETBSD:  return "NetBSD";
        default:                  return "Unknown";
    }
}

const char *e9gui_backend_name(E9Backend backend)
{
    switch (backend) {
        case E9_BACKEND_WIN32:       return "Win32";
        case E9_BACKEND_X11:         return "X11";
        case E9_BACKEND_COCOA:       return "Cocoa";
        case E9_BACKEND_FRAMEBUFFER: return "Framebuffer";
        case E9_BACKEND_TUI:         return "TUI";
        default:                     return "None";
    }
}

/*
 * ============================================================================
 * Backend Detection
 * ============================================================================
 */

static bool check_display_available(void)
{
    E9Platform platform = e9gui_get_platform();

    switch (platform) {
        case E9_PLATFORM_WINDOWS:
            /* Windows always has GUI available */
            return true;

        case E9_PLATFORM_LINUX:
        case E9_PLATFORM_FREEBSD:
        case E9_PLATFORM_OPENBSD:
        case E9_PLATFORM_NETBSD:
            /* Check DISPLAY environment variable for X11 */
            return getenv("DISPLAY") != NULL;

        case E9_PLATFORM_MACOS:
            /* macOS - check if running in GUI session */
            /* TODO: Better detection for headless macOS */
            return getenv("TERM_PROGRAM") != NULL ||
                   getenv("Apple_PubSub_Socket_Render") != NULL;

        default:
            return false;
    }
}

static bool check_ssh_session(void)
{
    /* Detect SSH session */
    return getenv("SSH_CONNECTION") != NULL ||
           getenv("SSH_CLIENT") != NULL ||
           getenv("SSH_TTY") != NULL;
}

E9Backend e9gui_detect_backend(void)
{
    /* Check environment override */
    const char *force_tui = getenv("E9STUDIO_TUI");
    if (force_tui && (strcmp(force_tui, "1") == 0 || strcmp(force_tui, "true") == 0)) {
        return E9_BACKEND_TUI;
    }

    const char *force_backend = getenv("E9STUDIO_BACKEND");
    if (force_backend) {
        if (strcmp(force_backend, "tui") == 0) return E9_BACKEND_TUI;
        if (strcmp(force_backend, "win32") == 0) return E9_BACKEND_WIN32;
        if (strcmp(force_backend, "x11") == 0) return E9_BACKEND_X11;
        if (strcmp(force_backend, "cocoa") == 0) return E9_BACKEND_COCOA;
    }

    /* SSH session - prefer TUI */
    if (check_ssh_session()) {
        return E9_BACKEND_TUI;
    }

    /* Check if display is available */
    if (!check_display_available()) {
        return E9_BACKEND_TUI;
    }

    /* Platform-specific backend */
    E9Platform platform = e9gui_get_platform();
    switch (platform) {
        case E9_PLATFORM_WINDOWS:
            return E9_BACKEND_WIN32;
        case E9_PLATFORM_LINUX:
        case E9_PLATFORM_FREEBSD:
        case E9_PLATFORM_OPENBSD:
        case E9_PLATFORM_NETBSD:
            return E9_BACKEND_X11;
        case E9_PLATFORM_MACOS:
            return E9_BACKEND_COCOA;
        default:
            return E9_BACKEND_TUI;
    }
}

/*
 * ============================================================================
 * TUI Fallback Detection
 * ============================================================================
 */

bool e9gui_should_use_tui(int argc, char **argv)
{
    /* Check command line for --tui flag */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--tui") == 0 ||
            strcmp(argv[i], "-t") == 0 ||
            strcmp(argv[i], "--no-gui") == 0) {
            return true;
        }
    }

    /* Check environment */
    const char *force_tui = getenv("E9STUDIO_TUI");
    if (force_tui && (strcmp(force_tui, "1") == 0 || strcmp(force_tui, "true") == 0)) {
        return true;
    }

    /* Detect backend */
    E9Backend backend = e9gui_detect_backend();
    return (backend == E9_BACKEND_TUI);
}

/*
 * ============================================================================
 * Window Structure
 * ============================================================================
 */

struct E9Window {
    char title[256];
    int width;
    int height;
    bool should_close;
    E9Backend backend;

    /* Backend-specific data */
    void *native_handle;

    /* Panel list */
    E9Panel **panels;
    size_t panel_count;
    size_t panel_capacity;
};

/*
 * ============================================================================
 * Window API
 * ============================================================================
 */

E9Window *e9gui_create_window(const E9WindowConfig *config)
{
    E9Window *win = calloc(1, sizeof(E9Window));
    if (!win) {
        set_error("Failed to allocate window");
        return NULL;
    }

    strncpy(win->title, config->title ? config->title : "E9Studio", sizeof(win->title) - 1);
    win->title[sizeof(win->title) - 1] = '\0';  /* Ensure null-termination */
    win->width = config->width > 0 ? config->width : 1024;
    win->height = config->height > 0 ? config->height : 768;
    win->should_close = false;

    /* Determine backend */
    win->backend = config->backend ? config->backend : e9gui_detect_backend();

    /* Initialize backend-specific window */
    switch (win->backend) {
        case E9_BACKEND_WIN32:
            /* TODO: Initialize Win32 window */
            fprintf(stderr, "[e9gui] Win32 backend not yet implemented, falling back to TUI\n");
            win->backend = E9_BACKEND_TUI;
            break;

        case E9_BACKEND_X11:
            /* TODO: Initialize X11 window */
            fprintf(stderr, "[e9gui] X11 backend not yet implemented, falling back to TUI\n");
            win->backend = E9_BACKEND_TUI;
            break;

        case E9_BACKEND_COCOA:
            /* TODO: Initialize Cocoa window */
            fprintf(stderr, "[e9gui] Cocoa backend not yet implemented, falling back to TUI\n");
            win->backend = E9_BACKEND_TUI;
            break;

        case E9_BACKEND_TUI:
        default:
            /* TUI mode - no native window needed */
            break;
    }

    return win;
}

void e9gui_destroy_window(E9Window *win)
{
    if (!win) return;

    /* Free panels */
    for (size_t i = 0; i < win->panel_count; i++) {
        e9gui_destroy_panel(win->panels[i]);
    }
    free(win->panels);

    /* Cleanup backend */
    switch (win->backend) {
        case E9_BACKEND_WIN32:
            /* TODO: Destroy Win32 window */
            break;
        case E9_BACKEND_X11:
            /* TODO: Destroy X11 window */
            break;
        case E9_BACKEND_COCOA:
            /* TODO: Destroy Cocoa window */
            break;
        default:
            break;
    }

    free(win);
}

bool e9gui_window_should_close(E9Window *win)
{
    return win ? win->should_close : true;
}

void e9gui_window_set_title(E9Window *win, const char *title)
{
    if (!win || !title) return;
    strncpy(win->title, title, sizeof(win->title) - 1);
    win->title[sizeof(win->title) - 1] = '\0';
    /* TODO: Update native window title */
}

void e9gui_window_get_size(E9Window *win, int *width, int *height)
{
    if (!win) return;
    if (width) *width = win->width;
    if (height) *height = win->height;
}

E9Backend e9gui_window_get_backend(E9Window *win)
{
    return win ? win->backend : E9_BACKEND_NONE;
}

/*
 * ============================================================================
 * Panel Structure
 * ============================================================================
 */

struct E9Panel {
    char id[64];
    char title[128];
    E9PanelType type;
    E9DockPosition dock;
    E9Rect rect;
    bool visible;
    char *text_content;
    size_t text_capacity;
    E9Window *window;
};

/*
 * ============================================================================
 * Panel API
 * ============================================================================
 */

E9Panel *e9gui_create_panel(E9Window *win, const char *id, E9PanelType type)
{
    if (!win || !id) return NULL;

    E9Panel *panel = calloc(1, sizeof(E9Panel));
    if (!panel) return NULL;

    strncpy(panel->id, id, sizeof(panel->id) - 1);
    panel->id[sizeof(panel->id) - 1] = '\0';
    panel->type = type;
    panel->dock = E9_DOCK_CENTER;
    panel->visible = true;
    panel->window = win;

    /* Set default title based on type */
    const char *default_titles[] = {
        [E9_PANEL_EDITOR] = "Editor",
        [E9_PANEL_DISASM] = "Disassembly",
        [E9_PANEL_DECOMPILE] = "Decompiled C",
        [E9_PANEL_HEX] = "Hex View",
        [E9_PANEL_CONSOLE] = "Console",
        [E9_PANEL_PROJECTS] = "Projects",
        [E9_PANEL_SYMBOLS] = "Symbols",
        [E9_PANEL_FUNCTIONS] = "Functions",
        [E9_PANEL_XREFS] = "Cross-References",
        [E9_PANEL_SCANNER] = "Memory Scanner",
        [E9_PANEL_CUSTOM] = "Custom"
    };
    if (type < sizeof(default_titles) / sizeof(default_titles[0])) {
        strncpy(panel->title, default_titles[type], sizeof(panel->title) - 1);
        panel->title[sizeof(panel->title) - 1] = '\0';
    }

    /* Add to window's panel list */
    if (win->panel_count >= win->panel_capacity) {
        size_t new_capacity = win->panel_capacity ? win->panel_capacity * 2 : 8;
        E9Panel **new_panels = realloc(win->panels, new_capacity * sizeof(E9Panel *));
        if (!new_panels) {
            free(panel);
            return NULL;
        }
        win->panels = new_panels;
        win->panel_capacity = new_capacity;
    }
    win->panels[win->panel_count++] = panel;

    return panel;
}

void e9gui_destroy_panel(E9Panel *panel)
{
    if (!panel) return;
    free(panel->text_content);
    free(panel);
}

void e9gui_panel_set_title(E9Panel *panel, const char *title)
{
    if (panel && title) {
        strncpy(panel->title, title, sizeof(panel->title) - 1);
        panel->title[sizeof(panel->title) - 1] = '\0';
    }
}

void e9gui_panel_set_dock(E9Panel *panel, E9DockPosition dock)
{
    if (panel) {
        panel->dock = dock;
    }
}

void e9gui_panel_set_visible(E9Panel *panel, bool visible)
{
    if (panel) {
        panel->visible = visible;
    }
}

E9Rect e9gui_panel_get_rect(E9Panel *panel)
{
    return panel ? panel->rect : (E9Rect){0, 0, 0, 0};
}

void e9gui_panel_set_text(E9Panel *panel, const char *text)
{
    if (!panel || !text) return;

    size_t len = strlen(text) + 1;
    if (len > panel->text_capacity) {
        size_t new_capacity = len * 2;
        char *new_content = realloc(panel->text_content, new_capacity);
        if (!new_content) return;  /* Keep existing content on failure */
        panel->text_content = new_content;
        panel->text_capacity = new_capacity;
    }
    memcpy(panel->text_content, text, len);
}

const char *e9gui_panel_get_text(E9Panel *panel)
{
    return panel ? panel->text_content : NULL;
}

/*
 * ============================================================================
 * Event Loop (Stub)
 * ============================================================================
 */

bool e9gui_poll_event(E9Window *win, E9Event *event)
{
    if (!win || !event) return false;

    /* TODO: Poll events from backend */
    event->type = E9_EVENT_NONE;
    return false;
}

void e9gui_begin_frame(E9Window *win)
{
    if (!win) return;
    /* TODO: Begin frame rendering */
}

void e9gui_end_frame(E9Window *win)
{
    if (!win) return;
    /* TODO: End frame, swap buffers */
}

int e9gui_main_loop(E9Window *win, E9FrameCallback callback, void *userdata)
{
    if (!win) return -1;

    /* If TUI backend, delegate to TUI main */
    if (win->backend == E9_BACKEND_TUI) {
        fprintf(stderr, "[e9gui] Running in TUI mode\n");
        /* The caller should handle TUI mode separately */
        return 0;
    }

    /* GUI main loop */
    while (!win->should_close) {
        E9Event event;
        while (e9gui_poll_event(win, &event)) {
            if (event.type == E9_EVENT_CLOSE) {
                win->should_close = true;
            }
        }

        e9gui_begin_frame(win);

        if (callback) {
            callback(win, userdata);
        }

        e9gui_end_frame(win);
    }

    return 0;
}

/*
 * ============================================================================
 * Drawing API (Stubs)
 * ============================================================================
 */

void e9gui_set_color(E9Window *win, E9Color color)
{
    (void)win; (void)color;
    /* TODO: Implement */
}

void e9gui_draw_rect(E9Window *win, E9Rect rect, bool filled)
{
    (void)win; (void)rect; (void)filled;
    /* TODO: Implement */
}

void e9gui_draw_line(E9Window *win, E9Point p1, E9Point p2)
{
    (void)win; (void)p1; (void)p2;
    /* TODO: Implement */
}

void e9gui_draw_text(E9Window *win, int x, int y, const char *text)
{
    (void)win; (void)x; (void)y; (void)text;
    /* TODO: Implement */
}

void e9gui_set_font(E9Window *win, const char *name, int size)
{
    (void)win; (void)name; (void)size;
    /* TODO: Implement */
}

void e9gui_get_text_size(E9Window *win, const char *text, int *width, int *height)
{
    (void)win; (void)text;
    if (width) *width = 0;
    if (height) *height = 0;
    /* TODO: Implement */
}

/*
 * ============================================================================
 * Plugin System (Stubs)
 * ============================================================================
 */

static E9PluginInfo *g_plugins[64] = {0};
static int g_plugin_count = 0;

int e9gui_register_plugin(E9PluginInfo *plugin)
{
    if (!plugin || g_plugin_count >= 64) return -1;
    if (plugin->api_version != E9_PLUGIN_API_VERSION) {
        set_error("Plugin API version mismatch");
        return -1;
    }
    g_plugins[g_plugin_count++] = plugin;
    if (plugin->init) {
        return plugin->init();
    }
    return 0;
}

int e9gui_load_plugin_file(const char *path)
{
    (void)path;
    /* TODO: Implement dynamic loading */
    set_error("Dynamic plugin loading not yet implemented");
    return -1;
}

void e9gui_unload_plugin(const char *name)
{
    for (int i = 0; i < g_plugin_count; i++) {
        if (g_plugins[i] && strcmp(g_plugins[i]->name, name) == 0) {
            if (g_plugins[i]->shutdown) {
                g_plugins[i]->shutdown();
            }
            /* Shift remaining plugins */
            for (int j = i; j < g_plugin_count - 1; j++) {
                g_plugins[j] = g_plugins[j + 1];
            }
            g_plugin_count--;
            return;
        }
    }
}

E9PluginInfo *e9gui_get_plugin(const char *name)
{
    for (int i = 0; i < g_plugin_count; i++) {
        if (g_plugins[i] && strcmp(g_plugins[i]->name, name) == 0) {
            return g_plugins[i];
        }
    }
    return NULL;
}

/*
 * ============================================================================
 * Dialogs (Stubs)
 * ============================================================================
 */

char *e9gui_file_dialog(E9Window *win, int flags, const char *filter, const char *default_path)
{
    (void)win; (void)flags; (void)filter; (void)default_path;
    /* TODO: Implement native file dialogs */
    return NULL;
}

int e9gui_message_box(E9Window *win, const char *title, const char *message, int type)
{
    (void)win; (void)type;
    /* Fallback to stderr */
    fprintf(stderr, "[%s] %s\n", title, message);
    return 0;
}

/*
 * ============================================================================
 * Configuration (Stubs)
 * ============================================================================
 */

struct E9Config {
    /* TODO: Implement INI parser */
    char dummy;
};

E9Config *e9gui_config_load(const char *path)
{
    (void)path;
    return calloc(1, sizeof(E9Config));
}

void e9gui_config_save(E9Config *config, const char *path)
{
    (void)config; (void)path;
    /* TODO: Implement */
}

void e9gui_config_free(E9Config *config)
{
    free(config);
}

const char *e9gui_config_get_string(E9Config *config, const char *section, const char *key, const char *default_val)
{
    (void)config; (void)section; (void)key;
    return default_val;
}

int e9gui_config_get_int(E9Config *config, const char *section, const char *key, int default_val)
{
    (void)config; (void)section; (void)key;
    return default_val;
}

bool e9gui_config_get_bool(E9Config *config, const char *section, const char *key, bool default_val)
{
    (void)config; (void)section; (void)key;
    return default_val;
}

void e9gui_config_set_string(E9Config *config, const char *section, const char *key, const char *value)
{
    (void)config; (void)section; (void)key; (void)value;
    /* TODO: Implement */
}

void e9gui_config_set_int(E9Config *config, const char *section, const char *key, int value)
{
    (void)config; (void)section; (void)key; (void)value;
    /* TODO: Implement */
}

void e9gui_config_set_bool(E9Config *config, const char *section, const char *key, bool value)
{
    (void)config; (void)section; (void)key; (void)value;
    /* TODO: Implement */
}
