/**
 * E9Patch Notepad++ Native Plugin
 *
 * Native DLL plugin for Notepad++ with WebSocket integration.
 * Compile with Visual Studio or MinGW.
 *
 * Build:
 *   cl /LD /EHsc /O2 e9patch_npp.cpp ws2_32.lib user32.lib /Fe:E9Patch.dll
 *
 * Install:
 *   Copy E9Patch.dll to %PROGRAMFILES%/Notepad++/plugins/E9Patch/
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <process.h>
#include <stdio.h>
#include <string.h>

#pragma comment(lib, "ws2_32.lib")

// Notepad++ plugin headers (simplified)
typedef struct {
    int _nCmdID;
    void (*_pFunc)();
    const TCHAR *_itemName;
    void *_pShKey;
} FuncItem;

typedef struct {
    HWND _nppHandle;
    HWND _scintillaMainHandle;
    HWND _scintillaSecondHandle;
} NppData;

// Plugin info
static const TCHAR PLUGIN_NAME[] = TEXT("E9Patch");
#define MENU_COUNT 8

// State
static NppData nppData;
static SOCKET g_socket = INVALID_SOCKET;
static volatile bool g_connected = false;
static volatile bool g_running = false;
static HANDLE g_recvThread = NULL;

// Configuration
static char g_host[256] = "localhost";
static int g_port = 9229;

// Forward declarations
void connect_server();
void disconnect_server();
void toggle_breakpoint();
void clear_breakpoints();
void hot_reload();
void show_status();
void open_browser();
void show_settings();

// Menu items
static FuncItem funcItems[MENU_COUNT] = {
    {0, connect_server, TEXT("Connect"), NULL},
    {0, disconnect_server, TEXT("Disconnect"), NULL},
    {0, NULL, TEXT("---"), NULL},
    {0, toggle_breakpoint, TEXT("Toggle Breakpoint"), NULL},
    {0, clear_breakpoints, TEXT("Clear Breakpoints"), NULL},
    {0, hot_reload, TEXT("Hot Reload"), NULL},
    {0, NULL, TEXT("---"), NULL},
    {0, show_status, TEXT("Status"), NULL},
};

// ============================================================================
// Helpers
// ============================================================================

static void log_message(const char *msg) {
    char buf[512];
    snprintf(buf, sizeof(buf), "[E9Patch] %s\n", msg);
    OutputDebugStringA(buf);
}

static bool send_message(const char *json) {
    if (!g_connected || g_socket == INVALID_SOCKET) {
        return false;
    }

    char buf[4096];
    snprintf(buf, sizeof(buf), "%s\n", json);

    int result = send(g_socket, buf, (int)strlen(buf), 0);
    return result > 0;
}

static void handle_message(const char *json) {
    // Simple JSON parsing (production code should use proper JSON library)
    if (strstr(json, "\"patchResult\"")) {
        if (strstr(json, "\"success\":true") || strstr(json, "\"success\": true")) {
            log_message("Patch applied successfully");
        } else {
            log_message("Patch failed");
        }
    } else if (strstr(json, "\"breakpointHit\"")) {
        log_message("Breakpoint hit");
    } else if (strstr(json, "\"status\"")) {
        log_message("Server ready");
    }
}

static unsigned __stdcall recv_thread(void *) {
    char buffer[8192];
    char line[4096];
    int linePos = 0;

    while (g_running && g_socket != INVALID_SOCKET) {
        fd_set readSet;
        FD_ZERO(&readSet);
        FD_SET(g_socket, &readSet);

        timeval timeout = {1, 0};  // 1 second
        int result = select(0, &readSet, NULL, NULL, &timeout);

        if (result <= 0) continue;

        int bytes = recv(g_socket, buffer, sizeof(buffer) - 1, 0);
        if (bytes <= 0) break;

        buffer[bytes] = '\0';

        // Process buffer character by character
        for (int i = 0; i < bytes; i++) {
            if (buffer[i] == '\n') {
                line[linePos] = '\0';
                if (linePos > 0) {
                    handle_message(line);
                }
                linePos = 0;
            } else if (linePos < sizeof(line) - 1) {
                line[linePos++] = buffer[i];
            }
        }
    }

    g_connected = false;
    closesocket(g_socket);
    g_socket = INVALID_SOCKET;

    log_message("Disconnected");
    return 0;
}

static char* get_current_file() {
    static char filepath[MAX_PATH];
    SendMessage(nppData._nppHandle, NPPM_GETFULLCURRENTPATH, MAX_PATH, (LPARAM)filepath);
    return filepath;
}

static int get_current_line() {
    return (int)SendMessage(nppData._scintillaMainHandle, SCI_LINEFROMPOSITION,
        SendMessage(nppData._scintillaMainHandle, SCI_GETCURRENTPOS, 0, 0), 0) + 1;
}

static bool is_c_file(const char *filepath) {
    const char *ext = strrchr(filepath, '.');
    if (!ext) return false;

    return _stricmp(ext, ".c") == 0 ||
           _stricmp(ext, ".cpp") == 0 ||
           _stricmp(ext, ".cc") == 0 ||
           _stricmp(ext, ".cxx") == 0 ||
           _stricmp(ext, ".h") == 0 ||
           _stricmp(ext, ".hpp") == 0;
}

// ============================================================================
// Commands
// ============================================================================

void connect_server() {
    if (g_connected) {
        MessageBoxA(nppData._nppHandle, "Already connected", "E9Patch", MB_OK);
        return;
    }

    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        MessageBoxA(nppData._nppHandle, "WSAStartup failed", "E9Patch Error", MB_ICONERROR);
        return;
    }

    g_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (g_socket == INVALID_SOCKET) {
        MessageBoxA(nppData._nppHandle, "Socket creation failed", "E9Patch Error", MB_ICONERROR);
        WSACleanup();
        return;
    }

    struct sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(g_port);
    inet_pton(AF_INET, g_host, &serverAddr.sin_addr);

    if (connect(g_socket, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        char msg[256];
        snprintf(msg, sizeof(msg), "Connection to %s:%d failed", g_host, g_port);
        MessageBoxA(nppData._nppHandle, msg, "E9Patch Error", MB_ICONERROR);
        closesocket(g_socket);
        g_socket = INVALID_SOCKET;
        WSACleanup();
        return;
    }

    g_connected = true;
    g_running = true;

    // Start receive thread
    g_recvThread = (HANDLE)_beginthreadex(NULL, 0, recv_thread, NULL, 0, NULL);

    // Send handshake
    send_message("{\"type\":\"hello\",\"data\":{\"client\":\"notepad++\",\"version\":\"1.0.0\"}}");

    log_message("Connected");
    MessageBoxA(nppData._nppHandle, "Connected to E9Patch server", "E9Patch", MB_OK);
}

void disconnect_server() {
    g_running = false;

    if (g_socket != INVALID_SOCKET) {
        closesocket(g_socket);
        g_socket = INVALID_SOCKET;
    }

    if (g_recvThread) {
        WaitForSingleObject(g_recvThread, 1000);
        CloseHandle(g_recvThread);
        g_recvThread = NULL;
    }

    g_connected = false;
    WSACleanup();

    log_message("Disconnected");
}

void toggle_breakpoint() {
    char *filepath = get_current_file();
    if (!is_c_file(filepath)) {
        MessageBoxA(nppData._nppHandle, "Not a C/C++ file", "E9Patch", MB_OK);
        return;
    }

    int line = get_current_line();

    char json[1024];
    snprintf(json, sizeof(json),
        "{\"type\":\"setBreakpoint\",\"data\":{\"file\":\"%s\",\"line\":%d}}",
        filepath, line);

    // Escape backslashes in path
    for (char *p = json; *p; p++) {
        if (*p == '\\' && *(p+1) != '\\') {
            memmove(p + 1, p, strlen(p) + 1);
            *p = '\\';
            p++;
        }
    }

    send_message(json);

    char msg[256];
    snprintf(msg, sizeof(msg), "Breakpoint set at line %d", line);
    log_message(msg);
}

void clear_breakpoints() {
    send_message("{\"type\":\"clearAllBreakpoints\",\"data\":{}}");
    log_message("Cleared all breakpoints");
}

void hot_reload() {
    char *filepath = get_current_file();
    if (!is_c_file(filepath)) {
        MessageBoxA(nppData._nppHandle, "Not a C/C++ file", "E9Patch", MB_OK);
        return;
    }

    char json[1024];
    snprintf(json, sizeof(json),
        "{\"type\":\"requestReload\",\"data\":{\"file\":\"%s\"}}",
        filepath);

    send_message(json);
    log_message("Hot reload requested");
}

void show_status() {
    char msg[512];
    snprintf(msg, sizeof(msg),
        "E9Patch Status\n"
        "==============\n"
        "Connected: %s\n"
        "Server: %s:%d",
        g_connected ? "Yes" : "No",
        g_host, g_port);

    MessageBoxA(nppData._nppHandle, msg, "E9Patch Status", MB_ICONINFORMATION);
}

// ============================================================================
// Notepad++ Plugin Interface
// ============================================================================

// Required message definitions (normally from Notepad++ SDK)
#define NPPM_GETFULLCURRENTPATH (WM_USER + 1000 + 72)
#define SCI_GETCURRENTPOS 2008
#define SCI_LINEFROMPOSITION 2166

extern "C" {

__declspec(dllexport) void setInfo(NppData notpadPlusData) {
    nppData = notpadPlusData;
}

__declspec(dllexport) const TCHAR * getName() {
    return PLUGIN_NAME;
}

__declspec(dllexport) FuncItem * getFuncsArray(int *nbF) {
    *nbF = MENU_COUNT;
    return funcItems;
}

__declspec(dllexport) void beNotified(void *notifyCode) {
    // Handle notifications (file save, etc.)
}

__declspec(dllexport) LRESULT messageProc(UINT, WPARAM, LPARAM) {
    return TRUE;
}

__declspec(dllexport) BOOL isUnicode() {
    return TRUE;
}

}  // extern "C"

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved) {
    switch (reason) {
        case DLL_PROCESS_ATTACH:
            break;
        case DLL_PROCESS_DETACH:
            disconnect_server();
            break;
    }
    return TRUE;
}
