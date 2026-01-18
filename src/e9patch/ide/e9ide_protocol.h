/*
 * e9ide_protocol.h
 * E9Studio IDE Integration Protocol
 *
 * Defines a JSON-RPC based protocol for IDE plugins to communicate
 * with E9Studio. Similar to LSP (Language Server Protocol) but
 * specialized for binary analysis and patching.
 *
 * Supported IDEs:
 * - VS Code (via extension)
 * - CLion / JetBrains IDEs (via plugin)
 * - Vim/Neovim (via plugin)
 * - Emacs (via package)
 *
 * Communication:
 * - JSON-RPC 2.0 over stdio or TCP
 * - Request-response and notification patterns
 *
 * Copyright (C) 2024 E9Patch Contributors
 * License: GPLv3+
 */

#ifndef E9IDE_PROTOCOL_H
#define E9IDE_PROTOCOL_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ============================================================================
 * Protocol Version
 * ============================================================================
 */

#define E9IDE_PROTOCOL_VERSION      "1.0.0"
#define E9IDE_PROTOCOL_VERSION_MAJOR 1
#define E9IDE_PROTOCOL_VERSION_MINOR 0

/*
 * ============================================================================
 * Transport Types
 * ============================================================================
 */

typedef enum {
    E9IDE_TRANSPORT_STDIO,      /* Standard input/output */
    E9IDE_TRANSPORT_TCP,        /* TCP socket */
    E9IDE_TRANSPORT_PIPE,       /* Named pipe */
} E9IDETransport;

/*
 * ============================================================================
 * Request/Response Types
 * ============================================================================
 */

/* Method names (JSON-RPC method field) */
#define E9IDE_METHOD_INITIALIZE         "initialize"
#define E9IDE_METHOD_SHUTDOWN           "shutdown"
#define E9IDE_METHOD_EXIT               "exit"

#define E9IDE_METHOD_OPEN_BINARY        "binary/open"
#define E9IDE_METHOD_CLOSE_BINARY       "binary/close"
#define E9IDE_METHOD_GET_INFO           "binary/getInfo"

#define E9IDE_METHOD_GET_FUNCTIONS      "analysis/getFunctions"
#define E9IDE_METHOD_GET_DISASM         "analysis/getDisassembly"
#define E9IDE_METHOD_GET_DECOMPILE      "analysis/getDecompilation"
#define E9IDE_METHOD_GET_CFG            "analysis/getCFG"
#define E9IDE_METHOD_GET_XREFS          "analysis/getXrefs"
#define E9IDE_METHOD_GET_STRINGS        "analysis/getStrings"
#define E9IDE_METHOD_GET_SYMBOLS        "analysis/getSymbols"

#define E9IDE_METHOD_PATCH_BYTES        "patch/bytes"
#define E9IDE_METHOD_PATCH_NOP          "patch/nop"
#define E9IDE_METHOD_PATCH_INSN         "patch/instruction"
#define E9IDE_METHOD_PATCH_CALL         "patch/call"
#define E9IDE_METHOD_PATCH_JMP          "patch/jump"
#define E9IDE_METHOD_PATCH_APPLY        "patch/apply"
#define E9IDE_METHOD_PATCH_REVERT       "patch/revert"
#define E9IDE_METHOD_PATCH_SAVE         "patch/save"
#define E9IDE_METHOD_PATCH_LIST         "patch/list"

#define E9IDE_METHOD_GOTO_ADDRESS       "navigate/gotoAddress"
#define E9IDE_METHOD_GOTO_SYMBOL        "navigate/gotoSymbol"
#define E9IDE_METHOD_SEARCH             "navigate/search"

/* Notifications (no response expected) */
#define E9IDE_NOTIFY_BINARY_CHANGED     "binary/changed"
#define E9IDE_NOTIFY_ANALYSIS_PROGRESS  "analysis/progress"
#define E9IDE_NOTIFY_PATCH_APPLIED      "patch/applied"
#define E9IDE_NOTIFY_LOG                "window/logMessage"

/*
 * ============================================================================
 * Error Codes (JSON-RPC error codes)
 * ============================================================================
 */

/* Standard JSON-RPC errors */
#define E9IDE_ERR_PARSE_ERROR           -32700
#define E9IDE_ERR_INVALID_REQUEST       -32600
#define E9IDE_ERR_METHOD_NOT_FOUND      -32601
#define E9IDE_ERR_INVALID_PARAMS        -32602
#define E9IDE_ERR_INTERNAL_ERROR        -32603

/* E9-specific errors (-32000 to -32099) */
#define E9IDE_ERR_BINARY_NOT_FOUND      -32001
#define E9IDE_ERR_BINARY_NOT_OPEN       -32002
#define E9IDE_ERR_INVALID_ADDRESS       -32003
#define E9IDE_ERR_PATCH_FAILED          -32004
#define E9IDE_ERR_ANALYSIS_FAILED       -32005
#define E9IDE_ERR_UNSUPPORTED_FORMAT    -32006
#define E9IDE_ERR_PERMISSION_DENIED     -32007

/*
 * ============================================================================
 * Capability Flags
 * ============================================================================
 */

typedef enum {
    E9IDE_CAP_DISASSEMBLY       = 0x0001,
    E9IDE_CAP_DECOMPILATION     = 0x0002,
    E9IDE_CAP_CFG               = 0x0004,
    E9IDE_CAP_PATCHING          = 0x0008,
    E9IDE_CAP_SYMBOL_INJECTION  = 0x0010,
    E9IDE_CAP_LIVE_EDIT         = 0x0020,
    E9IDE_CAP_DEBUG_INFO        = 0x0040,
    E9IDE_CAP_WASM_PLUGINS      = 0x0080,
    E9IDE_CAP_X86_64            = 0x0100,
    E9IDE_CAP_AARCH64           = 0x0200,
    E9IDE_CAP_ELF               = 0x0400,
    E9IDE_CAP_PE                = 0x0800,
    E9IDE_CAP_MACHO             = 0x1000,
    E9IDE_CAP_APE               = 0x2000,
} E9IDECapability;

/*
 * ============================================================================
 * Server Context
 * ============================================================================
 */

typedef struct E9IDEServer E9IDEServer;

typedef void (*E9IDELogCallback)(void *user, int level, const char *message);
typedef void (*E9IDERequestCallback)(E9IDEServer *server, int id,
                                      const char *method, const char *params);

/*
 * Server configuration
 */
typedef struct {
    E9IDETransport transport;
    int port;                   /* For TCP transport */
    const char *pipe_name;      /* For pipe transport */
    E9IDELogCallback log_cb;
    void *log_user;
    uint32_t capabilities;      /* E9IDECapability flags */
} E9IDEServerConfig;

/*
 * ============================================================================
 * API - Server Lifecycle
 * ============================================================================
 */

/*
 * Create IDE server with configuration
 */
E9IDEServer *e9ide_server_create(const E9IDEServerConfig *config);

/*
 * Free server resources
 */
void e9ide_server_free(E9IDEServer *server);

/*
 * Start server (begins listening for connections/input)
 */
int e9ide_server_start(E9IDEServer *server);

/*
 * Stop server
 */
void e9ide_server_stop(E9IDEServer *server);

/*
 * Process one message (call in event loop)
 * Returns: 1 = message processed, 0 = no message, -1 = error/shutdown
 */
int e9ide_server_process(E9IDEServer *server);

/*
 * Run server main loop (blocks until shutdown)
 */
int e9ide_server_run(E9IDEServer *server);

/*
 * ============================================================================
 * API - Response Helpers
 * ============================================================================
 */

/*
 * Send success response
 */
int e9ide_respond_success(E9IDEServer *server, int id, const char *result_json);

/*
 * Send error response
 */
int e9ide_respond_error(E9IDEServer *server, int id, int code, const char *message);

/*
 * Send notification
 */
int e9ide_notify(E9IDEServer *server, const char *method, const char *params_json);

/*
 * ============================================================================
 * API - Built-in Request Handlers
 * ============================================================================
 */

/*
 * Register standard handlers for all E9 methods
 * Server automatically handles: initialize, shutdown, exit, binary/*, analysis/*, patch/*
 */
int e9ide_register_standard_handlers(E9IDEServer *server);

/*
 * Register custom handler for a method
 */
typedef int (*E9IDEHandler)(E9IDEServer *server, int id, const char *params_json, void *user);

int e9ide_register_handler(E9IDEServer *server, const char *method,
                           E9IDEHandler handler, void *user);

/*
 * ============================================================================
 * JSON Helpers
 * ============================================================================
 */

/*
 * Build JSON-RPC request
 */
char *e9ide_json_request(int id, const char *method, const char *params);

/*
 * Build JSON-RPC response
 */
char *e9ide_json_response(int id, const char *result);

/*
 * Build JSON-RPC error
 */
char *e9ide_json_error(int id, int code, const char *message);

/*
 * Build JSON-RPC notification
 */
char *e9ide_json_notify(const char *method, const char *params);

/*
 * Parse JSON string field
 */
const char *e9ide_json_get_string(const char *json, const char *key);

/*
 * Parse JSON integer field
 */
int64_t e9ide_json_get_int(const char *json, const char *key);

/*
 * Parse JSON boolean field
 */
bool e9ide_json_get_bool(const char *json, const char *key);

#ifdef __cplusplus
}
#endif

#endif /* E9IDE_PROTOCOL_H */
