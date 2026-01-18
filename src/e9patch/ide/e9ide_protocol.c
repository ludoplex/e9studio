/*
 * e9ide_protocol.c
 * E9Studio IDE Integration Protocol Implementation
 *
 * Copyright (C) 2024 E9Patch Contributors
 * License: GPLv3+
 */

#include "e9ide_protocol.h"
#include "../analysis/e9analysis.h"
#include "../analysis/e9decompile.h"
#include "../analysis/e9binpatch.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <errno.h>
#endif

/*
 * ============================================================================
 * Internal Structures
 * ============================================================================
 */

#define MAX_HANDLERS 64
#define MAX_MESSAGE_SIZE (16 * 1024 * 1024)  /* 16 MB max message */
#define READ_BUFFER_SIZE 65536

typedef struct {
    const char *method;
    E9IDEHandler handler;
    void *user;
} E9IDEHandlerEntry;

struct E9IDEServer {
    E9IDEServerConfig config;

    /* Connection state */
    bool running;
    bool initialized;

#ifdef _WIN32
    SOCKET listen_sock;
    SOCKET client_sock;
#else
    int listen_fd;
    int client_fd;
#endif

    /* Read buffer */
    char *read_buffer;
    size_t read_pos;
    size_t read_capacity;

    /* Handlers */
    E9IDEHandlerEntry handlers[MAX_HANDLERS];
    int num_handlers;

    /* Currently open binary */
    E9Binary *current_binary;
    E9BinPatchSession *patch_session;
    char *binary_path;

    /* Request ID counter */
    int next_id;
};

/*
 * ============================================================================
 * Memory Helpers
 * ============================================================================
 */

static void *ide_alloc(size_t size)
{
    return calloc(1, size);
}

static void ide_free(void *ptr)
{
    free(ptr);
}

static char *ide_strdup(const char *s)
{
    if (!s) return NULL;
    size_t len = strlen(s) + 1;
    char *p = ide_alloc(len);
    if (p) memcpy(p, s, len);
    return p;
}

/*
 * ============================================================================
 * JSON Helpers (minimal implementation)
 * ============================================================================
 */

/* Escape string for JSON */
static char *json_escape(const char *s)
{
    if (!s) return ide_strdup("null");

    size_t len = strlen(s);
    size_t out_cap = len * 2 + 3;
    char *out = ide_alloc(out_cap);
    if (!out) return NULL;

    size_t pos = 0;
    out[pos++] = '"';

    for (size_t i = 0; i < len && pos < out_cap - 2; i++) {
        char c = s[i];
        switch (c) {
        case '"':  out[pos++] = '\\'; out[pos++] = '"'; break;
        case '\\': out[pos++] = '\\'; out[pos++] = '\\'; break;
        case '\n': out[pos++] = '\\'; out[pos++] = 'n'; break;
        case '\r': out[pos++] = '\\'; out[pos++] = 'r'; break;
        case '\t': out[pos++] = '\\'; out[pos++] = 't'; break;
        default:
            if (c >= 32 && c < 127) {
                out[pos++] = c;
            } else {
                pos += snprintf(out + pos, out_cap - pos, "\\u%04x", (unsigned char)c);
            }
        }
    }

    out[pos++] = '"';
    out[pos] = '\0';
    return out;
}

char *e9ide_json_request(int id, const char *method, const char *params)
{
    size_t cap = 256 + strlen(method) + (params ? strlen(params) : 2);
    char *buf = ide_alloc(cap);
    if (!buf) return NULL;

    snprintf(buf, cap,
             "{\"jsonrpc\":\"2.0\",\"id\":%d,\"method\":\"%s\",\"params\":%s}",
             id, method, params ? params : "{}");
    return buf;
}

char *e9ide_json_response(int id, const char *result)
{
    size_t cap = 128 + (result ? strlen(result) : 4);
    char *buf = ide_alloc(cap);
    if (!buf) return NULL;

    snprintf(buf, cap,
             "{\"jsonrpc\":\"2.0\",\"id\":%d,\"result\":%s}",
             id, result ? result : "null");
    return buf;
}

char *e9ide_json_error(int id, int code, const char *message)
{
    char *escaped = json_escape(message);
    size_t cap = 128 + (escaped ? strlen(escaped) : 4);
    char *buf = ide_alloc(cap);
    if (!buf) {
        ide_free(escaped);
        return NULL;
    }

    snprintf(buf, cap,
             "{\"jsonrpc\":\"2.0\",\"id\":%d,\"error\":{\"code\":%d,\"message\":%s}}",
             id, code, escaped ? escaped : "null");
    ide_free(escaped);
    return buf;
}

char *e9ide_json_notify(const char *method, const char *params)
{
    size_t cap = 128 + strlen(method) + (params ? strlen(params) : 2);
    char *buf = ide_alloc(cap);
    if (!buf) return NULL;

    snprintf(buf, cap,
             "{\"jsonrpc\":\"2.0\",\"method\":\"%s\",\"params\":%s}",
             method, params ? params : "{}");
    return buf;
}

/* Simple JSON field extraction (returns allocated string, caller frees) */
const char *e9ide_json_get_string(const char *json, const char *key)
{
    if (!json || !key) return NULL;

    char pattern[128];
    snprintf(pattern, sizeof(pattern), "\"%s\":", key);

    const char *pos = strstr(json, pattern);
    if (!pos) return NULL;

    pos += strlen(pattern);
    while (*pos == ' ' || *pos == '\t') pos++;

    if (*pos != '"') return NULL;
    pos++;

    const char *end = pos;
    while (*end && *end != '"') {
        if (*end == '\\') end++;
        end++;
    }

    size_t len = end - pos;
    char *result = ide_alloc(len + 1);
    if (!result) return NULL;
    memcpy(result, pos, len);
    result[len] = '\0';
    return result;
}

int64_t e9ide_json_get_int(const char *json, const char *key)
{
    if (!json || !key) return 0;

    char pattern[128];
    snprintf(pattern, sizeof(pattern), "\"%s\":", key);

    const char *pos = strstr(json, pattern);
    if (!pos) return 0;

    pos += strlen(pattern);
    while (*pos == ' ' || *pos == '\t') pos++;

    return strtoll(pos, NULL, 0);
}

bool e9ide_json_get_bool(const char *json, const char *key)
{
    if (!json || !key) return false;

    char pattern[128];
    snprintf(pattern, sizeof(pattern), "\"%s\":", key);

    const char *pos = strstr(json, pattern);
    if (!pos) return false;

    pos += strlen(pattern);
    while (*pos == ' ' || *pos == '\t') pos++;

    return (strncmp(pos, "true", 4) == 0);
}

/*
 * ============================================================================
 * Server Creation/Destruction
 * ============================================================================
 */

E9IDEServer *e9ide_server_create(const E9IDEServerConfig *config)
{
    if (!config) return NULL;

    E9IDEServer *server = ide_alloc(sizeof(E9IDEServer));
    if (!server) return NULL;

    server->config = *config;
    server->read_capacity = READ_BUFFER_SIZE;
    server->read_buffer = ide_alloc(server->read_capacity);
    if (!server->read_buffer) {
        ide_free(server);
        return NULL;
    }

#ifdef _WIN32
    server->listen_sock = INVALID_SOCKET;
    server->client_sock = INVALID_SOCKET;
#else
    server->listen_fd = -1;
    server->client_fd = -1;
#endif

    return server;
}

void e9ide_server_free(E9IDEServer *server)
{
    if (!server) return;

    e9ide_server_stop(server);

    if (server->current_binary) {
        e9_binary_free(server->current_binary);
    }
    if (server->patch_session) {
        e9_binpatch_session_free(server->patch_session);
    }
    ide_free(server->binary_path);
    ide_free(server->read_buffer);
    ide_free(server);
}

/*
 * ============================================================================
 * I/O Operations
 * ============================================================================
 */

static void write_message(E9IDEServer *server, const char *message)
{
    if (!message) return;

    size_t len = strlen(message);

    /* Write Content-Length header + message (LSP-style) */
    char header[64];
    int header_len = snprintf(header, sizeof(header), "Content-Length: %zu\r\n\r\n", len);

    if (server->config.transport == E9IDE_TRANSPORT_STDIO) {
        fwrite(header, 1, header_len, stdout);
        fwrite(message, 1, len, stdout);
        fflush(stdout);
    }
#ifndef _WIN32
    else if (server->config.transport == E9IDE_TRANSPORT_TCP && server->client_fd >= 0) {
        write(server->client_fd, header, header_len);
        write(server->client_fd, message, len);
    }
#endif
}

static char *read_message(E9IDEServer *server)
{
    /* Read Content-Length header */
    char line[256];
    size_t content_length = 0;

    if (server->config.transport == E9IDE_TRANSPORT_STDIO) {
        while (fgets(line, sizeof(line), stdin)) {
            if (strncmp(line, "Content-Length:", 15) == 0) {
                content_length = strtoul(line + 15, NULL, 10);
            }
            if (strcmp(line, "\r\n") == 0 || strcmp(line, "\n") == 0) {
                break;
            }
        }

        if (content_length == 0 || content_length > MAX_MESSAGE_SIZE) {
            return NULL;
        }

        char *message = ide_alloc(content_length + 1);
        if (!message) return NULL;

        size_t read = fread(message, 1, content_length, stdin);
        if (read != content_length) {
            ide_free(message);
            return NULL;
        }
        message[content_length] = '\0';
        return message;
    }

    return NULL;
}

/*
 * ============================================================================
 * Response/Notification Helpers
 * ============================================================================
 */

int e9ide_respond_success(E9IDEServer *server, int id, const char *result_json)
{
    if (!server) return -1;
    char *msg = e9ide_json_response(id, result_json);
    if (!msg) return -1;
    write_message(server, msg);
    ide_free(msg);
    return 0;
}

int e9ide_respond_error(E9IDEServer *server, int id, int code, const char *message)
{
    if (!server) return -1;
    char *msg = e9ide_json_error(id, code, message);
    if (!msg) return -1;
    write_message(server, msg);
    ide_free(msg);
    return 0;
}

int e9ide_notify(E9IDEServer *server, const char *method, const char *params_json)
{
    if (!server) return -1;
    char *msg = e9ide_json_notify(method, params_json);
    if (!msg) return -1;
    write_message(server, msg);
    ide_free(msg);
    return 0;
}

/*
 * ============================================================================
 * Standard Handlers
 * ============================================================================
 */

static int handle_initialize(E9IDEServer *server, int id,
                             const char *params, void *user)
{
    (void)params;
    (void)user;

    server->initialized = true;

    /* Build capabilities response */
    char result[1024];
    snprintf(result, sizeof(result),
             "{"
             "\"capabilities\":{"
             "\"disassembly\":true,"
             "\"decompilation\":true,"
             "\"cfg\":true,"
             "\"patching\":true,"
             "\"symbolInjection\":true,"
             "\"supportedArchitectures\":[\"x86-64\",\"aarch64\"],"
             "\"supportedFormats\":[\"elf\",\"pe\",\"macho\",\"ape\"]"
             "},"
             "\"serverInfo\":{"
             "\"name\":\"E9Studio\","
             "\"version\":\"%s\""
             "}"
             "}",
             E9IDE_PROTOCOL_VERSION);

    return e9ide_respond_success(server, id, result);
}

static int handle_shutdown(E9IDEServer *server, int id,
                           const char *params, void *user)
{
    (void)params;
    (void)user;

    server->running = false;
    return e9ide_respond_success(server, id, "null");
}

static int handle_exit(E9IDEServer *server, int id,
                       const char *params, void *user)
{
    (void)id;
    (void)params;
    (void)user;

    server->running = false;
    return 0;
}

static int handle_binary_open(E9IDEServer *server, int id,
                              const char *params, void *user)
{
    (void)user;

    const char *path = e9ide_json_get_string(params, "path");
    if (!path) {
        return e9ide_respond_error(server, id, E9IDE_ERR_INVALID_PARAMS,
                                   "Missing 'path' parameter");
    }

    /* Close existing binary */
    if (server->current_binary) {
        e9_binary_free(server->current_binary);
        server->current_binary = NULL;
    }
    if (server->patch_session) {
        e9_binpatch_session_free(server->patch_session);
        server->patch_session = NULL;
    }
    ide_free(server->binary_path);

    /* Open new binary */
    server->current_binary = e9_binary_open(path);
    if (!server->current_binary) {
        ide_free((void*)path);
        return e9ide_respond_error(server, id, E9IDE_ERR_BINARY_NOT_FOUND,
                                   "Failed to open binary");
    }

    server->binary_path = ide_strdup(path);
    ide_free((void*)path);

    /* Create patch session */
    server->patch_session = e9_binpatch_session_create(server->current_binary);

    /* Return binary info */
    E9Binary *bin = server->current_binary;
    char result[512];
    snprintf(result, sizeof(result),
             "{"
             "\"path\":\"%s\","
             "\"size\":%zu,"
             "\"arch\":\"%s\","
             "\"format\":\"%s\","
             "\"entryPoint\":\"0x%lx\","
             "\"baseAddress\":\"0x%lx\","
             "\"numFunctions\":%u,"
             "\"numSymbols\":%u"
             "}",
             server->binary_path,
             bin->size,
             bin->arch == E9_ARCH_AARCH64 ? "aarch64" : "x86-64",
             bin->format == E9_FORMAT_ELF ? "elf" :
             bin->format == E9_FORMAT_PE ? "pe" :
             bin->format == E9_FORMAT_MACHO ? "macho" : "unknown",
             (unsigned long)bin->entry_point,
             (unsigned long)bin->base_address,
             bin->num_functions,
             bin->num_symbols);

    return e9ide_respond_success(server, id, result);
}

static int handle_binary_close(E9IDEServer *server, int id,
                               const char *params, void *user)
{
    (void)params;
    (void)user;

    if (server->current_binary) {
        e9_binary_free(server->current_binary);
        server->current_binary = NULL;
    }
    if (server->patch_session) {
        e9_binpatch_session_free(server->patch_session);
        server->patch_session = NULL;
    }
    ide_free(server->binary_path);
    server->binary_path = NULL;

    return e9ide_respond_success(server, id, "null");
}

static int handle_get_disasm(E9IDEServer *server, int id,
                             const char *params, void *user)
{
    (void)user;

    if (!server->current_binary) {
        return e9ide_respond_error(server, id, E9IDE_ERR_BINARY_NOT_OPEN,
                                   "No binary is open");
    }

    uint64_t address = (uint64_t)e9ide_json_get_int(params, "address");
    int64_t count = e9ide_json_get_int(params, "count");
    if (count <= 0) count = 20;
    if (count > 100) count = 100;

    /* Build disassembly result */
    size_t cap = 256 + count * 128;
    char *result = ide_alloc(cap);
    if (!result) {
        return e9ide_respond_error(server, id, E9IDE_ERR_INTERNAL_ERROR,
                                   "Memory allocation failed");
    }

    size_t pos = 0;
    pos += snprintf(result + pos, cap - pos, "{\"instructions\":[");

    E9Binary *bin = server->current_binary;
    E9Instruction insn;
    uint64_t addr = address;

    for (int i = 0; i < count && pos < cap - 200; i++) {
        if (e9_disasm(bin, addr, &insn) < 0) break;

        char disasm_buf[128];
        e9_disasm_str(bin, &insn, disasm_buf, sizeof(disasm_buf));

        if (i > 0) pos += snprintf(result + pos, cap - pos, ",");
        pos += snprintf(result + pos, cap - pos,
                        "{\"address\":\"0x%lx\",\"size\":%u,\"mnemonic\":\"%s\",\"text\":\"%s\"}",
                        (unsigned long)addr, insn.size, insn.mnemonic, disasm_buf);

        addr += insn.size;
    }

    pos += snprintf(result + pos, cap - pos, "]}");

    int ret = e9ide_respond_success(server, id, result);
    ide_free(result);
    return ret;
}

static int handle_get_functions(E9IDEServer *server, int id,
                                const char *params, void *user)
{
    (void)params;
    (void)user;

    if (!server->current_binary) {
        return e9ide_respond_error(server, id, E9IDE_ERR_BINARY_NOT_OPEN,
                                   "No binary is open");
    }

    E9Binary *bin = server->current_binary;

    /* Build function list */
    size_t cap = 256 + bin->num_functions * 128;
    char *result = ide_alloc(cap);
    if (!result) {
        return e9ide_respond_error(server, id, E9IDE_ERR_INTERNAL_ERROR,
                                   "Memory allocation failed");
    }

    size_t pos = 0;
    pos += snprintf(result + pos, cap - pos, "{\"functions\":[");

    for (uint32_t i = 0; i < bin->num_functions && pos < cap - 200; i++) {
        E9Function *func = &bin->functions[i];
        if (i > 0) pos += snprintf(result + pos, cap - pos, ",");
        pos += snprintf(result + pos, cap - pos,
                        "{\"address\":\"0x%lx\",\"size\":%u,\"name\":\"%s\"}",
                        (unsigned long)func->address, func->size,
                        func->name ? func->name : "");
    }

    pos += snprintf(result + pos, cap - pos, "]}");

    int ret = e9ide_respond_success(server, id, result);
    ide_free(result);
    return ret;
}

static int handle_patch_nop(E9IDEServer *server, int id,
                            const char *params, void *user)
{
    (void)user;

    if (!server->patch_session) {
        return e9ide_respond_error(server, id, E9IDE_ERR_BINARY_NOT_OPEN,
                                   "No binary is open");
    }

    uint64_t address = (uint64_t)e9ide_json_get_int(params, "address");
    int64_t size = e9ide_json_get_int(params, "size");
    if (size <= 0) size = 1;

    int patch_id = e9_binpatch_nop(server->patch_session, address, size,
                                   E9_BINPATCH_FLAG_BACKUP);
    if (patch_id < 0) {
        return e9ide_respond_error(server, id, E9IDE_ERR_PATCH_FAILED,
                                   "Failed to create NOP patch");
    }

    char result[64];
    snprintf(result, sizeof(result), "{\"patchId\":%d}", patch_id);
    return e9ide_respond_success(server, id, result);
}

static int handle_patch_apply(E9IDEServer *server, int id,
                              const char *params, void *user)
{
    (void)params;
    (void)user;

    if (!server->patch_session) {
        return e9ide_respond_error(server, id, E9IDE_ERR_BINARY_NOT_OPEN,
                                   "No binary is open");
    }

    if (e9_binpatch_apply(server->patch_session) < 0) {
        return e9ide_respond_error(server, id, E9IDE_ERR_PATCH_FAILED,
                                   "Failed to apply patches");
    }

    return e9ide_respond_success(server, id, "{\"success\":true}");
}

static int handle_patch_save(E9IDEServer *server, int id,
                             const char *params, void *user)
{
    (void)user;

    if (!server->patch_session) {
        return e9ide_respond_error(server, id, E9IDE_ERR_BINARY_NOT_OPEN,
                                   "No binary is open");
    }

    const char *path = e9ide_json_get_string(params, "path");
    const char *output_path = path ? path : server->binary_path;

    if (e9_binpatch_write(server->patch_session, output_path) < 0) {
        ide_free((void*)path);
        return e9ide_respond_error(server, id, E9IDE_ERR_PATCH_FAILED,
                                   "Failed to write patched binary");
    }

    ide_free((void*)path);
    return e9ide_respond_success(server, id, "{\"success\":true}");
}

/*
 * ============================================================================
 * Handler Registration
 * ============================================================================
 */

int e9ide_register_handler(E9IDEServer *server, const char *method,
                           E9IDEHandler handler, void *user)
{
    if (!server || !method || !handler) return -1;
    if (server->num_handlers >= MAX_HANDLERS) return -1;

    E9IDEHandlerEntry *entry = &server->handlers[server->num_handlers++];
    entry->method = method;
    entry->handler = handler;
    entry->user = user;
    return 0;
}

int e9ide_register_standard_handlers(E9IDEServer *server)
{
    if (!server) return -1;

    e9ide_register_handler(server, E9IDE_METHOD_INITIALIZE, handle_initialize, NULL);
    e9ide_register_handler(server, E9IDE_METHOD_SHUTDOWN, handle_shutdown, NULL);
    e9ide_register_handler(server, E9IDE_METHOD_EXIT, handle_exit, NULL);

    e9ide_register_handler(server, E9IDE_METHOD_OPEN_BINARY, handle_binary_open, NULL);
    e9ide_register_handler(server, E9IDE_METHOD_CLOSE_BINARY, handle_binary_close, NULL);

    e9ide_register_handler(server, E9IDE_METHOD_GET_DISASM, handle_get_disasm, NULL);
    e9ide_register_handler(server, E9IDE_METHOD_GET_FUNCTIONS, handle_get_functions, NULL);

    e9ide_register_handler(server, E9IDE_METHOD_PATCH_NOP, handle_patch_nop, NULL);
    e9ide_register_handler(server, E9IDE_METHOD_PATCH_APPLY, handle_patch_apply, NULL);
    e9ide_register_handler(server, E9IDE_METHOD_PATCH_SAVE, handle_patch_save, NULL);

    return 0;
}

/*
 * ============================================================================
 * Server Start/Stop/Process
 * ============================================================================
 */

int e9ide_server_start(E9IDEServer *server)
{
    if (!server) return -1;

    server->running = true;

    if (server->config.transport == E9IDE_TRANSPORT_STDIO) {
        /* Nothing special needed for stdio */
        return 0;
    }

#ifndef _WIN32
    if (server->config.transport == E9IDE_TRANSPORT_TCP) {
        server->listen_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (server->listen_fd < 0) return -1;

        int opt = 1;
        setsockopt(server->listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

        struct sockaddr_in addr = {0};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(server->config.port);
        addr.sin_addr.s_addr = INADDR_ANY;

        if (bind(server->listen_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            close(server->listen_fd);
            server->listen_fd = -1;
            return -1;
        }

        if (listen(server->listen_fd, 1) < 0) {
            close(server->listen_fd);
            server->listen_fd = -1;
            return -1;
        }

        return 0;
    }
#endif

    return -1;
}

void e9ide_server_stop(E9IDEServer *server)
{
    if (!server) return;

    server->running = false;

#ifndef _WIN32
    if (server->client_fd >= 0) {
        close(server->client_fd);
        server->client_fd = -1;
    }
    if (server->listen_fd >= 0) {
        close(server->listen_fd);
        server->listen_fd = -1;
    }
#endif
}

static E9IDEHandler find_handler(E9IDEServer *server, const char *method)
{
    for (int i = 0; i < server->num_handlers; i++) {
        if (strcmp(server->handlers[i].method, method) == 0) {
            return server->handlers[i].handler;
        }
    }
    return NULL;
}

int e9ide_server_process(E9IDEServer *server)
{
    if (!server || !server->running) return -1;

    char *message = read_message(server);
    if (!message) {
        if (feof(stdin)) return -1;
        return 0;
    }

    /* Parse JSON-RPC message */
    int id = (int)e9ide_json_get_int(message, "id");
    const char *method = e9ide_json_get_string(message, "method");

    if (!method) {
        ide_free(message);
        return 1;  /* Ignore malformed messages */
    }

    /* Find and invoke handler */
    E9IDEHandler handler = find_handler(server, method);
    if (handler) {
        /* Extract params object (simplistic) */
        const char *params = strstr(message, "\"params\":");
        if (params) {
            params += 9;
            while (*params == ' ' || *params == '\t') params++;
        }

        handler(server, id, params ? params : "{}", NULL);
    } else {
        e9ide_respond_error(server, id, E9IDE_ERR_METHOD_NOT_FOUND,
                           "Method not found");
    }

    ide_free((void*)method);
    ide_free(message);
    return 1;
}

int e9ide_server_run(E9IDEServer *server)
{
    if (!server) return -1;

    while (server->running) {
        int result = e9ide_server_process(server);
        if (result < 0) break;
    }

    return 0;
}
