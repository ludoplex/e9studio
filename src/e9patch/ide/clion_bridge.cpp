/*
 * clion_bridge.cpp
 * CLion IDE integration bridge for e9patch
 *
 * Provides:
 * - WebSocket server for IDE communication
 * - File system watcher for source changes
 * - Hot reload triggering
 * - Debug breakpoint management
 *
 * This can run as:
 * 1. A standalone daemon process
 * 2. Embedded in e9tool
 * 3. As part of the WASM module in browser
 *
 * Copyright (C) 2024 E9Patch Contributors
 * License: GPLv3+
 */

#include "../platform/e9platform.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <map>
#include <functional>
#include <thread>
#include <mutex>
#include <atomic>

#ifndef E9_PLATFORM_WASM
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <poll.h>
#include <sys/inotify.h>
#endif

namespace e9ide {

/*
 * Message types for IDE <-> e9patch communication
 */
enum class MessageType {
    // From IDE to e9patch
    HELLO,              // Initial handshake
    LOAD_BINARY,        // Load binary for patching
    SOURCE_CHANGE,      // Source file changed
    SET_BREAKPOINT,     // Set debug breakpoint
    REMOVE_BREAKPOINT,  // Remove breakpoint
    REQUEST_RELOAD,     // Request hot reload
    GET_STATUS,         // Get current status

    // From e9patch to IDE
    HELLO_ACK,          // Handshake acknowledgment
    PATCH_RESULT,       // Patch applied result
    BREAKPOINT_HIT,     // Breakpoint was hit
    RELOAD_COMPLETE,    // Hot reload finished
    STATUS_UPDATE,      // Status update
    ERROR,              // Error occurred
};

/*
 * Simple JSON builder for messages
 */
class JsonBuilder {
    std::string json;
    bool first = true;

public:
    JsonBuilder() { json = "{"; }

    JsonBuilder& add(const char *key, const char *value) {
        if (!first) json += ",";
        first = false;
        json += "\"";
        json += key;
        json += "\":\"";
        // Escape value
        for (const char *p = value; *p; p++) {
            if (*p == '"') json += "\\\"";
            else if (*p == '\\') json += "\\\\";
            else if (*p == '\n') json += "\\n";
            else json += *p;
        }
        json += "\"";
        return *this;
    }

    JsonBuilder& add(const char *key, int64_t value) {
        if (!first) json += ",";
        first = false;
        json += "\"";
        json += key;
        json += "\":";
        json += std::to_string(value);
        return *this;
    }

    JsonBuilder& add(const char *key, bool value) {
        if (!first) json += ",";
        first = false;
        json += "\"";
        json += key;
        json += "\":";
        json += value ? "true" : "false";
        return *this;
    }

    std::string build() {
        return json + "}";
    }
};

/*
 * Simple JSON parser for messages
 */
class JsonParser {
    std::map<std::string, std::string> values;

public:
    bool parse(const char *json) {
        values.clear();
        // Very simple parser - assumes well-formed JSON
        const char *p = json;
        while (*p && *p != '{') p++;
        if (!*p) return false;
        p++;

        while (*p) {
            // Skip whitespace
            while (*p && (*p == ' ' || *p == '\n' || *p == '\r' || *p == '\t' || *p == ',')) p++;
            if (*p == '}') break;
            if (*p != '"') return false;

            // Parse key
            p++;
            const char *keyStart = p;
            while (*p && *p != '"') p++;
            std::string key(keyStart, p - keyStart);
            if (!*p) return false;
            p++;

            // Skip colon
            while (*p && *p != ':') p++;
            if (!*p) return false;
            p++;
            while (*p && *p == ' ') p++;

            // Parse value
            std::string value;
            if (*p == '"') {
                p++;
                while (*p && *p != '"') {
                    if (*p == '\\' && *(p+1)) {
                        p++;
                        if (*p == 'n') value += '\n';
                        else if (*p == 't') value += '\t';
                        else value += *p;
                    } else {
                        value += *p;
                    }
                    p++;
                }
                if (*p == '"') p++;
            } else {
                // Number or boolean
                const char *valStart = p;
                while (*p && *p != ',' && *p != '}') p++;
                value = std::string(valStart, p - valStart);
                // Trim
                while (!value.empty() && value.back() == ' ') value.pop_back();
            }

            values[key] = value;
        }
        return true;
    }

    std::string get(const char *key, const char *defaultVal = "") const {
        auto it = values.find(key);
        return it != values.end() ? it->second : defaultVal;
    }

    int64_t getInt(const char *key, int64_t defaultVal = 0) const {
        auto it = values.find(key);
        if (it == values.end()) return defaultVal;
        try {
            return std::stoll(it->second);
        } catch (...) {
            return defaultVal;
        }
    }

    bool getBool(const char *key, bool defaultVal = false) const {
        auto it = values.find(key);
        if (it == values.end()) return defaultVal;
        return it->second == "true" || it->second == "1";
    }
};

#ifndef E9_PLATFORM_WASM

/*
 * WebSocket frame encoder/decoder
 */
class WebSocket {
public:
    static std::vector<uint8_t> encodeFrame(const std::string &message) {
        std::vector<uint8_t> frame;
        frame.push_back(0x81);  // FIN + text frame

        size_t len = message.size();
        if (len < 126) {
            frame.push_back((uint8_t)len);
        } else if (len < 65536) {
            frame.push_back(126);
            frame.push_back((len >> 8) & 0xFF);
            frame.push_back(len & 0xFF);
        } else {
            frame.push_back(127);
            for (int i = 7; i >= 0; i--) {
                frame.push_back((len >> (i * 8)) & 0xFF);
            }
        }

        frame.insert(frame.end(), message.begin(), message.end());
        return frame;
    }

    static std::string decodeFrame(const uint8_t *data, size_t dataLen, size_t &consumed) {
        consumed = 0;
        if (dataLen < 2) return "";

        bool masked = (data[1] & 0x80) != 0;
        size_t len = data[1] & 0x7F;
        size_t headerLen = 2;

        if (len == 126) {
            if (dataLen < 4) return "";
            len = (data[2] << 8) | data[3];
            headerLen = 4;
        } else if (len == 127) {
            if (dataLen < 10) return "";
            len = 0;
            for (int i = 0; i < 8; i++) {
                len = (len << 8) | data[2 + i];
            }
            headerLen = 10;
        }

        if (masked) headerLen += 4;
        if (dataLen < headerLen + len) return "";

        std::string result;
        result.resize(len);

        if (masked) {
            const uint8_t *mask = data + headerLen - 4;
            const uint8_t *payload = data + headerLen;
            for (size_t i = 0; i < len; i++) {
                result[i] = payload[i] ^ mask[i % 4];
            }
        } else {
            memcpy(&result[0], data + headerLen, len);
        }

        consumed = headerLen + len;
        return result;
    }
};

/*
 * WebSocket Server for IDE communication
 */
class IDEServer {
    int serverFd = -1;
    int clientFd = -1;
    std::atomic<bool> running{false};
    std::thread serverThread;
    std::mutex sendMutex;

    // Callbacks
    std::function<void(const JsonParser&)> onMessage;
    std::function<void()> onConnect;
    std::function<void()> onDisconnect;

public:
    bool start(int port) {
        serverFd = socket(AF_INET, SOCK_STREAM, 0);
        if (serverFd < 0) return false;

        int opt = 1;
        setsockopt(serverFd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(port);

        if (bind(serverFd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            close(serverFd);
            serverFd = -1;
            return false;
        }

        if (listen(serverFd, 1) < 0) {
            close(serverFd);
            serverFd = -1;
            return false;
        }

        running = true;
        serverThread = std::thread([this]() { serverLoop(); });

        e9platform::platformLog(e9platform::LOG_INFO,
            "IDE server listening on port %d", port);
        return true;
    }

    void stop() {
        running = false;
        if (serverFd >= 0) {
            shutdown(serverFd, SHUT_RDWR);
            close(serverFd);
            serverFd = -1;
        }
        if (clientFd >= 0) {
            close(clientFd);
            clientFd = -1;
        }
        if (serverThread.joinable()) {
            serverThread.join();
        }
    }

    void send(const std::string &message) {
        std::lock_guard<std::mutex> lock(sendMutex);
        if (clientFd < 0) return;

        auto frame = WebSocket::encodeFrame(message);
        ::send(clientFd, frame.data(), frame.size(), 0);
    }

    void setOnMessage(std::function<void(const JsonParser&)> cb) { onMessage = cb; }
    void setOnConnect(std::function<void()> cb) { onConnect = cb; }
    void setOnDisconnect(std::function<void()> cb) { onDisconnect = cb; }

private:
    void serverLoop() {
        while (running) {
            struct pollfd pfd;
            pfd.fd = serverFd;
            pfd.events = POLLIN;

            int ret = poll(&pfd, 1, 1000);
            if (ret <= 0) continue;

            struct sockaddr_in clientAddr;
            socklen_t clientLen = sizeof(clientAddr);
            int newClient = accept(serverFd, (struct sockaddr*)&clientAddr, &clientLen);
            if (newClient < 0) continue;

            // Handle WebSocket handshake
            if (!handleHandshake(newClient)) {
                close(newClient);
                continue;
            }

            clientFd = newClient;
            e9platform::platformLog(e9platform::LOG_INFO, "IDE connected");

            if (onConnect) onConnect();

            // Read loop
            std::vector<uint8_t> buffer;
            buffer.reserve(65536);

            while (running && clientFd >= 0) {
                struct pollfd cpfd;
                cpfd.fd = clientFd;
                cpfd.events = POLLIN;

                ret = poll(&cpfd, 1, 100);
                if (ret < 0) break;
                if (ret == 0) continue;

                uint8_t chunk[4096];
                ssize_t n = recv(clientFd, chunk, sizeof(chunk), 0);
                if (n <= 0) break;

                buffer.insert(buffer.end(), chunk, chunk + n);

                // Try to decode frames
                while (!buffer.empty()) {
                    size_t consumed;
                    std::string msg = WebSocket::decodeFrame(buffer.data(), buffer.size(), consumed);
                    if (consumed == 0) break;

                    buffer.erase(buffer.begin(), buffer.begin() + consumed);

                    if (!msg.empty() && onMessage) {
                        JsonParser parser;
                        if (parser.parse(msg.c_str())) {
                            onMessage(parser);
                        }
                    }
                }
            }

            if (onDisconnect) onDisconnect();

            close(clientFd);
            clientFd = -1;
            e9platform::platformLog(e9platform::LOG_INFO, "IDE disconnected");
        }
    }

    bool handleHandshake(int fd) {
        char buf[4096];
        ssize_t n = recv(fd, buf, sizeof(buf) - 1, 0);
        if (n <= 0) return false;
        buf[n] = '\0';

        // Find Sec-WebSocket-Key
        const char *keyHeader = strstr(buf, "Sec-WebSocket-Key:");
        if (!keyHeader) return false;
        keyHeader += 18;
        while (*keyHeader == ' ') keyHeader++;

        char key[128];
        int i = 0;
        while (*keyHeader && *keyHeader != '\r' && *keyHeader != '\n' && i < 127) {
            key[i++] = *keyHeader++;
        }
        key[i] = '\0';

        // Compute accept key (simplified - should use SHA1 + base64)
        // For now, just send a minimal response
        const char *response =
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n"
            "\r\n";

        return ::send(fd, response, strlen(response), 0) > 0;
    }
};

/*
 * File system watcher using inotify
 */
class FileWatcher {
    int inotifyFd = -1;
    std::atomic<bool> running{false};
    std::thread watchThread;
    std::map<int, std::string> watchedPaths;
    std::function<void(const std::string&)> onChange;

public:
    bool start() {
        inotifyFd = inotify_init1(IN_NONBLOCK);
        if (inotifyFd < 0) return false;

        running = true;
        watchThread = std::thread([this]() { watchLoop(); });
        return true;
    }

    void stop() {
        running = false;
        if (inotifyFd >= 0) {
            close(inotifyFd);
            inotifyFd = -1;
        }
        if (watchThread.joinable()) {
            watchThread.join();
        }
    }

    bool addWatch(const std::string &path) {
        if (inotifyFd < 0) return false;

        int wd = inotify_add_watch(inotifyFd, path.c_str(),
            IN_MODIFY | IN_CLOSE_WRITE);
        if (wd < 0) return false;

        watchedPaths[wd] = path;
        return true;
    }

    void setOnChange(std::function<void(const std::string&)> cb) {
        onChange = cb;
    }

private:
    void watchLoop() {
        char buf[4096];

        while (running) {
            struct pollfd pfd;
            pfd.fd = inotifyFd;
            pfd.events = POLLIN;

            int ret = poll(&pfd, 1, 100);
            if (ret <= 0) continue;

            ssize_t n = read(inotifyFd, buf, sizeof(buf));
            if (n <= 0) continue;

            size_t offset = 0;
            while (offset < (size_t)n) {
                struct inotify_event *event = (struct inotify_event*)(buf + offset);

                auto it = watchedPaths.find(event->wd);
                if (it != watchedPaths.end() && onChange) {
                    std::string path = it->second;
                    if (event->len > 0) {
                        path += "/";
                        path += event->name;
                    }
                    onChange(path);
                }

                offset += sizeof(struct inotify_event) + event->len;
            }
        }
    }
};

#endif // !E9_PLATFORM_WASM

/*
 * CLion Bridge - main coordinator
 */
class CLionBridge {
#ifndef E9_PLATFORM_WASM
    IDEServer server;
    FileWatcher watcher;
#endif
    bool initialized = false;

    // Callbacks to e9patch core
    std::function<void(const std::string&, uint32_t, uint32_t, const std::string&)> onSourceChange;
    std::function<void(const std::string&)> onHotReload;
    std::function<void(intptr_t)> onSetBreakpoint;
    std::function<void(intptr_t)> onRemoveBreakpoint;

public:
    bool init(int port = 9229) {
#ifndef E9_PLATFORM_WASM
        // Start file watcher
        if (!watcher.start()) {
            e9platform::platformLog(e9platform::LOG_WARNING,
                "Failed to start file watcher");
        }

        watcher.setOnChange([this](const std::string &path) {
            handleFileChange(path);
        });

        // Start WebSocket server
        server.setOnMessage([this](const JsonParser &msg) {
            handleMessage(msg);
        });

        server.setOnConnect([this]() {
            // Send hello
            sendStatus();
        });

        if (!server.start(port)) {
            e9platform::platformLog(e9platform::LOG_ERROR,
                "Failed to start IDE server on port %d", port);
            return false;
        }
#else
        (void)port;
#endif
        initialized = true;
        return true;
    }

    void shutdown() {
#ifndef E9_PLATFORM_WASM
        server.stop();
        watcher.stop();
#endif
        initialized = false;
    }

    bool watchFile(const std::string &path) {
#ifndef E9_PLATFORM_WASM
        return watcher.addWatch(path);
#else
        (void)path;
        return false;
#endif
    }

    // Set callbacks
    void setOnSourceChange(std::function<void(const std::string&, uint32_t, uint32_t,
                                              const std::string&)> cb) {
        onSourceChange = cb;
    }

    void setOnHotReload(std::function<void(const std::string&)> cb) {
        onHotReload = cb;
    }

    void setOnSetBreakpoint(std::function<void(intptr_t)> cb) {
        onSetBreakpoint = cb;
    }

    void setOnRemoveBreakpoint(std::function<void(intptr_t)> cb) {
        onRemoveBreakpoint = cb;
    }

    // Send patch result to IDE
    void sendPatchResult(intptr_t address, bool success, const char *error = nullptr) {
#ifndef E9_PLATFORM_WASM
        JsonBuilder json;
        json.add("type", "patchResult")
            .add("address", address)
            .add("success", success);
        if (error) json.add("error", error);
        server.send(json.build());
#else
        (void)address; (void)success; (void)error;
#endif
    }

    // Send status to IDE
    void sendStatus() {
#ifndef E9_PLATFORM_WASM
        JsonBuilder json;
        json.add("type", "status")
            .add("version", "1.0.0")
            .add("ready", true);
        server.send(json.build());
#endif
    }

private:
    void handleMessage(const JsonParser &msg) {
        std::string type = msg.get("type");

        if (type == "sourceChange") {
            if (onSourceChange) {
                onSourceChange(
                    msg.get("file"),
                    (uint32_t)msg.getInt("lineStart"),
                    (uint32_t)msg.getInt("lineEnd"),
                    msg.get("content")
                );
            }
        } else if (type == "requestReload") {
            if (onHotReload) {
                onHotReload(msg.get("file"));
            }
        } else if (type == "setBreakpoint") {
            if (onSetBreakpoint) {
                onSetBreakpoint(msg.getInt("address"));
            }
        } else if (type == "removeBreakpoint") {
            if (onRemoveBreakpoint) {
                onRemoveBreakpoint(msg.getInt("address"));
            }
        }
    }

    void handleFileChange(const std::string &path) {
        e9platform::platformLog(e9platform::LOG_DEBUG,
            "File changed: %s", path.c_str());

        // Read file content
        auto buf = E9_FILE_IO()->readFile(path.c_str());
        if (buf.data && onSourceChange) {
            std::string content((char*)buf.data, buf.size);
            onSourceChange(path, 0, 0, content);
        }
    }
};

// Global instance
static CLionBridge *g_bridge = nullptr;

} // namespace e9ide

/*
 * C API
 */
extern "C" {

int e9ide_init(int port) {
    if (e9ide::g_bridge) return 0;
    e9ide::g_bridge = new e9ide::CLionBridge();
    return e9ide::g_bridge->init(port) ? 0 : -1;
}

void e9ide_shutdown() {
    if (e9ide::g_bridge) {
        e9ide::g_bridge->shutdown();
        delete e9ide::g_bridge;
        e9ide::g_bridge = nullptr;
    }
}

int e9ide_watch_file(const char *path) {
    if (!e9ide::g_bridge) return -1;
    return e9ide::g_bridge->watchFile(path) ? 0 : -1;
}

void e9ide_send_patch_result(intptr_t address, int success, const char *error) {
    if (e9ide::g_bridge) {
        e9ide::g_bridge->sendPatchResult(address, success != 0, error);
    }
}

} // extern "C"
