"""
E9Patch Sublime Text Plugin

Live binary patching integration for Sublime Text with hot-reload support.
Connects to e9patch server via WebSocket for real-time code updates.

Installation:
    1. Copy this folder to Sublime Text Packages directory
    2. Preferences -> Package Settings -> E9Patch -> Settings

Usage:
    1. Start e9patch: ./e9patch.com --ide-port=9229
    2. Open C/C++ file in Sublime Text
    3. Use Command Palette: E9Patch: Connect
    4. Edit and save files - changes sent automatically
"""

import sublime
import sublime_plugin
import json
import socket
import threading
import time
import webbrowser
from typing import Dict, List, Optional, Set, Tuple

# Plugin state
class E9PatchState:
    def __init__(self):
        self.connected = False
        self.socket: Optional[socket.socket] = None
        self.recv_thread: Optional[threading.Thread] = None
        self.running = False
        self.breakpoints: Dict[str, Set[int]] = {}  # {filepath: {line, ...}}
        self.patches: Dict[str, List[Tuple[int, int]]] = {}  # {filepath: [(line, addr), ...]}
        self.settings: Optional[sublime.Settings] = None

state = E9PatchState()

# Default settings
DEFAULT_SETTINGS = {
    "server_host": "localhost",
    "server_port": 9229,
    "auto_connect": True,
    "auto_reload": True,
    "show_notifications": True,
    "browser_url": "http://localhost:8080",
    "file_patterns": ["*.c", "*.cpp", "*.cc", "*.cxx", "*.h", "*.hpp", "*.hxx"]
}


def plugin_loaded():
    """Called when plugin is loaded."""
    state.settings = sublime.load_settings("E9Patch.sublime-settings")

    # Set defaults if not present
    for key, value in DEFAULT_SETTINGS.items():
        if not state.settings.has(key):
            state.settings.set(key, value)

    sublime.save_settings("E9Patch.sublime-settings")

    # Auto-connect if enabled
    if state.settings.get("auto_connect", True):
        sublime.set_timeout_async(lambda: connect(), 1000)


def plugin_unloaded():
    """Called when plugin is unloaded."""
    disconnect()


def log(message: str, error: bool = False):
    """Log message to console and optionally show popup."""
    print(f"[E9Patch] {message}")

    if state.settings and state.settings.get("show_notifications", True):
        if error:
            sublime.error_message(f"E9Patch: {message}")
        else:
            sublime.status_message(f"E9Patch: {message}")


def is_relevant_file(view: sublime.View) -> bool:
    """Check if file is C/C++ source."""
    if not view or not view.file_name():
        return False

    patterns = state.settings.get("file_patterns", DEFAULT_SETTINGS["file_patterns"])
    filename = view.file_name().lower()

    for pattern in patterns:
        ext = pattern.replace("*", "")
        if filename.endswith(ext):
            return True
    return False


def send_message(msg: dict):
    """Send JSON message to server."""
    if not state.connected or not state.socket:
        return False

    try:
        msg["timestamp"] = int(time.time() * 1000)
        data = json.dumps(msg) + "\n"
        state.socket.sendall(data.encode("utf-8"))
        return True
    except Exception as e:
        log(f"Send error: {e}", error=True)
        return False


def handle_message(data: str):
    """Handle incoming message from server."""
    try:
        msg = json.loads(data)
    except json.JSONDecodeError:
        return

    msg_type = msg.get("type", "")
    msg_data = msg.get("data", msg)

    if msg_type == "patchResult":
        if msg_data.get("success"):
            addr = msg_data.get("address", 0)
            log(f"Patched at 0x{addr:x}")

            # Track patch
            source_file = msg_data.get("sourceFile")
            source_line = msg_data.get("sourceLine")
            if source_file and source_line:
                if source_file not in state.patches:
                    state.patches[source_file] = []
                state.patches[source_file].append((source_line, addr))
                update_regions()
        else:
            log(f"Patch failed: {msg_data.get('error', 'unknown')}", error=True)

    elif msg_type == "breakpointHit":
        source_file = msg_data.get("sourceFile")
        line = msg_data.get("line", 1)
        log(f"Breakpoint hit: {source_file}:{line}")

        # Open file at location
        if source_file:
            sublime.active_window().open_file(
                f"{source_file}:{line}",
                sublime.ENCODED_POSITION
            )

    elif msg_type == "reloadComplete":
        log("Hot reload complete")

    elif msg_type == "status":
        log("Server ready")

    elif msg_type == "error":
        log(msg_data.get("message", "Unknown error"), error=True)


def recv_loop():
    """Receive messages from server."""
    buffer = ""

    while state.running and state.socket:
        try:
            data = state.socket.recv(4096)
            if not data:
                break

            buffer += data.decode("utf-8")

            # Process complete lines
            while "\n" in buffer:
                line, buffer = buffer.split("\n", 1)
                if line.strip():
                    sublime.set_timeout(lambda l=line: handle_message(l), 0)

        except socket.timeout:
            continue
        except Exception as e:
            if state.running:
                log(f"Receive error: {e}")
            break

    state.connected = False
    state.socket = None
    sublime.set_timeout(lambda: update_status(), 0)

    # Auto-reconnect
    if state.running and state.settings.get("auto_connect", True):
        sublime.set_timeout_async(lambda: connect(), 5000)


def connect():
    """Connect to e9patch server."""
    if state.connected:
        log("Already connected")
        return

    host = state.settings.get("server_host", "localhost")
    port = state.settings.get("server_port", 9229)

    log(f"Connecting to {host}:{port}...")

    try:
        state.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        state.socket.settimeout(5.0)
        state.socket.connect((host, port))
        state.socket.settimeout(1.0)

        state.connected = True
        state.running = True

        # Start receive thread
        state.recv_thread = threading.Thread(target=recv_loop, daemon=True)
        state.recv_thread.start()

        # Send handshake
        send_message({
            "type": "hello",
            "data": {
                "client": "sublime",
                "version": "1.0.0"
            }
        })

        log("Connected")
        update_status()

    except Exception as e:
        log(f"Connection failed: {e}", error=True)
        state.socket = None
        state.connected = False


def disconnect():
    """Disconnect from server."""
    state.running = False

    if state.socket:
        try:
            state.socket.close()
        except:
            pass
        state.socket = None

    state.connected = False
    log("Disconnected")
    update_status()


def update_status():
    """Update status bar."""
    status = "E9Patch: Connected" if state.connected else "E9Patch: Disconnected"
    for window in sublime.windows():
        for view in window.views():
            view.set_status("e9patch", status)


def update_regions():
    """Update gutter icons for breakpoints and patches."""
    for window in sublime.windows():
        for view in window.views():
            if not view.file_name():
                continue

            filepath = view.file_name()

            # Clear existing regions
            view.erase_regions("e9patch_breakpoints")
            view.erase_regions("e9patch_patches")

            # Add breakpoint regions
            if filepath in state.breakpoints:
                regions = []
                for line in state.breakpoints[filepath]:
                    point = view.text_point(line - 1, 0)
                    regions.append(sublime.Region(point, point))
                view.add_regions(
                    "e9patch_breakpoints",
                    regions,
                    "region.redish",
                    "circle",
                    sublime.DRAW_NO_FILL
                )

            # Add patch regions
            if filepath in state.patches:
                regions = []
                for line, _ in state.patches[filepath]:
                    point = view.text_point(line - 1, 0)
                    line_region = view.line(point)
                    regions.append(line_region)
                view.add_regions(
                    "e9patch_patches",
                    regions,
                    "region.greenish",
                    "dot",
                    sublime.DRAW_NO_FILL
                )


# ============================================================================
# Commands
# ============================================================================

class E9patchConnectCommand(sublime_plugin.ApplicationCommand):
    """Connect to e9patch server."""

    def run(self):
        sublime.set_timeout_async(connect, 0)


class E9patchDisconnectCommand(sublime_plugin.ApplicationCommand):
    """Disconnect from e9patch server."""

    def run(self):
        disconnect()


class E9patchToggleBreakpointCommand(sublime_plugin.TextCommand):
    """Toggle breakpoint at current line."""

    def run(self, edit):
        if not is_relevant_file(self.view):
            log("Not a C/C++ file")
            return

        filepath = self.view.file_name()
        line = self.view.rowcol(self.view.sel()[0].begin())[0] + 1

        if filepath not in state.breakpoints:
            state.breakpoints[filepath] = set()

        if line in state.breakpoints[filepath]:
            # Remove breakpoint
            state.breakpoints[filepath].remove(line)
            send_message({
                "type": "removeBreakpoint",
                "data": {"file": filepath, "line": line}
            })
            log(f"Removed breakpoint at line {line}")
        else:
            # Add breakpoint
            state.breakpoints[filepath].add(line)
            send_message({
                "type": "setBreakpoint",
                "data": {"file": filepath, "line": line}
            })
            log(f"Set breakpoint at line {line}")

        update_regions()


class E9patchClearBreakpointsCommand(sublime_plugin.ApplicationCommand):
    """Clear all breakpoints."""

    def run(self):
        state.breakpoints.clear()
        send_message({
            "type": "clearAllBreakpoints",
            "data": {}
        })
        update_regions()
        log("Cleared all breakpoints")


class E9patchHotReloadCommand(sublime_plugin.TextCommand):
    """Force hot reload of current file."""

    def run(self, edit):
        if not is_relevant_file(self.view):
            log("Not a C/C++ file")
            return

        filepath = self.view.file_name()
        send_message({
            "type": "requestReload",
            "data": {"file": filepath}
        })
        log(f"Requested hot reload")


class E9patchStatusCommand(sublime_plugin.ApplicationCommand):
    """Show connection status."""

    def run(self):
        bp_count = sum(len(bps) for bps in state.breakpoints.values())

        items = [
            f"Status: {'Connected' if state.connected else 'Disconnected'}",
            f"Server: {state.settings.get('server_host')}:{state.settings.get('server_port')}",
            f"Auto-connect: {'Yes' if state.settings.get('auto_connect') else 'No'}",
            f"Auto-reload: {'Yes' if state.settings.get('auto_reload') else 'No'}",
            f"Breakpoints: {bp_count}",
        ]

        sublime.active_window().show_quick_panel(items, None)


class E9patchOpenBrowserCommand(sublime_plugin.ApplicationCommand):
    """Open browser debugger."""

    def run(self):
        url = state.settings.get("browser_url", DEFAULT_SETTINGS["browser_url"])
        webbrowser.open(url)


# ============================================================================
# Event Listeners
# ============================================================================

class E9patchEventListener(sublime_plugin.EventListener):
    """Handle editor events."""

    def on_post_save_async(self, view):
        """Send source change on file save."""
        if not state.connected:
            return

        if not is_relevant_file(view):
            return

        if not state.settings.get("auto_reload", True):
            return

        filepath = view.file_name()
        content = view.substr(sublime.Region(0, view.size()))

        send_message({
            "type": "sourceChange",
            "data": {
                "file": filepath,
                "lineStart": 1,
                "lineEnd": view.rowcol(view.size())[0] + 1,
                "content": content
            }
        })

    def on_load(self, view):
        """Update regions when file is loaded."""
        update_regions()
        update_status()

    def on_activated(self, view):
        """Update regions when view is activated."""
        update_regions()
