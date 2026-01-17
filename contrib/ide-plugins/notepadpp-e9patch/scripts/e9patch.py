"""
E9Patch Notepad++ Plugin (PythonScript Version)

Live binary patching integration for Notepad++ with hot-reload support.
Requires: PythonScript plugin for Notepad++

Installation:
    1. Install PythonScript plugin from Plugin Admin
    2. Copy this file to:
       %APPDATA%/Notepad++/plugins/Config/PythonScript/scripts/
    3. Copy e9patch_startup.py to:
       %APPDATA%/Notepad++/plugins/Config/PythonScript/scripts/startup.py
       (or append to existing startup.py)

Usage:
    1. Start e9patch: e9patch.com --ide-port=9229
    2. Run script via Plugins -> PythonScript -> Scripts -> e9patch
    3. Or use startup.py for auto-connect
"""

import socket
import json
import threading
import time
from Npp import notepad, editor, NOTIFICATION, SCINTILLANOTIFICATION, MENUCOMMAND

# ============================================================================
# Configuration
# ============================================================================

CONFIG = {
    "server_host": "localhost",
    "server_port": 9229,
    "auto_connect": True,
    "auto_reload": True,
    "show_notifications": True,
    "file_extensions": [".c", ".cpp", ".cc", ".cxx", ".h", ".hpp", ".hxx"],
}

# ============================================================================
# State
# ============================================================================

class E9PatchState:
    def __init__(self):
        self.connected = False
        self.socket = None
        self.recv_thread = None
        self.running = False
        self.breakpoints = {}  # {filepath: set(lines)}
        self.patches = {}  # {filepath: [(line, addr), ...]}
        self.markers = {}  # Track marker handles

state = E9PatchState()

# Marker IDs (Scintilla supports markers 0-31)
MARKER_BREAKPOINT = 20
MARKER_PATCH = 21

# ============================================================================
# Helpers
# ============================================================================

def log(message, is_error=False):
    """Log message to console and optionally show message box."""
    console.write(f"[E9Patch] {message}\n")
    if CONFIG["show_notifications"]:
        if is_error:
            notepad.messageBox(message, "E9Patch Error", 0x10)  # MB_ICONERROR
        else:
            notepad.setStatusBar(STATUSBAR.DOC_TYPE, f"E9Patch: {message}")


def is_relevant_file(filename):
    """Check if file is C/C++ source."""
    if not filename:
        return False
    lower = filename.lower()
    return any(lower.endswith(ext) for ext in CONFIG["file_extensions"])


def get_current_file():
    """Get current file path."""
    return notepad.getCurrentFilename()


def get_current_line():
    """Get current line number (1-based)."""
    return editor.lineFromPosition(editor.getCurrentPos()) + 1


def get_file_content():
    """Get entire file content."""
    return editor.getText()


def send_message(msg):
    """Send JSON message to server."""
    if not state.connected or not state.socket:
        return False
    try:
        msg["timestamp"] = int(time.time() * 1000)
        data = json.dumps(msg) + "\n"
        state.socket.sendall(data.encode("utf-8"))
        return True
    except Exception as e:
        log(f"Send error: {e}", is_error=True)
        return False


def handle_message(data):
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
            log(f"Patched at 0x{addr:X}")

            # Track patch
            source_file = msg_data.get("sourceFile")
            source_line = msg_data.get("sourceLine")
            if source_file and source_line:
                if source_file not in state.patches:
                    state.patches[source_file] = []
                state.patches[source_file].append((source_line, addr))
                update_markers()
        else:
            log(f"Patch failed: {msg_data.get('error', 'unknown')}", is_error=True)

    elif msg_type == "breakpointHit":
        source_file = msg_data.get("sourceFile")
        line = msg_data.get("line", 1)
        log(f"Breakpoint hit: {source_file}:{line}")

        # Open file at location
        if source_file:
            notepad.open(source_file)
            editor.gotoLine(line - 1)

    elif msg_type == "reloadComplete":
        log("Hot reload complete")

    elif msg_type == "status":
        log("Server ready")

    elif msg_type == "error":
        log(msg_data.get("message", "Unknown error"), is_error=True)


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
                    handle_message(line)

        except socket.timeout:
            continue
        except Exception as e:
            if state.running:
                log(f"Receive error: {e}")
            break

    state.connected = False
    state.socket = None

    # Auto-reconnect
    if state.running and CONFIG["auto_connect"]:
        time.sleep(5)
        connect()


def setup_markers():
    """Setup marker styles."""
    # Breakpoint marker (red circle)
    editor.markerDefine(MARKER_BREAKPOINT, MARKER.CIRCLE)
    editor.markerSetFore(MARKER_BREAKPOINT, (255, 0, 0))  # Red
    editor.markerSetBack(MARKER_BREAKPOINT, (255, 0, 0))

    # Patch marker (green arrow)
    editor.markerDefine(MARKER_PATCH, MARKER.ARROW)
    editor.markerSetFore(MARKER_PATCH, (0, 255, 0))  # Green
    editor.markerSetBack(MARKER_PATCH, (0, 200, 0))


def update_markers():
    """Update markers for current file."""
    filepath = get_current_file()
    if not filepath:
        return

    # Clear existing markers
    editor.markerDeleteAll(MARKER_BREAKPOINT)
    editor.markerDeleteAll(MARKER_PATCH)

    # Add breakpoint markers
    if filepath in state.breakpoints:
        for line in state.breakpoints[filepath]:
            editor.markerAdd(line - 1, MARKER_BREAKPOINT)

    # Add patch markers
    if filepath in state.patches:
        for line, _ in state.patches[filepath]:
            editor.markerAdd(line - 1, MARKER_PATCH)


# ============================================================================
# Public API
# ============================================================================

def connect():
    """Connect to e9patch server."""
    if state.connected:
        log("Already connected")
        return

    host = CONFIG["server_host"]
    port = CONFIG["server_port"]

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
                "client": "notepad++",
                "version": "1.0.0"
            }
        })

        setup_markers()
        log("Connected")

    except Exception as e:
        log(f"Connection failed: {e}", is_error=True)
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


def toggle_breakpoint():
    """Toggle breakpoint at current line."""
    filepath = get_current_file()
    if not is_relevant_file(filepath):
        log("Not a C/C++ file")
        return

    line = get_current_line()

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

    update_markers()


def clear_breakpoints():
    """Clear all breakpoints."""
    state.breakpoints.clear()
    send_message({
        "type": "clearAllBreakpoints",
        "data": {}
    })
    update_markers()
    log("Cleared all breakpoints")


def hot_reload():
    """Force hot reload of current file."""
    filepath = get_current_file()
    if not is_relevant_file(filepath):
        log("Not a C/C++ file")
        return

    send_message({
        "type": "requestReload",
        "data": {"file": filepath}
    })
    log("Requested hot reload")


def send_source_change():
    """Send current file content to server."""
    if not state.connected:
        return

    filepath = get_current_file()
    if not is_relevant_file(filepath):
        return

    content = get_file_content()
    line_count = editor.getLineCount()

    send_message({
        "type": "sourceChange",
        "data": {
            "file": filepath,
            "lineStart": 1,
            "lineEnd": line_count,
            "content": content
        }
    })


def show_status():
    """Show connection status."""
    bp_count = sum(len(bps) for bps in state.breakpoints.values())

    status = f"""E9Patch Status
==============
Connected: {'Yes' if state.connected else 'No'}
Server: {CONFIG['server_host']}:{CONFIG['server_port']}
Auto-connect: {'Yes' if CONFIG['auto_connect'] else 'No'}
Auto-reload: {'Yes' if CONFIG['auto_reload'] else 'No'}
Breakpoints: {bp_count}"""

    notepad.messageBox(status, "E9Patch Status", 0x40)  # MB_ICONINFORMATION


# ============================================================================
# Event Callbacks
# ============================================================================

def on_file_saved(args):
    """Called when file is saved."""
    if CONFIG["auto_reload"]:
        send_source_change()


def on_buffer_activated(args):
    """Called when buffer is activated."""
    update_markers()


# ============================================================================
# Main Menu
# ============================================================================

def show_menu():
    """Show E9Patch menu."""
    import ctypes

    menu_items = [
        ("Connect", connect),
        ("Disconnect", disconnect),
        ("---", None),
        ("Toggle Breakpoint", toggle_breakpoint),
        ("Clear All Breakpoints", clear_breakpoints),
        ("---", None),
        ("Hot Reload", hot_reload),
        ("---", None),
        ("Status", show_status),
    ]

    # Create simple selection
    options = [item[0] for item in menu_items if item[0] != "---"]
    funcs = [item[1] for item in menu_items if item[1] is not None]

    choice = notepad.prompt(
        "Select action:\n" + "\n".join(f"{i+1}. {opt}" for i, opt in enumerate(options)),
        "E9Patch Menu",
        "1"
    )

    try:
        idx = int(choice) - 1
        if 0 <= idx < len(funcs):
            funcs[idx]()
    except (ValueError, TypeError):
        pass


# ============================================================================
# Initialization
# ============================================================================

def init():
    """Initialize plugin."""
    # Register callbacks
    notepad.callback(on_file_saved, [NOTIFICATION.FILESAVED])
    notepad.callback(on_buffer_activated, [NOTIFICATION.BUFFERACTIVATED])

    # Auto-connect
    if CONFIG["auto_connect"]:
        connect()

    log("E9Patch plugin initialized")


# Run initialization
init()

# Show menu when script is run directly
if __name__ == "__main__":
    show_menu()
