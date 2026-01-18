"""
E9Patch Notepad++ Startup Script

Add this to your PythonScript startup.py to auto-load E9Patch plugin.

Location: %APPDATA%/Notepad++/plugins/Config/PythonScript/scripts/startup.py
"""

# Import and initialize E9Patch plugin
try:
    import e9patch
    # Plugin is initialized automatically on import
except ImportError:
    console.write("[E9Patch] Plugin not found. Make sure e9patch.py is in the scripts folder.\n")
except Exception as e:
    console.write(f"[E9Patch] Failed to load: {e}\n")
