/**
 * E9Patch VS Code Extension
 *
 * Provides live binary patching integration with hot-reload support.
 * Connects to e9patch server via WebSocket for real-time code updates.
 */

import * as vscode from 'vscode';
import WebSocket from 'ws';

// Extension state
let ws: WebSocket | null = null;
let statusBarItem: vscode.StatusBarItem;
let outputChannel: vscode.OutputChannel;
let reconnectTimer: NodeJS.Timeout | null = null;
let breakpointDecorations: vscode.TextEditorDecorationType;
let patchDecorations: vscode.TextEditorDecorationType;

// Breakpoint tracking
const breakpoints: Map<string, Set<number>> = new Map();
const appliedPatches: Map<string, Array<{line: number, address: number}>> = new Map();

/**
 * Extension activation
 */
export function activate(context: vscode.ExtensionContext) {
    outputChannel = vscode.window.createOutputChannel('E9Patch');
    log('E9Patch extension activated');

    // Create status bar item
    statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
    statusBarItem.command = 'e9patch.showStatus';
    updateStatusBar('disconnected');
    statusBarItem.show();

    // Create decorations for breakpoints and patches
    breakpointDecorations = vscode.window.createTextEditorDecorationType({
        gutterIconPath: context.asAbsolutePath('resources/breakpoint.svg'),
        gutterIconSize: 'contain',
        overviewRulerColor: 'red',
        overviewRulerLane: vscode.OverviewRulerLane.Left
    });

    patchDecorations = vscode.window.createTextEditorDecorationType({
        backgroundColor: 'rgba(0, 255, 0, 0.1)',
        border: '1px solid rgba(0, 255, 0, 0.3)',
        overviewRulerColor: 'green',
        overviewRulerLane: vscode.OverviewRulerLane.Right
    });

    // Register commands
    context.subscriptions.push(
        vscode.commands.registerCommand('e9patch.connect', connect),
        vscode.commands.registerCommand('e9patch.disconnect', disconnect),
        vscode.commands.registerCommand('e9patch.setBreakpoint', setBreakpointAtCursor),
        vscode.commands.registerCommand('e9patch.clearBreakpoints', clearAllBreakpoints),
        vscode.commands.registerCommand('e9patch.hotReload', forceHotReload),
        vscode.commands.registerCommand('e9patch.showStatus', showStatus),
        vscode.commands.registerCommand('e9patch.openBrowser', openBrowser)
    );

    // Register file save handler
    context.subscriptions.push(
        vscode.workspace.onDidSaveTextDocument(onDocumentSaved)
    );

    // Register document change handler (for real-time updates)
    context.subscriptions.push(
        vscode.workspace.onDidChangeTextDocument(onDocumentChanged)
    );

    // Register editor change handler (for decoration updates)
    context.subscriptions.push(
        vscode.window.onDidChangeActiveTextEditor(updateDecorations)
    );

    // Auto-connect if enabled
    const config = vscode.workspace.getConfiguration('e9patch');
    if (config.get('autoConnect')) {
        connect();
    }

    context.subscriptions.push(statusBarItem, outputChannel);
}

/**
 * Extension deactivation
 */
export function deactivate() {
    disconnect();
    if (reconnectTimer) {
        clearTimeout(reconnectTimer);
    }
}

/**
 * Connect to e9patch server
 */
async function connect() {
    if (ws && ws.readyState === WebSocket.OPEN) {
        vscode.window.showInformationMessage('E9Patch: Already connected');
        return;
    }

    const config = vscode.workspace.getConfiguration('e9patch');
    const host = config.get<string>('serverHost', 'localhost');
    const port = config.get<number>('serverPort', 9229);
    const url = `ws://${host}:${port}`;

    log(`Connecting to ${url}...`);
    updateStatusBar('connecting');

    try {
        ws = new WebSocket(url);

        ws.on('open', () => {
            log('Connected to E9Patch server');
            updateStatusBar('connected');

            // Send handshake
            sendMessage({
                type: 'hello',
                data: {
                    client: 'vscode',
                    version: '1.0.0'
                }
            });

            if (config.get('showNotifications')) {
                vscode.window.showInformationMessage('E9Patch: Connected');
            }
        });

        ws.on('message', (data) => {
            handleMessage(JSON.parse(data.toString()));
        });

        ws.on('close', () => {
            log('Disconnected from E9Patch server');
            updateStatusBar('disconnected');
            ws = null;

            // Schedule reconnect
            if (config.get('autoConnect')) {
                reconnectTimer = setTimeout(() => {
                    log('Attempting to reconnect...');
                    connect();
                }, 5000);
            }
        });

        ws.on('error', (error) => {
            log(`WebSocket error: ${error.message}`);
            updateStatusBar('error');
        });

    } catch (error) {
        log(`Connection failed: ${error}`);
        updateStatusBar('error');
        vscode.window.showErrorMessage(`E9Patch: Connection failed - ${error}`);
    }
}

/**
 * Disconnect from e9patch server
 */
function disconnect() {
    if (reconnectTimer) {
        clearTimeout(reconnectTimer);
        reconnectTimer = null;
    }

    if (ws) {
        ws.close();
        ws = null;
    }

    updateStatusBar('disconnected');
    log('Disconnected');
}

/**
 * Handle incoming WebSocket messages
 */
function handleMessage(msg: any) {
    log(`Received: ${msg.type}`);

    switch (msg.type) {
        case 'patchResult':
            handlePatchResult(msg.data);
            break;

        case 'breakpointHit':
            handleBreakpointHit(msg.data);
            break;

        case 'reloadComplete':
            handleReloadComplete(msg.data);
            break;

        case 'status':
            handleStatusUpdate(msg.data);
            break;

        case 'error':
            handleError(msg.data);
            break;

        default:
            log(`Unknown message type: ${msg.type}`);
    }
}

/**
 * Handle patch result from server
 */
function handlePatchResult(data: any) {
    const config = vscode.workspace.getConfiguration('e9patch');

    if (data.success) {
        log(`Patch applied at 0x${data.address.toString(16)}`);

        // Track applied patch
        if (data.sourceFile) {
            const patches = appliedPatches.get(data.sourceFile) || [];
            patches.push({ line: data.sourceLine, address: data.address });
            appliedPatches.set(data.sourceFile, patches);
            updateDecorations();
        }

        if (config.get('showNotifications')) {
            vscode.window.showInformationMessage(
                `E9Patch: Patched at 0x${data.address.toString(16)}`
            );
        }
    } else {
        log(`Patch failed: ${data.error}`);
        if (config.get('showNotifications')) {
            vscode.window.showErrorMessage(`E9Patch: ${data.error}`);
        }
    }
}

/**
 * Handle breakpoint hit notification
 */
function handleBreakpointHit(data: any) {
    log(`Breakpoint hit at 0x${data.address.toString(16)}`);

    vscode.window.showInformationMessage(
        `E9Patch: Breakpoint hit at ${data.sourceFile}:${data.line}`,
        'Go to Location'
    ).then(selection => {
        if (selection === 'Go to Location' && data.sourceFile) {
            const uri = vscode.Uri.file(data.sourceFile);
            vscode.window.showTextDocument(uri).then(editor => {
                const position = new vscode.Position(data.line - 1, 0);
                editor.selection = new vscode.Selection(position, position);
                editor.revealRange(new vscode.Range(position, position));
            });
        }
    });
}

/**
 * Handle reload complete notification
 */
function handleReloadComplete(data: any) {
    log(`Hot reload complete: ${data.file}`);

    const config = vscode.workspace.getConfiguration('e9patch');
    if (config.get('showNotifications')) {
        vscode.window.showInformationMessage(`E9Patch: Hot reload complete`);
    }
}

/**
 * Handle status update from server
 */
function handleStatusUpdate(data: any) {
    log(`Status: ${JSON.stringify(data)}`);
}

/**
 * Handle error from server
 */
function handleError(data: any) {
    log(`Error: ${data.message}`);
    vscode.window.showErrorMessage(`E9Patch: ${data.message}`);
}

/**
 * Called when a document is saved
 */
function onDocumentSaved(document: vscode.TextDocument) {
    if (!isRelevantDocument(document)) {
        return;
    }

    const config = vscode.workspace.getConfiguration('e9patch');
    if (!config.get('autoReload')) {
        return;
    }

    sendSourceChange(document);
}

/**
 * Called when a document is changed (for real-time updates)
 */
function onDocumentChanged(event: vscode.TextDocumentChangeEvent) {
    // Could implement real-time updates here if desired
    // For now, we only send changes on save
}

/**
 * Send source change to server
 */
function sendSourceChange(document: vscode.TextDocument) {
    if (!ws || ws.readyState !== WebSocket.OPEN) {
        return;
    }

    const text = document.getText();

    // Find changed lines (simplified - sends entire file)
    sendMessage({
        type: 'sourceChange',
        data: {
            file: document.uri.fsPath,
            lineStart: 1,
            lineEnd: document.lineCount,
            content: text
        }
    });

    log(`Sent source change: ${document.uri.fsPath}`);
}

/**
 * Set breakpoint at cursor position
 */
async function setBreakpointAtCursor() {
    const editor = vscode.window.activeTextEditor;
    if (!editor || !isRelevantDocument(editor.document)) {
        vscode.window.showWarningMessage('E9Patch: Open a C/C++ file first');
        return;
    }

    const line = editor.selection.active.line + 1;
    const file = editor.document.uri.fsPath;

    // Track breakpoint locally
    const fileBreakpoints = breakpoints.get(file) || new Set();

    if (fileBreakpoints.has(line)) {
        // Remove breakpoint
        fileBreakpoints.delete(line);
        sendMessage({
            type: 'removeBreakpoint',
            data: { file, line }
        });
        log(`Removed breakpoint at ${file}:${line}`);
    } else {
        // Add breakpoint
        fileBreakpoints.add(line);
        sendMessage({
            type: 'setBreakpoint',
            data: { file, line }
        });
        log(`Set breakpoint at ${file}:${line}`);
    }

    breakpoints.set(file, fileBreakpoints);
    updateDecorations();
}

/**
 * Clear all breakpoints
 */
function clearAllBreakpoints() {
    breakpoints.clear();

    sendMessage({
        type: 'clearAllBreakpoints',
        data: {}
    });

    updateDecorations();
    log('Cleared all breakpoints');
}

/**
 * Force hot reload of current file
 */
function forceHotReload() {
    const editor = vscode.window.activeTextEditor;
    if (!editor || !isRelevantDocument(editor.document)) {
        vscode.window.showWarningMessage('E9Patch: Open a C/C++ file first');
        return;
    }

    sendMessage({
        type: 'requestReload',
        data: {
            file: editor.document.uri.fsPath
        }
    });

    log(`Requested hot reload: ${editor.document.uri.fsPath}`);
}

/**
 * Show connection status
 */
function showStatus() {
    const connected = ws && ws.readyState === WebSocket.OPEN;
    const config = vscode.workspace.getConfiguration('e9patch');

    const items: string[] = [
        `Status: ${connected ? 'Connected' : 'Disconnected'}`,
        `Server: ${config.get('serverHost')}:${config.get('serverPort')}`,
        `Auto-connect: ${config.get('autoConnect') ? 'Yes' : 'No'}`,
        `Auto-reload: ${config.get('autoReload') ? 'Yes' : 'No'}`,
        `Breakpoints: ${Array.from(breakpoints.values()).reduce((a, b) => a + b.size, 0)}`
    ];

    vscode.window.showQuickPick(items, {
        placeHolder: 'E9Patch Status'
    });
}

/**
 * Open browser debugger
 */
function openBrowser() {
    const config = vscode.workspace.getConfiguration('e9patch');
    const url = config.get<string>('browserUrl', 'http://localhost:8080');
    vscode.env.openExternal(vscode.Uri.parse(url));
}

/**
 * Update editor decorations
 */
function updateDecorations() {
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
        return;
    }

    const file = editor.document.uri.fsPath;

    // Update breakpoint decorations
    const fileBreakpoints = breakpoints.get(file);
    if (fileBreakpoints) {
        const ranges = Array.from(fileBreakpoints).map(line => {
            const pos = new vscode.Position(line - 1, 0);
            return new vscode.Range(pos, pos);
        });
        editor.setDecorations(breakpointDecorations, ranges);
    } else {
        editor.setDecorations(breakpointDecorations, []);
    }

    // Update patch decorations
    const filePatches = appliedPatches.get(file);
    if (filePatches) {
        const ranges = filePatches.map(patch => {
            const pos = new vscode.Position(patch.line - 1, 0);
            return new vscode.Range(pos, pos.translate(0, 1000));
        });
        editor.setDecorations(patchDecorations, ranges);
    } else {
        editor.setDecorations(patchDecorations, []);
    }
}

/**
 * Send WebSocket message
 */
function sendMessage(msg: any) {
    if (ws && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({
            ...msg,
            timestamp: Date.now()
        }));
    }
}

/**
 * Check if document is C/C++
 */
function isRelevantDocument(document: vscode.TextDocument): boolean {
    return ['c', 'cpp', 'h', 'hpp'].includes(document.languageId) ||
           document.fileName.match(/\.(c|cpp|cc|cxx|h|hpp|hxx)$/i) !== null;
}

/**
 * Update status bar
 */
function updateStatusBar(state: 'connected' | 'disconnected' | 'connecting' | 'error') {
    const icons: Record<string, string> = {
        connected: '$(check)',
        disconnected: '$(circle-slash)',
        connecting: '$(sync~spin)',
        error: '$(error)'
    };

    const colors: Record<string, string> = {
        connected: '#4ade80',
        disconnected: '#a0a0a0',
        connecting: '#fbbf24',
        error: '#ef4444'
    };

    statusBarItem.text = `${icons[state]} E9Patch`;
    statusBarItem.color = colors[state];
    statusBarItem.tooltip = `E9Patch: ${state}`;
}

/**
 * Log message to output channel
 */
function log(message: string) {
    const timestamp = new Date().toISOString();
    outputChannel.appendLine(`[${timestamp}] ${message}`);
}
