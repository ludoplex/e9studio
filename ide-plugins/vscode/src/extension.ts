/**
 * E9Studio VS Code Extension
 * Binary analysis and patching integration
 */

import * as vscode from 'vscode';
import * as cp from 'child_process';
import { createMessageConnection, StreamMessageReader, StreamMessageWriter } from 'vscode-jsonrpc/node';

let e9studioProcess: cp.ChildProcess | null = null;
let connection: any = null;
let currentBinaryPath: string | null = null;

export function activate(context: vscode.ExtensionContext) {
    console.log('E9Studio extension activated');

    // Register commands
    context.subscriptions.push(
        vscode.commands.registerCommand('e9studio.openBinary', openBinary),
        vscode.commands.registerCommand('e9studio.showDisassembly', showDisassembly),
        vscode.commands.registerCommand('e9studio.showDecompilation', showDecompilation),
        vscode.commands.registerCommand('e9studio.gotoAddress', gotoAddress),
        vscode.commands.registerCommand('e9studio.patchNop', patchNop),
        vscode.commands.registerCommand('e9studio.applyPatches', applyPatches),
        vscode.commands.registerCommand('e9studio.saveBinary', saveBinary),
        vscode.commands.registerCommand('e9studio.showFunctions', showFunctions)
    );
}

export function deactivate() {
    if (e9studioProcess) {
        e9studioProcess.kill();
        e9studioProcess = null;
    }
}

async function startE9Studio(): Promise<void> {
    if (e9studioProcess && connection) {
        return;
    }

    const config = vscode.workspace.getConfiguration('e9studio');
    const execPath = config.get<string>('executablePath', 'e9studio.com');

    return new Promise((resolve, reject) => {
        e9studioProcess = cp.spawn(execPath, ['--ide-mode'], {
            stdio: ['pipe', 'pipe', 'pipe']
        });

        if (!e9studioProcess.stdout || !e9studioProcess.stdin) {
            reject(new Error('Failed to start E9Studio process'));
            return;
        }

        connection = createMessageConnection(
            new StreamMessageReader(e9studioProcess.stdout),
            new StreamMessageWriter(e9studioProcess.stdin)
        );

        connection.listen();

        // Initialize
        connection.sendRequest('initialize', {
            clientInfo: { name: 'vscode-e9studio', version: '1.0.0' }
        }).then((result: any) => {
            console.log('E9Studio initialized:', result);
            resolve();
        }).catch(reject);

        e9studioProcess.on('exit', (code) => {
            console.log(`E9Studio exited with code ${code}`);
            e9studioProcess = null;
            connection = null;
        });

        e9studioProcess.stderr?.on('data', (data) => {
            console.error(`E9Studio stderr: ${data}`);
        });
    });
}

async function openBinary() {
    const uri = await vscode.window.showOpenDialog({
        canSelectFiles: true,
        canSelectFolders: false,
        canSelectMany: false,
        filters: {
            'Executables': ['elf', 'exe', 'com', 'bin', 'so', 'dylib', 'dll'],
            'All Files': ['*']
        },
        title: 'Open Binary for Analysis'
    });

    if (!uri || uri.length === 0) {
        return;
    }

    const path = uri[0].fsPath;

    try {
        await startE9Studio();

        const result = await connection.sendRequest('binary/open', { path });

        currentBinaryPath = path;
        vscode.commands.executeCommand('setContext', 'e9studio.binaryOpen', true);

        vscode.window.showInformationMessage(
            `Opened ${result.arch} ${result.format} binary: ${result.numFunctions} functions, ${result.numSymbols} symbols`
        );

        // Show functions view
        showFunctions();
    } catch (error: any) {
        vscode.window.showErrorMessage(`Failed to open binary: ${error.message}`);
    }
}

async function showDisassembly() {
    if (!connection || !currentBinaryPath) {
        vscode.window.showWarningMessage('No binary is open');
        return;
    }

    const addressStr = await vscode.window.showInputBox({
        prompt: 'Enter address (hex)',
        placeHolder: '0x401000'
    });

    if (!addressStr) return;

    const address = parseInt(addressStr, 16);

    try {
        const result = await connection.sendRequest('analysis/getDisassembly', {
            address,
            count: 50
        });

        // Create document with disassembly
        const content = result.instructions.map((insn: any) =>
            `${insn.address}  ${insn.text}`
        ).join('\n');

        const doc = await vscode.workspace.openTextDocument({
            content,
            language: 'asm'
        });

        await vscode.window.showTextDocument(doc);
    } catch (error: any) {
        vscode.window.showErrorMessage(`Failed to disassemble: ${error.message}`);
    }
}

async function showDecompilation() {
    if (!connection || !currentBinaryPath) {
        vscode.window.showWarningMessage('No binary is open');
        return;
    }

    const addressStr = await vscode.window.showInputBox({
        prompt: 'Enter function address (hex)',
        placeHolder: '0x401000'
    });

    if (!addressStr) return;

    const address = parseInt(addressStr, 16);

    try {
        const result = await connection.sendRequest('analysis/getDecompilation', {
            address
        });

        const doc = await vscode.workspace.openTextDocument({
            content: result.code,
            language: 'c'
        });

        await vscode.window.showTextDocument(doc);
    } catch (error: any) {
        vscode.window.showErrorMessage(`Failed to decompile: ${error.message}`);
    }
}

async function gotoAddress() {
    const addressStr = await vscode.window.showInputBox({
        prompt: 'Enter address (hex)',
        placeHolder: '0x401000'
    });

    if (addressStr) {
        showDisassembly();
    }
}

async function patchNop() {
    if (!connection || !currentBinaryPath) {
        vscode.window.showWarningMessage('No binary is open');
        return;
    }

    const addressStr = await vscode.window.showInputBox({
        prompt: 'Enter address to NOP (hex)',
        placeHolder: '0x401000'
    });

    if (!addressStr) return;

    const sizeStr = await vscode.window.showInputBox({
        prompt: 'Enter size in bytes',
        placeHolder: '5'
    });

    if (!sizeStr) return;

    const address = parseInt(addressStr, 16);
    const size = parseInt(sizeStr, 10);

    try {
        const result = await connection.sendRequest('patch/nop', { address, size });
        vscode.window.showInformationMessage(`Created NOP patch (id: ${result.patchId})`);
    } catch (error: any) {
        vscode.window.showErrorMessage(`Failed to create patch: ${error.message}`);
    }
}

async function applyPatches() {
    if (!connection) {
        vscode.window.showWarningMessage('No binary is open');
        return;
    }

    try {
        await connection.sendRequest('patch/apply', {});
        vscode.window.showInformationMessage('Patches applied');
    } catch (error: any) {
        vscode.window.showErrorMessage(`Failed to apply patches: ${error.message}`);
    }
}

async function saveBinary() {
    if (!connection || !currentBinaryPath) {
        vscode.window.showWarningMessage('No binary is open');
        return;
    }

    const uri = await vscode.window.showSaveDialog({
        defaultUri: vscode.Uri.file(currentBinaryPath + '.patched'),
        filters: {
            'Executables': ['elf', 'exe', 'com', 'bin'],
            'All Files': ['*']
        },
        title: 'Save Patched Binary'
    });

    if (!uri) return;

    try {
        await connection.sendRequest('patch/save', { path: uri.fsPath });
        vscode.window.showInformationMessage(`Saved patched binary to ${uri.fsPath}`);
    } catch (error: any) {
        vscode.window.showErrorMessage(`Failed to save binary: ${error.message}`);
    }
}

async function showFunctions() {
    if (!connection || !currentBinaryPath) {
        vscode.window.showWarningMessage('No binary is open');
        return;
    }

    try {
        const result = await connection.sendRequest('analysis/getFunctions', {});

        const items = result.functions.map((func: any) => ({
            label: func.name || `sub_${func.address.slice(2)}`,
            description: `${func.address} (${func.size} bytes)`,
            address: func.address
        }));

        const selected = await vscode.window.showQuickPick(items, {
            placeHolder: 'Select a function to view'
        });

        if (selected) {
            // Show disassembly at selected function
            const address = parseInt(selected.address, 16);
            const disasm = await connection.sendRequest('analysis/getDisassembly', {
                address,
                count: 50
            });

            const content = disasm.instructions.map((insn: any) =>
                `${insn.address}  ${insn.text}`
            ).join('\n');

            const doc = await vscode.workspace.openTextDocument({
                content,
                language: 'asm'
            });

            await vscode.window.showTextDocument(doc);
        }
    } catch (error: any) {
        vscode.window.showErrorMessage(`Failed to get functions: ${error.message}`);
    }
}
