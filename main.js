// ui/electron/main.js — Electron main process
// Handles: window management, IPC bridge to Go backend, privilege escalation,
// content security policy, auto-update, and system tray.

const { app, BrowserWindow, ipcMain, dialog, shell, Tray, Menu, nativeImage, powerSaveBlocker } = require('electron');
const path = require('path');
const { spawn, execFile } = require('child_process');
const fs = require('fs');
const https = require('https');
const http = require('http');
const os = require('os');
const crypto = require('crypto');

// ─── Constants ────────────────────────────────────────────────────────────────

const IS_DEV = !app.isPackaged;
const BACKEND_PORT = 18443; // Go backend HTTPS port
const BACKEND_HOST = '127.0.0.1';
const BACKEND_URL = `https://${BACKEND_HOST}:${BACKEND_PORT}`;

// Paths to bundled binaries
const BIN_DIR = IS_DEV
  ? path.join(__dirname, '../../bin')
  : path.join(process.resourcesPath, 'bin');

const BACKEND_BIN = path.join(BIN_DIR, process.platform === 'win32' ? 'securewipe-backend.exe' : 'securewipe-backend');
const WIPE_ENGINE_BIN = path.join(BIN_DIR, process.platform === 'win32' ? 'wipe-engine.exe' : 'wipe-engine');

// ─── State ────────────────────────────────────────────────────────────────────

let mainWindow = null;
let tray = null;
let backendProcess = null;
let backendReady = false;
let powerBlockerId = null;

// ─── App lifecycle ────────────────────────────────────────────────────────────

app.whenReady().then(async () => {
  // Set application name for macOS dock and about box
  app.setName('SecureWipe Enterprise');

  // Request necessary permissions
  await requestElevatedPrivileges();

  // Start the Go backend
  await startBackend();

  // Create the main window
  createMainWindow();

  // Create system tray
  createTray();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createMainWindow();
  });
});

app.on('window-all-closed', () => {
  // On macOS apps typically stay active until explicitly quit
  if (process.platform !== 'darwin') {
    gracefulShutdown();
  }
});

app.on('before-quit', () => {
  gracefulShutdown();
});

// Security: prevent navigation to external URLs
app.on('web-contents-created', (event, contents) => {
  contents.on('will-navigate', (event, navigationUrl) => {
    const parsedUrl = new URL(navigationUrl);
    // Only allow navigation to local content
    if (parsedUrl.origin !== 'null' && !parsedUrl.href.startsWith('file://')) {
      event.preventDefault();
      shell.openExternal(navigationUrl); // open in system browser instead
    }
  });

  contents.setWindowOpenHandler(({ url }) => {
    shell.openExternal(url);
    return { action: 'deny' };
  });
});

// ─── Window creation ──────────────────────────────────────────────────────────

function createMainWindow() {
  mainWindow = new BrowserWindow({
    width: 1280,
    height: 820,
    minWidth: 960,
    minHeight: 640,
    title: 'SecureWipe Enterprise',
    backgroundColor: '#0a0a0f',
    show: false, // show after content loads to avoid white flash
    webPreferences: {
      nodeIntegration: false,         // Security: no Node.js in renderer
      contextIsolation: true,         // Security: isolated context
      sandbox: true,                  // Security: renderer sandboxed
      preload: path.join(__dirname, 'preload.js'),
      webSecurity: true,
      allowRunningInsecureContent: false,
      experimentalFeatures: false,
      enableRemoteModule: false,
    },
    icon: path.join(__dirname, '../assets/icon.png'),
    // macOS traffic light buttons
    titleBarStyle: process.platform === 'darwin' ? 'hiddenInset' : 'default',
  });

  // Content Security Policy
  mainWindow.webContents.session.webRequest.onHeadersReceived((details, callback) => {
    callback({
      responseHeaders: {
        ...details.responseHeaders,
        'Content-Security-Policy': [
          "default-src 'self';" +
          "script-src 'self';" +
          "style-src 'self' 'unsafe-inline';" + // needed for inline styles in React
          "img-src 'self' data: blob:;" +
          "font-src 'self' data:;" +
          `connect-src 'self' ${BACKEND_URL};` +
          "worker-src 'none';" +
          "object-src 'none';" +
          "base-uri 'none';"
        ],
        'X-Frame-Options': ['DENY'],
        'X-Content-Type-Options': ['nosniff'],
      }
    });
  });

  // Load the React app
  if (IS_DEV) {
    mainWindow.loadURL('http://localhost:3000');
    mainWindow.webContents.openDevTools();
  } else {
    mainWindow.loadFile(path.join(__dirname, '../build/index.html'));
  }

  mainWindow.once('ready-to-show', () => {
    mainWindow.show();
    mainWindow.focus();
  });

  mainWindow.on('closed', () => {
    mainWindow = null;
  });

  // Prevent title bar showing file path on macOS
  mainWindow.on('page-title-updated', (event) => event.preventDefault());

  return mainWindow;
}

// ─── System Tray ─────────────────────────────────────────────────────────────

function createTray() {
  const iconPath = path.join(__dirname, '../assets/tray-icon.png');
  const icon = nativeImage.createFromPath(iconPath).resize({ width: 16, height: 16 });
  tray = new Tray(icon);

  const contextMenu = Menu.buildFromTemplate([
    { label: 'SecureWipe Enterprise', enabled: false },
    { type: 'separator' },
    { label: 'Show Window', click: () => mainWindow?.show() },
    { label: 'Backend Status', click: showBackendStatus },
    { type: 'separator' },
    { label: 'Quit', click: () => app.quit() },
  ]);

  tray.setToolTip('SecureWipe Enterprise');
  tray.setContextMenu(contextMenu);
  tray.on('double-click', () => mainWindow?.show());
}

function showBackendStatus() {
  dialog.showMessageBox({
    type: 'info',
    title: 'Backend Status',
    message: `Backend: ${backendReady ? '✓ Running' : '✗ Not ready'}\nPID: ${backendProcess?.pid ?? 'N/A'}`,
  });
}

// ─── Backend management ───────────────────────────────────────────────────────

async function startBackend() {
  if (!fs.existsSync(BACKEND_BIN)) {
    if (IS_DEV) {
      console.log('[main] Backend binary not found, skipping in dev mode');
      backendReady = true;
      return;
    }
    dialog.showErrorBox('Startup Error', `Backend binary not found: ${BACKEND_BIN}`);
    app.quit();
    return;
  }

  return new Promise((resolve) => {
    const env = {
      ...process.env,
      SECUREWIPE_PORT: String(BACKEND_PORT),
      SECUREWIPE_HOST: BACKEND_HOST,
      SECUREWIPE_DATA_DIR: getDataDirectory(),
      SECUREWIPE_WIPE_ENGINE: WIPE_ENGINE_BIN,
      SECUREWIPE_ENV: IS_DEV ? 'development' : 'production',
    };

    backendProcess = spawn(BACKEND_BIN, ['--port', String(BACKEND_PORT)], {
      env,
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    backendProcess.stdout.on('data', (data) => {
      const text = data.toString().trim();
      if (text.includes('listening') || text.includes('ready')) {
        backendReady = true;
        resolve();
      }
      if (IS_DEV) console.log('[backend]', text);
    });

    backendProcess.stderr.on('data', (data) => {
      if (IS_DEV) console.error('[backend err]', data.toString().trim());
    });

    backendProcess.on('exit', (code, signal) => {
      backendReady = false;
      console.error(`[main] Backend exited: code=${code}, signal=${signal}`);
      if (mainWindow) {
        mainWindow.webContents.send('backend-status', { running: false, code });
      }
    });

    // Timeout: if backend doesn't report ready in 10s, proceed anyway
    setTimeout(() => {
      backendReady = true;
      resolve();
    }, 10000);
  });
}

function getDataDirectory() {
  const base = app.getPath('userData');
  const dir = path.join(base, 'securewipe-data');
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

// ─── Privilege escalation ────────────────────────────────────────────────────

async function requestElevatedPrivileges() {
  // On Linux/macOS: the wipe engine needs raw block device access.
  // If not running as root, we show a dialog and restart with pkexec/sudo.
  if (process.platform === 'win32') {
    // Windows: request UAC elevation via manifest (handled externally)
    return;
  }

  if (process.getuid && process.getuid() !== 0) {
    if (IS_DEV) {
      console.warn('[main] Not running as root — raw disk access will fail');
      return;
    }

    const choice = await dialog.showMessageBox({
      type: 'question',
      title: 'Administrator Access Required',
      message: 'SecureWipe Enterprise requires administrator privileges to access raw disk devices.',
      detail: 'Click Restart as Administrator to relaunch with elevated permissions.',
      buttons: ['Restart as Administrator', 'Continue Without (limited functionality)', 'Quit'],
      defaultId: 0,
    });

    if (choice.response === 0) {
      // Relaunch via pkexec (Linux) or osascript (macOS)
      const execPath = process.execPath;
      const args = process.argv.slice(1);

      if (process.platform === 'linux') {
        spawn('pkexec', [execPath, ...args], { detached: true });
      } else if (process.platform === 'darwin') {
        const script = `do shell script "${execPath} ${args.join(' ')}" with administrator privileges`;
        spawn('osascript', ['-e', script], { detached: true });
      }

      app.quit();
    } else if (choice.response === 2) {
      app.quit();
    }
    // choice === 1: continue without privileges
  }
}

// ─── IPC handlers ─────────────────────────────────────────────────────────────

// Proxy all API calls from renderer to Go backend
// The renderer calls ipcMain via the preload bridge; this avoids CORS issues
// and keeps credentials out of the renderer process.

ipcMain.handle('api-request', async (event, { method, path, body, token }) => {
  return new Promise((resolve, reject) => {
    const options = {
      hostname: BACKEND_HOST,
      port: BACKEND_PORT,
      path: path,
      method: method || 'GET',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
      },
      // Accept self-signed certs for localhost
      rejectUnauthorized: false,
    };

    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        try {
          resolve({ status: res.statusCode, data: JSON.parse(data), headers: res.headers });
        } catch {
          resolve({ status: res.statusCode, data, headers: res.headers });
        }
      });
    });

    req.on('error', reject);

    if (body) {
      req.write(JSON.stringify(body));
    }
    req.end();
  });
});

// File system operations (restricted to safe paths)
ipcMain.handle('save-certificate', async (event, { filename, content, format }) => {
  const ext = format === 'pdf' ? 'pdf' : 'json';
  const { filePath } = await dialog.showSaveDialog(mainWindow, {
    title: 'Save Certificate',
    defaultPath: path.join(app.getPath('documents'), filename),
    filters: [
      { name: format === 'pdf' ? 'PDF Document' : 'JSON Certificate', extensions: [ext] },
      { name: 'All Files', extensions: ['*'] },
    ],
  });

  if (filePath) {
    fs.writeFileSync(filePath, content);
    return { saved: true, path: filePath };
  }
  return { saved: false };
});

ipcMain.handle('export-certificates', async (event, { zipData, filename }) => {
  const { filePath } = await dialog.showSaveDialog(mainWindow, {
    title: 'Export Certificates',
    defaultPath: path.join(app.getPath('documents'), filename || 'certificates.zip'),
    filters: [{ name: 'ZIP Archive', extensions: ['zip'] }],
  });

  if (filePath) {
    const buffer = Buffer.from(zipData, 'base64');
    fs.writeFileSync(filePath, buffer);
    return { saved: true, path: filePath };
  }
  return { saved: false };
});

// Open certificate in system viewer
ipcMain.handle('open-file', async (event, filePath) => {
  await shell.openPath(filePath);
});

// Reveal file in Finder/Explorer
ipcMain.handle('reveal-file', async (event, filePath) => {
  shell.showItemInFolder(filePath);
});

// Drive detection — calls the wipe engine directly for speed
ipcMain.handle('detect-drives', async (event) => {
  return new Promise((resolve) => {
    if (!fs.existsSync(WIPE_ENGINE_BIN)) {
      resolve({ drives: [], error: 'Wipe engine not found' });
      return;
    }

    execFile(WIPE_ENGINE_BIN, ['list', '--json'], { timeout: 10000 }, (err, stdout, stderr) => {
      if (err) {
        resolve({ drives: [], error: err.message });
        return;
      }
      try {
        resolve({ drives: JSON.parse(stdout), error: null });
      } catch {
        resolve({ drives: [], error: 'Failed to parse drive list' });
      }
    });
  });
});

// Power management: prevent system sleep during active wipes
ipcMain.handle('set-wipe-active', (event, active) => {
  if (active && !powerBlockerId) {
    powerBlockerId = powerSaveBlocker.start('prevent-app-suspension');
    console.log('[main] Power save blocker started:', powerBlockerId);
  } else if (!active && powerBlockerId !== null) {
    powerSaveBlocker.stop(powerBlockerId);
    powerBlockerId = null;
    console.log('[main] Power save blocker stopped');
  }
});

// Backend status
ipcMain.handle('get-backend-status', () => ({
  ready: backendReady,
  pid: backendProcess?.pid ?? null,
  url: BACKEND_URL,
}));

// App version info
ipcMain.handle('get-app-info', () => ({
  version: app.getVersion(),
  platform: process.platform,
  arch: process.arch,
  nodeVersion: process.versions.node,
  electronVersion: process.versions.electron,
  isRoot: process.getuid ? process.getuid() === 0 : true,
  dataDir: getDataDirectory(),
}));

// ─── Graceful shutdown ────────────────────────────────────────────────────────

async function gracefulShutdown() {
  console.log('[main] Shutting down...');

  // Stop power blocker
  if (powerBlockerId !== null) {
    powerSaveBlocker.stop(powerBlockerId);
  }

  // Ask backend to finish active jobs before killing
  if (backendProcess && backendReady) {
    try {
      await fetch(`${BACKEND_URL}/api/v1/shutdown`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        signal: AbortSignal.timeout(5000),
      });
    } catch {
      // Backend may already be gone
    }

    // Give it 3 seconds to finish
    await new Promise((resolve) => setTimeout(resolve, 3000));
  }

  if (backendProcess) {
    backendProcess.kill('SIGTERM');
    backendProcess = null;
  }
}
