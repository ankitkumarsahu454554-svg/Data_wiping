// ui/electron/preload.js — Secure preload script
// Exposes a minimal, typed API to the renderer via contextBridge.
// The renderer NEVER has access to Node.js or Electron APIs directly.

const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electronAPI', {
  // ── Backend API proxy ────────────────────────────────────────────────────
  apiRequest: (method, path, body, token) =>
    ipcRenderer.invoke('api-request', { method, path, body, token }),

  // ── File operations ──────────────────────────────────────────────────────
  saveCertificate: (filename, content, format) =>
    ipcRenderer.invoke('save-certificate', { filename, content, format }),

  exportCertificates: (zipData, filename) =>
    ipcRenderer.invoke('export-certificates', { zipData, filename }),

  openFile: (filePath) =>
    ipcRenderer.invoke('open-file', filePath),

  revealFile: (filePath) =>
    ipcRenderer.invoke('reveal-file', filePath),

  // ── Drive operations ─────────────────────────────────────────────────────
  detectDrives: () =>
    ipcRenderer.invoke('detect-drives'),

  // ── Power management ─────────────────────────────────────────────────────
  setWipeActive: (active) =>
    ipcRenderer.invoke('set-wipe-active', active),

  // ── App info ─────────────────────────────────────────────────────────────
  getBackendStatus: () =>
    ipcRenderer.invoke('get-backend-status'),

  getAppInfo: () =>
    ipcRenderer.invoke('get-app-info'),

  // ── Event listeners ──────────────────────────────────────────────────────
  onBackendStatus: (callback) => {
    ipcRenderer.on('backend-status', (event, data) => callback(data));
  },

  removeAllListeners: (channel) => {
    ipcRenderer.removeAllListeners(channel);
  },
});
