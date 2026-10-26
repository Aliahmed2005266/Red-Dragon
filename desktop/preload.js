'use strict';

/**
 * Red Dragon - preload bridge
 *
 * The renderer is sandboxed with context isolation on, so the page has no Node
 * access at all. This file is the only channel between the page and the main
 * process, and it deliberately exposes a very small surface: just enough for
 * the UI to know it is running inside the desktop app.
 *
 * Nothing here hands the page the launch token. The page receives that from the
 * bootstrap script the backend injects, which only the real app can fetch.
 */

const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("redDragon", {
  /** Identifies the shell, so the UI can adapt its wording. */
  isDesktop: true,

  /**
   * Open the results-only window for a scan. The main process owns the window
   * because popups and extra windows are denied at the webContents level.
   */
  openResultsWindow: (scanId) => ipcRenderer.invoke("results-window:open", scanId),

  /** Versions of the app and the engine, for the about screen. */
  versions: {
    app: "1.0.0",
    electron: process.versions.electron,
    chrome: process.versions.chrome,
    node: process.versions.node,
  },

  platform: process.platform,
});
