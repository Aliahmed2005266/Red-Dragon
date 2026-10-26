'use strict';

/**
 * Red Dragon - Electron main process
 *
 * Owns the application window and the Python backend that does the scanning.
 * The window never loads a remote page: it always points at the loopback
 * backend, which serves the bundled UI. That keeps the renderer sandboxed and
 * means there is no web origin in the app that could be navigated away to.
 *
 * Security posture of the window, and why:
 *   contextIsolation  - preload and page scripts get separate worlds
 *   nodeIntegration   - off, so page JS has no filesystem or process access
 *   sandbox           - on, so the renderer runs in an OS sandbox
 *   webSecurity       - left on, so same-origin rules still apply
 * Plus navigation, popups and device permissions are blocked outright, so even
 * a successful injection cannot reach the network, the disk or a new window.
 */

const { app, BrowserWindow, shell, dialog, Menu, ipcMain } = require("electron");
const path = require("path");
const { BackendProcess } = require("./backend");

const isDev = !app.isPackaged;

let mainWindow = null;
let backend = null;
let quitting = false;

// Only one instance may run: the app owns a scan session and a local port, and
// two copies would confuse both.
if (!app.requestSingleInstanceLock()) {
  app.quit();
} else {
  app.on("second-instance", () => {
    if (mainWindow) {
      if (mainWindow.isMinimized()) mainWindow.restore();
      mainWindow.focus();
    }
  });
}

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1440,
    height: 940,
    minWidth: 1024,
    minHeight: 700,
    backgroundColor: "#0a0a0a",
    show: false,
    title: "Red Dragon",
    icon: path.join(__dirname, "..", "build", "icon.png"),
    webPreferences: {
      preload: path.join(__dirname, "preload.js"),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      webSecurity: true,
      spellcheck: false,
    },
  });

  // The app draws its own chrome, so hide the native menu bar.
  mainWindow.setMenuBarVisibility(false);
  hardenWindow(mainWindow);

  mainWindow.on("ready-to-show", () => mainWindow.show());
  mainWindow.on("closed", () => {
    mainWindow = null;
  });

  return mainWindow;
}

/**
 * Lock the window down: no navigation off the loopback origin, no popups, and
 * no device permissions.
 */
function hardenWindow(win) {
  win.webContents.on("will-navigate", (event, url) => {
    const allowed = backend && backend.origin;
    if (!allowed || !url.startsWith(allowed)) {
      event.preventDefault();
      // Send genuine external links to the real browser rather than the app.
      if (/^https?:\/\//i.test(url)) shell.openExternal(url);
    }
  });

  win.webContents.setWindowOpenHandler(({ url }) => {
    if (/^https?:\/\//i.test(url)) shell.openExternal(url);
    return { action: "deny" };
  });

  // Nothing in this app needs a camera, a microphone or notifications.
  win.webContents.session.setPermissionRequestHandler((_wc, _perm, cb) =>
    cb(false)
  );
  win.webContents.session.setPermissionCheckHandler(() => false);
}

// The secondary window that shows only a scan's results. Kept as a single
// instance: opening it again for another scan reuses it.
let resultsWindow = null;

/**
 * Open (or focus) the results-only window for a scan.
 *
 * It loads the same loopback origin as the main window with a view flag, so it
 * receives the launch token the same way and is hardened identically. Returns
 * false when the backend is not up yet or the scan id is malformed.
 */
function openResultsWindow(scanId) {
  if (!backend || !backend.origin) return false;
  if (typeof scanId !== "string" || !/^[\w-]{1,128}$/.test(scanId)) {
    return false;
  }

  const url =
    backend.origin + "/?view=results&scanId=" + encodeURIComponent(scanId);

  if (resultsWindow && !resultsWindow.isDestroyed()) {
    resultsWindow.loadURL(url);
    if (resultsWindow.isMinimized()) resultsWindow.restore();
    resultsWindow.focus();
    return true;
  }

  resultsWindow = new BrowserWindow({
    width: 1280,
    height: 900,
    minWidth: 900,
    minHeight: 600,
    backgroundColor: "#0a0a0a",
    show: false,
    title: "Red Dragon - Results",
    icon: path.join(__dirname, "..", "build", "icon.png"),
    webPreferences: {
      preload: path.join(__dirname, "preload.js"),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      webSecurity: true,
      spellcheck: false,
    },
  });

  resultsWindow.setMenuBarVisibility(false);
  hardenWindow(resultsWindow);
  resultsWindow.on("ready-to-show", () => resultsWindow.show());
  resultsWindow.on("closed", () => {
    resultsWindow = null;
  });
  resultsWindow.loadURL(url);
  return true;
}

ipcMain.handle("results-window:open", (_event, scanId) =>
  openResultsWindow(scanId)
);

// Shown while the backend boots, so the window is never blank.
const LOADING_HTML =
  "data:text/html;charset=utf-8," +
  encodeURIComponent(`<!doctype html><meta charset="utf-8">
  <style>body{background:#0a0a0a;color:#00d4ff;font:14px -apple-system,Segoe UI,Roboto,sans-serif;
  display:flex;align-items:center;justify-content:center;height:100vh;margin:0;flex-direction:column;gap:16px}
  .dot{width:10px;height:10px;border-radius:50%;background:#00d4ff;animation:p 1.2s infinite}
  @keyframes p{0%,100%{opacity:.25}50%{opacity:1}}</style>
  <div class="dot"></div><div>Starting the scanning engine...</div>`);

const esc = (s) => String(s).replace(/[<>&]/g, (c) => ({ "<": "&lt;", ">": "&gt;", "&": "&amp;" }[c]));

/** Show a readable error screen instead of a blank or broken window. */
async function showStartupError(error) {
  const detail = (error && error.message) || String(error);
  if (!mainWindow || mainWindow.isDestroyed()) createWindow();

  mainWindow.loadURL(
    "data:text/html;charset=utf-8," +
      encodeURIComponent(`<!doctype html><meta charset="utf-8">
      <style>
        body{background:#0a0a0a;color:#e0e0e0;font:14px/1.6 -apple-system,Segoe UI,Roboto,sans-serif;
             display:flex;align-items:center;justify-content:center;height:100vh;margin:0}
        .box{max-width:660px;padding:32px;background:#1a1a1a;border:1px solid #333;border-radius:8px}
        h1{color:#ff6b6b;font-size:18px;margin:0 0 12px}
        pre{white-space:pre-wrap;word-break:break-word;background:#111;padding:12px;
            border-radius:6px;color:#ffb3b3;font-size:12px}
        .hint{color:#888;font-size:12px;margin-top:16px}
        code{background:#111;padding:2px 6px;border-radius:4px}
      </style>
      <div class="box">
        <h1>Red Dragon could not start</h1>
        <pre>${esc(detail)}</pre>
        <div class="hint">Reinstall the application, or run
          <code>npm run backend:debug</code> from the project folder to see the
          full backend output.</div>
      </div>`)
  );
  mainWindow.show();
}

async function bootstrap() {
  backend = new BackendProcess();

  // Surface backend tracebacks in the terminal while developing.
  if (isDev) {
    backend.on("stderr", (chunk) => process.stderr.write(`[backend] ${chunk}`));
  }

  // If the backend dies later, say so instead of leaving a dead window.
  backend.on("exit", ({ code, signal, error }) => {
    if (quitting) return;
    const why = error ? error.message : `code ${code}`;
    dialog.showErrorBox(
      "Scanner stopped",
      `The scanning engine stopped unexpectedly (${why}).`
    );
    if (mainWindow && !mainWindow.isDestroyed()) mainWindow.reload();
  });

  let info;
  try {
    // The packaged engine is a windowed binary with no stdout on Windows, so
    // the start-up handshake is written to a file we name.
    const readyFile = path.join(app.getPath("temp"), `red-dragon-${process.pid}.json`);
    info = await backend.start(readyFile);
  } catch (err) {
    await showStartupError(err);
    return;
  }

  if (!info.ui) {
    await showStartupError(
      new Error(
        "The scanning engine started, but the interface files were not found.\n" +
          "Reinstall the application."
      )
    );
    return;
  }

  await backend.waitForHealth();
  mainWindow.loadURL(backend.origin);
}

app.whenReady().then(async () => {
  Menu.setApplicationMenu(null);
  mainWindow = createWindow();
  mainWindow.loadURL(LOADING_HTML);
  await bootstrap();
});

app.on("window-all-closed", () => app.quit());

// Stop the backend on the way out so no orphaned server is left listening.
app.on("before-quit", () => {
  quitting = true;
});

app.on("will-quit", (event) => {
  if (backend && !backend.exited && !quitting) {
    event.preventDefault();
    quitting = true;
    backend.stop().finally(() => app.quit());
  }
});

