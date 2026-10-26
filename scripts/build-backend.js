"use strict";

/**
 * Builds the Python scanning engine into a self-contained bundle.
 *
 * Run before packaging the app:
 *   npm run build:backend
 *
 * The result lands in build/backend/red-dragon-backend/ and is shipped inside
 * the installer as an Electron extraResource, so the finished app needs no
 * Python installation on the user's machine.
 */

const { spawnSync } = require("child_process");
const fs = require("fs");
const path = require("path");

const ROOT = path.join(__dirname, "..");
const OUT_DIR = path.join(ROOT, "build", "backend");
const DIST_DIR = path.join(ROOT, "dist", "backend");
// PyInstaller keeps intermediate files in build/<name> by default, which collides
// with the build/ folder electron-builder reads. Keep it out of the way.
const WORK_DIR = path.join(ROOT, "dist", "pyi-work");
const SPEC = path.join(ROOT, "packaging", "red-dragon-backend.spec");
const UI_BUILD = path.join(ROOT, "frontend", "build");

function fail(message) {
  console.error(`\n  ${message}\n`);
  process.exit(1);
}

function run(command, args, label) {
  console.log(`\n> ${label}`);
  const result = spawnSync(command, args, {
    stdio: "inherit",
    cwd: ROOT,
    // shell:false so argument quoting is not re-done by the shell
    shell: false,
  });
  if (result.error) fail(`${label} could not start: ${result.error.message}`);
  if (result.status !== 0) fail(`${label} failed (exit ${result.status}).`);
}

/** Locate a Python that has PyInstaller available. */
function findPython() {
  const candidates =
    process.platform === "win32" ? ["python", "python3", "py"] : ["python3", "python"];
  // shell:false on purpose: with shell:true the OS re-splits the snippet on
  // spaces, so the import statement gets truncated at the first one.
  for (const name of candidates) {
    const probe = spawnSync(
      name,
      ["-c", "import PyInstaller;print(PyInstaller.__version__)"],
      { encoding: "utf8" }
    );
    if (!probe.error && probe.status === 0) {
      return { command: name, version: (probe.stdout || "").trim() };
    }
  }
  return null;
}

function main() {
  if (!fs.existsSync(path.join(UI_BUILD, "index.html"))) {
    fail(
      "The interface has not been built yet.\n" +
        "  Run:  npm run build:ui"
    );
  }

  const python = findPython();
  if (!python) {
    fail(
      "PyInstaller was not found.\n\n" +
        "  Install it with:  pip install pyinstaller\n" +
        "  (and install the backend requirements: pip install -r backend/requirements.txt)"
    );
  }
  console.log(`Using ${python.command} with PyInstaller ${python.version}`);

  // Clean so a removed dependency cannot linger in the bundle.
  for (const dir of [OUT_DIR, DIST_DIR]) {
    fs.rmSync(dir, { recursive: true, force: true });
  }

  run(
    python.command,
    ["-m", "PyInstaller", SPEC, "--noconfirm", "--clean", "--distpath", DIST_DIR, "--workpath", WORK_DIR],
    "Bundling the scanning engine"
  );

  const produced = path.join(DIST_DIR, "red-dragon-backend");
  if (!fs.existsSync(produced)) {
    fail(`Expected the backend bundle at ${produced}, but it was not created.`);
  }

  // electron-builder expects extraResources under build/, so copy it there.
  // A rename is tried first, but it fails with EPERM when the project lives in
  // a synced folder such as OneDrive, because the destination is still held
  // open; fall back to a recursive copy.
  const destination = path.join(OUT_DIR, "red-dragon-backend");
  fs.mkdirSync(OUT_DIR, { recursive: true });
  try {
    fs.renameSync(produced, destination);
  } catch (err) {
    fs.rmSync(destination, { recursive: true, force: true });
    fs.cpSync(produced, destination, { recursive: true, force: true });
    fs.rmSync(produced, { recursive: true, force: true });
  }

  // A quick sanity check: the UI must have travelled with the engine.
  // PyInstaller 6 places bundled data under `_internal`, so accept either
  // location - this must stay in step with desktop.find_ui_build().
  const bundleRoot = path.join(OUT_DIR, "red-dragon-backend");
  const uiLocations = [
    path.join(bundleRoot, "ui", "index.html"),
    path.join(bundleRoot, "_internal", "ui", "index.html"),
  ];
  if (!uiLocations.some((p) => fs.existsSync(p))) {
    fail(
      "The backend built, but the interface files are missing from it.\n" +
        "Looked in:\n  " +
        uiLocations.join("\n  ")
    );
  }

  const exe = process.platform === "win32"
    ? path.join(OUT_DIR, "red-dragon-backend", "red-dragon-backend.exe")
    : path.join(OUT_DIR, "red-dragon-backend", "red-dragon-backend");
  if (!fs.existsSync(exe)) {
    fail(`The backend executable is missing at ${exe}.`);
  }

  console.log(`\n  Backend bundle ready: ${path.join(OUT_DIR, "red-dragon-backend")}`);
  console.log("  Next: npm run dist\n");
}

main();
