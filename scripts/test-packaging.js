/**
 * Validates the packaging configuration without running a full build.
 *
 * A full electron-builder run downloads hundreds of megabytes, so this checks
 * the things that silently break a release: a missing icon, an extraResources
 * path that does not exist, a preload file that main.js names but that is not
 * shipped, or a spec file pointing at a build that was never produced.
 *
 * Run with:  npm run test:packaging
 */

const assert = require("assert");
const fs = require("fs");
const path = require("path");

const ROOT = path.join(__dirname, "..");
const read = (rel) => fs.readFileSync(path.join(ROOT, rel), "utf8");
const exists = (rel) => fs.existsSync(path.join(ROOT, rel));

let passed = 0;
let failed = 0;

function check(name, fn) {
  try {
    fn();
    passed += 1;
    console.log(`  ok   ${name}`);
  } catch (err) {
    failed += 1;
    console.log(`  FAIL ${name}: ${err.message}`);
  }
}

function section(title) {
  console.log(`\n${title}`);
}

const pkg = JSON.parse(read("package.json"));
const build = pkg.build || {};

section("Project manifest");

check("main points at the Electron entry point", () => {
  assert.strictEqual(pkg.main, "desktop/main.js");
  assert.ok(exists(pkg.main), `${pkg.main} is missing`);
});

check("appId and productName are set", () => {
  assert.ok(build.appId, "appId missing");
  assert.ok(build.productName, "productName missing");
});

check("output directory is configured", () => {
  assert.ok(build.directories && build.directories.output);
});

section("Installer targets");

check("Windows builds an NSIS installer", () => {
  const targets = build.win.target.map((t) => t.target);
  assert.ok(targets.includes("nsis"), `targets: ${targets}`);
});

check("Linux builds AppImage and deb", () => {
  const targets = build.linux.target;
  assert.ok(targets.includes("AppImage"), "AppImage missing");
  assert.ok(targets.includes("deb"), "deb missing");
});

check("deb declares its runtime libraries", () => {
  const depends = build.deb.depends || [];
  assert.ok(depends.length > 0, "no dependencies declared");
  assert.ok(depends.includes("libgtk-3-0"), "GTK missing");
  assert.ok(depends.includes("libnss3"), "NSS missing");
});

check("installer artefacts are named", () => {
  assert.ok(build.win.artifactName, "windows artefact name missing");
  assert.ok(build.linux.artifactName, "linux artefact name missing");
});

section("Icons");

check("the Windows icon exists", () => {
  assert.ok(exists("build/icon.ico"), "build/icon.ico is missing");
});

check("the Linux icon exists", () => {
  assert.ok(exists("build/icon.png"), "build/icon.png is missing");
});

check("the icon is a real PNG", () => {
  const buf = fs.readFileSync(path.join(ROOT, "build", "icon.png"));
  const magic = buf.slice(0, 8).toString("hex");
  assert.strictEqual(magic, "89504e470d0a1a0a", "not a PNG");
});

section("Shipped files");

check("the preload script exists", () => {
  const main = read("desktop/main.js");
  assert.ok(main.includes("preload.js"), "preload is not referenced");
  assert.ok(exists("desktop/preload.js"), "preload.js is missing");
});

check("the shell files are included in the package", () => {
  const files = build.files || [];
  assert.ok(
    files.some((f) => f.includes("desktop")),
    `desktop not in files: ${files}`
  );
});

section("Bundled engine");

const extra = (build.extraResources || [])[0];
check("the engine is shipped as an extraResource", () => {
  assert.ok(extra, "no extraResources entry");
  assert.strictEqual(extra.to, "backend", "engine must land in resources/backend");
});

check("the engine path matches what the build script produces", () => {
  assert.strictEqual(
    extra.from,
    "build/backend/red-dragon-backend",
    "extraResources.from does not match the build:backend output"
  );
});

check("the build script writes where electron-builder reads", () => {
  const script = read("scripts/build-backend.js");
  assert.ok(
    script.includes('path.join(ROOT, "build", "backend")'),
    "build script does not target build/backend"
  );
});

check("the engine bundle is present", () => {
  const dir = path.join(ROOT, "build", "backend", "red-dragon-backend");
  assert.ok(fs.existsSync(dir), "run `npm run build:backend` first");
  const exe = process.platform === "win32" ? "red-dragon-backend.exe" : "red-dragon-backend";
  assert.ok(
    fs.existsSync(path.join(dir, exe)),
    `${exe} is missing from the bundle`
  );
});

check("the engine carries the interface with it", () => {
  const dir = path.join(ROOT, "build", "backend", "red-dragon-backend");
  const flat = path.join(dir, "ui", "index.html");
  const internal = path.join(dir, "_internal", "ui", "index.html");
  assert.ok(
    fs.existsSync(flat) || fs.existsSync(internal),
    "the bundled engine has no interface files"
  );
});

check("backend.js looks for the engine where it is shipped", () => {
  const js = read("desktop/backend.js");
  assert.ok(
    js.includes('path.join(resourceRoot, "backend")') ||
      js.includes('"backend"'),
    "backend.js does not look in resources/backend"
  );
});

section("PyInstaller spec");

check("the spec file exists", () => {
  assert.ok(exists("packaging/red-dragon-backend.spec"));
});

check("the spec bundles the interface", () => {
  const spec = read("packaging/red-dragon-backend.spec");
  assert.ok(spec.includes('"ui"'), "spec does not bundle the ui folder");
});

check("the spec hides the console window", () => {
  const spec = read("packaging/red-dragon-backend.spec");
  assert.ok(/console\s*=\s*False/.test(spec), "console window would flash on launch");
});

section("Build scripts");

check("every documented script exists", () => {
  for (const name of ["dev", "start", "build:ui", "build:backend",
                      "build", "dist", "dist:win", "dist:linux"]) {
    assert.ok(pkg.scripts[name], `npm run ${name} is not defined`);
  }
});

check("dist runs the full build first", () => {
  assert.ok(pkg.scripts.dist.includes("build"), "dist skips the build step");
});

check("the backend is not a native dependency any more", () => {
  const reqs = read("backend/requirements.txt");
  assert.ok(!/^python-nmap/m.test(reqs), "python-nmap is still a dependency");
});

section("Security posture");

check("the backend binds to loopback only", () => {
  const desktop = read("backend/desktop.py");
  assert.ok(desktop.includes("host='127.0.0.1'"), "backend does not bind to 127.0.0.1");
  assert.ok(!/host\s*=\s*'0\.0\.0\.0'/.test(desktop), "backend binds to all interfaces");
});

check("the dev server also binds to loopback", () => {
  const server = read("backend/server.py");
  assert.ok(!/app\.run\(\s*host='0\.0\.0\.0'/.test(server),
    "server.py still binds to 0.0.0.0");
  assert.ok(!/debug=True/.test(server), "server.py still enables the debugger");
});

check("the API requires the launch token", () => {
  const desktop = read("backend/desktop.py");
  assert.ok(desktop.includes("X-RD-Token"), "no token header check");
  assert.ok(desktop.includes("compare_digest"), "token is not compared in constant time");
});

check("the renderer is sandboxed", () => {
  const main = read("desktop/main.js");
  assert.ok(/contextIsolation:\s*true/.test(main), "context isolation is off");
  assert.ok(/nodeIntegration:\s*false/.test(main), "node integration is on");
  assert.ok(/sandbox:\s*true/.test(main), "the renderer is not sandboxed");
});

check("the preload bridge exposes nothing dangerous", () => {
  const preload = read("desktop/preload.js");
  assert.ok(!/require\(\s*["']fs["']\s*\)/.test(preload), "preload requires fs");
  assert.ok(!/require\(\s*["']child_process["']\s*\)/.test(preload),
    "preload requires child_process");
  // Comments explain why the token is withheld, so strip them before checking
  // what is actually handed across the bridge.
  const code = preload
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .split("\n")
    .filter((line) => !line.trim().startsWith("//"))
    .join("\n");
  assert.ok(!/token/i.test(code), "the preload bridge hands the token to the page");
});

check("navigation away from the app origin is blocked", () => {
  const main = read("desktop/main.js");
  assert.ok(main.includes("will-navigate"), "no navigation guard");
  assert.ok(main.includes("setWindowOpenHandler"), "no popup guard");
});

console.log(`\n${passed} passed, ${failed} failed\n`);
process.exit(failed ? 1 : 0);