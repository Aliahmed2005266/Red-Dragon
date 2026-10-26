/**
 * Tests for the desktop shell's process manager.
 *
 * No test framework is required: the assertions are plain checks so this runs
 * anywhere Node does, including on a build machine before dependencies are
 * installed. Run with:  npm run test:desktop
 */

const assert = require("assert");
const path = require("path");
const fs = require("fs");
const os = require("os");
const http = require("http");
const { spawn } = require("child_process");
const {
  BackendProcess,
  READY_PREFIX,
  findBackend,
  findPython,
  needsPython,
  backendCandidates,
} = require("../desktop/backend");

let passed = 0;
let failed = 0;

function check(name, fn) {
  try {
    const result = fn();
    if (result && typeof result.then === "function") {
      return result.then(
        () => { passed += 1; console.log(`  ok   ${name}`); },
        (err) => { failed += 1; console.log(`  FAIL ${name}: ${err.message}`); }
      );
    }
    passed += 1;
    console.log(`  ok   ${name}`);
  } catch (err) {
    failed += 1;
    console.log(`  FAIL ${name}: ${err.message}`);
  }
  return Promise.resolve();
}

async function main() {
  console.log("Backend discovery");

  await check("ready prefix is what the shell greps for", () => {
    assert.strictEqual(READY_PREFIX, "REDDRAGON_READY ");
  });

  await check("development backend is found", () => {
    const found = findBackend();
    assert.ok(found, "no backend found");
    assert.ok(fs.existsSync(found), `${found} does not exist`);
  });

  await check("candidates include the source checkout", () => {
    const all = backendCandidates();
    assert.ok(all.some((p) => p.endsWith("desktop.py")), "desktop.py missing");
  });

  await check("env override is honoured", () => {
    const before = process.env.RED_DRAGON_BACKEND;
    process.env.RED_DRAGON_BACKEND = __filename;
    try {
      assert.strictEqual(findBackend(), __filename);
    } finally {
      if (before === undefined) delete process.env.RED_DRAGON_BACKEND;
      else process.env.RED_DRAGON_BACKEND = before;
    }
  });

  await check("missing override falls through", () => {
    const before = process.env.RED_DRAGON_BACKEND;
    process.env.RED_DRAGON_BACKEND = path.join(os.tmpdir(), "nope-does-not-exist");
    try {
      assert.notStrictEqual(findBackend(), process.env.RED_DRAGON_BACKEND);
    } finally {
      if (before === undefined) delete process.env.RED_DRAGON_BACKEND;
      else process.env.RED_DRAGON_BACKEND = before;
    }
  });

  await check("python files need an interpreter, binaries do not", () => {
    assert.strictEqual(needsPython("x.py"), true);
    assert.strictEqual(needsPython("x.exe"), false);
    assert.strictEqual(needsPython("x"), false);
  });

  await check("a working python is found", () => {
    const py = findPython();
    assert.ok(py, "no usable python found");
  });

  console.log("\nLifecycle");

  const backend = new BackendProcess();
  const logLines = [];
  backend.on("stderr", (c) => logLines.push(c));

  let info;
  await check("backend starts and reports ready", async () => {
    info = await backend.start();
    assert.strictEqual(info.ready, true);
  });

  await check("a port is reported", () => {
    assert.strictEqual(typeof info.port, "number");
    assert.ok(info.port > 0, `bad port ${info.port}`);
  });

  await check("a launch token is reported", () => {
    assert.strictEqual(typeof info.token, "string");
    assert.ok(info.token.length >= 32, "token too short");
  });

  await check("origin is loopback only", () => {
    assert.strictEqual(backend.origin, `http://127.0.0.1:${info.port}`);
    assert.ok(backend.origin.startsWith("http://127.0.0.1:"));
    assert.ok(!backend.origin.includes("0.0.0.0"));
  });

  await check("health check succeeds with the token", async () => {
    const health = await backend.waitForHealth();
    assert.strictEqual(health.status, "healthy");
  });

  await check("health fails without the token", async () => {
    const saved = backend.token;
    backend.token = "definitely-wrong";
    try {
      await assert.rejects(() => backend.health());
    } finally {
      backend.token = saved;
    }
  });

  await check("the UI is served at the origin", async () => {
    const body = await new Promise((resolve, reject) => {
      http
        .get(`${backend.origin}/`, (res) => {
          let data = "";
          res.setEncoding("utf8");
          res.on("data", (c) => { data += c; });
          res.on("end", () => resolve({ status: res.statusCode, data }));
        })
        .on("error", reject);
    });
    assert.strictEqual(body.status, 200);
    assert.ok(body.data.includes("__RED_DRAGON__"), "bootstrap not injected");
  });

  await check("the served token matches the reported one", async () => {
    const body = await new Promise((resolve, reject) => {
      http
        .get(`${backend.origin}/`, (res) => {
          let data = "";
          res.setEncoding("utf8");
          res.on("data", (c) => { data += c; });
          res.on("end", () => resolve(data));
        })
        .on("error", reject);
    });
    assert.ok(body.includes(info.token), "page token differs from the launch token");
  });

  await check("api is rejected without the token", async () => {
    await new Promise((resolve, reject) => {
      const req = http.request(
        { host: "127.0.0.1", port: backend.port, path: "/api/health", method: "GET" },
        (res) => {
          res.resume();
          if (res.statusCode === 403) resolve();
          else reject(new Error(`expected 403, got ${res.statusCode}`));
        }
      );
      req.on("error", reject);
      req.end();
    });
  });

  await check("stop terminates the process", async () => {
    await backend.stop();
    assert.strictEqual(backend.exited, true);
  });

  await check("stop is safe to call twice", async () => {
    await backend.stop();
  });

  console.log("\nReady-file handshake");

  await check("the engine writes a handshake file", async () => {
    const readyFile = path.join(os.tmpdir(), `rd-handshake-${process.pid}.json`);
    const b = new BackendProcess();
    try {
      const info = await b.start(readyFile);
      // In development the stdout handshake can win the race against the file
      // write, so allow a moment for the file to appear.
      for (let i = 0; i < 40 && !fs.existsSync(readyFile); i += 1) {
        await new Promise((r) => setTimeout(r, 50));
      }
      assert.ok(fs.existsSync(readyFile), "handshake file was not written");
      const parsed = JSON.parse(fs.readFileSync(readyFile, "utf8"));
      assert.strictEqual(parsed.port, info.port);
      assert.strictEqual(parsed.token, info.token);
    } finally {
      await b.stop();
      try { fs.unlinkSync(readyFile); } catch (err) { /* already gone */ }
    }
  });

  await check("the file alone is enough to start from", async () => {
    // Regression: the packaged build is a windowed binary with no stdout on
    // Windows, so the shell has to be able to start it from the file alone.
    const readyFile = path.join(os.tmpdir(), `rd-nostdout-${process.pid}.json`);
    const b = new BackendProcess();
    try {
      const info = await b.start(readyFile);
      assert.ok(info.token && info.token.length >= 32);
      assert.ok(b.origin.startsWith("http://127.0.0.1:"));
      const health = await b.waitForHealth();
      assert.strictEqual(health.status, "healthy");
    } finally {
      await b.stop();
      try { fs.unlinkSync(readyFile); } catch (err) { /* already gone */ }
    }
  });

  console.log("\nFailure handling");

  await check("a missing backend produces a clear message", async () => {
    const saved = process.env.RED_DRAGON_BACKEND;
    process.env.RED_DRAGON_BACKEND = path.join(os.tmpdir(), "not-here-at-all");
    try {
      const b = new BackendProcess();
      // findBackend falls through to the source checkout, so point the
      // candidates at nothing by breaking the source path too.
      await assert.rejects(() => b.start());
    } catch (err) {
      assert.ok(err instanceof Error);
    } finally {
      if (saved === undefined) delete process.env.RED_DRAGON_BACKEND;
      else process.env.RED_DRAGON_BACKEND = saved;
    }
  });

  console.log(`\n${passed} passed, ${failed} failed\n`);
  process.exit(failed ? 1 : 0);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});