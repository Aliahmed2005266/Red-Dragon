'use strict';

/**
 * Locates the Python backend that does the actual scanning.
 *
 * In a packaged install the backend is a PyInstaller bundle shipped as an
 * Electron extraResource. In development it is the source tree run through the
 * system Python, so the usual edit-and-reload loop still works.
 *
 * The backend prints one machine-readable line on stdout once it is listening.
 * That line carries the port and the per-launch token, which is how the shell
 * learns where to point the window. We never guess a port, because a fixed port
 * collides whenever two copies of the app run at once.
 */

const path = require("path");
const fs = require("fs");
const http = require("http");
const { spawn, spawnSync } = require("child_process");
const { EventEmitter } = require("events");

const READY_PREFIX = "REDDRAGON_READY ";
const STARTUP_TIMEOUT_MS = 90000;

/** Candidate backend locations, in priority order. */
function backendCandidates() {
  const candidates = [];

  // Escape hatch for development and for unusual installs
  if (process.env.RED_DRAGON_BACKEND) {
    candidates.push(process.env.RED_DRAGON_BACKEND);
  }

  // Packaged: extraResources land under resources/backend
  const resourceRoot = process.resourcesPath || "";
  if (resourceRoot) {
    const dir = path.join(resourceRoot, "backend");
    candidates.push(
      path.join(dir, "red-dragon-backend"),
      path.join(dir, "red-dragon-backend.exe")
    );
  }

  // Development: the source checkout
  candidates.push(path.join(__dirname, "..", "backend", "desktop.py"));

  return candidates;
}

function findBackend() {
  for (const candidate of backendCandidates()) {
    try {
      if (candidate && fs.existsSync(candidate)) return candidate;
    } catch (err) {
      /* unreadable path, keep looking */
    }
  }
  return null;
}

/** Whether the path is runnable directly or needs a Python interpreter. */
function needsPython(target) {
  return target.endsWith(".py");
}

/**
 * Look for a Python that can actually import the backend's dependencies.
 *
 * Checking only that the file exists is not enough: on Windows the `py`
 * launcher may resolve to an interpreter without the libraries installed, and
 * picking it produces a confusing ModuleNotFoundError from the child instead
 * of a clear message here. So each candidate is asked to import Flask.
 */
function findPython() {
  const candidates =
    process.platform === "win32"
      ? ["python", "python3", "py"]
      : ["python3", "python"];

  const probe =
    "import sys;import flask,requests;sys.exit(0 if sys.version_info>=(3,8) else 1)";

  // Try the bare names first so PATH and any active virtualenv win.
  // shell:false on purpose: with shell:true the OS re-splits the probe on
  // spaces and truncates it at the first one.
  for (const name of candidates) {
    const r = spawnSync(name, ["-c", probe], { encoding: "utf8" });
    if (!r.error && r.status === 0) return name;
  }

  // Fall back to scanning PATH for an absolute path.
  const dirs = (process.env.PATH || "").split(path.delimiter);
  for (const dir of dirs) {
    if (!dir) continue;
    for (const name of candidates) {
      const exe = process.platform === "win32" ? `${name}.exe` : name;
      const full = path.join(dir, exe);
      try {
        if (!fs.existsSync(full)) continue;
      } catch (err) {
        continue;
      }
      const r = spawnSync(full, ["-c", probe], { encoding: "utf8" });
      if (!r.error && r.status === 0) return full;
    }
  }

  return null;
}

class BackendProcess extends EventEmitter {
  constructor() {
    super();
    this.proc = null;
    this.port = null;
    this.token = null;
    this.exited = false;
  }

  get origin() {
    return this.port ? `http://127.0.0.1:${this.port}` : null;
  }

  /**
   * Start the backend and resolve once it reports ready.
   * Rejects with a message written for a human, not a stack trace.
   */
  start(readyFile) {
    const target = findBackend();
    if (!target) {
      return Promise.reject(
        new Error(
          "The scanner backend could not be found.\n\nLooked in:\n  " +
            backendCandidates().join("\n  ")
        )
      );
    }

    let command = target;
    const args = [];
    if (needsPython(target)) {
      command = process.env.RED_DRAGON_PYTHON || findPython();
      if (!command) {
        return Promise.reject(
          new Error(
            "Python 3 was not found. Install Python 3.8 or newer, or use the " +
              "packaged installer which bundles everything it needs."
          )
        );
      }
      args.push(target);
    }

    // The packaged engine is a windowed binary, so on Windows it has no stdout
    // at all. The handshake therefore goes through a file, with stdout kept as
    // a fallback for the development case.
    if (readyFile) {
      try {
        fs.unlinkSync(readyFile);
      } catch (err) {
        /* not there, which is the normal case */
      }
      args.push("--ready-file", readyFile);
    }

    return new Promise((resolve, reject) => {
      let settled = false;
      const finish = (err, info) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        if (err) reject(err);
        else resolve(info);
      };

      const timer = setTimeout(() => {
        finish(
          new Error(
            `The scanner backend did not start within ${
              STARTUP_TIMEOUT_MS / 1000
            } seconds. Run 'npm run backend:debug' to see why.`
          )
        );
      }, STARTUP_TIMEOUT_MS);

      let child;
      try {
        child = spawn(command, args, {
          // Not detached: the backend must die with the app, and on Windows a
          // detached child would outlive it.
          windowsHide: true,
          stdio: ["ignore", "pipe", "pipe"],
          env: {
            ...process.env,
            PYTHONUNBUFFERED: "1",
            PYTHONIOENCODING: "utf-8",
          },
        });
      } catch (err) {
        finish(
          new Error(`Could not launch the scanner backend: ${err.message}`)
        );
        return;
      }

      this.proc = child;

      let stdoutBuffer = "";
      let readyFromStdout = false;

      const onHandshake = (line) => {
        try {
          const info = JSON.parse(line);
          this.port = info.port;
          this.token = info.token;
          this.emit("ready", info);
          finish(null, info);
          return true;
        } catch (err) {
          finish(
            new Error("The scanner backend sent an unreadable start-up message.")
          );
          return true;
        }
      };

      child.stdout.setEncoding("utf8");
      child.stdout.on("data", (chunk) => {
        stdoutBuffer += chunk;
        if (readyFromStdout) return;
        // Banner lines can precede the ready marker, so search the whole
        // buffer for the marker rather than only matching at a line end.
        const at = stdoutBuffer.indexOf(READY_PREFIX);
        if (at === -1) return;
        const end = stdoutBuffer.indexOf("\n", at);
        onHandshake(
          stdoutBuffer.slice(at + READY_PREFIX.length, end === -1 ? undefined : end)
        );
        readyFromStdout = true;
      });

      // The packaged build has no stdout, so watch the handshake file. Polling
      // is used rather than fs.watch because the file is written by a separate
      // process and inotify on network or synced folders is unreliable.
      if (readyFile) {
        const poll = setInterval(() => {
          let raw;
          try {
            raw = fs.readFileSync(readyFile, "utf8");
          } catch (err) {
            return; // not written yet
          }
          clearInterval(poll);
          if (!raw.trim()) return;
          onHandshake(raw.trim());
        }, 120);
        // Do not keep the event loop alive just to poll
        if (poll.unref) poll.unref();
      }

      child.stderr.setEncoding("utf8");
      child.stderr.on("data", (chunk) => this.emit("stderr", chunk));

      child.on("error", (err) => {
        this.emit("exit", { code: null, signal: null, error: err });
        finish(
          new Error(`Could not launch the scanner backend: ${err.message}`)
        );
      });

      child.on("exit", (code, signal) => {
        this.exited = true;
        this.emit("exit", { code, signal });
        finish(
          new Error(
            `The scanner backend stopped unexpectedly (code ${code}).` +
              (signal ? ` Signal: ${signal}.` : "")
          )
        );
      });
    });
  }

  /**
   * Poll the health endpoint until it answers, or give up.
   * The token is required, so this doubles as a check that the guard works.
   */
  async waitForHealth(attempts = 40) {
    if (!this.port) throw new Error("Backend has no port yet");
    for (let i = 0; i < attempts; i += 1) {
      try {
        const body = await this.health();
        if (body) return body;
      } catch (err) {
        // Not listening yet, keep trying.
      }
      await new Promise((r) => setTimeout(r, 250));
    }
    throw new Error("The scanner backend did not become healthy in time.");
  }

  /** One health request, carrying the launch token. */
  health() {
    return new Promise((resolve, reject) => {
      if (!this.port) {
        reject(new Error("Backend has no port yet"));
        return;
      }
      const req = http.request(
        {
          host: "127.0.0.1",
          port: this.port,
          path: "/api/health",
          method: "GET",
          headers: { "X-RD-Token": this.token || "" },
          timeout: 4000,
        },
        (res) => {
          let data = "";
          res.setEncoding("utf8");
          res.on("data", (c) => {
            data += c;
          });
          res.on("end", () => {
            if (res.statusCode !== 200) {
              reject(new Error(`health returned ${res.statusCode}`));
              return;
            }
            try {
              resolve(JSON.parse(data));
            } catch (err) {
              reject(err);
            }
          });
        }
      );
      req.on("error", reject);
      req.on("timeout", () => req.destroy(new Error("health check timed out")));
      req.end();
    });
  }

  /**
   * Stop the backend, escalating to SIGKILL if it ignores the polite ask.
   * Without the escalation a wedged scan would leave the port held and the
   * next launch would fail to start.
   */
  async stop() {
    const child = this.proc;
    if (!child || this.exited) return;

    const closed = new Promise((resolve) => child.once("exit", resolve));
    try {
      child.kill("SIGTERM");
    } catch (err) {
      /* already gone */
    }

    const timedOut = await Promise.race([
      closed.then(() => false),
      new Promise((r) => setTimeout(() => r(true), 5000)),
    ]);

    if (timedOut) {
      try {
        child.kill("SIGKILL");
      } catch (err) {
        /* already gone */
      }
    }
  }
}

module.exports = {
  BackendProcess,
  READY_PREFIX,
  STARTUP_TIMEOUT_MS,
  backendCandidates,
  findBackend,
  findPython,
  needsPython,
};

