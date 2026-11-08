// Lineage behavior monitor. npm preloads it into every script it runs (install hooks, tests),
// through NPM_CONFIG_NODE_OPTIONS. It records what dependencies *do*: credential files read,
// secret env vars read, processes started, network connections. Nobody has to read their code.
// shortcut: telemetry from inside the sandbox, so a package can tamper with it; enforcement is
// the stand-in key plus egress, outside the sandbox (DECISIONS D34).
"use strict";

const fs = require("fs");
const childProcess = require("child_process");
const http = require("http");
const https = require("https");
const net = require("net");

const spawnSyncOriginal = childProcess.spawnSync;
const realEnv = process.env;
const HOOK_TOKEN = realEnv.LINEAGE_HOOK_TOKEN;
const HOOK_URL = realEnv.LINEAGE_HOOK_URL || "http://control:8000/hooks/agent-output";
const SECRET_FILE = /(^|[\\/])(\.env(\.[^\\/]*)?|[^\\/]*\.pem|id_rsa[^\\/]*|\.npmrc|\.netrc|credentials)$/;
const SECRET_ENV = /TOKEN|SECRET|KEY|PASSWORD/i;
const PACKAGE_FRAME = /node_modules[\\/]((?:@[^\\/]+[\\/])?[^\\/]+)[\\/]/;
const seen = new Set();
let busy = false;

function who() {
  for (const line of new Error().stack.split("\n").slice(1)) {
    if (line.includes("watch.js")) continue;
    const match = PACKAGE_FRAME.exec(line);
    if (match) return match[1].replace("\\", "/");
  }
  // An install hook runs with its own package as the working directory.
  if (realEnv.npm_lifecycle_event && PACKAGE_FRAME.test(process.cwd() + "/")) return realEnv.npm_package_name || null;
  return null;
}

function note(op, target) {
  if (busy) return;
  const pkg = who();
  if (!pkg) return;
  const key = `${pkg}|${op}|${target}`;
  if (seen.has(key)) return;
  seen.add(key);
  const event = { kind: "pkg", package: pkg, phase: realEnv.npm_lifecycle_event || "runtime", op, target: String(target).slice(0, 300) };
  if (!HOOK_TOKEN) return;
  busy = true;
  try {
    // Synchronous on purpose: the report lands before the package's next step (often the exfil).
    spawnSyncOriginal(
      "curl",
      ["-s", "-m", "2", "--noproxy", "*", "-H", "Content-Type: application/json",
        "-H", `X-Lineage-Hook-Token: ${HOOK_TOKEN}`, "--data-binary", "@-", HOOK_URL],
      { input: JSON.stringify(event), env: { PATH: realEnv.PATH }, stdio: ["pipe", "ignore", "ignore"] },
    );
  } catch {
    // Reporting must never break the package's own behavior.
  } finally {
    busy = false;
  }
}

function wrap(obj, name, describe) {
  const original = obj[name];
  if (typeof original !== "function") return;
  obj[name] = function (...args) {
    try {
      const target = describe(...args);
      if (target) note(...target);
    } catch {}
    // Spawning reads every env var; that's not the package reading secrets.
    const wasBusy = busy;
    busy = true;
    try {
      return original.apply(this, args);
    } finally {
      busy = wasBusy;
    }
  };
}

const fileTarget = (file) => (typeof file === "string" && SECRET_FILE.test(file) ? ["file", file] : null);
for (const name of ["readFileSync", "readFile", "openSync", "open", "createReadStream"]) wrap(fs, name, fileTarget);
wrap(fs.promises, "readFile", fileTarget);

const commandTarget = (command, args) => ["spawn", [command, ...(Array.isArray(args) ? args : [])].join(" ")];
for (const name of ["spawn", "spawnSync", "exec", "execSync", "execFile", "execFileSync", "fork"]) {
  wrap(childProcess, name, commandTarget);
}

const urlTarget = (input) => {
  if (typeof input === "string" || input instanceof URL) return ["net", new URL(input).host];
  return ["net", (input && (input.host || input.hostname)) || "?"];
};
for (const mod of [http, https]) for (const name of ["request", "get"]) wrap(mod, name, urlTarget);
const socketTarget = (options, host) =>
  ["net", typeof options === "object" ? `${options.host || "localhost"}:${options.port}` : `${host || "localhost"}:${options}`];
wrap(net, "connect", socketTarget);
wrap(net, "createConnection", socketTarget);

process.env = new Proxy(realEnv, {
  get(target, key) {
    if (typeof key === "string" && SECRET_ENV.test(key) && !/^(npm_|LINEAGE_)/.test(key)) note("env", key);
    return Reflect.get(target, key);
  },
});
