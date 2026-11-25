import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const scriptPath = (name) => fileURLToPath(new URL(`./${name}`, import.meta.url));
const wranglerPath = fileURLToPath(new URL("../node_modules/wrangler/bin/wrangler.js", import.meta.url));
const run = (command, args) => spawnSync(command, args, { stdio: "inherit" });

let exitCode = 1;
let prepareError;

try {
  const prepared = run(process.execPath, [scriptPath("prepare-opaque-wasm.mjs")]);
  if (prepared.error) {
    throw prepared.error;
  }
  if (prepared.status !== 0) {
    exitCode = prepared.status ?? 1;
  } else {
    const deployed = run(process.execPath, [wranglerPath, "deploy", ...process.argv.slice(2)]);
    if (deployed.error) {
      throw deployed.error;
    }
    exitCode = deployed.status ?? 1;
  }
} catch (error) {
  prepareError = error;
} finally {
  const restored = run(process.execPath, [scriptPath("restore-opaque-wasm.mjs")]);
  if (restored.error) {
    throw restored.error;
  }
  if (restored.status !== 0) {
    exitCode = restored.status ?? 1;
  }
}

if (prepareError) {
  throw prepareError;
}

process.exitCode = exitCode;
