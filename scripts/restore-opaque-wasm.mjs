import { readFile, rm, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

const modulePath = fileURLToPath(new URL("../node_modules/@serenity-kit/opaque/esm/index.js", import.meta.url));
const backupPath = `${modulePath}.sparrow-original`;
const wasmPath = fileURLToPath(new URL("../node_modules/@serenity-kit/opaque/esm/opaque_bg.wasm", import.meta.url));

let original;
try {
  original = await readFile(backupPath);
} catch (error) {
  if (error.code === "ENOENT") {
    process.exit(0);
  }
  throw error;
}

await writeFile(modulePath, original);
await rm(backupPath);
await rm(wasmPath, { force: true });
