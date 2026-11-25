import { copyFile, readFile, rm, writeFile } from "node:fs/promises";
import { constants } from "node:fs";
import { fileURLToPath } from "node:url";

const modulePath = fileURLToPath(new URL("../node_modules/@serenity-kit/opaque/esm/index.js", import.meta.url));
const backupPath = `${modulePath}.sparrow-original`;
const wasmPath = fileURLToPath(new URL("../node_modules/@serenity-kit/opaque/esm/opaque_bg.wasm", import.meta.url));
const source = await readFile(modulePath, "utf8");
const match = source.match(/function wasmData\(imports\)\{return _loadWasmModule\(0, null, '([^']+)'\)\}/);

if (!match) {
  throw new Error("Could not find the embedded OPAQUE WASM module in @serenity-kit/opaque.");
}

const wasm = Buffer.from(match[1], "base64");
if (wasm.length === 0) {
  throw new Error("The embedded OPAQUE WASM module was empty.");
}

let backupCreated = false;
let wasmCreated = false;

try {
  await copyFile(modulePath, backupPath, constants.COPYFILE_EXCL);
  backupCreated = true;
  await writeFile(wasmPath, wasm, { flag: "wx" });
  wasmCreated = true;

  const patchedSource = `import wasmModule from "./opaque_bg.wasm";\n${source.replace(match[0], "function wasmData(){return wasmModule}")}`;
  await writeFile(modulePath, patchedSource, "utf8");
} catch (error) {
  if (backupCreated) {
    await copyFile(backupPath, modulePath);
    await rm(backupPath);
  }
  if (wasmCreated) {
    await rm(wasmPath);
  }
  throw error;
}
