import { randomBytes } from "node:crypto";
import { access, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import * as opaque from "../src/opaque.js";
import { b64uEncode } from "../src/bytes.ts";

const varsPath = resolve(".dev.vars");
try {
  await access(varsPath);
  console.log(".dev.vars already exists; left unchanged. Check that it has the local admin variables described in README.md.");
} catch {
  await opaque.ready;
  const contents = [
    `OPAQUE_SERVER_SETUP=${opaque.server.createSetup()}`,
    `TOKEN_SIGNING_KEY=${b64uEncode(new Uint8Array(randomBytes(32)))}`,
    "LOCAL_ADMIN_ENABLED=true",
    `LOCAL_ADMIN_PASSWORD=${b64uEncode(new Uint8Array(randomBytes(24)))}`,
    `LOCAL_ADMIN_SESSION_SECRET=${b64uEncode(new Uint8Array(randomBytes(32)))}`,
    "LOCAL_ADMIN_ORIGIN=http://127.0.0.1:5173",
    "",
  ].join("\n");
  await writeFile(varsPath, contents, { flag: "wx", mode: 0o600 });
  console.log("Created ignored .dev.vars with fresh local secrets. Open that file locally to copy the admin password; do not share it.");
}
