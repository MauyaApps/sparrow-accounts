import test from "node:test";
import assert from "node:assert/strict";
import { ALLOWED_ORIGINS, hostFor, ISSUER } from "../src/config.ts";

test("workers.dev: host = <worker>.<domain>", () => {
  assert.equal(hostFor("radio", "sparrownet.workers.dev"), "sparrow-radio-api.sparrownet.workers.dev");
});
test("custom domain: host = <product>.<domain>, no code changes needed", () => {
  assert.equal(hostFor("account", "sparrownet.app"), "account.sparrownet.app");
  assert.equal(hostFor("pass", "sparrownet.app"), "pass.sparrownet.app");
});
test("issuer and CORS are derived from one constant", () => {
  assert.equal(ISSUER, "https://sparrow-account-api.sparrownet.workers.dev");
  assert.ok(ISSUER.startsWith("https://"));
  assert.ok(ALLOWED_ORIGINS.includes(ISSUER));
  assert.equal(ALLOWED_ORIGINS.length, 5);
});
