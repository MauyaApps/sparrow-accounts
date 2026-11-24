import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { ISSUER, TTL } from "../src/config.ts";
import { userIdFromRequest } from "../integration/radio/auth.ts";
import { login, makeStand, register } from "./harness.ts";

test("radio integration verify.ts is identical to source", () => {
  const a = readFileSync(new URL("../src/verify.ts", import.meta.url), "utf8");
  const b = readFileSync(new URL("../integration/radio/verify.ts", import.meta.url), "utf8");
  assert.equal(a, b);
});

async function radioEnv() {
  const s = await makeStand();
  await register(s, "alice", "radio listener pw 1");
  const t = (await login(s, "alice", "radio listener pw 1")).res.body;
  const keys = (await s.call("GET", "/v1/keys")).body;
  const env = { ACCOUNT_PUBLIC_KEY: keys.publicKey, ACCOUNT_ISSUER: keys.issuer, ALLOW_DEV_AUTH: "false" };
  const req = (token?: string, extra: Record<string, string> = {}) =>
    new Request("https://radio.test/graphql", { method: "POST", headers: { ...(token ? { authorization: `Bearer ${token}` } : {}), ...extra } });
  return { s, t, env, req };
}

test("radio gets context.userId from account token", async () => {
  const { s, t, env, req } = await radioEnv();
  assert.equal(userIdFromRequest(req(t.accessToken), env, s.clock.ms), t.userId);
});

test("missing, invalid, expired token or wrong issuer returns null", async () => {
  const { s, t, env, req } = await radioEnv();
  assert.equal(userIdFromRequest(req(), env, s.clock.ms), null);
  assert.equal(userIdFromRequest(req("garbage.token.value"), env, s.clock.ms), null);
  assert.equal(userIdFromRequest(req(t.accessToken), env, s.clock.ms + (TTL.accessSec + 120) * 1000), null);
  assert.equal(userIdFromRequest(req(t.accessToken), { ...env, ACCOUNT_ISSUER: "https://evil.example" }, s.clock.ms), null);
  assert.equal(env.ACCOUNT_ISSUER, ISSUER);
});

test("x-sparrow-user works only when ALLOW_DEV_AUTH=true", async () => {
  const { s, env, req } = await radioEnv();
  assert.equal(userIdFromRequest(req(undefined, { "x-sparrow-user": "dev-user" }), env, s.clock.ms), null);
  assert.equal(userIdFromRequest(req(undefined, { "x-sparrow-user": "dev-user" }), { ...env, ALLOW_DEV_AUTH: "true" }, s.clock.ms), "dev-user");
});

test("spoofed x-sparrow-user does not override token user", async () => {
  const { s, t, env, req } = await radioEnv();
  assert.equal(userIdFromRequest(req(t.accessToken, { "x-sparrow-user": "admin" }), { ...env, ALLOW_DEV_AUTH: "true" }, s.clock.ms), t.userId);
});
