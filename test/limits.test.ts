import test from "node:test";
import assert from "node:assert/strict";
import * as opaque from "../src/opaque.js";
import { LIMITS } from "../src/config.ts";
import { login, makeStand, register } from "./harness.ts";

const startReq = () => opaque.client.startLogin({ password: "whatever password" }).startLoginRequest;

test("per-user limit: 11th attempt in window is RATE_LIMITED with Retry-After; window resets", async () => {
  const s = await makeStand();
  const n = LIMITS.loginUser.limit;
  for (let i = 0; i < n; i++) {
    const r = await s.call("POST", "/v1/login/start", { username: "victim", startLoginRequest: startReq() }, { ip: `198.51.100.${i + 1}` });
    assert.equal(r.status, 200, `attempt ${i + 1}`);
  }
  const blocked = await s.call("POST", "/v1/login/start", { username: "victim", startLoginRequest: startReq() }, { ip: "198.51.100.200" });
  assert.equal(blocked.status, 429);
  assert.equal(blocked.body.error.code, "RATE_LIMITED");
  assert.ok(Number(blocked.headers.get("retry-after")) > 0);

  // Another user from a different IP is unaffected.
  assert.equal((await s.call("POST", "/v1/login/start", { username: "someone", startLoginRequest: startReq() }, { ip: "198.51.100.201" })).status, 200);

  s.clock.ms += LIMITS.loginUser.windowMs + 1000;
  assert.equal((await s.call("POST", "/v1/login/start", { username: "victim", startLoginRequest: startReq() }, { ip: "198.51.100.202" })).status, 200);
});

test("IP limit for attempts against different names", async () => {
  const s = await makeStand();
  const n = LIMITS.loginIp.limit;
  for (let i = 0; i < n; i++) {
    const r = await s.call("POST", "/v1/login/start", { username: `user-${i}`, startLoginRequest: startReq() }, { ip: "192.0.2.50" });
    assert.equal(r.status, 200, `attempt ${i + 1}`);
  }
  const blocked = await s.call("POST", "/v1/login/start", { username: "user-next", startLoginRequest: startReq() }, { ip: "192.0.2.50" });
  assert.equal(blocked.status, 429);
});

test("registration limit per IP", async () => {
  const s = await makeStand();
  const req = opaque.client.startRegistration({ password: "pw for limits" }).registrationRequest;
  const n = LIMITS.registerIp.limit;
  for (let i = 0; i < n; i++) {
    assert.equal((await s.call("POST", "/v1/register/start", { username: `newuser-${i}`, registrationRequest: req }, { ip: "192.0.2.60" })).status, 200);
  }
  assert.equal((await s.call("POST", "/v1/register/start", { username: "newuser-x", registrationRequest: req }, { ip: "192.0.2.60" })).status, 429);
});

test("normal login stays within limits", async () => {
  const s = await makeStand();
  await register(s, "alice", "a fine password 1");
  for (let i = 0; i < 3; i++) assert.equal((await login(s, "alice", "a fine password 1")).res.status, 200);
});
