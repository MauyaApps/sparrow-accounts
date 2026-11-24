import test from "node:test";
import assert from "node:assert/strict";
import * as opaque from "../src/opaque.js";
import { login, makeStand, register } from "./harness.ts";

const PW = "correct horse battery staple";

test("registration and login issue tokens and derive matching client/server session keys", async () => {
  const s = await makeStand();
  assert.equal((await register(s, "alice", PW)).status, 200);
  const { res, clientKey } = await login(s, "alice", PW);
  assert.equal(res.status, 200);
  assert.ok(clientKey);
  assert.equal(s.serverSessionKeys.at(-1), clientKey);
  const me = await s.call("GET", "/v1/me", undefined, { token: res.body.accessToken });
  assert.equal(me.status, 200);
  assert.equal(me.body.username, "alice");
});

test("usernames are case-insensitive; a taken name returns USERNAME_TAKEN", async () => {
  const s = await makeStand();
  assert.equal((await register(s, "Alice", PW)).status, 200);
  assert.equal((await login(s, "ALICE", PW)).res.status, 200);
  const dup = await register(s, "alice", "another password 123");
  assert.equal(dup.status, 409);
  assert.equal(dup.body.error.code, "USERNAME_TAKEN");
});

test("wrong password and nonexistent user are indistinguishable", async () => {
  const s = await makeStand();
  await register(s, "alice", PW);
  const wrong = (await login(s, "alice", "wrong password")).res;
  const ghost = (await login(s, "nobody-here", PW)).res;
  assert.equal(wrong.status, 401);
  assert.equal(ghost.status, 401);
  assert.deepEqual(wrong.body, ghost.body);
  assert.equal(wrong.body.error.code, "UNAUTHENTICATED");
});

test("login start response has the same shape for a nonexistent username", async () => {
  const s = await makeStand();
  await register(s, "alice", PW);
  const c = opaque.client.startLogin({ password: PW });
  const real = await s.call("POST", "/v1/login/start", { username: "alice", startLoginRequest: c.startLoginRequest });
  const fake = await s.call("POST", "/v1/login/start", { username: "ghost-user", startLoginRequest: c.startLoginRequest });
  assert.deepEqual(Object.keys(real.body).sort(), Object.keys(fake.body).sort());
  assert.equal(real.body.loginResponse.length, fake.body.loginResponse.length);
});

test("login attempt is single-use and expires after 60 seconds", async () => {
  const s = await makeStand();
  await register(s, "alice", PW);

  const c = opaque.client.startLogin({ password: PW });
  const a = await s.call("POST", "/v1/login/start", { username: "alice", startLoginRequest: c.startLoginRequest });
  const f = opaque.client.finishLogin({ clientLoginState: c.clientLoginState, loginResponse: a.body.loginResponse, password: PW })!;
  const ok = await s.call("POST", "/v1/login/finish", { attemptId: a.body.attemptId, finishLoginRequest: f.finishLoginRequest });
  assert.equal(ok.status, 200);
  const replay = await s.call("POST", "/v1/login/finish", { attemptId: a.body.attemptId, finishLoginRequest: f.finishLoginRequest });
  assert.equal(replay.status, 401);

  const c2 = opaque.client.startLogin({ password: PW });
  const a2 = await s.call("POST", "/v1/login/start", { username: "alice", startLoginRequest: c2.startLoginRequest });
  const f2 = opaque.client.finishLogin({ clientLoginState: c2.clientLoginState, loginResponse: a2.body.loginResponse, password: PW })!;
  s.clock.ms += 61_000;
  const late = await s.call("POST", "/v1/login/finish", { attemptId: a2.body.attemptId, finishLoginRequest: f2.finishLoginRequest });
  assert.equal(late.status, 401);
});

test("validation rejects bad and reserved names, extra fields, invalid JSON, and oversized bodies", async () => {
  const s = await makeStand();
  const c = opaque.client.startRegistration({ password: PW });
  const req = c.registrationRequest;
  for (const username of ["ab", "a".repeat(40), "bad name", "-lead", "dou..ble", "админ", "admin"]) {
    const r = await s.call("POST", "/v1/register/start", { username, registrationRequest: req });
    assert.equal(r.status, 400, username);
    assert.equal(r.body.error.code, "BAD_USER_INPUT");
  }
  assert.equal((await s.call("POST", "/v1/register/start", { username: "bob", registrationRequest: req, extra: 1 })).status, 400);
  assert.equal((await s.call("POST", "/v1/register/start", undefined, { rawBody: "not json" })).status, 400);
  assert.equal((await s.call("POST", "/v1/register/start", undefined, { rawBody: "[]" })).status, 400);
  assert.equal((await s.call("POST", "/v1/register/start", undefined, { rawBody: "x".repeat(20_000) })).status, 400);
  assert.equal((await s.call("POST", "/v1/register/start", { username: "bob", registrationRequest: "has spaces!" })).status, 400);
});

test("suspended accounts cannot login and existing sessions are rejected", async () => {
  const s = await makeStand();
  await register(s, "alice", PW);
  const { res } = await login(s, "alice", PW);
  s.raw.exec("UPDATE users SET status = 'suspended' WHERE username = 'alice'");
  assert.equal((await s.call("GET", "/v1/me", undefined, { token: res.body.accessToken })).status, 401);
  assert.equal((await s.call("POST", "/v1/token/refresh", { refreshToken: res.body.refreshToken })).status, 401);
  const again = await login(s, "alice", PW);
  assert.equal(again.res.status, 403);
  assert.equal(again.res.body.error.code, "FORBIDDEN");
});

test("unknown route and health", async () => {
  const s = await makeStand();
  assert.equal((await s.call("GET", "/nope")).status, 404);
  assert.equal((await s.call("GET", "/health")).body.ok, true);
});
