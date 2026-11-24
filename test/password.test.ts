import test from "node:test";
import assert from "node:assert/strict";
import { confirmPassword, login, makeStand, register, setNewPassword } from "./harness.ts";

const OLD = "old password for alice";
const NEW = "brand new password 42";

async function twoSessions() {
  const s = await makeStand();
  await register(s, "alice", OLD);
  const a = (await login(s, "alice", OLD)).res.body;
  const b = (await login(s, "alice", OLD)).res.body;
  return { s, a, b };
}

test("password change: old password fails, new works, other sessions revoked, current session remains", async () => {
  const { s, a, b } = await twoSessions();
  const reauth = await confirmPassword(s, a.accessToken, OLD);
  assert.equal(reauth.status, 200);
  const done = await setNewPassword(s, a.accessToken, reauth.body.reauthToken, NEW);
  assert.equal(done.status, 200);
  assert.equal(done.body.otherSessionsRevoked, 1);

  assert.equal((await s.call("GET", "/v1/me", undefined, { token: a.accessToken })).status, 200);
  assert.equal((await s.call("GET", "/v1/me", undefined, { token: b.accessToken })).status, 401);
  assert.equal((await login(s, "alice", OLD)).res.status, 401);
  assert.equal((await login(s, "alice", NEW)).res.status, 200);
});

test("wrong current password does not issue a reauth token", async () => {
  const { s, a } = await twoSessions();
  const r = await confirmPassword(s, a.accessToken, "not my password");
  assert.equal(r.status, 401);
  assert.equal(r.body.reauthToken, undefined);
});

test("password cannot be changed without reauth token; token is single-use", async () => {
  const { s, a } = await twoSessions();
  const fake = "A".repeat(43);
  assert.equal((await setNewPassword(s, a.accessToken, fake, NEW)).status, 401);

  const reauth = await confirmPassword(s, a.accessToken, OLD);
  assert.equal((await setNewPassword(s, a.accessToken, reauth.body.reauthToken, NEW)).status, 200);
  assert.equal((await setNewPassword(s, a.accessToken, reauth.body.reauthToken, "third password 777")).status, 401);
  assert.equal((await login(s, "alice", NEW)).res.status, 200);
});

test("reauth token is bound to the user", async () => {
  const { s, a } = await twoSessions();
  await register(s, "bobby", "bobs password 99");
  const bob = (await login(s, "bobby", "bobs password 99")).res.body;
  const reauth = await confirmPassword(s, a.accessToken, OLD);
  assert.equal((await setNewPassword(s, bob.accessToken, reauth.body.reauthToken, NEW)).status, 401);
});

test("reauth token expires after 2 minutes", async () => {
  const { s, a } = await twoSessions();
  const reauth = await confirmPassword(s, a.accessToken, OLD);
  s.clock.ms += 121_000;
  assert.equal((await setNewPassword(s, a.accessToken, reauth.body.reauthToken, NEW)).status, 401);
});

test("all password-change steps require Bearer", async () => {
  const s = await makeStand();
  for (const path of ["/v1/password/verify/start", "/v1/password/verify/finish", "/v1/password/start", "/v1/password/finish"]) {
    assert.equal((await s.call("POST", path, {})).status, 401, path);
  }
});
