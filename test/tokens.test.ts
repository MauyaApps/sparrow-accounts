import test from "node:test";
import assert from "node:assert/strict";
import { b64uDecode, b64uEncode, utf8 } from "../src/bytes.ts";
import { ISSUER, TTL } from "../src/config.ts";
import { signAccess, loadSigningKey } from "../src/tokens.ts";
import { TokenError, verifyAccessToken } from "../src/verify.ts";
import { login, makeStand, register } from "./harness.ts";

const PW = "correct horse battery staple";
const nowSec = (ms: number) => Math.floor(ms / 1000);

async function signedIn(user = "alice") {
  const s = await makeStand();
  await register(s, user, PW);
  const { res } = await login(s, user, PW, { ua: "test-agent/1.0" });
  return { s, t: res.body as Record<string, any> };
}

test("access token verifies with public key from /v1/keys without server call", async () => {
  const { s, t } = await signedIn();
  const keys = await s.call("GET", "/v1/keys");
  const claims = verifyAccessToken(t.accessToken, b64uDecode(keys.body.publicKey), { issuer: keys.body.issuer, nowSec: nowSec(s.clock.ms) });
  assert.equal(claims.sub, t.userId);
  assert.equal(claims.sid, t.sessionId);
  assert.equal(claims.exp - claims.iat, TTL.accessSec);
});

test("forgeries rejected: modified payload, alg none, wrong key, wrong issuer, expired", async () => {
  const { s, t } = await signedIn();
  const pub = s.deps.signingKey.publicKey;
  const opts = { issuer: ISSUER, nowSec: nowSec(s.clock.ms) };
  const [h, p, sig] = (t.accessToken as string).split(".") as [string, string, string];

  const evil = { ...JSON.parse(new TextDecoder().decode(b64uDecode(p))), sub: "someone-else" };
  assert.throws(() => verifyAccessToken(`${h}.${b64uEncode(utf8(JSON.stringify(evil)))}.${sig}`, pub, opts), TokenError);

  const none = b64uEncode(utf8(JSON.stringify({ alg: "none", typ: "JWT" })));
  assert.throws(() => verifyAccessToken(`${none}.${p}.`, pub, opts), TokenError);
  assert.throws(() => verifyAccessToken(`${none}.${p}.${sig}`, pub, opts), TokenError);

  const other = loadSigningKey(b64uEncode(new Uint8Array(32).fill(7)));
  assert.throws(() => verifyAccessToken(t.accessToken, other.publicKey, opts), TokenError);
  assert.throws(() => verifyAccessToken(t.accessToken, pub, { ...opts, issuer: "https://evil.example" }), TokenError);
  assert.throws(() => verifyAccessToken(t.accessToken, pub, { ...opts, nowSec: opts.nowSec + TTL.accessSec + 60 }), TokenError);
  assert.throws(() => verifyAccessToken("a.b", pub, opts), TokenError);
  assert.throws(() => verifyAccessToken("x".repeat(2000), pub, opts), TokenError);
});

test("token signed with correct key but nonexistent session is rejected by API", async () => {
  const { s, t } = await signedIn();
  const forged = signAccess(s.deps.signingKey, {
    iss: ISSUER, sub: t.userId, sid: "0".repeat(32), iat: nowSec(s.clock.ms), exp: nowSec(s.clock.ms) + 600,
  });
  assert.equal((await s.call("GET", "/v1/me", undefined, { token: forged })).status, 401);
});

test("expired access token is rejected by API", async () => {
  const { s, t } = await signedIn();
  s.clock.ms += (TTL.accessSec + 120) * 1000;
  assert.equal((await s.call("GET", "/v1/me", undefined, { token: t.accessToken })).status, 401);
});

test("refresh token is stored only as SHA-256 hash", async () => {
  const { s, t } = await signedIn();
  const secret = (t.refreshToken as string).split(".")[1]!;
  const row = s.raw.prepare("SELECT * FROM sessions").get() as Record<string, string>;
  assert.match(row.refresh_hash!, /^[0-9a-f]{64}$/);
  assert.ok(!JSON.stringify(row).includes(secret));
  assert.equal(row.user_agent, "test-agent/1.0");
});

test("refresh rotates; replay of old token revokes session", async () => {
  const { s, t } = await signedIn();
  const r1 = await s.call("POST", "/v1/token/refresh", { refreshToken: t.refreshToken });
  assert.equal(r1.status, 200);
  assert.notEqual(r1.body.refreshToken, t.refreshToken);
  assert.equal(r1.body.sessionId, t.sessionId);
  assert.equal((await s.call("GET", "/v1/me", undefined, { token: r1.body.accessToken })).status, 200);

  // Replay means the token may have been stolen, so revoke the session.
  const stolen = await s.call("POST", "/v1/token/refresh", { refreshToken: t.refreshToken });
  assert.equal(stolen.status, 401);
  assert.equal((await s.call("POST", "/v1/token/refresh", { refreshToken: r1.body.refreshToken })).status, 401);
  assert.equal((await s.call("GET", "/v1/me", undefined, { token: r1.body.accessToken })).status, 401);
});

test("parallel refresh with same token succeeds exactly once", async () => {
  const { s, t } = await signedIn();
  const rs = await Promise.all([1, 2, 3].map(() => s.call("POST", "/v1/token/refresh", { refreshToken: t.refreshToken })));
  assert.equal(rs.filter((r) => r.status === 200).length, 1);
});

test("refresh sliding window is 30 days with an absolute 180-day cap", async () => {
  const { s, t } = await signedIn();
  let refreshToken = t.refreshToken as string;
  const created = nowSec(s.clock.ms);
  for (let i = 0; i < 8; i++) {
    s.clock.ms += 25 * 24 * 3600 * 1000;
    const r = await s.call("POST", "/v1/token/refresh", { refreshToken });
    if (r.status !== 200) break;
    refreshToken = r.body.refreshToken;
    assert.ok(r.body.refreshExpiresAt <= created + TTL.refreshMaxSec);
  }
  s.clock.ms += (TTL.refreshMaxSec + 1) * 1000;
  assert.equal((await s.call("POST", "/v1/token/refresh", { refreshToken })).status, 401);
});

test("expired session refresh fails", async () => {
  const { s, t } = await signedIn();
  s.clock.ms += (TTL.refreshSec + 10) * 1000;
  assert.equal((await s.call("POST", "/v1/token/refresh", { refreshToken: t.refreshToken })).status, 401);
});

test("logout revokes session while other sessions remain active", async () => {
  const { s, t } = await signedIn();
  const other = (await login(s, "alice", PW)).res.body;
  assert.equal((await s.call("POST", "/v1/logout", undefined, { token: t.accessToken })).status, 200);
  assert.equal((await s.call("GET", "/v1/me", undefined, { token: t.accessToken })).status, 401);
  assert.equal((await s.call("POST", "/v1/token/refresh", { refreshToken: t.refreshToken })).status, 401);
  assert.equal((await s.call("GET", "/v1/me", undefined, { token: other.accessToken })).status, 200);
});

test("missing token returns UNAUTHENTICATED message for radio clients", async () => {
  const s = await makeStand();
  const r = await s.call("GET", "/v1/me");
  assert.equal(r.status, 401);
  assert.equal(r.body.error.message, "Sign in with your Sparrow account");
});
