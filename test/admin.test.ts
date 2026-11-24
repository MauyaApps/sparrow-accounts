import test from "node:test";
import assert from "node:assert/strict";
import { handle } from "../src/http.ts";
import { login, makeStand, register } from "./harness.ts";

const ADMIN = {
  LOCAL_ADMIN_ENABLED: "true",
  LOCAL_ADMIN_PASSWORD: "local-admin-password-123",
  LOCAL_ADMIN_SESSION_SECRET: "local-admin-session-secret-at-least-32",
  LOCAL_ADMIN_ORIGIN: "http://127.0.0.1:5173",
};

interface AdminBody extends Record<string, unknown> {
  accounts?: Array<Record<string, unknown>>;
  account?: Record<string, unknown>;
  sessions?: Array<Record<string, unknown>>;
  revoked?: number;
}

async function adminCall(
  stand: Awaited<ReturnType<typeof makeStand>>,
  method: string,
  path: string,
  body?: unknown,
  cookie?: string,
  url = `http://127.0.0.1:8787${path}`,
) {
  const headers: Record<string, string> = { origin: ADMIN.LOCAL_ADMIN_ORIGIN };
  if (body !== undefined) headers["content-type"] = "application/json";
  if (cookie) headers.cookie = cookie;
  const request = new Request(url, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
  const response = await handle(request, stand.deps, "127.0.0.1", ADMIN);
  const text = await response.text();
  return { status: response.status, body: text ? JSON.parse(text) as AdminBody : null, headers: response.headers };
}

test("local admin endpoints fail closed when disabled or accessed remotely", async () => {
  const stand = await makeStand();
  const disabled = await handle(
    new Request("http://127.0.0.1:8787/admin/api/login", { method: "POST" }),
    stand.deps,
    "127.0.0.1",
  );
  assert.equal(disabled.status, 404);
  const remote = await adminCall(stand, "POST", "/admin/api/login", { password: ADMIN.LOCAL_ADMIN_PASSWORD }, undefined, "https://sparrow-account-api.sparrownet.workers.dev/admin/api/login");
  assert.equal(remote.status, 404);
});

test("local admin manages accounts without exposing OPAQUE records or refresh hashes", async () => {
  const stand = await makeStand();
  await register(stand, "admin.test", "account password 123");
  const { res: session } = await login(stand, "admin.test", "account password 123");
  assert.equal(session.status, 200);

  const badLogin = await adminCall(stand, "POST", "/admin/api/login", { password: "wrong password" });
  assert.equal(badLogin.status, 401);
  const loginResponse = await adminCall(stand, "POST", "/admin/api/login", { password: ADMIN.LOCAL_ADMIN_PASSWORD });
  assert.equal(loginResponse.status, 200);
  const setCookie = loginResponse.headers.get("set-cookie");
  assert.ok(setCookie?.includes("HttpOnly"));
  assert.ok(setCookie?.includes("SameSite=Strict"));
  const cookie = setCookie!.split(";")[0]!;

  const unauthenticated = await adminCall(stand, "GET", "/admin/api/accounts");
  assert.equal(unauthenticated.status, 401);
  const listed = await adminCall(stand, "GET", "/admin/api/accounts?q=admin", undefined, cookie);
  assert.equal(listed.status, 200);
  const listedAccount = listed.body!.accounts![0]!;
  assert.equal(listedAccount.username, "admin.test");
  assert.equal("opaque_record" in listedAccount, false);

  const userId = listedAccount.id as string;
  const edited = await adminCall(stand, "PATCH", `/admin/api/accounts/${userId}`, { username: "admin.renamed", status: "suspended" }, cookie);
  assert.equal(edited.status, 200);
  assert.equal(edited.body!.account!.username, "admin.renamed");
  assert.equal(edited.body!.account!.status, "suspended");
  const suspendedToken = await stand.call("GET", "/v1/me", undefined, { token: session.body.accessToken as string });
  assert.equal(suspendedToken.status, 401);

  const sessions = await adminCall(stand, "GET", `/admin/api/accounts/${userId}/sessions`, undefined, cookie);
  assert.equal(sessions.status, 200);
  const accountSessions = sessions.body!.sessions!;
  assert.equal(accountSessions.length, 1);
  assert.equal("refresh_hash" in accountSessions[0]!, false);
  const revoke = await adminCall(stand, "POST", `/admin/api/accounts/${userId}/revoke-sessions`, {}, cookie);
  assert.equal(revoke.status, 200);
  assert.equal(revoke.body!.revoked, 1);

  const deleted = await adminCall(stand, "DELETE", `/admin/api/accounts/${userId}`, undefined, cookie);
  assert.equal(deleted.status, 200);
  assert.equal(stand.raw.prepare("SELECT id FROM users WHERE id = ?").get(userId), undefined);
  assert.equal(stand.raw.prepare("SELECT id FROM sessions WHERE user_id = ?").get(userId), undefined);
});

test("local admin mutations reject unexpected fields and foreign origins", async () => {
  const stand = await makeStand();
  const loginResponse = await adminCall(stand, "POST", "/admin/api/login", { password: ADMIN.LOCAL_ADMIN_PASSWORD });
  const cookie = loginResponse.headers.get("set-cookie")!.split(";")[0]!;
  const user = await register(stand, "safe.user", "account password 123");
  assert.equal(user.status, 200);
  const row = stand.raw.prepare("SELECT id FROM users WHERE username = ?").get("safe.user") as { id: string };
  const unexpected = await adminCall(stand, "PATCH", `/admin/api/accounts/${row.id}`, { status: "active", opaque_record: "replacement" }, cookie);
  assert.equal(unexpected.status, 400);
  const foreignOrigin = await handle(
    new Request(`http://127.0.0.1:8787/admin/api/accounts/${row.id}`, {
      method: "DELETE",
      headers: { origin: "https://attacker.example", cookie, "content-type": "application/json" },
    }),
    stand.deps,
    "127.0.0.1",
    ADMIN,
  );
  assert.equal(foreignOrigin.status, 404);
});
