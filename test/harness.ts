// Test stand: real OPAQUE implementation, actual SQL migration (via node:sqlite instead of D1),
// and actual HTTP layer. The OPAQUE client simulates a browser/app client.
import { DatabaseSync } from "node:sqlite";
import { readFileSync } from "node:fs";
import { randomBytes } from "node:crypto";
import * as opaque from "../src/opaque.js";
import { handle } from "../src/http.ts";
import { MemoryStore } from "../src/store.ts";
import { loadSigningKey } from "../src/tokens.ts";
import { b64uEncode } from "../src/bytes.ts";
import type { Deps } from "../src/service.ts";
import type { D1Like, D1Stmt } from "../src/types.ts";

class Stmt implements D1Stmt {
  private db: DatabaseSync;
  private sql: string;
  private params: unknown[];
  constructor(db: DatabaseSync, sql: string, params: unknown[] = []) {
    this.db = db;
    this.sql = sql;
    this.params = params;
  }
  bind(...v: unknown[]): D1Stmt {
    return new Stmt(this.db, this.sql, v);
  }
  async first<T>(): Promise<T | null> {
    return ((this.db.prepare(this.sql).get(...(this.params as never[])) as T | undefined) ?? null);
  }
  async run() {
    const r = this.db.prepare(this.sql).run(...(this.params as never[]));
    return { meta: { changes: Number(r.changes) } };
  }
  async all<T>() {
    return { results: this.db.prepare(this.sql).all(...(this.params as never[])) as T[] };
  }
}

export function makeD1(): { d1: D1Like; raw: DatabaseSync } {
  const raw = new DatabaseSync(":memory:");
  raw.exec("PRAGMA foreign_keys = ON");
  raw.exec(readFileSync(new URL("../migrations/0001_accounts.sql", import.meta.url), "utf8"));
  const d1: D1Like = {
    prepare: (sql) => new Stmt(raw, sql),
    async batch(stmts) {
      raw.exec("BEGIN");
      try {
        const out = [];
        for (const s of stmts) out.push(await s.run());
        raw.exec("COMMIT");
        return out;
      } catch (e) {
        raw.exec("ROLLBACK");
        throw e;
      }
    },
  };
  return { d1, raw };
}

export interface WireEntry {
  method: string;
  path: string;
  requestHeaders: string;
  requestBody: string;
  responseBody: string;
}

export interface Stand {
  deps: Deps;
  raw: DatabaseSync;
  clock: { ms: number };
  wire: WireEntry[];
  /** Session keys observed by the server in finishLogin, for comparison with client keys. */
  serverSessionKeys: string[];
  call(method: string, path: string, body?: unknown, opts?: { token?: string; ip?: string; ua?: string; rawBody?: string }): Promise<{ status: number; body: any; headers: Headers }>;
}

export async function makeStand(): Promise<Stand> {
  await opaque.ready;
  const { d1, raw } = makeD1();
  const clock = { ms: 1_800_000_000_000 };
  const serverSessionKeys: string[] = [];
  const spyServer = {
    ...opaque.server,
    finishLogin(p: { serverLoginState: string; finishLoginRequest: string }) {
      const r = opaque.server.finishLogin(p);
      serverSessionKeys.push(r.sessionKey);
      return r;
    },
  };
  const deps: Deps = {
    db: d1,
    store: new MemoryStore(() => clock.ms),
    opaque: spyServer,
    serverSetup: opaque.server.createSetup(),
    signingKey: loadSigningKey(b64uEncode(randomBytes(32))),
    now: () => clock.ms,
    randomBytes: (n) => new Uint8Array(randomBytes(n)),
  };
  const wire: WireEntry[] = [];
  return {
    deps,
    raw,
    clock,
    wire,
    serverSessionKeys,
    async call(method, path, body, opts = {}) {
      const headers: Record<string, string> = { "content-type": "application/json" };
      if (opts.token) headers.authorization = `Bearer ${opts.token}`;
      if (opts.ua) headers["user-agent"] = opts.ua;
      const requestBody = opts.rawBody ?? (body === undefined ? "" : JSON.stringify(body));
      const req = new Request(`https://account.test${path}`, { method, headers, body: method === "GET" ? undefined : requestBody });
      const res = await handle(req, deps, opts.ip ?? "203.0.113.7");
      const text = await res.text();
      wire.push({ method, path, requestHeaders: JSON.stringify(headers), requestBody, responseBody: text });
      return { status: res.status, body: text ? JSON.parse(text) : null, headers: res.headers };
    },
  };
}

// ───── Client helpers (what the browser/app actually does) ─────

export async function register(s: Stand, username: string, password: string, ip?: string) {
  const c1 = opaque.client.startRegistration({ password });
  const a = await s.call("POST", "/v1/register/start", { username, registrationRequest: c1.registrationRequest }, { ip });
  if (a.status !== 200) return a;
  const c2 = opaque.client.finishRegistration({
    clientRegistrationState: c1.clientRegistrationState,
    registrationResponse: a.body.registrationResponse,
    password,
  });
  return s.call("POST", "/v1/register/finish", { username, registrationRecord: c2.registrationRecord }, { ip });
}

export async function login(s: Stand, username: string, password: string, opts: { ip?: string; ua?: string } = {}) {
  const c1 = opaque.client.startLogin({ password });
  const a = await s.call("POST", "/v1/login/start", { username, startLoginRequest: c1.startLoginRequest }, opts);
  if (a.status !== 200) return { res: a, clientKey: undefined as string | undefined };
  const c2 = opaque.client.finishLogin({ clientLoginState: c1.clientLoginState, loginResponse: a.body.loginResponse, password });
  if (!c2) {
    // On a wrong password the client still sends a bogus final message, as an attacker would.
    const res = await s.call("POST", "/v1/login/finish", { attemptId: a.body.attemptId, finishLoginRequest: "AAAA" }, opts);
    return { res, clientKey: undefined };
  }
  const res = await s.call("POST", "/v1/login/finish", { attemptId: a.body.attemptId, finishLoginRequest: c2.finishLoginRequest }, opts);
  return { res, clientKey: c2.sessionKey };
}

export async function confirmPassword(s: Stand, token: string, password: string) {
  const c1 = opaque.client.startLogin({ password });
  const a = await s.call("POST", "/v1/password/verify/start", { startLoginRequest: c1.startLoginRequest }, { token });
  if (a.status !== 200) return a;
  const c2 = opaque.client.finishLogin({ clientLoginState: c1.clientLoginState, loginResponse: a.body.loginResponse, password });
  const req = c2 ? c2.finishLoginRequest : "AAAA";
  return s.call("POST", "/v1/password/verify/finish", { attemptId: a.body.attemptId, finishLoginRequest: req }, { token });
}

export async function setNewPassword(s: Stand, token: string, reauthToken: string, newPassword: string) {
  const c1 = opaque.client.startRegistration({ password: newPassword });
  const a = await s.call("POST", "/v1/password/start", { registrationRequest: c1.registrationRequest }, { token });
  if (a.status !== 200) return a;
  const c2 = opaque.client.finishRegistration({
    clientRegistrationState: c1.clientRegistrationState,
    registrationResponse: a.body.registrationResponse,
    password: newPassword,
  });
  return s.call("POST", "/v1/password/finish", { reauthToken, registrationRecord: c2.registrationRecord }, { token });
}
