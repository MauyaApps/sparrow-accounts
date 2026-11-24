import { AppError } from "./errors.ts";
import { normalizeUsername } from "./validation.ts";
import type { D1Like } from "./types.ts";

const COOKIE_NAME = "sparrow_local_admin";
const SESSION_SECONDS = 8 * 60 * 60;
const STATUSES = ["active", "suspended", "banned"] as const;
type AccountStatus = (typeof STATUSES)[number];

export interface LocalAdminEnv {
  LOCAL_ADMIN_ENABLED?: string;
  LOCAL_ADMIN_PASSWORD?: string;
  LOCAL_ADMIN_SESSION_SECRET?: string;
  LOCAL_ADMIN_ORIGIN?: string;
}

function json(body: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      "x-content-type-options": "nosniff",
      ...headers,
    },
  });
}

function b64uEncode(data: Uint8Array): string {
  let binary = "";
  for (const byte of data) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

function b64uDecode(value: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]+$/.test(value) || value.length % 4 === 1) throw new Error("invalid encoding");
  const binary = atob(value.replaceAll("-", "+").replaceAll("_", "/") + "=".repeat((4 - value.length % 4) % 4));
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}

async function hmac(secret: string, value: string): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(value)));
}

async function passwordMatches(submitted: string, expected: string): Promise<boolean> {
  const enc = new TextEncoder();
  const [a, b] = await Promise.all([crypto.subtle.digest("SHA-256", enc.encode(submitted)), crypto.subtle.digest("SHA-256", enc.encode(expected))]);
  const left = new Uint8Array(a);
  const right = new Uint8Array(b);
  let diff = 0;
  for (let i = 0; i < left.length; i++) diff |= left[i]! ^ right[i]!;
  return diff === 0;
}

function localOrigin(request: Request, env: LocalAdminEnv): boolean {
  const url = new URL(request.url);
  if (!["127.0.0.1", "localhost", "[::1]", "::1"].includes(url.hostname)) return false;
  const origin = request.headers.get("origin");
  return origin === null || origin === (env.LOCAL_ADMIN_ORIGIN ?? "http://127.0.0.1:5173");
}

function cookieValue(request: Request): string | null {
  const cookies = request.headers.get("cookie") ?? "";
  const match = new RegExp(`(?:^|;\\s*)${COOKIE_NAME}=([^;]+)`).exec(cookies);
  return match?.[1] ?? null;
}

async function authorized(request: Request, env: LocalAdminEnv): Promise<boolean> {
  const token = cookieValue(request);
  if (!token || !env.LOCAL_ADMIN_SESSION_SECRET) return false;
  const [version, expiryText, signature, extra] = token.split(".");
  if (version !== "v1" || !expiryText || !signature || extra !== undefined) return false;
  const expiry = Number(expiryText);
  if (!Number.isSafeInteger(expiry) || expiry <= Math.floor(Date.now() / 1000)) return false;
  try {
    const key = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(env.LOCAL_ADMIN_SESSION_SECRET),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["verify"],
    );
    const signatureBytes = b64uDecode(signature);
    const signatureBuffer = new ArrayBuffer(signatureBytes.length);
    new Uint8Array(signatureBuffer).set(signatureBytes);
    return await crypto.subtle.verify("HMAC", key, signatureBuffer, new TextEncoder().encode(`${version}.${expiryText}`));
  } catch {
    return false;
  }
}

function sessionCookie(value: string, maxAge: number): string {
  return `${COOKIE_NAME}=${value}; Path=/admin/api; HttpOnly; SameSite=Strict; Max-Age=${maxAge}`;
}

async function readJson(request: Request): Promise<Record<string, unknown> | null> {
  if (Number(request.headers.get("content-length") ?? 0) > 4096) return null;
  const text = await request.text();
  if (text.length > 4096) return null;
  try {
    const value: unknown = JSON.parse(text);
    return value !== null && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : null;
  } catch {
    return null;
  }
}

function apiError(error: unknown): Response {
  if (error instanceof AppError) return json({ error: { code: error.code, message: error.message } }, error.status);
  console.error(JSON.stringify({ message: "local admin request failed", error: error instanceof Error ? error.name : "Error" }));
  return json({ error: { code: "INTERNAL", message: "Internal error" } }, 500);
}

export async function handleLocalAdmin(request: Request, db: D1Like, env: LocalAdminEnv): Promise<Response | null> {
  const url = new URL(request.url);
  if (!url.pathname.startsWith("/admin/api/")) return null;
  if (
    env.LOCAL_ADMIN_ENABLED !== "true" ||
    !env.LOCAL_ADMIN_PASSWORD ||
    env.LOCAL_ADMIN_PASSWORD.length < 16 ||
    !env.LOCAL_ADMIN_SESSION_SECRET ||
    env.LOCAL_ADMIN_SESSION_SECRET.length < 32
  ) {
    return json({ error: { code: "NOT_FOUND", message: "Not found" } }, 404);
  }
  if (!localOrigin(request, env)) return json({ error: { code: "NOT_FOUND", message: "Not found" } }, 404);
  if (request.method !== "GET" && request.headers.get("origin") !== (env.LOCAL_ADMIN_ORIGIN ?? "http://127.0.0.1:5173")) {
    return json({ error: { code: "FORBIDDEN", message: "Local admin origin required" } }, 403);
  }

  if (url.pathname === "/admin/api/login" && request.method === "POST") {
    const body = await readJson(request);
    if (!body || Object.keys(body).some((key) => key !== "password") || typeof body.password !== "string" || body.password.length > 1024) {
      return json({ error: { code: "BAD_USER_INPUT", message: "Invalid request" } }, 400);
    }
    if (!(await passwordMatches(body.password, env.LOCAL_ADMIN_PASSWORD))) {
      return json({ error: { code: "UNAUTHENTICATED", message: "Invalid admin password" } }, 401);
    }
    const expiry = Math.floor(Date.now() / 1000) + SESSION_SECONDS;
    const value = `v1.${expiry}.${b64uEncode(await hmac(env.LOCAL_ADMIN_SESSION_SECRET, `v1.${expiry}`))}`;
    return json({ ok: true }, 200, { "set-cookie": sessionCookie(value, SESSION_SECONDS) });
  }

  if (url.pathname === "/admin/api/logout" && request.method === "POST") {
    return json({ ok: true }, 200, { "set-cookie": sessionCookie("", 0) });
  }

  if (!(await authorized(request, env))) return json({ error: { code: "UNAUTHENTICATED", message: "Sign in to the local admin panel" } }, 401);

  try {
    if (url.pathname === "/admin/api/accounts" && request.method === "GET") {
      const q = (url.searchParams.get("q") ?? "").trim().slice(0, 32);
      const status = url.searchParams.get("status");
      if (status && !STATUSES.includes(status as AccountStatus)) {
        return json({ error: { code: "BAD_USER_INPUT", message: "Invalid account status" } }, 400);
      }
      const requestedPage = Number(url.searchParams.get("page") ?? 1);
      const page = Number.isSafeInteger(requestedPage) ? Math.max(1, Math.min(200, requestedPage)) : 1;
      const where: string[] = [];
      const values: unknown[] = [];
      if (q) {
        where.push("username LIKE ? ESCAPE '!'");
        values.push(`%${q.replace(/[!%_]/g, "!$&")}%`);
      }
      if (status) {
        where.push("status = ?");
        values.push(status);
      }
      const clause = where.length ? `WHERE ${where.join(" AND ")}` : "";
      const rows = await db.prepare(
        `SELECT id, username, status, created_at AS createdAt, updated_at AS updatedAt FROM users ${clause} ORDER BY created_at DESC, username LIMIT ? OFFSET ?`,
      ).bind(...values, 51, (page - 1) * 50).all<{
        id: string; username: string; status: AccountStatus; createdAt: number; updatedAt: number;
      }>();
      return json({ accounts: rows.results.slice(0, 50), page, pageSize: 50, hasMore: rows.results.length > 50 });
    }

    const revokeMatch = /^\/admin\/api\/accounts\/([0-9a-f]{32})\/sessions\/([0-9a-f]{32})\/revoke$/.exec(url.pathname);
    if (request.method === "POST" && revokeMatch) {
      const [, ownerId, sessionId] = revokeMatch;
      const result = await db.prepare("UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND id = ? AND revoked_at IS NULL")
        .bind(Math.floor(Date.now() / 1000), ownerId, sessionId).run();
      if (result.meta.changes !== 1) return json({ error: { code: "NOT_FOUND", message: "Active session not found" } }, 404);
      return json({ ok: true });
    }

    const accountMatch = /^\/admin\/api\/accounts\/([0-9a-f]{32})(?:\/(sessions|revoke-sessions))?$/.exec(url.pathname);
    const accountId = accountMatch?.[1];
    const action = accountMatch?.[2];
    if (!accountId) return json({ error: { code: "NOT_FOUND", message: "Not found" } }, 404);

    if (action === "sessions" && request.method === "GET") {
      const owner = await db.prepare("SELECT id FROM users WHERE id = ?").bind(accountId).first<{ id: string }>();
      if (!owner) return json({ error: { code: "NOT_FOUND", message: "Account not found" } }, 404);
      const rows = await db.prepare(
        "SELECT id, created_at AS createdAt, last_used_at AS lastUsedAt, expires_at AS expiresAt, revoked_at AS revokedAt, user_agent AS userAgent FROM sessions WHERE user_id = ? ORDER BY created_at DESC LIMIT 100",
      ).bind(accountId).all<{
        id: string; createdAt: number; lastUsedAt: number; expiresAt: number; revokedAt: number | null; userAgent: string | null;
      }>();
      return json({ sessions: rows.results });
    }

    if (action === "revoke-sessions" && request.method === "POST") {
      const result = await db.prepare("UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL")
        .bind(Math.floor(Date.now() / 1000), accountId).run();
      return json({ ok: true, revoked: result.meta.changes });
    }

    if (!action && request.method === "PATCH") {
      const body = await readJson(request);
      if (!body || Object.keys(body).length === 0 || Object.keys(body).some((key) => key !== "username" && key !== "status")) {
        return json({ error: { code: "BAD_USER_INPUT", message: "Invalid account changes" } }, 400);
      }
      const current = await db.prepare("SELECT id, username, status FROM users WHERE id = ?").bind(accountId)
        .first<{ id: string; username: string; status: AccountStatus }>();
      if (!current) return json({ error: { code: "NOT_FOUND", message: "Account not found" } }, 404);
      let username = current.username;
      let nextStatus = current.status;
      try {
        if ("username" in body) username = normalizeUsername(body.username);
      } catch (error) {
        return apiError(error);
      }
      if ("status" in body) {
        if (typeof body.status !== "string" || !STATUSES.includes(body.status as AccountStatus)) {
          return json({ error: { code: "BAD_USER_INPUT", message: "Invalid account status" } }, 400);
        }
        nextStatus = body.status as AccountStatus;
      }
      try {
        await db.prepare("UPDATE users SET username = ?, status = ?, updated_at = ? WHERE id = ?")
          .bind(username, nextStatus, Math.floor(Date.now() / 1000), accountId).run();
      } catch (error) {
        if (/UNIQUE/i.test(String(error))) return json({ error: { code: "USERNAME_TAKEN", message: "This username is already taken" } }, 409);
        throw error;
      }
      return json({ ok: true, account: { id: accountId, username, status: nextStatus } });
    }

    if (!action && request.method === "DELETE") {
      const owner = await db.prepare("SELECT id FROM users WHERE id = ?").bind(accountId).first<{ id: string }>();
      if (!owner) return json({ error: { code: "NOT_FOUND", message: "Account not found" } }, 404);
      await db.batch([
        db.prepare("DELETE FROM sessions WHERE user_id = ?").bind(accountId),
        db.prepare("DELETE FROM users WHERE id = ?").bind(accountId),
      ]);
      return json({ ok: true });
    }

    return json({ error: { code: "NOT_FOUND", message: "Not found" } }, 404);
  } catch (error) {
    return apiError(error);
  }
}
