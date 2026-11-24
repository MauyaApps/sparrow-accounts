// Бизнес-логика аккаунтов. Пароль сюда не попадает ни в каком виде: сервер видит только OPAQUE-сообщения.
import { ISSUER, LIMITS, TTL } from "./config.ts";
import { AppError } from "./errors.ts";
import { b64uDecode, b64uEncode, ctEqual, toHex } from "./bytes.ts";
import { sha256Hex, signAccess, type SigningKey } from "./tokens.ts";
import { TokenError, verifyAccessToken, type AccessClaims } from "./verify.ts";
import type { StateStore } from "./store.ts";
import type { D1Like } from "./types.ts";

/** Серверная часть OPAQUE (подмножество opaque.js). */
export interface OpaqueServer {
  createRegistrationResponse(p: { serverSetup: string; userIdentifier: string; registrationRequest: string }): { registrationResponse: string };
  startLogin(p: {
    serverSetup: string;
    userIdentifier: string;
    registrationRecord: string | undefined;
    startLoginRequest: string;
  }): { serverLoginState: string; loginResponse: string };
  finishLogin(p: { serverLoginState: string; finishLoginRequest: string }): { sessionKey: string };
}

export interface Deps {
  db: D1Like;
  store: StateStore;
  opaque: OpaqueServer;
  serverSetup: string;
  signingKey: SigningKey;
  now: () => number; // мс
  randomBytes: (n: number) => Uint8Array;
}

export interface Ctx {
  ip: string;
  userAgent: string | null;
}

interface UserRow {
  id: string;
  username: string;
  opaque_record: string;
  status: string;
}
interface SessionRow {
  id: string;
  user_id: string;
  refresh_hash: string;
  prev_refresh_hash: string | null;
  created_at: number;
  expires_at: number;
  revoked_at: number | null;
}

const sec = (d: Deps): number => Math.floor(d.now() / 1000);
const rid = (d: Deps): string => toHex(d.randomBytes(16));
const BAD_CREDENTIALS = (): AppError => new AppError("UNAUTHENTICATED", "Invalid username or password");

async function limit(d: Deps, key: string, cfg: { limit: number; windowMs: number }): Promise<void> {
  const r = await d.store.hit(key, cfg.limit, cfg.windowMs);
  if (!r.ok) throw new AppError("RATE_LIMITED", "Too many attempts. Try again later.", r.retryAfterSec);
}

async function userByName(d: Deps, username: string): Promise<UserRow | null> {
  return d.db.prepare("SELECT id, username, opaque_record, status FROM users WHERE username = ?").bind(username).first<UserRow>();
}
async function userById(d: Deps, id: string): Promise<UserRow | null> {
  return d.db.prepare("SELECT id, username, opaque_record, status FROM users WHERE id = ?").bind(id).first<UserRow>();
}

// ───────── Регистрация ─────────

export async function registerStart(d: Deps, ctx: Ctx, i: { username: string; registrationRequest: string }) {
  await limit(d, `reg:ip:${ctx.ip}`, LIMITS.registerIp);
  if (await userByName(d, i.username)) throw new AppError("USERNAME_TAKEN", "This username is already taken");
  const r = d.opaque.createRegistrationResponse({
    serverSetup: d.serverSetup,
    userIdentifier: i.username,
    registrationRequest: i.registrationRequest,
  });
  return { registrationResponse: r.registrationResponse };
}

export async function registerFinish(d: Deps, ctx: Ctx, i: { username: string; registrationRecord: string }) {
  await limit(d, `reg:ip:${ctx.ip}`, LIMITS.registerIp);
  const id = rid(d);
  const t = sec(d);
  try {
    await d.db
      .prepare("INSERT INTO users (id, username, opaque_record, status, created_at, updated_at) VALUES (?, ?, ?, 'active', ?, ?)")
      .bind(id, i.username, i.registrationRecord, t, t)
      .run();
  } catch (e) {
    if (/UNIQUE/i.test(String((e as Error)?.message))) throw new AppError("USERNAME_TAKEN", "This username is already taken");
    throw e;
  }
  return { userId: id };
}

// ───────── Вход (OPAQUE, 2 шага) ─────────

interface Attempt {
  u: string; // userIdentifier, с которым стартовали
  uid: string | null; // null = пользователя нет (ответ был фиктивным)
  s: string; // serverLoginState
  reauth: boolean;
}

export async function loginStart(
  d: Deps,
  ctx: Ctx,
  i: { username: string; startLoginRequest: string },
  reauthFor?: AccessClaims,
) {
  let user: UserRow | null;
  if (reauthFor) {
    user = await userById(d, reauthFor.sub); // при подтверждении пароля имя берётся из токена, не из тела
  } else {
    user = await userByName(d, i.username);
  }
  const name = user?.username ?? i.username;
  await limit(d, `login:ip:${ctx.ip}`, LIMITS.loginIp);
  await limit(d, `login:user:${name}`, LIMITS.loginUser);

  // registrationRecord = undefined для неизвестного имени: библиотека отдаёт неотличимый фиктивный ответ.
  const r = d.opaque.startLogin({
    serverSetup: d.serverSetup,
    userIdentifier: name,
    registrationRecord: user?.opaque_record,
    startLoginRequest: i.startLoginRequest,
  });
  const attemptId = rid(d);
  const a: Attempt = { u: name, uid: user?.id ?? null, s: r.serverLoginState, reauth: !!reauthFor };
  await d.store.put("att", attemptId, JSON.stringify(a), TTL.loginAttemptMs);
  return { attemptId, loginResponse: r.loginResponse };
}

export async function loginFinish(d: Deps, ctx: Ctx, i: { attemptId: string; finishLoginRequest: string }) {
  const raw = await d.store.take("att", i.attemptId); // одноразово
  if (!raw) throw new AppError("UNAUTHENTICATED", "Login attempt expired. Start again.");
  const a = JSON.parse(raw) as Attempt;

  try {
    d.opaque.finishLogin({ serverLoginState: a.s, finishLoginRequest: i.finishLoginRequest });
  } catch {
    throw BAD_CREDENTIALS();
  }
  if (!a.uid) throw BAD_CREDENTIALS();

  const user = await userById(d, a.uid);
  if (!user) throw BAD_CREDENTIALS();
  if (user.status !== "active") throw new AppError("FORBIDDEN", "This account is suspended");

  if (a.reauth) {
    const token = b64uEncode(d.randomBytes(32));
    await d.store.put("reauth", sha256Hex(b64uDecode(token)), user.id, TTL.reauthMs);
    return { reauthToken: token };
  }
  return createSession(d, ctx, user.id);
}

// ───────── Сессии и токены ─────────

async function createSession(d: Deps, ctx: Ctx, userId: string) {
  const sid = rid(d);
  const secret = d.randomBytes(32);
  const t = sec(d);
  const refreshExp = t + TTL.refreshSec;
  await d.db
    .prepare(
      "INSERT INTO sessions (id, user_id, refresh_hash, prev_refresh_hash, created_at, last_used_at, expires_at, revoked_at, user_agent) VALUES (?, ?, ?, NULL, ?, ?, ?, NULL, ?)",
    )
    .bind(sid, userId, sha256Hex(secret), t, t, refreshExp, ctx.userAgent?.slice(0, 200) ?? null)
    .run();
  return issue(d, userId, sid, `${sid}.${b64uEncode(secret)}`, refreshExp);
}

function issue(d: Deps, userId: string, sid: string, refreshToken: string, refreshExpiresAt: number) {
  const t = sec(d);
  const claims: AccessClaims = { iss: ISSUER, sub: userId, sid, iat: t, exp: t + TTL.accessSec };
  return {
    userId,
    sessionId: sid,
    accessToken: signAccess(d.signingKey, claims),
    accessExpiresAt: claims.exp,
    refreshToken,
    refreshExpiresAt,
  };
}

export async function refresh(d: Deps, i: { refreshToken: string }) {
  const [sid, secretB64] = i.refreshToken.split(".") as [string, string];
  const presented = sha256Hex(b64uDecode(secretB64));
  const t = sec(d);

  const row = await d.db
    .prepare("SELECT id, user_id, refresh_hash, prev_refresh_hash, created_at, expires_at, revoked_at FROM sessions WHERE id = ?")
    .bind(sid)
    .first<SessionRow>();
  const invalid = () => new AppError("UNAUTHENTICATED", "Session is no longer valid. Sign in again.");
  if (!row || row.revoked_at !== null || row.expires_at <= t) throw invalid();

  if (!ctEqual(presented, row.refresh_hash)) {
    // Предъявлен уже использованный токен: считаем кражей и закрываем сессию целиком.
    if (row.prev_refresh_hash && ctEqual(presented, row.prev_refresh_hash)) {
      await d.db.prepare("UPDATE sessions SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL").bind(t, sid).run();
    }
    throw invalid();
  }

  const user = await userById(d, row.user_id);
  if (!user || user.status !== "active") throw invalid();

  const next = d.randomBytes(32);
  const exp = Math.min(t + TTL.refreshSec, row.created_at + TTL.refreshMaxSec);
  // Условный UPDATE: из двух параллельных запросов с одним токеном ротацию выиграет только один.
  const res = await d.db
    .prepare(
      "UPDATE sessions SET prev_refresh_hash = refresh_hash, refresh_hash = ?, last_used_at = ?, expires_at = ? WHERE id = ? AND refresh_hash = ? AND revoked_at IS NULL",
    )
    .bind(sha256Hex(next), t, exp, sid, row.refresh_hash)
    .run();
  if (res.meta.changes !== 1) throw invalid();
  return issue(d, row.user_id, sid, `${sid}.${b64uEncode(next)}`, exp);
}

/** Проверка Bearer-токена + сверка с БД (сессия не отозвана, аккаунт активен). */
export async function authenticate(d: Deps, bearer: string | null): Promise<AccessClaims> {
  if (!bearer) throw new AppError("UNAUTHENTICATED", "Sign in with your Sparrow account");
  let claims: AccessClaims;
  try {
    claims = verifyAccessToken(bearer, d.signingKey.publicKey, { issuer: ISSUER, nowSec: sec(d) });
  } catch (e) {
    if (e instanceof TokenError) throw new AppError("UNAUTHENTICATED", "Invalid or expired token");
    throw e;
  }
  const s = await d.db
    .prepare(
      "SELECT s.revoked_at AS revoked_at, s.expires_at AS expires_at, u.status AS status FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.id = ? AND s.user_id = ?",
    )
    .bind(claims.sid, claims.sub)
    .first<{ revoked_at: number | null; expires_at: number; status: string }>();
  if (!s || s.revoked_at !== null || s.expires_at <= sec(d) || s.status !== "active") {
    throw new AppError("UNAUTHENTICATED", "Session has ended. Sign in again.");
  }
  return claims;
}

export async function logout(d: Deps, claims: AccessClaims) {
  await d.db.prepare("UPDATE sessions SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL").bind(sec(d), claims.sid).run();
  return { ok: true };
}

export async function me(d: Deps, claims: AccessClaims) {
  const u = await userById(d, claims.sub);
  if (!u) throw new AppError("UNAUTHENTICATED", "Account not found");
  return { userId: u.id, username: u.username, sessionId: claims.sid };
}

// ───────── Смена пароля ─────────
// 1) loginStart/loginFinish в режиме reauth (старый пароль) -> reauthToken
// 2) passwordStart: OPAQUE-регистрация нового пароля  3) passwordFinish: reauthToken + новая запись

export async function passwordStart(d: Deps, claims: AccessClaims, i: { registrationRequest: string }) {
  const u = await userById(d, claims.sub);
  if (!u) throw new AppError("UNAUTHENTICATED", "Account not found");
  const r = d.opaque.createRegistrationResponse({
    serverSetup: d.serverSetup,
    userIdentifier: u.username,
    registrationRequest: i.registrationRequest,
  });
  return { registrationResponse: r.registrationResponse };
}

export async function passwordFinish(d: Deps, claims: AccessClaims, i: { reauthToken: string; registrationRecord: string }) {
  const owner = await d.store.take("reauth", sha256Hex(b64uDecode(i.reauthToken))); // одноразовый
  if (!owner || owner !== claims.sub) throw new AppError("UNAUTHENTICATED", "Confirm your current password first");
  const t = sec(d);
  const results = await d.db.batch([
    d.db.prepare("UPDATE users SET opaque_record = ?, updated_at = ? WHERE id = ?").bind(i.registrationRecord, t, claims.sub),
    d.db
      .prepare("UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND id <> ? AND revoked_at IS NULL")
      .bind(t, claims.sub, claims.sid),
  ]);
  const revoked = (results[1] as { meta?: { changes?: number } } | undefined)?.meta?.changes ?? 0;
  return { ok: true, otherSessionsRevoked: revoked };
}
