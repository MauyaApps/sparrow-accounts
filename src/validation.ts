// Вся валидация входных данных. Тело запроса — строгая схема: неизвестные поля отклоняются,
// поэтому поле `password` сервер не примет даже по ошибке клиента.
import { AppError } from "./errors.ts";
import { MAX_BODY_BYTES } from "./config.ts";

const RESERVED = new Set([
  "admin", "administrator", "root", "support", "help", "security", "abuse", "postmaster",
  "sparrow", "system", "staff", "moderator", "mod", "noreply", "api", "www", "mail", "pass",
  "calls", "radio", "account",
]);

const USERNAME_RE = /^[a-z0-9](?:[a-z0-9._-]{1,30})[a-z0-9]$/;

export function normalizeUsername(raw: unknown): string {
  if (typeof raw !== "string") throw new AppError("BAD_USER_INPUT", "username must be a string");
  const u = raw.normalize("NFKC").trim().toLowerCase();
  if (!USERNAME_RE.test(u) || /[._-]{2}/.test(u)) {
    throw new AppError("BAD_USER_INPUT", "Username must be 3-32 chars: a-z, 0-9, '.', '_', '-'; start and end with a letter or digit");
  }
  if (RESERVED.has(u)) throw new AppError("BAD_USER_INPUT", "This username is reserved");
  return u;
}

export type FieldKind = "username" | "opaque" | "hex32" | "refresh" | "secret";

const CHECKS: Record<Exclude<FieldKind, "username">, RegExp> = {
  opaque: /^[A-Za-z0-9_\-+/]{1,4096}={0,2}$/, // base64/base64url, без пробелов
  hex32: /^[0-9a-f]{32}$/,
  refresh: /^[0-9a-f]{32}\.[A-Za-z0-9_-]{43}$/,
  secret: /^[A-Za-z0-9_-]{43}$/,
};

export type Spec = Record<string, FieldKind>;

export function parseBody<S extends Spec>(text: string, spec: S): { [K in keyof S]: string } {
  if (text.length > MAX_BODY_BYTES) throw new AppError("BAD_USER_INPUT", "Request body too large");
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch {
    throw new AppError("BAD_USER_INPUT", "Body must be valid JSON");
  }
  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) {
    throw new AppError("BAD_USER_INPUT", "Body must be a JSON object");
  }
  const obj = raw as Record<string, unknown>;
  for (const k of Object.keys(obj)) {
    if (!(k in spec)) throw new AppError("BAD_USER_INPUT", `Unexpected field: ${k}`);
  }
  const out: Record<string, string> = {};
  for (const [k, kind] of Object.entries(spec)) {
    const v = obj[k];
    if (kind === "username") {
      out[k] = normalizeUsername(v);
    } else {
      if (typeof v !== "string" || !CHECKS[kind].test(v)) throw new AppError("BAD_USER_INPUT", `Invalid field: ${k}`);
      out[k] = v;
    }
  }
  return out as { [K in keyof S]: string };
}
