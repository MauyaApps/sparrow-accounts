import { ALLOWED_ORIGINS, ISSUER } from "./config.ts";
import { b64uEncode } from "./bytes.ts";
import { AppError } from "./errors.ts";
import { parseBody, type Spec } from "./validation.ts";
import * as svc from "./service.ts";
import { bearerFrom } from "./verify.ts";
import { handleLocalAdmin, type LocalAdminEnv } from "./admin.ts";

function corsHeaders(request: Request): Record<string, string> {
  const origin = request.headers.get("origin");
  if (!origin || !ALLOWED_ORIGINS.includes(origin)) return {};
  return {
    "access-control-allow-origin": origin,
    "access-control-allow-headers": "authorization, content-type",
    "access-control-allow-methods": "GET, POST, OPTIONS",
    "access-control-max-age": "600",
    vary: "Origin",
  };
}

function json(request: Request, body: unknown, status = 200, extra: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "content-type": "application/json",
      "cache-control": "no-store",
      "x-content-type-options": "nosniff",
      ...corsHeaders(request),
      ...extra,
    },
  });
}

type Handler = (d: svc.Deps, ctx: svc.Ctx, request: Request) => Promise<unknown>;

async function body<S extends Spec>(request: Request, spec: S) {
  return parseBody(await request.text(), spec);
}

const routes: Record<string, Handler> = {
  "GET /health": async () => ({ ok: true }),
  "GET /v1/keys": async (d) => ({
    issuer: ISSUER,
    alg: "EdDSA",
    kid: d.signingKey.kid,
    publicKey: b64uEncode(d.signingKey.publicKey),
  }),

  "POST /v1/register/start": async (d, ctx, r) =>
    svc.registerStart(d, ctx, await body(r, { username: "username", registrationRequest: "opaque" })),
  "POST /v1/register/finish": async (d, ctx, r) =>
    svc.registerFinish(d, ctx, await body(r, { username: "username", registrationRecord: "opaque" })),

  "POST /v1/login/start": async (d, ctx, r) =>
    svc.loginStart(d, ctx, await body(r, { username: "username", startLoginRequest: "opaque" })),
  "POST /v1/login/finish": async (d, ctx, r) =>
    svc.loginFinish(d, ctx, await body(r, { attemptId: "hex32", finishLoginRequest: "opaque" })),

  "POST /v1/token/refresh": async (d, _ctx, r) => svc.refresh(d, await body(r, { refreshToken: "refresh" })),

  "GET /v1/me": async (d, _ctx, r) => svc.me(d, await svc.authenticate(d, bearerFrom(r))),
  "POST /v1/logout": async (d, _ctx, r) => svc.logout(d, await svc.authenticate(d, bearerFrom(r))),

  // Смена пароля: подтверждение старого пароля = обычный OPAQUE-вход в режиме reauth
  "POST /v1/password/verify/start": async (d, ctx, r) => {
    const claims = await svc.authenticate(d, bearerFrom(r));
    const b = await body(r, { startLoginRequest: "opaque" });
    return svc.loginStart(d, ctx, { username: "unused", startLoginRequest: b.startLoginRequest }, claims);
  },
  "POST /v1/password/verify/finish": async (d, ctx, r) => {
    await svc.authenticate(d, bearerFrom(r));
    return svc.loginFinish(d, ctx, await body(r, { attemptId: "hex32", finishLoginRequest: "opaque" }));
  },
  "POST /v1/password/start": async (d, _ctx, r) =>
    svc.passwordStart(d, await svc.authenticate(d, bearerFrom(r)), await body(r, { registrationRequest: "opaque" })),
  "POST /v1/password/finish": async (d, _ctx, r) =>
    svc.passwordFinish(d, await svc.authenticate(d, bearerFrom(r)), await body(r, { reauthToken: "secret", registrationRecord: "opaque" })),
};

export async function handle(request: Request, d: svc.Deps, ip: string, adminEnv: LocalAdminEnv = {}): Promise<Response> {
  const url = new URL(request.url);
  const admin = await handleLocalAdmin(request, d.db, adminEnv);
  if (admin) return admin;
  if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: corsHeaders(request) });

  const route = routes[`${request.method} ${url.pathname}`];
  if (!route) return json(request, { error: { code: "NOT_FOUND", message: "Not found" } }, 404);

  try {
    const ctx: svc.Ctx = { ip, userAgent: request.headers.get("user-agent") };
    return json(request, await route(d, ctx, request));
  } catch (e) {
    if (e instanceof AppError) {
      const extra: Record<string, string> = e.retryAfterSec ? { "retry-after": String(e.retryAfterSec) } : {};
      return json(request, { error: { code: e.code, message: e.message } }, e.status, extra);
    }
    // В лог только тип ошибки: тела запросов и их производные никогда не логируются.
    console.error("unhandled", (e as Error)?.name ?? "Error");
    return json(request, { error: { code: "INTERNAL", message: "Internal error" } }, 500);
  }
}
