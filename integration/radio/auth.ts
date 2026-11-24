// Для sparrow-radio: положить рядом с src/index.ts вместе с verify.ts (копия из sparrow-account/src/verify.ts).
// Зависимость: @noble/curves. Обращаться к сервису аккаунтов не нужно, проверка локальная по публичному ключу.
import { bearerFrom, TokenError, verifyAccessToken } from "./verify.ts";

export interface AuthEnv {
  /** wrangler.toml [vars]: публичный ключ из GET /v1/keys (base64url). Не секрет. */
  ACCOUNT_PUBLIC_KEY?: string;
  /** wrangler.toml [vars]: https://<хост аккаунтов>; при переезде на домен меняется здесь и в sparrow-account/src/config.ts. */
  ACCOUNT_ISSUER?: string;
  ALLOW_DEV_AUTH?: string;
}

const keyCache = new Map<string, Uint8Array>();
function publicKey(b64u: string): Uint8Array {
  let k = keyCache.get(b64u);
  if (!k) {
    const bin = atob(b64u.replaceAll("-", "+").replaceAll("_", "/") + "=".repeat((4 - (b64u.length % 4)) % 4));
    k = Uint8Array.from(bin, (c) => c.charCodeAt(0));
    keyCache.set(b64u, k);
  }
  return k;
}

/** Идентификатор пользователя из заголовка Authorization: Bearer, либо null. Подставляется в context.userId. */
export function userIdFromRequest(request: Request, env: AuthEnv, nowMs: number = Date.now()): string | null {
  const token = bearerFrom(request);
  if (token && env.ACCOUNT_PUBLIC_KEY && env.ACCOUNT_ISSUER) {
    try {
      return verifyAccessToken(token, publicKey(env.ACCOUNT_PUBLIC_KEY), {
        issuer: env.ACCOUNT_ISSUER,
        nowSec: Math.floor(nowMs / 1000),
      }).sub;
    } catch (e) {
      if (e instanceof TokenError) return null;
      throw e;
    }
  }
  // Только локальная разработка: в продакшене ALLOW_DEV_AUTH = "false", и заголовок игнорируется.
  if (env.ALLOW_DEV_AUTH === "true") return request.headers.get("x-sparrow-user");
  return null;
}
