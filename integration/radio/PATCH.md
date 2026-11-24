# Подключение аккаунтов к sparrow-radio

1. Скопировать `auth.ts` и `verify.ts` в `sparrow-radio/src/`, добавить зависимость `@noble/curves@^2.4.0`.
2. В `wrangler.toml` радио добавить переменные (публичные, не секреты):
   ```toml
   [vars]
   ALLOW_DEV_AUTH = "false"
   ACCOUNT_ISSUER = "https://sparrow-account-api.sparrownet.workers.dev"
   ACCOUNT_PUBLIC_KEY = "<publicKey из GET /v1/keys>"
   ```
3. В `src/index.ts`, в построении контекста yoga, заменить чтение `x-sparrow-user`:
   ```ts
   import { userIdFromRequest } from "./auth.ts";
   // было: userId: env.ALLOW_DEV_AUTH === "true" ? request.headers.get("x-sparrow-user") : null
   context: ({ request }) => ({ userId: userIdFromRequest(request, env) }),
   ```
4. `resolvers.createStream` не меняется: при `userId === null` он по-прежнему отдаёт `UNAUTHENTICATED`
   с текстом «Sign in with your Sparrow account».

Отзыв токена (logout, смена пароля) доходит до радио с задержкой до TTL access-токена (10 минут).
