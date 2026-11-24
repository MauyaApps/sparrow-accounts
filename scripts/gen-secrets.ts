// Генерация секретов для первого запуска. Вывод в консоль, в файлы ничего не пишется.
//   npx tsx scripts/gen-secrets.ts
// Затем:
//   wrangler secret put OPAQUE_SERVER_SETUP   (вставить строку serverSetup)
//   wrangler secret put TOKEN_SIGNING_KEY     (вставить строку seed)
// ВАЖНО: OPAQUE_SERVER_SETUP нельзя пересоздавать: все записи паролей станут нечитаемыми.
import { randomBytes } from "node:crypto";
import * as opaque from "../src/opaque.js";
import { b64uEncode } from "../src/bytes.ts";
import { loadSigningKey } from "../src/tokens.ts";

await opaque.ready;
const seed = b64uEncode(new Uint8Array(randomBytes(32)));
console.log("OPAQUE_SERVER_SETUP=" + opaque.server.createSetup());
console.log("TOKEN_SIGNING_KEY=" + seed);
console.log("# публичный ключ (его же отдаёт GET /v1/keys): " + b64uEncode(loadSigningKey(seed).publicKey));
