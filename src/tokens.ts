import { ed25519 } from "@noble/curves/ed25519.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { b64uDecode, b64uEncode, toHex, utf8 } from "./bytes.ts";
import type { AccessClaims } from "./verify.ts";

export interface SigningKey {
  secret: Uint8Array;
  publicKey: Uint8Array;
  kid: string;
}

/** TOKEN_SIGNING_KEY: 32 случайных байта в base64url. Сгенерировать: `npx tsx scripts/gen-secrets.ts`. */
export function loadSigningKey(seedB64u: string): SigningKey {
  const secret = b64uDecode(seedB64u);
  if (secret.length !== 32) throw new Error("TOKEN_SIGNING_KEY must be 32 bytes");
  const publicKey = ed25519.getPublicKey(secret);
  return { secret, publicKey, kid: toHex(sha256(publicKey)).slice(0, 16) };
}

export function signAccess(key: SigningKey, claims: AccessClaims): string {
  const h = b64uEncode(utf8(JSON.stringify({ alg: "EdDSA", typ: "JWT", kid: key.kid })));
  const p = b64uEncode(utf8(JSON.stringify(claims)));
  const sig = ed25519.sign(utf8(`${h}.${p}`), key.secret);
  return `${h}.${p}.${b64uEncode(sig)}`;
}

export const sha256Hex = (b: Uint8Array): string => toHex(sha256(b));
