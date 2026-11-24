import * as opaque from "./opaque.js";
import { DoStateStore } from "./store.ts";
import { handle } from "./http.ts";
import { loadSigningKey } from "./tokens.ts";
import type { Env } from "./types.ts";

export { AuthState } from "./authState.ts";

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    if (!env.OPAQUE_SERVER_SETUP || !env.TOKEN_SIGNING_KEY) {
      return Response.json({ error: { code: "INTERNAL", message: "Server is not configured" } }, { status: 500 });
    }
    await opaque.ready;
    return handle(
      request,
      {
        db: env.DB,
        store: new DoStateStore(env.AUTH_STATE),
        opaque: opaque.server,
        serverSetup: env.OPAQUE_SERVER_SETUP,
        signingKey: loadSigningKey(env.TOKEN_SIGNING_KEY),
        now: Date.now,
        randomBytes: (n) => crypto.getRandomValues(new Uint8Array(n)),
      },
      request.headers.get("cf-connecting-ip") ?? "0.0.0.0",
      env,
    );
  },
};
