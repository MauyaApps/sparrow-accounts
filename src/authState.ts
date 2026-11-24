// Durable Object (SQLite-backed, бесплатный тариф). Один объект = один ключ (попытка входа, reauth-токен или счётчик).
import { applyHit, type Window } from "./store.ts";
import type { DOStateLike } from "./types.ts";

export class AuthState {
  private state: DOStateLike;
  constructor(state: DOStateLike, _env: unknown) {
    this.state = state;
  }

  async fetch(request: Request): Promise<Response> {
    const path = new URL(request.url).pathname;
    const body = (await request.json()) as Record<string, unknown>;
    const now = Date.now();
    const s = this.state.storage;

    if (path === "/put") {
      const ttlMs = Number(body.ttlMs);
      await s.put("v", { v: String(body.value), exp: now + ttlMs });
      await s.setAlarm(now + ttlMs + 1000);
      return Response.json({ ok: true });
    }
    if (path === "/take") {
      const e = await s.get<{ v: string; exp: number }>("v");
      await s.delete("v");
      return Response.json({ value: e && e.exp > now ? e.v : null });
    }
    if (path === "/hit") {
      const windowMs = Number(body.windowMs);
      const { next, result } = applyHit(await s.get<Window>("w"), now, Number(body.limit), windowMs);
      await s.put("w", next);
      await s.setAlarm(next.start + windowMs + 1000);
      return Response.json(result);
    }
    return new Response("not found", { status: 404 });
  }

  /** Просроченное состояние стирается само. */
  async alarm(): Promise<void> {
    await this.state.storage.deleteAll();
  }
}
