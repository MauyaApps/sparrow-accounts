// Эфемерное состояние: промежуточные шаги OPAQUE-входа, reauth-токены, счётчики попыток.
// Живёт в Durable Object, а не в памяти воркера (воркеров много, память у каждого своя).
import { sha256 } from "@noble/hashes/sha2.js";
import { toHex, utf8 } from "./bytes.ts";
import type { DONamespaceLike } from "./types.ts";

export interface HitResult {
  ok: boolean;
  retryAfterSec: number;
}

export interface StateStore {
  put(kind: string, key: string, value: string, ttlMs: number): Promise<void>;
  /** Прочитать и удалить за одну операцию: значение одноразовое. */
  take(kind: string, key: string): Promise<string | null>;
  /** Фиксированное окно: ok=false, когда обращений больше limit. */
  hit(key: string, limit: number, windowMs: number): Promise<HitResult>;
}

export interface Window {
  start: number;
  count: number;
}

/** Общая логика окна: используется и Durable Object, и тестовой памятью. */
export function applyHit(prev: Window | undefined, now: number, limit: number, windowMs: number): { next: Window; result: HitResult } {
  const cur = !prev || now - prev.start >= windowMs ? { start: now, count: 0 } : prev;
  const next = { start: cur.start, count: cur.count + 1 };
  return {
    next,
    result: { ok: next.count <= limit, retryAfterSec: Math.max(1, Math.ceil((next.start + windowMs - now) / 1000)) },
  };
}

export class MemoryStore implements StateStore {
  private values = new Map<string, { v: string; exp: number }>();
  private windows = new Map<string, Window>();
  private now: () => number;
  constructor(now: () => number = Date.now) {
    this.now = now;
  }
  async put(kind: string, key: string, value: string, ttlMs: number): Promise<void> {
    this.values.set(`${kind}:${key}`, { v: value, exp: this.now() + ttlMs });
  }
  async take(kind: string, key: string): Promise<string | null> {
    const k = `${kind}:${key}`;
    const e = this.values.get(k);
    this.values.delete(k);
    return e && e.exp > this.now() ? e.v : null;
  }
  async hit(key: string, limit: number, windowMs: number): Promise<HitResult> {
    const { next, result } = applyHit(this.windows.get(key), this.now(), limit, windowMs);
    this.windows.set(key, next);
    return result;
  }
}

/** Адаптер к Durable Object. Имена объектов хешируются, чтобы IP и логины не светились в именах. */
export class DoStateStore implements StateStore {
  private ns: DONamespaceLike;
  constructor(ns: DONamespaceLike) {
    this.ns = ns;
  }
  private async call<T>(name: string, path: string, body: unknown): Promise<T> {
    const stub = this.ns.get(this.ns.idFromName(toHex(sha256(utf8(name)))));
    const res = await stub.fetch(`https://state${path}`, { method: "POST", body: JSON.stringify(body) });
    if (!res.ok) throw new Error(`state store error ${res.status}`);
    return (await res.json()) as T;
  }
  async put(kind: string, key: string, value: string, ttlMs: number): Promise<void> {
    await this.call(`${kind}:${key}`, "/put", { value, ttlMs });
  }
  async take(kind: string, key: string): Promise<string | null> {
    return (await this.call<{ value: string | null }>(`${kind}:${key}`, "/take", {})).value;
  }
  async hit(key: string, limit: number, windowMs: number): Promise<HitResult> {
    return this.call<HitResult>(`rl:${key}`, "/hit", { limit, windowMs });
  }
}
