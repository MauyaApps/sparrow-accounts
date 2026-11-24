// Минимальные структурные типы Cloudflare-биндингов (чтобы не тянуть @cloudflare/workers-types).
export interface D1Stmt {
  bind(...values: unknown[]): D1Stmt;
  first<T = Record<string, unknown>>(): Promise<T | null>;
  run(): Promise<{ meta: { changes: number } }>;
  all<T = Record<string, unknown>>(): Promise<{ results: T[] }>;
}
export interface D1Like {
  prepare(sql: string): D1Stmt;
  batch(stmts: D1Stmt[]): Promise<unknown[]>;
}

export interface DOStubLike {
  fetch(url: string, init?: { method?: string; body?: string }): Promise<Response>;
}
export interface DONamespaceLike {
  idFromName(name: string): unknown;
  get(id: unknown): DOStubLike;
}
export interface DOStateLike {
  storage: {
    get<T>(key: string): Promise<T | undefined>;
    put(key: string, value: unknown): Promise<void>;
    delete(key: string): Promise<boolean>;
    deleteAll(): Promise<void>;
    setAlarm(ms: number): Promise<void>;
  };
}

export interface Env {
  DB: D1Like;
  AUTH_STATE: DONamespaceLike;
  /** wrangler secret: строка serverSetup из opaque.server.createSetup() */
  OPAQUE_SERVER_SETUP: string;
  /** wrangler secret: 32 байта Ed25519-seed в base64url */
  TOKEN_SIGNING_KEY: string;
  LOCAL_ADMIN_ENABLED?: string;
  LOCAL_ADMIN_PASSWORD?: string;
  LOCAL_ADMIN_SESSION_SECRET?: string;
  LOCAL_ADMIN_ORIGIN?: string;
}
