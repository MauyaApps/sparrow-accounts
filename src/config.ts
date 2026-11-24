// Единственное место, где зашит домен. Переезд с workers.dev на купленный домен = правка BASE_DOMAIN.
export const BASE_DOMAIN = "sparrownet.workers.dev";

export const PRODUCTS = ["account", "pass", "calls", "radio", "mail"] as const;
export type Product = (typeof PRODUCTS)[number];

// Имена воркеров нужны только пока всё живёт на *.workers.dev
const WORKER_NAMES: Record<Product, string> = {
  account: "sparrow-account-api",
  pass: "sparrow-pass-api",
  calls: "sparrow-calls-api",
  radio: "sparrow-radio-api",
  mail: "sparrow-mail-api",
};

/** Хост продукта: на workers.dev это <worker>.<account>.workers.dev, на своём домене — <product>.<domain>. */
export function hostFor(product: Product, baseDomain: string = BASE_DOMAIN): string {
  return baseDomain.endsWith("workers.dev") ? `${WORKER_NAMES[product]}.${baseDomain}` : `${product}.${baseDomain}`;
}

export const ISSUER = `https://${hostFor("account")}`;
/** Источники, которым разрешён CORS (веб-клиенты продуктов). */
export const ALLOWED_ORIGINS: readonly string[] = PRODUCTS.map((p) => `https://${hostFor(p)}`);

export const TTL = {
  accessSec: 10 * 60,
  refreshSec: 30 * 24 * 3600, // скользящее окно
  refreshMaxSec: 180 * 24 * 3600, // абсолютный предел жизни сессии
  loginAttemptMs: 60_000,
  reauthMs: 120_000,
} as const;

export const LIMITS = {
  registerIp: { limit: 20, windowMs: 10 * 60_000 },
  loginIp: { limit: 30, windowMs: 10 * 60_000 },
  loginUser: { limit: 10, windowMs: 10 * 60_000 },
} as const;

export const MAX_BODY_BYTES = 16 * 1024;
