// Main OPAQUE property: passwords never leave the client.
import test from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { Buffer } from "node:buffer";
import { confirmPassword, login, makeStand, register, setNewPassword } from "./harness.ts";

const PASSWORD = "Zq7!needle-PASSWORD-9f3a";
const NEXT = "Yw2@needle-NEXT-77bd";

function variants(secret: string): string[] {
  const raw = Buffer.from(secret, "utf8");
  return [
    secret,
    encodeURIComponent(secret),
    raw.toString("base64"),
    raw.toString("base64").replace(/=+$/, ""),
    raw.toString("base64url"),
    raw.toString("hex"),
    JSON.stringify(secret).slice(1, -1),
  ];
}

test("passwords are absent from requests, responses, database, and logs in common encodings", async () => {
  const logs: string[] = [];
  const orig = { log: console.log, error: console.error, warn: console.warn, info: console.info, debug: console.debug };
  for (const k of Object.keys(orig) as (keyof typeof orig)[]) console[k] = (...a: unknown[]) => void logs.push(a.map(String).join(" "));

  const s = await makeStand();
  try {
    await register(s, "alice", PASSWORD);
    const t = (await login(s, "alice", PASSWORD)).res.body;
    await login(s, "alice", NEXT); // A wrong password must not leak either.
    const reauth = await confirmPassword(s, t.accessToken, PASSWORD);
    await setNewPassword(s, t.accessToken, reauth.body.reauthToken, NEXT);
    await login(s, "alice", NEXT);
  } finally {
    Object.assign(console, orig);
  }

  const haystacks: Record<string, string> = {
    wire: JSON.stringify(s.wire),
    db: JSON.stringify({
      users: s.raw.prepare("SELECT * FROM users").all(),
      sessions: s.raw.prepare("SELECT * FROM sessions").all(),
    }),
    logs: logs.join("\n"),
  };
  assert.ok(s.wire.length >= 10, "real exchanges were recorded");
  for (const secret of [PASSWORD, NEXT]) {
    for (const v of variants(secret)) {
      for (const [where, text] of Object.entries(haystacks)) {
        assert.ok(!text.includes(v), `found ${v} in ${where}`);
      }
    }
  }
});

test("server rejects request bodies with a password field without echoing its value", async () => {
  const s = await makeStand();
  for (const [path, body] of [
    ["/v1/register/start", { username: "alice", password: PASSWORD }],
    ["/v1/login/start", { username: "alice", password: PASSWORD }],
    ["/v1/register/finish", { username: "alice", registrationRecord: "AAAA", password: PASSWORD }],
  ] as const) {
    const r = await s.call("POST", path, body);
    assert.equal(r.status, 400, path);
    assert.ok(!JSON.stringify(r.body).includes(PASSWORD));
  }
  assert.equal(s.raw.prepare("SELECT COUNT(*) AS n FROM users").get()!.n, 0);
});

test("same passwords produce different records", async () => {
  const s = await makeStand();
  await register(s, "alice", PASSWORD);
  await register(s, "bobby", PASSWORD);
  const rows = s.raw.prepare("SELECT opaque_record FROM users ORDER BY username").all() as { opaque_record: string }[];
  assert.equal(rows.length, 2);
  assert.notEqual(rows[0]!.opaque_record, rows[1]!.opaque_record);
});

test("server code does not use OPAQUE client functions", () => {
  const dir = new URL("../src/", import.meta.url);
  for (const f of readdirSync(dir).filter((n) => n.endsWith(".ts") && n !== "opaque.d.ts")) {
    const text = readFileSync(new URL(f, dir), "utf8");
    assert.ok(!/opaque\.client|client\.(startLogin|finishLogin|startRegistration|finishRegistration)/.test(text), `${f} calls client.*`);
  }
});
