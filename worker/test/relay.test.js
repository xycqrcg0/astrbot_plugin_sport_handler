import assert from "node:assert/strict";
import { test } from "node:test";
import worker, { LoginTicket } from "../src/worker.js";

const secret = "test-relay-secret-with-at-least-32-characters";
const ticket = "a".repeat(43);
const envelope = { key: "k".repeat(344), nonce: "n".repeat(16), data: "ciphertext" };

function environment() {
  const objects = new Map();
  return {
    BOT_SECRET: secret,
    ASSETS: { fetch: async () => new Response("login page") },
    objects,
    LOGINS: {
      idFromName: (name) => name,
      get(name) {
        if (!objects.has(name)) {
          const data = new Map();
          let tail = Promise.resolve();
          const storage = {
            get: async (key) => structuredClone(data.get(key)),
            put: async (key, value) => data.set(key, structuredClone(value)),
            delete: async (key) => data.delete(key),
            deleteAll: async () => data.clear(),
            setAlarm: async () => {},
            transaction(callback) {
              const result = tail.then(() => callback(storage));
              tail = result.catch(() => {});
              return result;
            },
          };
          objects.set(name, { storage, object: new LoginTicket({ storage }) });
        }
        return objects.get(name).object;
      },
    },
  };
}

async function call(env, action, payload = {}, role = "bot", headers = {}) {
  return worker.fetch(new Request(`https://login.example/api/${role}/${action}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json", "Origin": "https://login.example",
      ...(role === "bot" ? { Authorization: `Bearer ${secret}` } : {}), ...headers,
    },
    body: JSON.stringify({ ticket, ...payload }),
  }), env);
}

test("bot authentication and same-origin browser requests are required", async () => {
  const env = environment();
  assert.equal((await call(env, "create", {}, "bot", { Authorization: "Bearer wrong" })).status, 403);
  assert.equal((await call(env, "status", {}, "user", { Origin: "https://other.example" })).status, 403);
  assert.equal(env.objects.size, 0);
  env.BOT_SECRET = "short";
  assert.equal((await call(env, "create")).status, 503);
});

test("submission is single-use and ciphertext is available only to the bot", async () => {
  const env = environment();
  assert.equal((await call(env, "create", { public_key: "key", captcha: "gif" })).status, 200);
  assert.equal((await call(env, "create", { public_key: "key", captcha: "gif" })).status, 409);
  const status = await (await call(env, "status", {}, "user")).json();
  assert.equal(status.captcha, "gif");
  const results = await Promise.all([
    call(env, "submit", { envelope }, "user"), call(env, "submit", { envelope }, "user"),
  ]);
  assert.deepEqual(results.map((item) => item.status).sort(), [200, 409]);
  const publicStatus = await (await call(env, "status", {}, "user")).json();
  assert.equal(publicStatus.envelope, undefined);
  assert.equal(publicStatus.captcha, undefined);
  assert.deepEqual((await (await call(env, "poll")).json()).envelope, envelope);
  assert.equal((await call(env, "poll", {}, "user")).status, 404);
  assert.equal((await call(env, "complete", { success: true })).status, 200);
  assert.equal((await call(env, "complete", { success: true })).status, 200);
  const completed = await (await call(env, "status", {}, "user")).json();
  assert.equal(completed.status, "success");
  const stored = await env.objects.get(ticket).storage.get("login");
  assert.equal(stored.envelope, undefined);
  assert.equal(stored.public_key, undefined);
});

test("expiry, revocation and alarms discard ticket data", async () => {
  const env = environment();
  await call(env, "create", { public_key: "key", captcha: "gif" });
  const storage = env.objects.get(ticket).storage;
  const record = await storage.get("login");
  record.expires = Date.now() - 1;
  await storage.put("login", record);
  assert.equal((await call(env, "status", {}, "user")).status, 410);
  assert.equal(await storage.get("login"), undefined);
  await call(env, "create", { public_key: "key", captcha: "gif" });
  await call(env, "revoke");
  assert.equal((await call(env, "submit", { envelope }, "user")).status, 410);
  await call(env, "create", { public_key: "key", captcha: "gif" });
  await env.objects.get(ticket).object.alarm();
  assert.equal(await storage.get("login"), undefined);
});

test("static pages have no-store and CSP headers", async () => {
  const response = await worker.fetch(new Request("https://login.example/"), environment());
  assert.equal(response.headers.get("cache-control"), "no-store");
  assert.match(response.headers.get("content-security-policy"), /frame-ancestors 'none'/);
});
