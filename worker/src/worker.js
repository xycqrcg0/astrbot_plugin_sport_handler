/** Short-lived login mailbox. Campus tokens and private keys stay in AstrBot. */

function json(data, status = 200) {
  return Response.json(data, {
    status, headers: { "Cache-Control": "no-store", "Referrer-Policy": "no-referrer" },
  });
}

export default {
  async fetch(request, env) {
    let response;
    try {
      const url = new URL(request.url);
      if (!url.pathname.startsWith("/api/")) {
        response = await env.ASSETS.fetch(request);
      } else if (request.method !== "POST") {
        response = json({ message: "Method not allowed" }, 405);
      } else {
        const bot = url.pathname.startsWith("/api/bot/");
        const actions = bot ? ["create", "poll", "challenge", "complete", "revoke"] : ["status", "submit", "verify"];
        const prefix = bot ? "/api/bot/" : "/api/user/";
        const action = url.pathname.slice(prefix.length);
        if (!url.pathname.startsWith(prefix) || !actions.includes(action)) {
          response = json({ message: "Not found" }, 404);
        } else if (bot && (typeof env.BOT_SECRET !== "string" || env.BOT_SECRET.length < 32)) {
          response = json({ message: "Relay secret is not configured" }, 503);
        } else {
          let authorized = true;
          if (bot) {
            const encoder = new TextEncoder();
            const actual = new Uint8Array(await crypto.subtle.digest("SHA-256",
              encoder.encode(request.headers.get("Authorization") || "")));
            const expected = new Uint8Array(await crypto.subtle.digest("SHA-256",
              encoder.encode(`Bearer ${env.BOT_SECRET}`)));
            let difference = 0;
            for (let i = 0; i < expected.length; i++) difference |= expected[i] ^ actual[i];
            authorized = difference === 0;
          } else {
            authorized = request.headers.get("Origin") === url.origin;
          }
          if (!authorized) {
            response = json({ message: "Unauthorized" }, 403);
          } else if (!(request.headers.get("Content-Type") || "").startsWith("application/json")) {
            response = json({ message: "JSON is required" }, 415);
          } else {
            const limit = bot && action === "create" ? 512000 : 8192;
            // Stream with a bound even when Content-Length is absent or incorrect.
            const reader = request.body?.getReader();
            const chunks = [];
            let length = 0;
            if (reader) {
              while (true) {
                const { value, done } = await reader.read();
                if (done) break;
                length += value.byteLength;
                if (length > limit) {
                  await reader.cancel();
                  return json({ message: "Request too large" }, 413);
                }
                chunks.push(value);
              }
            }
            const bytes = new Uint8Array(length);
            let offset = 0;
            for (const chunk of chunks) {
              bytes.set(chunk, offset);
              offset += chunk.byteLength;
            }
            let payload;
            try {
              payload = JSON.parse(new TextDecoder().decode(bytes));
            } catch {
              return json({ message: "Invalid JSON" }, 400);
            }
            if (!payload || typeof payload.ticket !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(payload.ticket)) {
              response = json({ message: "Invalid ticket" }, 400);
            } else {
              const object = env.LOGINS.get(env.LOGINS.idFromName(payload.ticket));
              response = await object.fetch(new Request(`https://ticket.internal/${action}`, {
                method: "POST", body: JSON.stringify({ payload, bot }),
              }));
            }
          }
        }
      }
    } catch {
      response = json({ message: "登录服务暂时不可用，请稍后重试。" }, 503);
    }
    const headers = new Headers(response.headers);
    headers.set("Cache-Control", "no-store");
    headers.set("Referrer-Policy", "no-referrer");
    headers.set("X-Content-Type-Options", "nosniff");
    headers.set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'");
    return new Response(response.body, { status: response.status, headers });
  },
};

export class LoginTicket {
  constructor(ctx) {
    this.ctx = ctx;
  }

  async fetch(request) {
    const { payload, bot } = await request.json();
    const action = new URL(request.url).pathname.slice(1);
    return this.ctx.storage.transaction(async (transaction) => {
      let record = await transaction.get("login");
      if (action === "create" && bot) {
        if (record) return json({ message: "Ticket already exists" }, 409);
        if (typeof payload.public_key !== "string" || payload.public_key.length > 1024 ||
            typeof payload.captcha !== "string" || payload.captcha.length > 450000) {
          return json({ message: "Invalid challenge" }, 400);
        }
        record = {
          status: "ready", public_key: payload.public_key, captcha: payload.captcha,
          expires: Date.now() + 180000,
        };
        await transaction.put("login", record);
        // SQLite storage operations here participate in the same transaction.
        await this.ctx.storage.setAlarm(record.expires);
        return json({ status: "ready", expires: record.expires });
      }
      if (!record || record.expires <= Date.now()) {
        await transaction.delete("login");
        return json({ status: "expired", message: "链接已失效，请返回机器人重新获取。" }, 410);
      }
      if (action === "revoke" && bot) {
        await transaction.delete("login");
        return json({ status: "cancelled" });
      }
      if (action === "poll" && bot) {
        return json({ status: record.status, envelope: record.envelope });
      }
      if (action === "challenge" && bot) {
        if (record.status === "submitted") {
          record.status = "challenge";
          delete record.envelope;
          record.expires = Date.now() + 180000;
          await transaction.put("login", record);
          await this.ctx.storage.setAlarm(record.expires);
        }
        return ["challenge", "verified_input"].includes(record.status)
          ? json({ status: record.status }) : json({ message: "Invalid challenge state" }, 409);
      }
      if (action === "status" && !bot) {
        return json({
          status: record.status, expires: record.expires, message: record.message,
          public_key: ["ready", "challenge"].includes(record.status) ? record.public_key : undefined,
          captcha: record.status === "ready" ? record.captcha : undefined,
        });
      }
      if (["submit", "verify"].includes(action) && !bot) {
        if (record.status !== (action === "verify" ? "challenge" : "ready")) return json({ message: "此链接已提交，请等待结果或重新获取链接。" }, 409);
        const envelope = payload.envelope;
        if (!envelope || typeof envelope.key !== "string" || envelope.key.length !== 344 ||
            typeof envelope.nonce !== "string" || envelope.nonce.length !== 16 ||
            typeof envelope.data !== "string" || envelope.data.length > 6000 || !envelope.data) {
          return json({ message: "Invalid encrypted submission" }, 400);
        }
        record.status = action === "verify" ? "verified_input" : "submitted";
        record.envelope = { key: envelope.key, nonce: envelope.nonce, data: envelope.data };
        delete record.captcha;
        await transaction.put("login", record);
        return json({ status: record.status });
      }
      if (action === "complete" && bot) {
        // Completion retries are idempotent after a lost network response.
        if (["success", "error"].includes(record.status)) return json({ status: record.status });
        if (!["submitted", "challenge", "verified_input"].includes(record.status) || typeof payload.success !== "boolean") {
          return json({ message: "No pending submission" }, 409);
        }
        record = {
          status: payload.success ? "success" : "error", expires: record.expires,
          message: payload.success
            ? "登录成功，已绑定账号。返回机器人发送 /cam run 即可执行。"
            : "登录未完成，请返回机器人重新发送 /cam web，检查账号、密码和验证码。",
        };
        await transaction.put("login", record);
        return json({ status: record.status });
      }
      return json({ message: "Not found" }, 404);
    });
  }

  async alarm() {
    await this.ctx.storage.deleteAll();
  }
}
