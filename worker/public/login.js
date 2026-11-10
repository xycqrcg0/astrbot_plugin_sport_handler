const ticket = location.hash.slice(1);
const status = document.querySelector("#status");
const form = document.querySelector("#login");
let publicKey;
let expires = 0;
let polling = false;

function encode(bytes) {
  return btoa(String.fromCharCode(...new Uint8Array(bytes)));
}

function decode(value) {
  return Uint8Array.from(atob(value), (character) => character.charCodeAt(0));
}

async function api(action, payload = {}) {
  const response = await fetch(`/api/user/${action}`, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ ticket, ...payload }), cache: "no-store",
  });
  const result = await response.json();
  if (!response.ok) throw new Error(result.message || "请求失败，请稍后重试。");
  return result;
}

async function refresh() {
  if (!/^[A-Za-z0-9_-]{43}$/.test(ticket)) {
    status.textContent = "请从机器人发送的专属链接打开此页面。";
    return;
  }
  try {
    const result = await api("status");
    expires = result.expires;
    if (result.status === "ready") {
      publicKey = result.public_key;
      document.querySelector("#captcha-image").src = `data:image/gif;base64,${result.captcha}`;
      status.textContent = "请输入账号、密码和验证码，链接有效期为 3 分钟。";
      form.hidden = false;
      polling = false;
    } else if (result.status === "submitted") {
      form.hidden = true;
      status.textContent = "已提交，正在等待机器人完成登录…";
      polling = true;
    } else {
      form.hidden = true;
      polling = false;
      status.textContent = result.message || "链接已失效，请返回机器人重新获取。";
    }
  } catch (error) {
    status.textContent = error.message;
    if (!expires || Date.now() >= expires) {
      polling = false;
      form.hidden = true;
    }
  }
  if (polling) setTimeout(refresh, 3000);
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = form.querySelector("button");
  button.disabled = true;
  try {
    if (Date.now() >= expires) throw new Error("链接已过期，请返回机器人重新获取。");
    const encoder = new TextEncoder();
    const credentials = encoder.encode(JSON.stringify({
      username: form.elements.username.value.trim(),
      password: form.elements.password.value,
      captcha: form.elements.captcha.value.trim(),
    }));
    const aes = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt"]);
    const rsa = await crypto.subtle.importKey("spki", decode(publicKey),
      { name: "RSA-OAEP", hash: "SHA-256" }, false, ["encrypt"]);
    const nonce = crypto.getRandomValues(new Uint8Array(12));
    const data = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: nonce, additionalData: encoder.encode(ticket) }, aes, credentials);
    const wrappedKey = await crypto.subtle.encrypt(
      { name: "RSA-OAEP" }, rsa, await crypto.subtle.exportKey("raw", aes));
    await api("submit", { envelope: { key: encode(wrappedKey), nonce: encode(nonce), data: encode(data) } });
    form.reset();
    form.hidden = true;
    polling = true;
    await refresh();
  } catch (error) {
    // Check status after a lost response before offering another submission.
    status.textContent = error.message;
    try {
      const result = await api("status");
      if (result.status !== "ready") {
        form.reset();
        await refresh();
      }
    } catch {
      form.hidden = true;
      status.textContent = "无法确认提交状态，请刷新页面查询，或返回机器人重新获取链接。";
    }
  } finally {
    button.disabled = false;
  }
});

await refresh();
