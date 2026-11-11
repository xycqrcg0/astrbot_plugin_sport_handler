"""Campus running protocol adapted from the supplied script."""

import asyncio
import copy
import gzip
import hashlib
import io
import json
import random
import re
import struct
import time
import urllib.parse
import uuid
from base64 import b64decode, b64encode
from datetime import datetime, timedelta, timezone
from html.parser import HTMLParser

import httpx
import qrcode
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers.modes import CBC, ECB
from cryptography.hazmat.primitives.padding import PKCS7

LOGIN_URL = (
    "https://pass.hust.edu.cn/cas/login?service="
    "https%3A%2F%2Fpetzjk.hust.edu.cn%2Fcgapp-server%2Fcas%2FappLogin"
)
USER_AGENT = "Mozilla/5.0 (Linux; Android 16) AppleWebKit/537.36 Mobile Safari/537.36 agentweb/4.0.2"
CHINA_TIME = timezone(timedelta(hours=8))


class CampusLoginError(ValueError):
    """Represent a login failure using a safe reason and user-facing message."""

    def __init__(self, reason: str, message: str):
        super().__init__(message)
        self.reason = reason


class LoginForm(HTMLParser):
    """Read CAS hidden inputs independently of HTML attribute order."""

    def __init__(self, html: str):
        super().__init__()
        self.values: dict[str, str] = {}
        self.error_parts: list[str] = []
        self.error_depth = 0
        self.dynamic_input = False
        self.action = None
        self.feed(html)

    def handle_starttag(self, tag: str, attrs):
        """Collect named input values.

        Args:
            tag: HTML tag name.
            attrs: Parsed HTML attributes.
        """
        attributes = dict(attrs)
        if tag == "form" and attributes.get("id") == "loginForm":
            self.action = attributes.get("action")
        if (
            tag == "input"
            and attributes.get("id") == "phoneCode"
            and attributes.get("type") != "hidden"
        ):
            self.dynamic_input = True
        if tag not in {"input", "img", "br", "hr", "meta", "link"}:
            if self.error_depth:
                self.error_depth += 1
            elif (
                attributes.get("id") in {"errormsg", "errormsghide"}
                or "error-msg-box" in (attributes.get("class") or "").split()
            ):
                self.error_depth = 1
        if tag == "input" and attributes.get("name"):
            self.values[attributes["name"]] = attributes.get("value") or ""

    def handle_endtag(self, tag: str):
        """Track the end of nested error containers.

        Args:
            tag: Closing HTML tag name.
        """
        if self.error_depth and tag not in {"input", "img", "br", "hr", "meta", "link"}:
            self.error_depth -= 1

    def handle_data(self, data: str):
        """Collect error text for classification without exposing raw responses.

        Args:
            data: Text inside an HTML element.
        """
        if self.error_depth and data.strip():
            self.error_parts.append(data.strip())


async def login(
    session: httpx.AsyncClient,
    form: dict,
    username: str,
    password: str,
    captcha: str,
    ask_code=None,
    *,
    dynamic_code: str = "",
    target: str = LOGIN_URL,
) -> tuple[str, str]:
    """Finish CAS login using the session that issued the captcha.

    Args:
        session: Cookie-preserving HTTP session.
        form: Hidden inputs from the login page.
        username: Campus account name.
        password: Account password, used only for this request.
        captcha: User-provided captcha text.
        ask_code: Async callback that collects the school's dynamic code.
        dynamic_code: One-time code for the second submission.
        target: Validated CAS login form URL.

    Returns:
        Authorization token and protocol secret.

    Raises:
        ValueError: Authentication failed or the response is unsupported.
        httpx.HTTPError: A network request failed.
    """
    response = await session.post(
        "https://pass.hust.edu.cn/cas/rsa",
        headers={"Referer": LOGIN_URL, "X-Requested-With": "XMLHttpRequest"},
    )
    response.raise_for_status()
    try:
        key_material = response.json()["publicKey"]
        public_key = (
            serialization.load_pem_public_key(key_material.encode())
            if "BEGIN" in key_material
            else serialization.load_der_public_key(b64decode(key_material))
        )
    except (ValueError, KeyError, TypeError, AttributeError) as exc:
        raise CampusLoginError(
            "rsa_response", "校园认证返回的 RSA 公钥格式异常"
        ) from exc
    if not isinstance(public_key, RSAPublicKey):
        raise CampusLoginError("rsa_type", "校园认证返回了不支持的公钥类型")
    post_data = dict(form)
    for key in ("un", "pd", "username", "password", "rsa"):
        post_data.pop(key, None)
    user_agent = session.headers.get("User-Agent", USER_AGENT)
    post_data.update(
        {
            "ul": b64encode(public_key.encrypt(username.encode(), PKCS1v15())).decode(),
            "pl": b64encode(public_key.encrypt(password.encode(), PKCS1v15())).decode(),
            "code": captcha,
            "phoneCode": dynamic_code,
            "_eventId": post_data.get("_eventId") or "submit",
            "ua": json.dumps(
                {
                    "ua": user_agent,
                    "browser": {"name": "Chrome", "major": "120"},
                    "device": {"type": "mobile"},
                    "os": {"name": "Android", "version": "16"},
                },
                separators=(",", ":"),
            ),
            "visitorId": hashlib.sha256(user_agent.encode()).hexdigest()[:32],
        }
    )
    response = await session.post(
        target,
        data=post_data,
        headers={"Origin": "https://pass.hust.edu.cn", "Referer": LOGIN_URL},
    )
    response.raise_for_status()
    bundle = parse_login_callback(response.text)
    if bundle:
        return bundle
    challenge = LoginForm(response.text)
    if challenge.dynamic_input:
        if dynamic_code:
            raise CampusLoginError("dynamic_code", "学校未接受动态验证码，请重新登录")
        if ask_code and challenge.values.get("execution") and challenge.action:
            destination = urllib.parse.urljoin(str(response.url), challenge.action)
            url = httpx.URL(destination)
            if url.copy_with(query=None, fragment=None) != httpx.URL(
                "https://pass.hust.edu.cn/cas/login"
            ):
                raise CampusLoginError("challenge_action", "学校动态验证表单地址异常")
            code = (await ask_code()).strip()
            if not code or len(code) > 64:
                raise CampusLoginError("dynamic_code", "动态验证码格式无效")
            return await login(
                session,
                challenge.values,
                username,
                password,
                "",
                dynamic_code=code,
                target=destination,
            )
        raise CampusLoginError("second_factor", "学校要求动态验证，未取得完整验证表单")
    error_text = " ".join(challenge.error_parts)
    if "动态验证码" in error_text or "企业微信" in error_text:
        raise CampusLoginError(
            "second_factor", "校园认证要求动态验证码，当前登录流程尚未完成二次验证"
        )
    if "验证码" in error_text:
        raise CampusLoginError(
            "captcha", "校园认证未通过图片验证码校验，请获取新验证码重试"
        )
    if "密码" in error_text or "用户名" in error_text:
        raise CampusLoginError("credentials", "校园认证提示账号或密码校验失败")
    if any(word in error_text for word in ("锁定", "冻结", "禁用")):
        raise CampusLoginError("account_restricted", "校园认证提示账号已被限制登录")
    raise CampusLoginError(
        "missing_callback", "校园认证未返回登录凭据，需要检查登录回调或额外验证步骤"
    )


def parse_login_callback(html: str) -> tuple[str, str] | None:
    """Read the campus app's shared CAS callback.

    Args:
        html: Campus callback page.

    Returns:
        App token and signing secret when the callback is present.

    Raises:
        CampusLoginError: The callback contains malformed credentials.
    """
    match = re.search(
        r"""getUserName\s*\(\s*["'][^"']*["']\s*,\s*["']([^"']+)["']""", html
    )
    if match is None:
        return None
    parts = match.group(1).split(".")
    if len(parts) < 4 or not all(parts[:4]):
        raise CampusLoginError("token_bundle", "校园认证回调中的登录凭据格式异常")
    return ".".join(parts[:3]), parts[3]


async def qr_login(session: httpx.AsyncClient, send_image) -> tuple[str, str]:
    """Issue a campus QR code and redeem its confirmation in the issuing session.

    Args:
        session: Cookie-preserving campus HTTP client.
        send_image: Async function delivering PNG bytes to the initiating user.

    Returns:
        Campus app token and signing secret.

    Raises:
        CampusLoginError: The QR code expired or CAS returned an unexpected redirect.
        httpx.HTTPError: A campus request failed.
    """
    page = await session.get(LOGIN_URL)
    page.raise_for_status()
    ticket = str(uuid.uuid4())
    params = {"uuid": ticket, "service": httpx.URL(LOGIN_URL).params["service"]}
    scan_url = httpx.URL("https://pass.hust.edu.cn/cas/qyQrLogin", params=params)
    image = io.BytesIO()
    qrcode.make(str(scan_url)).save(image, format="PNG")
    deadline = time.monotonic() + 180
    await send_image(image.getvalue())
    while time.monotonic() < deadline:
        await asyncio.sleep(3)
        response = await session.get(
            "https://pass.hust.edu.cn/cas/checkQRCodeScan",
            params={"uuid": ticket, "random": str(time.time_ns())},
            headers={"Referer": LOGIN_URL, "X-Requested-With": "XMLHttpRequest"},
        )
        response.raise_for_status()
        if not response.content.strip():
            continue
        result = response.json()
        target = result.get("redirect_url") if isinstance(result, dict) else None
        if not isinstance(target, str) or not target:
            raise CampusLoginError("qr_response", "学校返回了无法识别的扫码结果")
        url = page.url.join(target)
        for _ in range(10):
            if (
                url.scheme != "https"
                or url.host not in {"pass.hust.edu.cn", "petzjk.hust.edu.cn"}
                or url.port
                or url.userinfo
            ):
                break
            response = await session.get(url, follow_redirects=False)
            if response.is_redirect and response.headers.get("location"):
                url = url.join(response.headers["location"])
                continue
            response.raise_for_status()
            if url.host == "petzjk.hust.edu.cn":
                bundle = parse_login_callback(response.text)
                if bundle:
                    return bundle
            break
        raise CampusLoginError("qr_callback", "扫码后未收到校园跑登录凭据")
    raise CampusLoginError("qr_expired", "二维码已过期，请重新发送 /cam login")


class CrighClient:
    """Sign campus service requests using a user's saved credentials."""

    MASK = (1 << 64) - 1
    BASE_URL = "https://petzjk.hust.edu.cn/cgapp-server"
    CRIGH_SECRET_KEY = bytes.fromhex(
        "ad8dad2869c5e017303e5f48858db3129bf4d07a47d85beaaaa9d26f436d232a"
    )

    def __init__(self, session: httpx.AsyncClient, token: str, secret: str):
        raw = b64decode(secret)[4:]
        decryptor = Cipher(AES(self.CRIGH_SECRET_KEY), CBC(raw[:16])).decryptor()
        self.a = (decryptor.update(raw[16:]) + decryptor.finalize()).decode()
        self.token, self.secret, self.session = token, secret, session

    def get_timestamp(self, t_ms: int) -> int:
        """Mix the timestamp according to the campus protocol.

        Args:
            t_ms: Unix time in milliseconds.

        Returns:
            Mixed unsigned timestamp.
        """
        t_ms = ((t_ms ^ (t_ms >> 30)) * 0xBF58476D1CE4E5B9) & self.MASK
        t_ms = ((t_ms ^ (t_ms >> 27)) * 0x94D049BB133111EB) & self.MASK
        return t_ms ^ (t_ms >> 31)

    def get_sign(self, path: str, kv: dict[str, str], t_ms: int) -> str:
        """Sign the path, sorted form values and timestamp.

        Args:
            path: Campus API path.
            kv: Combined query and body parameters.
            t_ms: Unix time in milliseconds.

        Returns:
            Protocol-specific signature.
        """
        x = path + "".join(
            k + urllib.parse.unquote_plus(v) for k, v in sorted(kv.items())
        )
        msg = (
            self.a.encode()
            + x.encode()
            + struct.pack(">Q", t_ms)
            + self.a[::-1].encode()
        )
        d = hashlib.sha256(msg).hexdigest()
        return f"{d[:12]}1{d[12:27]}9{d[27:34]}9{d[34]}s{d[35:54]}t{d[54:]}"

    async def request(
        self,
        method: str,
        path: str,
        params: dict[str, str] | None = None,
        data: dict[str, str] | None = None,
        file: tuple[str, str] | None = None,
    ) -> dict:
        """Send a signed request without automatically retrying writes.

        Args:
            method: HTTP method.
            path: Campus API path.
            params: Query parameters.
            data: Form parameters.
            file: Optional filename and file content.

        Returns:
            JSON response from the service.

        Raises:
            PermissionError: The saved login has expired.
            ValueError: The service returned invalid JSON.
            httpx.HTTPError: The request failed.
        """
        params, data = params or {}, data or {}
        t_ms = time.time_ns() // 1000000
        response = await self.session.request(
            method,
            self.BASE_URL + path,
            headers={
                "imei": "ffffffff-a681-9aa3-a681-9aa300000000",
                "v1": hashlib.md5(str(t_ms).encode()).hexdigest(),
                "timestamp": str(self.get_timestamp(t_ms)),
                "sign": self.get_sign(path, params | data, t_ms),
                "cgAuthorization": self.token,
                "User-Agent": "hzkjapp/1.2.1(Linux;Android 16;OnePlus/BP4A.251205.006)",
            },
            params=params,
            data=data or None,
            files={file[0]: (file[0], file[1], "application/octet-stream")}
            if file
            else None,
        )
        if response.status_code in {401, 403}:
            raise PermissionError("Campus login expired")
        response.raise_for_status()
        result = response.json()
        if not isinstance(result, dict):
            raise ValueError("Unexpected campus response")
        if str(result.get("code")) in {"401", "403"}:
            raise PermissionError("Campus login expired")
        return result


def make_data(
    orig_data: dict, name: str, student_id: str, sport_id: str, end_time: datetime
) -> tuple[dict, list[float]]:
    """Adapt the supplied track and generate sensor samples as in the script.

    Args:
        orig_data: Original track template.
        name: Campus account display name.
        student_id: Campus student number.
        sport_id: Server-issued activity ID.
        end_time: Activity end time in local campus time.

    Returns:
        Adapted activity and sensor samples.

    Raises:
        ValueError: The template duration or coordinates are invalid.
    """
    time_format = "%Y-%m-%d %H:%M:%S"
    h, m, s = map(int, orig_data["activeTime"].split(":"))
    elapsed = h * 3600 + m * 60 + s
    if not (0 <= m < 60 and 0 <= s < 60 and 0 < elapsed <= 86400):
        raise ValueError("Invalid template duration")
    if not isinstance(orig_data["coordinate"], list) or not orig_data["coordinate"]:
        raise ValueError("Missing template coordinates")
    data = copy.deepcopy(orig_data)
    data.update(
        name=name,
        xh=student_id,
        sportId=sport_id,
        beginTime=(end_time - timedelta(seconds=elapsed)).strftime(time_format),
        endTime=end_time.strftime(time_format),
    )
    delta_ms = int(
        (
            end_time - datetime.strptime(orig_data["endTime"], time_format)
        ).total_seconds()
        * 1000
    )
    for coord in data["coordinate"]:
        if coord["t"] != 0:
            coord["t"] += delta_ms
    sensor = [round(9.7936 + random.uniform(-2.2, 2.2), 6) for _ in range(20 * elapsed)]
    return data, sensor


def encode_activity(data: dict, sensor: list[float], secret: str) -> tuple[str, str]:
    """Encode activity and sensor payloads using the supplied protocol.

    Args:
        data: Adapted activity data.
        sensor: Sensor samples.
        secret: User-specific protocol secret.

    Returns:
        Base64 activity ciphertext and compressed sensor payload.
    """
    plaintext = json.dumps(data, separators=(",", ":"), ensure_ascii=False).encode()
    padder = PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    encryptor = Cipher(AES(secret[:16].encode()), ECB()).encryptor()
    activity = b64encode(encryptor.update(padded) + encryptor.finalize()).decode()
    sensor_zip = b64encode(
        gzip.compress(json.dumps(sensor, separators=(",", ":")).encode())
    ).decode()
    return activity, sensor_zip
