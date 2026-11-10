"""Campus running protocol adapted from the supplied script."""

import copy
import gzip
import hashlib
import json
import random
import re
import struct
import time
import urllib.parse
from base64 import b64decode, b64encode
from datetime import datetime, timedelta, timezone
from html.parser import HTMLParser

import httpx
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


class LoginForm(HTMLParser):
    """Read CAS hidden inputs independently of HTML attribute order."""

    def __init__(self, html: str):
        super().__init__()
        self.values: dict[str, str] = {}
        self.feed(html)

    def handle_starttag(self, tag: str, attrs):
        """Collect named input values.

        Args:
            tag: HTML tag name.
            attrs: Parsed HTML attributes.
        """
        attributes = dict(attrs)
        if tag == "input" and attributes.get("name"):
            self.values[attributes["name"]] = attributes.get("value") or ""


async def login(
    session: httpx.AsyncClient, form: dict, username: str, password: str, captcha: str
) -> tuple[str, str]:
    """Finish CAS login using the session that issued the captcha.

    Args:
        session: Cookie-preserving HTTP session.
        form: Hidden inputs from the login page.
        username: Campus account name.
        password: Account password, used only for this request.
        captcha: User-provided captcha text.

    Returns:
        Authorization token and protocol secret.

    Raises:
        ValueError: Authentication failed or the response is unsupported.
        httpx.HTTPError: A network request failed.
    """
    response = await session.post("https://pass.hust.edu.cn/cas/rsa")
    response.raise_for_status()
    public_key = serialization.load_der_public_key(
        b64decode(response.json()["publicKey"])
    )
    if not isinstance(public_key, RSAPublicKey):
        raise ValueError("Unsupported CAS public key")
    response = await session.post(
        LOGIN_URL,
        data={
            "ul": b64encode(public_key.encrypt(username.encode(), PKCS1v15())).decode(),
            "pl": b64encode(public_key.encrypt(password.encode(), PKCS1v15())).decode(),
            "code": captcha,
            "lt": form["lt"],
            "execution": form["execution"],
            "_eventId": "submit",
        },
    )
    response.raise_for_status()
    match = re.search(
        r"window\.app\.getUserName\(\s*'[^']*'\s*,\s*'([^']*)'\s*\)", response.text
    )
    if match is None or len(parts := match.group(1).split(".")) != 4:
        raise ValueError("CAS login did not return credentials")
    return ".".join(parts[:3]), parts[3]


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
