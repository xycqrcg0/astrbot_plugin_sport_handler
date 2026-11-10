"""Authenticated Worker relay for browser-based campus login."""

from __future__ import annotations

import asyncio
import base64
import json
import secrets
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

import httpx
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from astrbot.api.event import AstrMessageEvent, MessageChain

from .client import LOGIN_URL, USER_AGENT, CampusLoginError, LoginForm

if TYPE_CHECKING:
    from .main import Main


@dataclass
class PendingLogin:
    """Keep campus cookies and decryption keys inside the bot process."""

    user_key: str
    origin: str
    session: httpx.AsyncClient
    form: dict
    key: rsa.RSAPrivateKey
    deadline: float
    task: asyncio.Task | None = None


class WorkerLogin:
    """Issue short-lived links and retrieve encrypted login submissions."""

    def __init__(self, plugin: Main, config: dict):
        self.plugin = plugin
        self.url = str(config.get("worker_url", "")).strip().rstrip("/")
        self.secret = str(config.get("worker_secret", ""))
        self.pending: dict[str, PendingLogin] = {}
        self.issuing = 0
        self.http = httpx.AsyncClient(timeout=15)

    async def _request(self, action: str, ticket: str, **payload) -> dict:
        """Call an authenticated bot endpoint without logging its payload.

        Args:
            action: Relay operation name.
            ticket: Opaque one-time ticket.
            payload: Operation-specific fields.

        Returns:
            Relay response object.

        Raises:
            httpx.HTTPError: The relay request failed.
            ValueError: The relay returned an invalid response.
        """
        response = await self.http.post(
            f"{self.url}/api/bot/{action}",
            headers={"Authorization": f"Bearer {self.secret}"},
            json={"ticket": ticket, **payload},
        )
        response.raise_for_status()
        result = response.json()
        if not isinstance(result, dict):
            raise ValueError("Invalid relay response")
        return result

    async def issue(self, event: AstrMessageEvent, user_key: str) -> str:
        """Create a campus captcha and publish a user-bound login ticket.

        Args:
            event: Private bot event that initiated login.
            user_key: Trusted platform user identity.

        Returns:
            One-time link or a configuration error.
        """
        parsed = urlsplit(self.url)
        if (
            parsed.scheme != "https"
            or not parsed.netloc
            or parsed.username
            or parsed.password
            or parsed.path
            or parsed.query
            or parsed.fragment
            or len(self.secret) < 32
        ):
            return "请先配置 Worker 的 HTTPS 根地址 worker_url 和至少 32 字符的 worker_secret；也可使用 /cam login。"
        await self.revoke(user_key)
        if len(self.pending) + self.issuing >= 100:
            return "当前网页登录人数较多，请稍后重试。"
        self.issuing += 1
        session = httpx.AsyncClient(
            timeout=30, follow_redirects=True, headers={"User-Agent": USER_AGENT}
        )
        try:
            response = await session.get(LOGIN_URL)
            response.raise_for_status()
            form = LoginForm(response.text).values
            if not form.get("lt") or not form.get("execution"):
                raise ValueError("Campus login form changed")
            captcha = await session.get("https://pass.hust.edu.cn/cas/code")
            captcha.raise_for_status()
            key = await asyncio.to_thread(
                rsa.generate_private_key, public_exponent=65537, key_size=2048
            )
            ticket = secrets.token_urlsafe(32)
            await self._request(
                "create",
                ticket,
                public_key=base64.b64encode(
                    key.public_key().public_bytes(
                        serialization.Encoding.DER,
                        serialization.PublicFormat.SubjectPublicKeyInfo,
                    )
                ).decode(),
                captcha=base64.b64encode(captcha.content).decode(),
            )
            pending = PendingLogin(
                user_key,
                event.unified_msg_origin,
                session,
                form,
                key,
                time.monotonic() + 180,
            )
            self.pending[ticket] = pending
            pending.task = asyncio.create_task(self._wait(ticket, pending))
        except BaseException:
            await session.aclose()
            raise
        finally:
            self.issuing -= 1
        # A URL fragment keeps the ticket out of HTTP URLs and access logs.
        return f"请打开专属链接登录，3 分钟内有效，仅限本人使用，请勿转发：\n{self.url}/#{ticket}"

    async def _wait(self, ticket: str, pending: PendingLogin) -> None:
        """Poll a ticket and cache completion so retries never repeat CAS login.

        Args:
            ticket: One-time relay ticket.
            pending: Local cookies, user identity and ephemeral private key.
        """
        completion = None
        warned = False
        try:
            while time.monotonic() < pending.deadline:
                try:
                    if completion is not None:
                        await self._request("complete", ticket, **completion)
                        return
                    result = await self._request("poll", ticket)
                    if result.get("status") in {
                        "expired",
                        "cancelled",
                        "success",
                        "error",
                    }:
                        return
                    if result.get("status") == "submitted":
                        credentials = {}
                        try:
                            envelope = result["envelope"]
                            aes_key = pending.key.decrypt(
                                base64.b64decode(envelope["key"], validate=True),
                                padding.OAEP(
                                    mgf=padding.MGF1(hashes.SHA256()),
                                    algorithm=hashes.SHA256(),
                                    label=None,
                                ),
                            )
                            plaintext = AESGCM(aes_key).decrypt(
                                base64.b64decode(envelope["nonce"], validate=True),
                                base64.b64decode(envelope["data"], validate=True),
                                ticket.encode(),
                            )
                            credentials = json.loads(plaintext)
                            if (
                                not isinstance(credentials, dict)
                                or set(credentials)
                                != {"username", "password", "captcha"}
                                or any(
                                    not isinstance(v, str) or not v or len(v) > 256
                                    for v in credentials.values()
                                )
                            ):
                                raise ValueError("Invalid browser credentials")
                            async with self.plugin.user_locks[pending.user_key]:
                                await self.plugin._complete_login(
                                    pending.session,
                                    pending.form,
                                    pending.user_key,
                                    credentials["username"].strip(),
                                    credentials["password"],
                                    credentials["captcha"].strip(),
                                )
                            completion = {
                                "success": True,
                                "message": "登录成功，已绑定账号。返回机器人发送 /cam run 即可执行。",
                            }
                        except Exception as exc:
                            self.plugin.logger.warning(
                                "Campus browser login failed: reason=%s",
                                exc.reason
                                if isinstance(exc, CampusLoginError)
                                else type(exc).__name__,
                            )
                            completion = {
                                "success": False,
                                "message": "登录未完成，请返回机器人重新发送 /cam web，检查账号、密码和验证码。",
                            }
                        finally:
                            if isinstance(credentials, dict):
                                credentials.clear()
                        if completion["success"]:
                            try:
                                await self.plugin.context.send_message(
                                    pending.origin,
                                    MessageChain().message(completion["message"]),
                                )
                            except Exception:
                                self.plugin.logger.warning(
                                    "Campus login notification failed"
                                )
                        continue
                except (httpx.HTTPError, ValueError):
                    if not warned:
                        self.plugin.logger.warning("Campus login relay unavailable")
                        warned = True
                await asyncio.sleep(3)
        finally:
            self.pending.pop(ticket, None)
            await pending.session.aclose()

    async def revoke(self, user_key: str) -> None:
        """Invalidate a user's outstanding browser link before login or logout.

        Args:
            user_key: Trusted platform identity whose link should be revoked.
        """
        for ticket, pending in list(self.pending.items()):
            if pending.user_key != user_key:
                continue
            self.pending.pop(ticket, None)
            if pending.task:
                pending.task.cancel()
                await asyncio.gather(pending.task, return_exceptions=True)
            await pending.session.aclose()
            try:
                await self._request("revoke", ticket)
            except (httpx.HTTPError, ValueError):
                self.plugin.logger.warning(
                    "Campus relay revocation failed; ticket will expire"
                )

    async def close(self) -> None:
        """Cancel pending browser logins and close relay connections."""
        await asyncio.gather(
            *(
                self.revoke(user_key)
                for user_key in {item.user_key for item in self.pending.values()}
            )
        )
        await self.http.aclose()
