"""Regress both login modes without loading or migrating live AstrBot config."""

import asyncio
import base64
import copy
import hashlib
import importlib
import json
import logging
import secrets
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs

import httpx
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

PLUGIN = Path(__file__).resolve().parents[1]
ROOT = PLUGIN.parents[2]


class Event:
    def __init__(self, user="user", text="", group=None):
        self.user = user
        self.message_str = text
        self.unified_msg_origin = "platform:FriendMessage:" + user
        if group:
            self.unified_msg_origin = "platform:GroupMessage:" + group

    def is_private_chat(self):
        return ":FriendMessage:" in self.unified_msg_origin

    def get_platform_name(self):
        return "aiocqhttp"

    def get_sender_id(self):
        return self.user

    def get_platform_id(self):
        return "platform"

    def plain_result(self, value):
        return value

    def chain_result(self, value):
        return value

    async def send(self, value):
        pass


class Star:
    def __init__(self, context):
        self.context = context
        self.logger = logging.getLogger("campus-login-test")
        self.store = {}

    async def put_kv_data(self, key, value):
        self.store[key] = copy.deepcopy(value)

    async def get_kv_data(self, key, default):
        return copy.deepcopy(self.store.get(key, default))

    async def delete_kv_data(self, key):
        self.store.pop(key, None)


class Decorators:
    def command(self, *args, **kwargs):
        return lambda function: function

    def llm_tool(self, *args, **kwargs):
        return lambda function: function


class MessageChain:
    def message(self, text):
        return text


class LoginTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="campus-login-test-")
        modules = {}
        for name, path in {
            "astrbot": ROOT / "astrbot",
            "astrbot.core": ROOT / "astrbot/core",
            "astrbot.core.utils": ROOT / "astrbot/core/utils",
            "astrbot.core.message": ROOT / "astrbot/core/message",
            "astrbot.api": ROOT / "astrbot/api",
            "campus_login_test": PLUGIN,
        }.items():
            module = types.ModuleType(name)
            module.__path__ = [str(path)]
            modules[name] = module
        modules["astrbot.api"].AstrBotConfig = dict
        for name, values in {
            "astrbot.api.event": {
                "AstrMessageEvent": Event,
                "filter": Decorators(),
                "MessageChain": MessageChain,
            },
            "astrbot.api.star": {
                "Context": object,
                "Star": Star,
                "StarTools": types.SimpleNamespace(
                    get_data_dir=lambda _: Path(self.temp.name)
                ),
            },
            "astrbot.api.message_components": {
                "Image": types.SimpleNamespace(fromBytes=lambda value: value)
            },
            "astrbot.core.message.components": {"BaseMessageComponent": object},
            "astrbot.core.platform": {"AstrMessageEvent": Event},
        }.items():
            module = types.ModuleType(name)
            module.__dict__.update(values)
            modules[name] = module
        self.imports = patch.dict(sys.modules, modules)
        self.imports.start()
        self.module = importlib.import_module("campus_login_test.main")
        self.waiter = importlib.import_module("astrbot.core.utils.session_waiter")
        self.app = self.module.Main(
            types.SimpleNamespace(send_message=self.notify),
            {"worker_url": "https://relay.example", "worker_secret": "s" * 40},
        )
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.public = base64.b64encode(
            self.key.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        ).decode()
        protocol = importlib.import_module("campus_login_test.client")
        iv = b"1" * 16
        encryptor = Cipher(
            algorithms.AES(protocol.CrighClient.CRIGH_SECRET_KEY), modes.CBC(iv)
        ).encryptor()
        self.secret = base64.b64encode(
            b"0000" + iv + encryptor.update(b"signing-secret!!") + encryptor.finalize()
        ).decode()
        self.records = {}
        self.notifications = []
        self.cas_posts = 0
        self.login_html = None
        self.cas_forms = []
        self.uploads = []
        self.completions = 0
        self.lose_completion = False
        self.tamper = False
        factory = httpx.AsyncClient
        transport = httpx.MockTransport(self.respond)
        await self.app.web_login.http.aclose()
        self.app.web_login.http = factory(transport=transport)
        self.http = patch.object(
            httpx,
            "AsyncClient",
            side_effect=lambda **kw: factory(transport=transport, **kw),
        )
        self.http.start()

    async def asyncTearDown(self):
        await self.app.terminate()
        self.http.stop()
        self.imports.stop()
        for name in list(sys.modules):
            if name.startswith("campus_login_test"):
                sys.modules.pop(name, None)
        self.temp.cleanup()

    async def notify(self, origin, message):
        self.notifications.append((origin, message))
        return True

    async def respond(self, request):
        path = request.url.path
        if request.url.host == "relay.example":
            self.assertEqual(request.headers["Authorization"], "Bearer " + "s" * 40)
            body = json.loads(request.content)
            ticket = body["ticket"]
            if path.endswith("/create"):
                public = serialization.load_der_public_key(
                    base64.b64decode(body["public_key"])
                )
                key, nonce = (
                    AESGCM.generate_key(bit_length=256),
                    secrets.token_bytes(12),
                )
                data = AESGCM(key).encrypt(
                    nonce,
                    json.dumps(
                        {
                            "username": "student",
                            "password": " password ",
                            "captcha": "1234",
                        }
                    ).encode(),
                    ("wrong-ticket" if self.tamper else ticket).encode(),
                )
                self.records[ticket] = {
                    "status": "submitted",
                    "envelope": {
                        "key": base64.b64encode(
                            public.encrypt(
                                key,
                                padding.OAEP(
                                    mgf=padding.MGF1(hashes.SHA256()),
                                    algorithm=hashes.SHA256(),
                                    label=None,
                                ),
                            )
                        ).decode(),
                        "nonce": base64.b64encode(nonce).decode(),
                        "data": base64.b64encode(data).decode(),
                    },
                }
            elif path.endswith("/complete"):
                self.completions += 1
                if self.lose_completion and self.completions == 1:
                    raise httpx.ReadTimeout("simulated lost response", request=request)
                self.records[ticket] = {
                    "status": "success" if body["success"] else "error"
                }
            elif path.endswith("/revoke"):
                self.records[ticket] = {"status": "cancelled"}
            return httpx.Response(200, json=self.records[ticket])
        if path == "/cas/login" and request.method == "GET":
            return httpx.Response(
                200,
                text='<input value="LT" name="lt"><input name="execution" value="E">',
                headers={"set-cookie": "cas=session; Path=/"},
            )
        if path == "/cas/code":
            return httpx.Response(200, content=b"GIF89a")
        if path == "/cas/rsa":
            return httpx.Response(200, json={"publicKey": self.public})
        if path == "/cas/login":
            self.cas_posts += 1
            fields = parse_qs(request.content.decode())
            self.cas_forms.append(fields)
            password = self.key.decrypt(
                base64.b64decode(fields["pl"][0]), padding.PKCS1v15()
            )
            self.assertEqual(password, b" password ")
            self.assertIn("cas=session", request.headers["cookie"])
            return httpx.Response(
                200,
                text=self.login_html
                or f"window.app.getUserName('x','a.b.c.{self.secret}.2026-11-17')",
            )
        if path.endswith("/u/info"):
            return httpx.Response(200, json={"data": {"xm": "Name", "xh": "123"}})
        if path.endswith("/sportsId"):
            return httpx.Response(200, json={"data": "sport-id"})
        if path.endswith("/savesports"):
            fields = parse_qs(request.content.decode())
            decryptor = Cipher(
                algorithms.AES(self.secret[:16].encode()), modes.ECB()
            ).decryptor()
            padded = (
                decryptor.update(base64.b64decode(fields["jsonsports"][0]))
                + decryptor.finalize()
            )
            from cryptography.hazmat.primitives.padding import PKCS7

            unpadder = PKCS7(128).unpadder()
            self.uploads.append(
                json.loads(unpadder.update(padded) + unpadder.finalize())
            )
            return httpx.Response(200, json={"code": 200})
        if path.endswith("/sensorZipFile"):
            self.assertEqual(request.url.params["sportId"], "sport-id")
            self.assertIn(b"application/octet-stream", request.content)
            return httpx.Response(200, json={"code": 200})
        raise AssertionError(str(request.url))

    async def test_login_accepts_expiry_and_callback_quote_variants(self):
        client = importlib.import_module("campus_login_test.client")
        for callback in [
            f"window.app.getUserName('x','a.b.c.{self.secret}')",
            f"window.app.getUserName('x','a.b.c.{self.secret}.2026-11-17')",
            f'getUserName ("x", "a.b.c.{self.secret}.2026-11-17");',
        ]:
            with self.subTest(callback=callback.split("(", 1)[0]):
                self.login_html = callback
                async with httpx.AsyncClient() as session:
                    await session.get(client.LOGIN_URL)
                    token, secret = await client.login(
                        session,
                        {
                            "lt": "LT",
                            "execution": "E",
                            "extra": "kept",
                            "un": "plain-user",
                            "pd": "plain-password",
                        },
                        "student",
                        " password ",
                        "1234",
                    )
                self.assertEqual(token, "a.b.c")
                self.assertEqual(secret, self.secret)
                self.assertEqual(self.cas_forms[-1]["extra"], ["kept"])
                self.assertIn("ua", self.cas_forms[-1])
                self.assertIn("visitorId", self.cas_forms[-1])
                self.assertNotIn("un", self.cas_forms[-1])
                self.assertNotIn("pd", self.cas_forms[-1])

    async def test_login_classifies_cas_errors_without_echoing_response(self):
        client = importlib.import_module("campus_login_test.client")
        for text, reason in [
            ("验证码错误", "captcha"),
            ("用户名或密码错误", "credentials"),
            ("动态验证码已发送到企业微信", "second_factor"),
            ("账号锁定", "account_restricted"),
            ("unrecognized server response", "missing_callback"),
        ]:
            with self.subTest(reason=reason):
                self.login_html = f'<div id="errormsg"><span>{text}</span> private-user private-password</div>'
                async with httpx.AsyncClient() as session:
                    await session.get(client.LOGIN_URL)
                    with self.assertRaises(client.CampusLoginError) as caught:
                        await client.login(
                            session,
                            {"lt": "LT", "execution": "E"},
                            "student",
                            " password ",
                            "1234",
                        )
                self.assertEqual(caught.exception.reason, reason)
                self.assertNotIn("private-user", str(caught.exception))
                self.assertNotIn("private-password", str(caught.exception))

    async def test_run_generates_data_without_external_template(self):
        user_key = (
            "user:"
            + hashlib.sha256(json.dumps(["platform", "user"]).encode()).hexdigest()
        )
        account = {
            "username": "student",
            "student_id": "123",
            "token": "a.b.c",
            "secret": self.secret,
        }
        self.app.store[user_key] = self.app.cipher.encrypt(
            json.dumps(account).encode()
        ).decode()
        result = await self.app.campus_run(Event(), "run")
        self.assertIn("轨迹返回码 200", result)
        self.assertEqual(len(self.uploads), 1)
        data = self.uploads[0]
        self.assertEqual(data["sportId"], "sport-id")
        self.assertEqual(data["xh"], "123")
        self.assertEqual(data["name"], "Name")
        self.assertGreaterEqual(data["coordinate"][-1]["da"], 2150)
        self.assertFalse((Path(self.temp.name) / "data.json").exists())

    async def test_existing_template_remains_preferred(self):
        user_key = (
            "user:"
            + hashlib.sha256(json.dumps(["platform", "user"]).encode()).hexdigest()
        )
        account = {
            "username": "student",
            "student_id": "123",
            "token": "a.b.c",
            "secret": self.secret,
        }
        self.app.store[user_key] = self.app.cipher.encrypt(
            json.dumps(account).encode()
        ).decode()
        template = {
            "activeTime": "00:00:01",
            "endTime": "2025-01-01 00:00:01",
            "coordinate": [{"t": 0}, {"t": 1735689600000}],
            "marker": "legacy",
        }
        (Path(self.temp.name) / "data.json").write_text(json.dumps(template))
        self.assertIn("轨迹返回码 200", await self.app.campus_run(Event(), "run"))
        self.assertEqual(self.uploads[0]["marker"], "legacy")
        self.assertEqual(self.uploads[0]["activeTime"], "00:00:01")

    async def test_invalid_template_stops_before_submission(self):
        user_key = (
            "user:"
            + hashlib.sha256(json.dumps(["platform", "user"]).encode()).hexdigest()
        )
        account = {
            "username": "student",
            "student_id": "123",
            "token": "a.b.c",
            "secret": self.secret,
        }
        self.app.store[user_key] = self.app.cipher.encrypt(
            json.dumps(account).encode()
        ).decode()
        (Path(self.temp.name) / "data.json").write_text("invalid json")
        self.assertIn("数据异常", await self.app.campus_run(Event(), "run"))
        self.assertFalse(self.uploads)

    async def test_null_template_is_reported_instead_of_using_generated_data(self):
        account = {
            "username": "student",
            "student_id": "123",
            "token": "a.b.c",
            "secret": self.secret,
        }
        (Path(self.temp.name) / "data.json").write_text("null")
        with self.assertRaisesRegex(ValueError, "JSON object"):
            await self.app._run(account, "activity:test")
        self.assertFalse(self.uploads)

    async def test_web_login_retries_completion_without_reauthenticating(self):
        self.lose_completion = True
        link = await self.app._handle(Event(), "web")
        ticket = link.rsplit("#", 1)[1]
        await asyncio.wait_for(self.app.web_login.pending[ticket].task, timeout=8)
        self.assertEqual(self.cas_posts, 1)
        self.assertEqual(self.completions, 2)
        self.assertEqual(self.records[ticket]["status"], "success")
        self.assertEqual(len(self.app.store), 1)
        saved = next(iter(self.app.store.values()))
        self.assertNotIn("password", saved)
        self.assertEqual(
            json.loads(self.app.cipher.decrypt(saved.encode()))["username"], "student"
        )
        self.assertEqual(self.notifications[0][0], Event().unified_msg_origin)

    async def test_immediate_logout_revokes_unstarted_task_and_closes_cookies(self):
        link = await self.app._handle(Event(), "web")
        ticket = link.rsplit("#", 1)[1]
        session = self.app.web_login.pending[ticket].session
        await self.app._handle(Event(), "logout")
        self.assertFalse(self.app.web_login.pending)
        self.assertTrue(session.is_closed)
        self.assertEqual(self.records[ticket]["status"], "cancelled")
        self.assertFalse(self.app.store)

    async def test_cross_ticket_ciphertext_is_rejected(self):
        self.tamper = True
        link = await self.app._handle(Event(), "web")
        ticket = link.rsplit("#", 1)[1]
        await asyncio.wait_for(self.app.web_login.pending[ticket].task, timeout=5)
        self.assertEqual(self.records[ticket]["status"], "error")
        self.assertEqual(self.cas_posts, 0)
        self.assertFalse(self.app.store)

    async def test_worker_auth_error_identifies_service_without_logging_secrets(self):
        request = httpx.Request(
            "POST",
            "https://relay.example/api/bot/create?ticket=private-ticket",
            headers={"Authorization": "Bearer private-key"},
        )
        error = httpx.HTTPStatusError(
            "private-key",
            request=request,
            response=httpx.Response(403, request=request),
        )
        with patch.object(self.app.web_login, "_request", side_effect=error):
            with self.assertLogs(self.app.logger, level="WARNING") as logs:
                result = await self.app._handle(Event(), "web")
        self.assertIn("Worker请求失败（HTTP 403）", result)
        self.assertIn("BOT_SECRET", result)
        self.assertNotIn("部分保存", result)
        self.assertIn("path=/api/bot/create", logs.output[0])
        self.assertNotIn("private-ticket", logs.output[0])
        self.assertNotIn("private-key", logs.output[0])
        self.assertFalse(self.app.web_login.pending)

    async def test_worker_configuration_error_reports_bindings(self):
        request = httpx.Request("POST", "https://relay.example/api/bot/create")
        error = httpx.HTTPStatusError(
            "unavailable",
            request=request,
            response=httpx.Response(503, request=request),
        )
        with patch.object(self.app.web_login, "_request", side_effect=error):
            with self.assertLogs(self.app.logger, level="WARNING"):
                result = await self.app._handle(Event(), "web")
        self.assertIn("HTTP 503", result)
        self.assertIn("LOGINS", result)

    async def test_chat_login_still_isolates_concurrent_users(self):
        async def chat(user):
            event = Event(user)
            task = asyncio.create_task(self.app._handle(event, "password"))
            for _ in range(100):
                if event.unified_msg_origin in self.waiter.USER_SESSIONS:
                    break
                await asyncio.sleep(0.01)
            for text in [user, " password ", "1234"]:
                await self.waiter.SessionWaiter.trigger(
                    event.unified_msg_origin, Event(user, text)
                )
            self.assertIn("登录成功", await task)
            return (
                "user:"
                + hashlib.sha256(json.dumps(["platform", user]).encode()).hexdigest()
            )

        first, second = await asyncio.gather(chat("first"), chat("second"))
        self.assertNotEqual(first, second)
        self.assertEqual(len(self.app.store), 2)
        self.assertFalse(self.waiter.USER_SESSIONS)
        self.assertFalse(self.waiter.FILTERS)

    async def test_group_users_share_only_their_own_private_binding(self):
        alice = Event("alice", group="shared")
        bob = Event("bob", group="shared")
        first, second = await asyncio.gather(
            self.app._handle(alice, "web"), self.app._handle(bob, "web")
        )
        self.assertEqual(first, second)
        self.assertNotIn("#", first)
        self.assertIn("已私发", first)
        self.assertEqual(
            {origin for origin, _ in self.notifications},
            {"platform:FriendMessage:alice", "platform:FriendMessage:bob"},
        )
        await asyncio.gather(
            *(p.task for p in list(self.app.web_login.pending.values()))
        )
        self.assertIn("登录有效", await self.app.campus_run(alice, "status"))
        await self.app._handle(alice, "logout")
        self.assertIn("尚未登录", await self.app._handle(Event("alice"), "status"))
        self.assertIn("登录有效", await self.app._handle(Event("bob"), "status"))
        self.assertIn("私聊", await self.app._handle(bob, "password"))
        self.assertFalse(self.waiter.USER_SESSIONS)

    async def test_group_failed_private_delivery_revokes_link(self):
        with patch.object(self.app.context, "send_message", return_value=False):
            result = await self.app._handle(Event(group="shared"), "web")
        self.assertIn("私发失败", result)
        self.assertNotIn("#", result)
        self.assertFalse(self.app.web_login.pending)
        self.assertEqual(
            [item["status"] for item in self.records.values()], ["cancelled"]
        )


if __name__ == "__main__":
    unittest.main()
