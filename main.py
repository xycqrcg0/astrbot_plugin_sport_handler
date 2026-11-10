"""Multi-user campus running commands and LLM tool."""

import asyncio
import hashlib
import json
from datetime import datetime
from pathlib import Path

import httpx
from cryptography.fernet import Fernet, InvalidToken

from astrbot.api import AstrBotConfig
from astrbot.api.event import AstrMessageEvent, filter
from astrbot.api.message_components import Image
from astrbot.api.star import Context, Star, StarTools
from astrbot.core.utils.session_waiter import SessionController, session_waiter

from .client import (
    CHINA_TIME,
    LOGIN_URL,
    USER_AGENT,
    CrighClient,
    LoginForm,
    encode_activity,
    login,
    make_data,
)
from .generation import generate_data
from .worker_login import WorkerLogin


class Main(Star):
    """Bind platform users to encrypted campus sessions."""

    def __init__(self, context: Context, config: AstrBotConfig | None = None):
        super().__init__(context)
        self.data_dir = StarTools.get_data_dir("astrbot_plugin_sport_handler")
        key_file = self.data_dir / "session.key"
        try:
            with key_file.open("xb") as stream:
                stream.write(Fernet.generate_key())
            key_file.chmod(0o600)
        except FileExistsError:
            pass
        self.cipher = Fernet(key_file.read_bytes())
        self.user_locks: dict[str, asyncio.Lock] = {}
        self.account_locks: dict[str, asyncio.Lock] = {}
        self.tasks: set[asyncio.Task] = set()
        self.web_login = WorkerLogin(self, config or {})

    @filter.command("cam")
    async def campus_run_command(self, event: AstrMessageEvent, action: str = "run"):
        """Handle campus running commands.

        Args:
            event: Current message event.
            action: Execute, chat login, web login, status, logout or reset.
        """
        event.stop_event()
        yield event.plain_result(await self._handle(event, action))

    @filter.llm_tool(name="campus_run")
    async def campus_run(self, event: AstrMessageEvent, action: str = "status") -> str:
        """Check campus login or submit one generated activity for the current user.

        Call run only when the user explicitly requests a submission. If login is
        required, direct the user to privately send /cam login. Report only the
        returned result. An accepted request still requires campus grade review.

        Args:
            action(string): status to check login, or run to submit one activity.

        Returns:
            Current user's operation result without login credentials.
        """
        if action not in {"run", "status"}:
            return "action 只能为 run 或 status。登录请私聊发送 /cam login。"
        return await self._handle(event, action)

    async def _handle(self, event: AstrMessageEvent, action: str) -> str:
        """Dispatch commands with user isolation and serialized account changes.

        Args:
            event: Current message event.
            action: Requested command operation.

        Returns:
            Sanitized result suitable for the user or LLM.
        """
        if not event.is_private_chat():
            return "请在私聊中使用校园跑。发送 /cam login 开始绑定账号。"
        if action not in {"login", "web", "status", "logout", "run", "reset"}:
            return "用法：/cam [login|web|status|logout|run|reset]；省略操作时执行一次校园跑。"
        identity = json.dumps([event.get_platform_id(), event.get_sender_id()])
        user_key = "user:" + hashlib.sha256(identity.encode()).hexdigest()
        lock = self.user_locks.setdefault(user_key, asyncio.Lock())
        if lock.locked():
            return "你的校园跑操作正在进行，请等待完成。登录过程中可回复 取消。"
        task = asyncio.current_task()
        self.tasks.add(task)
        try:
            async with lock:
                if action == "login":
                    await self.web_login.revoke(user_key)
                    return await self._login(event, user_key)
                if action == "web":
                    return await self.web_login.issue(event, user_key)
                if action == "logout":
                    await self.web_login.revoke(user_key)
                    await self.delete_kv_data(user_key)
                    return "已解除当前用户的账号绑定并删除保存的登录状态。"
                encrypted = await self.get_kv_data(user_key, None)
                if not encrypted:
                    return "尚未登录，请私聊发送 /cam login。"
                account = json.loads(self.cipher.decrypt(encrypted.encode()))
                account_key = (
                    "activity:"
                    + hashlib.sha256(account["student_id"].encode()).hexdigest()
                )
                account_lock = self.account_locks.setdefault(
                    account_key, asyncio.Lock()
                )
                if account_lock.locked():
                    return "该校园账号正在执行校园跑，请等待结果。"
                async with account_lock:
                    previous = await self.get_kv_data(account_key, None)
                    if action == "status":
                        masked = (
                            "*" * max(0, len(account["username"]) - 4)
                            + account["username"][-4:]
                        )
                        async with httpx.AsyncClient(timeout=30) as session:
                            info = await CrighClient(
                                session, account["token"], account["secret"]
                            ).request("GET", "/api/l/v6/u/info")
                        if not isinstance(info.get("data"), dict) or not info[
                            "data"
                        ].get("xh"):
                            return "已保存账号绑定，但登录状态校验失败。请发送 /cam login。"
                        detail = (
                            f"上次操作 {previous['sport_id']}，阶段 {previous['phase']}。"
                            if previous
                            else "尚无运行记录。"
                        )
                        return f"账号 {masked} 登录有效。{detail}"
                    if action == "reset":
                        await self.delete_kv_data(account_key)
                        return "已清除上次提交标记。请确认校园跑客户端中的记录后，再发送 /cam run。"
                    if previous and previous["phase"] != "complete":
                        return (
                            f"上次操作 {previous['sport_id']} 停留在 {previous['phase']} 阶段，"
                            "可能已部分提交。请先在校园跑客户端核查记录；确认可重新提交后发送 /cam reset。"
                        )
                    return await self._run(account, account_key)
        except PermissionError:
            await self.delete_kv_data(user_key)
            return "登录已失效，请私聊发送 /cam login。"
        except InvalidToken:
            return "保存的登录状态无法解密，请发送 /cam login 重新绑定。"
        except httpx.HTTPError:
            self.logger.warning("Campus request failed")
            return "校园服务请求失败。若正在提交，结果可能已部分保存，请先核查客户端记录，再查询 /cam status。"
        except (ValueError, KeyError, TypeError, OSError):
            self.logger.warning("Campus response, template or stored state is invalid")
            return "校园服务响应、模板或存储数据异常。请检查模板，或发送 /cam login 重新登录；提交过程中出错请先核查客户端记录。"
        finally:
            self.tasks.discard(task)

    async def _login(self, event: AstrMessageEvent, user_key: str) -> str:
        """Collect credentials through an isolated private conversation.

        Args:
            event: Private command event.
            user_key: Platform-scoped user storage key.

        Returns:
            Login completion, cancellation or timeout message.
        """
        credentials: list[str] = []
        cancelled = False
        async with httpx.AsyncClient(
            timeout=30, follow_redirects=True, headers={"User-Agent": USER_AGENT}
        ) as session:
            response = await session.get(LOGIN_URL)
            response.raise_for_status()
            form = LoginForm(response.text).values
            if not form.get("lt") or not form.get("execution"):
                return "校园登录页面格式发生变化，暂时无法登录。"
            await event.send(
                event.plain_result(
                    "请回复校园账号。随后依次输入密码和图片验证码，每步限时 180 秒，回复 取消 结束。"
                    "密码仅用于本次登录，聊天平台和机器人日志仍可能保留消息。"
                )
            )

            @session_waiter(timeout=180, record_history_chains=False)
            async def collect(controller: SessionController, reply: AstrMessageEvent):
                # The default waiter isolates private conversations by message origin.
                nonlocal cancelled
                if (
                    not reply.is_private_chat()
                    or reply.get_sender_id() != event.get_sender_id()
                ):
                    return
                text = reply.message_str
                if text.strip() in {"取消", "/取消"}:
                    cancelled = True
                    controller.stop()
                    return
                if not text.strip():
                    await reply.send(
                        reply.plain_result("请输入有效文本，或回复 取消。")
                    )
                    return
                credentials.append(text if len(credentials) == 1 else text.strip())
                if len(credentials) == 1:
                    await reply.send(reply.plain_result("请回复校园账号密码。"))
                elif len(credentials) == 2:
                    captcha = await session.get("https://pass.hust.edu.cn/cas/code")
                    captcha.raise_for_status()
                    await reply.send(
                        reply.chain_result(
                            [
                                Image.fromBytes(captcha.content),
                            ]
                        )
                    )
                    await reply.send(reply.plain_result("请回复图片中的验证码。"))
                else:
                    controller.stop()
                    return
                controller.keep(180, reset_timeout=True)

            try:
                await collect(event)
                if cancelled:
                    return "已取消登录。"
                await self._complete_login(session, form, user_key, *credentials)
                return "登录成功，已保存当前用户的账号绑定和登录状态。发送 /cam run 执行一次，/cam status 查看状态。"
            except TimeoutError:
                return "登录等待超时，请发送 /cam login 重新开始。"
            except ValueError:
                return "登录失败，请检查账号、密码和验证码后发送 /cam login 重试。"
            finally:
                credentials.clear()

    async def _complete_login(
        self,
        session: httpx.AsyncClient,
        form: dict,
        user_key: str,
        username: str,
        password: str,
        captcha: str,
    ) -> None:
        """Verify a campus login and persist the same binding for both login modes.

        Args:
            session: Campus HTTP session that issued the captcha.
            form: CAS hidden fields.
            user_key: Platform-scoped identity from the originating bot event.
            username: Campus account name.
            password: Password used only for authentication.
            captcha: User-entered captcha text.

        Raises:
            ValueError: Authentication or account verification failed.
            httpx.HTTPError: A campus request failed.
        """
        token, secret = await login(session, form, username, password, captcha)
        client = CrighClient(session, token, secret)
        info = (await client.request("GET", "/api/l/v6/u/info")).get("data")
        if not isinstance(info, dict) or not info.get("xh") or not info.get("xm"):
            raise ValueError("Campus account information is missing")
        account = {
            "username": username,
            "student_id": str(info["xh"]),
            "token": token,
            "secret": secret,
        }
        await self.put_kv_data(
            user_key, self.cipher.encrypt(json.dumps(account).encode()).decode()
        )

    async def _run(self, account: dict, account_key: str) -> str:
        """Submit one activity and persist progress before side effects.

        Args:
            account: Decrypted credentials for the invoking user.
            account_key: Shared activity state key for this campus account.

        Returns:
            Submission responses or an actionable failure message.
        """
        template_path = self.data_dir / "data.json"
        if not template_path.is_file():
            template_path = Path(__file__).parent / "data.json"
        template = None
        if template_path.is_file():
            template = json.loads(template_path.read_text(encoding="utf-8-sig"))
            if not isinstance(template, dict):
                raise ValueError("Activity template must be a JSON object")
        async with httpx.AsyncClient(timeout=30) as session:
            client = CrighClient(session, account["token"], account["secret"])
            info = (await client.request("GET", "/api/l/v6/u/info")).get("data")
            if not isinstance(info, dict) or not info.get("xh") or not info.get("xm"):
                return "无法获取账号信息，请发送 /cam login 重新登录。"
            if str(info["xh"]) != account["student_id"]:
                return "当前登录账号与保存的绑定不一致，请重新登录。"
            # Prepare the entire payload before creating an activity ID.
            end_time = datetime.now(CHINA_TIME).replace(tzinfo=None)
            if template is not None:
                data, sensor = await asyncio.to_thread(
                    make_data, template, info["xm"], str(info["xh"]), "", end_time
                )
            else:
                data, sensor = await asyncio.to_thread(
                    generate_data, info["xm"], str(info["xh"]), "", end_time
                )
            sport_id = (await client.request("GET", "/api/l/v7/sportsId")).get("data")
            if (
                not isinstance(sport_id, (str, int))
                or isinstance(sport_id, bool)
                or not sport_id
            ):
                return "校园服务未返回有效的运动编号，无法提交。"
            sport_id = str(sport_id)
            data["sportId"] = sport_id
            activity, sensor_zip = await asyncio.to_thread(
                encode_activity, data, sensor, account["secret"]
            )
            progress = {"sport_id": sport_id, "phase": "submitting"}
            await self.put_kv_data(account_key, progress)
            # Preserve the supplied script's endpoint and signing/encryption protocol.
            saved = await client.request(
                "POST", "/api/l/v6.1/savesports", data={"jsonsports": activity}
            )
            progress["phase"] = "activity_response_received"
            await self.put_kv_data(account_key, progress)
            if (
                str(saved.get("code")) not in {"0", "200"}
                or saved.get("success") is False
            ):
                return (
                    f"运动编号 {sport_id}，轨迹提交返回码 {saved.get('code', '未知')}，"
                    "提交结果尚未确认。请先在校园跑客户端核查记录。"
                )
            uploaded = await client.request(
                "POST",
                "/api/l/v7/upload/sensorZipFile",
                params={"sportId": sport_id, "sensorZipFile": f"{sport_id}.txt"},
                file=(f"{sport_id}.txt", sensor_zip),
            )
            # Unknown response schemas remain unconfirmed until checked by the user.
            accepted = all(
                str(result.get("code")) in {"0", "200"}
                and result.get("success") is not False
                for result in (saved, uploaded)
            )
            progress["phase"] = "complete" if accepted else "unconfirmed"
            await self.put_kv_data(account_key, progress)
            # Only expose status fields, never echo arbitrary user data or tokens.
            return (
                f"运动编号 {sport_id}，已收到轨迹提交和传感器上传响应。"
                f"轨迹返回码 {saved.get('code', '未知')}，"
                f"传感器返回码 {uploaded.get('code', '未知')}。"
                "请在校园跑客户端查看审核和有效成绩。"
            )

    async def terminate(self):
        """Cancel active plugin operations and release login waiters."""
        await self.web_login.close()
        tasks = list(self.tasks)
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
