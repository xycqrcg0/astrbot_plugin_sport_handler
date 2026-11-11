# 校园跑插件

为 AstrBot 提供校园账号登录、登录状态查询和单次校园跑提交，支持多用户独立绑定账号及 LLM 调用。

默认按内置操场路线生成约 2.15 公里的记录，使用男生路线配置。提交后的审核结果和有效成绩以校园跑客户端为准。

## 安装

将插件目录放到 AstrBot 的 `data/plugins/astrbot_plugin_sport_handler` 下。在运行 AstrBot 的 Python 环境中，从 AstrBot 项目根目录安装依赖。

```bash
python -m pip install -r data/plugins/astrbot_plugin_sport_handler/requirements.txt
```

在 WebUI 插件管理中加载或重载校园跑插件。

## 使用

所有命令在机器人私聊中使用。

- `/cam login`，机器人在私聊中发送学校登录二维码。使用华中科技大学企业微信扫码并确认，二维码 3 分钟内有效，仅供本人使用。过期后重新发送命令即可。扫码登录无需配置 Worker。
- `/cam password`，依次输入校园账号、密码和图片验证码。如果学校要求二次验证，再回复学校发送的动态验证码。每步限时 180 秒，回复 `取消` 结束。
- `/cam web`，打开机器人发送的专属链接，在网页中完成登录。需要先部署并配置下方的 Worker。
- `/cam run`，使用已绑定账号执行一次校园跑。直接发送 `/cam` 也会执行。
- `/cam status`，查询登录状态和最近提交阶段。
- `/cam logout`，解除当前用户的账号绑定并删除保存的登录状态。
- `/cam reset`，清除上次提交标记。提交中断后，先在校园跑客户端核查记录，确认可以重新提交，再执行此命令及 `/cam run`。

每个聊天用户绑定一个校园账号，登录状态在机器人重启后保留。私聊输入的密码可能被聊天平台或机器人消息日志保留。

启用 `campus_run` LLM 工具后，也可以对机器人说“查看校园跑状态”或“执行一次校园跑”。

## 网页登录部署

准备 Node.js 22+、pnpm 和 Cloudflare 账号。从 AstrBot 项目根目录进入 Worker 目录并部署。

```bash
cd data/plugins/astrbot_plugin_sport_handler/worker
pnpm install
pnpm exec wrangler login
pnpm deploy
```

保存部署后显示的 HTTPS 站点地址。随后生成通信密钥。

```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

保存生成的字符串，执行下列命令，在提示中粘贴该密钥。

```bash
pnpm exec wrangler secret put BOT_SECRET
```

在 AstrBot 的校园跑插件配置中填写以下字段，保存并重载插件。

- `worker_url`，Worker 的 HTTPS 根地址，例如 `https://astrbot-campus-login.example.workers.dev`。
- `worker_secret`，与 `BOT_SECRET` 完全一致的通信密钥。

私聊发送 `/cam web` 获取个人登录链接，3 分钟内提交。若学校要求二次验证，在同一页面输入动态验证码，每步仅可提交一次。登录失败、验证码过期或插件重载后重新获取链接。

## 使用已有模板

默认使用内置路线自动生成数据。需要使用已有 `data.json` 时，将文件放到 `data/plugin_data/astrbot_plugin_sport_handler/data.json`。也支持放在插件目录下，数据目录中的模板优先。

模板格式错误时，修复或移走模板后再执行 `/cam run`。

路线与数据生成逻辑参考 [hust-nailong-sports](https://github.com/Wu-LQUE/hust-nailong-sports)，MIT 许可正文见 [THIRD_PARTY_LICENSES.txt](THIRD_PARTY_LICENSES.txt)。
