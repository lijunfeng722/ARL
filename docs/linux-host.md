# Linux x86_64 宿主与服务设置

Linux 入口复用 ARL 的应用会话、任务包、队列、取消和回执。进程身份由 Unix socket 的 `SO_PEERCRED` 与 `/proc` 的 UID、启动代次和可执行路径校验。仅同账号进程可接入；应用 ID、名称由调用方声明，不是发行者签名证明。服务授权是当前操作系统账号内的管理边界，不隔离已控制该账号的恶意进程。

默认状态目录为 `${XDG_STATE_HOME:-$HOME/.local/state}/arl`，环境变量须为绝对路径。目录必须归当前账号所有且权限为 0700，配置为 0600。现有 `disabled` 暂停标记保留，重启不会清除它。

## 准备与启动

在包含本次适配的仓库中，使用 Python 3.12。飞猪的上下文封装需要 CPU 版 `cryptography`，其他设置、地图和挂载目录操作不加载模型。

```sh
python3 -m venv .venv-linux
.venv-linux/bin/pip install '.[linux]'
.venv-linux/bin/python -m arl.linux_host check
.venv-linux/bin/python -m arl.linux_settings serve
```

打开终端显示的 `http://127.0.0.1:18745/#...`。设置服务只监听回环地址，每次启动生成新令牌；令牌保存在页面内存，读取后移除 URL fragment，不进入访问日志。不要把终端链接作为公开截图。Ctrl+C 关闭设置入口；ARL 宿主另用以下命令运行：

```sh
.venv-linux/bin/python -m arl.linux_host serve
```

保存或查看配置不会登录、提交模型任务或访问供应商。点击“检查连接”才执行一次明确的只读查询。检查成功仅表示收到这一次响应，不证明其他服务、模型、设备就绪。设置入口可与宿主分开启停。当前代码尚未发布到稳定安装器；不能拿旧版本执行新入口。

## 服务操作

| 服务 | 配置 | 开放范围 |
| --- | --- | --- |
| 高德 | 自己的 Web 服务 Key | 地理编码、地点、路径、距离、天气；固定 HTTPS 主机和路径 |
| 飞猪 | 自己的服务 Key | 机票、酒店、关键词、AI、火车与景点查询；沿用原生客户端的公开 FlyAI 1.0.16 请求签名与真实 Linux 客户端上下文 |
| 网易云音乐 | 官方 ncm-cli 0.1.7 的绝对路径、核验的 SHA-256；在 CLI 自行完成配置与登录 | 默认歌单列表、详情、歌曲搜索；另勾选写入后才允许创建歌单、添加歌曲 |
| NAS | 先用系统工具挂载，再选绝对目录 | 列出最多 1000 项、读取最多 32 KiB 的普通文件；拒绝符号链接、上级路径与特殊文件，不新增远程写入授权 |

每项服务还必须填写允许使用的应用 ID 并启用；留空不向任何应用授权。配置修改、暂停、移除即时影响后续准入；排队和正在处理的调用会重新检查授权。网络请求最多等待 12 秒；撤销不保证供应商已停止处理已发出的请求。音乐写入使用现有非幂等队列规则，不重放结果不明的写入。

高德、飞猪凭据保存在当前账号私有的 `linux-services-v1.json`，**是受文件权限保护的明文，不是加密钥匙串**；没有借用 Apple Keychain，也不会导入 Mac 凭据。状态、页面和错误不回显凭据；留空保留旧值，“移除”删除配置。网易云的登录资料仍由官方 CLI 管理。系统磁盘加密与备份由部署者管理。

Linux 出行工具返回有界 `provider` 与 `adaptation` 对象，不生成原生会话的本地游标；描述中不发布 `cursor` 参数。供应商 `page`、`offset`、`limit` 按原查询传递，不静默截断过大的响应。NAS 挂载认证由系统负责；原生上传模块要求独立写入授权，未因读取设置而默认启用。

## AI 任务与任务档位

从 [Codex 官方发行](https://github.com/openai/codex/releases)安装 x86_64 CLI 并自行登录。核对发行来源与实际二进制 SHA-256，在设置页填写绝对路径、摘要、可用模型 ID 和调用上限。也可使用命令行：

```sh
.venv-linux/bin/python -m arl.linux_host configure-models --binary /absolute/path/to/codex --sha256 VERIFIED_SHA256 --model AVAILABLE_MODEL_ID --max-calls 100
```

示例值必须替换。配置保存不登录、不推理。模型配置变更或停用立即撤销旧授权；启用新配置须重启宿主。二进制变化必须重新核验，不自动接受更新。调用次数不是跨重启账单限额。AI 任务可能使用联网模型，“Linux 本地宿主”不等于全离线推理。

宿主预检取得模型目录后，页面显示五个任务档位，可修改模型、推理强度和服务等级；只允许目录实际支持的组合，并检查配置版本冲突。并行数可设为 1–8，宿主在现有刷新周期内采用新值。未取得目录时不伪造模型选项。

## CLI 管理与应用接入

```sh
.venv-linux/bin/python -m arl.linux_settings status
.venv-linux/bin/python -m arl.linux_settings configure --service amap --revision 0 --replace-secret --apps demo.friday --enabled
.venv-linux/bin/python -m arl.linux_settings pause --service amap --revision 1
```

`--revision` 使用最近一次 `status` 的值，不能照抄。`--replace-secret` 从终端隐藏输入读取凭据，不把它放进命令行；参数用 `--parameters` JSON，NAS 为 `{"root":"/mnt/example-share"}`，音乐为 `{"binary":"/absolute/path/to/ncm","sha256":"VERIFIED_SHA256","allow_writes":false}`。没有设置操作需要把密钥交给 AI。

应用先按原 `Client.open_app_session` 握手并保持心跳，再使用 `submit/get/cancel` 调用已授予的工具。`connection.open` 的 capabilities 应声明所需工具。保存授权后原会话可在下次请求采用新范围；断开、进程代次变化和宿主暂停都会阻止新调用。Friday 与 ARL 使用同一账号、同一状态目录。

## 平台与验证边界

Apple 日历、提醒事项、信息、备忘录、钥匙串明确不支持。macOS 原生 ARL Control 不运行于 Linux，由本机浏览器设置页与 CLI 提供上述管理入口。Python 运行、配置和服务适配均不需要 GPU；供应商账号可用性仍取决于独立配置。

回归使用合成供应商响应、私有临时目录和本机 Unix/HTTP socket，覆盖配置权限、秘密不回显、请求签名、路径逃逸、应用握手和撤销。没有连接真实账号、执行模型推理或设备操作。页面截图由 `python3 -m tests.linux_settings_preview` 提供只读示例，可在桌面和移动宽度重复检查。

本轮相关 Linux 回归为 59 项通过、1 项 macOS Swift 条件跳过；另在源码目录之外安装 wheel，确认包内协议快照、设置静态资源、宿主装配及 FlyAI CPU 上下文编码可用。三个受维护仓库的规则检查、用户手册导出与严格构建、索引与公开内容检查通过。未提交、推送、发布或部署。


### 容器集成审查

Linux 宿主、服务和 Unix 身份测试已纳入显式回归清单，不再依赖手工运行新增模块。完整源码清单同步包含平台适配模块；原 macOS 合成凭据用例同时支持 Linux 的 `SO_PEERCRED` 数据布局。源码位于浅目录时，Apple 信息接收仍明确返回未打包，不因路径层数不足抛出异常。

镜像继续将 Friday 与 ARL 放在同一容器，保留进程身份、socket 和状态目录边界。自动构建需固定包含 Linux 适配的公开 ARL 提交；上游写入权限不足时，先准备经审阅的分支来源，不能仅用旧提交号标注本地新代码。

本轮 Linux 容器中以普通账号执行完整 portable 清单：902 项通过，0 失败、0 错误、0 阻断；不启动真实供应商连接或模型。
