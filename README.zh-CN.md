# 情侣猫猫日记

[English](README.md) | [简体中文](README.zh-CN.md)

一个供情侣两人使用的 Flask + SQLite 小应用，包含双账号注册、共享愿望清单、纪念日、留言簿和共享养猫功能。

## 项目说明

本项目代码由 ChatGPT 与 MiniMax 生成，并经人工整理与测试。

## 隐私说明

本仓库不包含原站点的数据库、账号、密码散列、登录令牌、留言、纪念日、使用记录、证书、私钥、日志、局域网 IP 或本机绝对路径。

## 一键本地预览（Windows）

双击 `start-local-8080.bat`。脚本会自动创建 `.venv`、安装依赖，并在首次运行时初始化一个全新的本地数据库。随后访问：

`http://127.0.0.1:8080/`

| 账号 | 密码 |
| --- | --- |
| `preview_a` | `PreviewCat-A!8080` |
| `preview_b` | `PreviewCat-B!8080` |

两个账号共享同一套预览数据。这些密码公开写在启动脚本中，只适合本机预览；不要用于公网或真实数据环境。

Windows 启动脚本使用自身所在目录定位文件，因此可以把整个项目解压到任意本地目录，包括带空格或中文的目录。

## 一键本地预览（macOS）

解压项目后，双击 `start-local-8080.command`，或在“终端”中执行该脚本。如果 macOS 拦截脚本，请在“系统设置 > 隐私与安全性”中允许运行。

```bash
chmod +x ./start-local-8080.command
./start-local-8080.command
```

脚本会使用 `python3` 创建 `.venv`、安装依赖并初始化本地预览数据库，然后监听 `http://127.0.0.1:8080/`。

| 账号 | 密码 |
| --- | --- |
| `preview_a` | `PreviewCat-A!8080` |
| `preview_b` | `PreviewCat-B!8080` |

## 手动运行

需要 Python 3.10 或更高版本。

### Windows PowerShell

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python init_db.py
python app.py
```

### macOS 或 Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements.txt
python3 init_db.py
python3 app.py
```

`init_db.py` 会创建一个新的 `diary.db`，并生成两个示例账号及随机密码。请妥善保存终端中显示的密码。

默认访问地址为 `http://127.0.0.1:8080/`。程序默认只监听本机。如确需局域网访问，请先配置防火墙，然后显式设置主机和端口。

Windows PowerShell：

```powershell
$env:HOST = '0.0.0.0'
$env:PORT = '8080'
python app.py
```

macOS 或 Linux：

```bash
export HOST="0.0.0.0"
export PORT="8080"
python3 app.py
```

若项目根目录存在 `certs/cert.pem` 和 `certs/key.pem`，程序会自动启用 HTTPS。不要把私钥提交到 GitHub。

当前项目适合个人设备或受控局域网使用，不应在未配置反向代理、可信 HTTPS、备份和额外访问控制的情况下直接暴露到公网。

注册接口允许访客创建新的双账号组合；若无需开放注册，应在部署前增加管理员审批或邀请码机制。

## 项目结构

- `app.py`：Flask API 与静态文件服务。
- `init_db.py`：数据库结构、迁移和本地初始化。
- `couple-bucket-list.html`：单页前端。
- `images/`：页面实际使用的通用图片资源。
- `tools/test_regressions.py`：安全与业务逻辑回归测试。
- `start-local-8080.ps1`：创建本地环境并在 8080 端口启动。
- `start-local-8080.bat`：供 Windows 双击运行的启动入口。
- `start-local-8080.command`：供 macOS Terminal/Finder 使用的启动入口。

## 开源许可

本项目（包括代码和仓库内的图片素材）使用 [MIT License](LICENSE) 开源。

你可以自由使用、复制、修改、发布、分发、再许可和销售本项目的副本，但必须在副本或实质性部分中保留原版权声明和 MIT 许可声明。
