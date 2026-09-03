# Couples Cat Diary

[English](README.md) | [简体中文](README.zh-CN.md)

A small Flask and SQLite application for couples. It includes paired-account registration, a shared bucket list, anniversaries, a guestbook, and a shared virtual cat.

## About

The code in this project was generated with ChatGPT and MiniMax, then manually organized and tested.

## Privacy

This repository does not contain the original website's database, accounts, password hashes, login tokens, guestbook messages, anniversaries, activity records, certificates, private keys, logs, local-network IP addresses, or absolute local paths.

## One-click local preview on Windows

Double-click `start-local-8080.bat`. The launcher automatically creates `.venv`, installs the dependencies, and initializes a fresh local database on the first run. Then open:

`http://127.0.0.1:8080/`

| Username | Password |
| --- | --- |
| `preview_a` | `PreviewCat-A!8080` |
| `preview_b` | `PreviewCat-B!8080` |

The two accounts share the same preview data. These credentials are publicly included in the launcher and are intended only for local preview. Do not use them for an internet-facing deployment or with real data.

The Windows launcher resolves files relative to its own location, so the entire project can be extracted to any local directory, including a path containing spaces or non-ASCII characters.

## One-click local preview on macOS

After extracting the project, double-click `start-local-8080.command`, or run it from Terminal. If macOS blocks the script, allow it under **System Settings > Privacy & Security**.

```bash
chmod +x ./start-local-8080.command
./start-local-8080.command
```

The launcher uses `python3` to create `.venv`, install the dependencies, initialize a local preview database, and start the application at `http://127.0.0.1:8080/`.

| Username | Password |
| --- | --- |
| `preview_a` | `PreviewCat-A!8080` |
| `preview_b` | `PreviewCat-B!8080` |

## Manual setup

Python 3.10 or later is required.

### Windows PowerShell

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python init_db.py
python app.py
```

### macOS or Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements.txt
python3 init_db.py
python3 app.py
```

`init_db.py` creates a new `diary.db` and generates two sample accounts with random passwords. Save the passwords printed in the terminal.

The default address is `http://127.0.0.1:8080/`. The application listens only on the local machine by default. If access from the local network is required, configure the firewall first and explicitly set the host and port.

Windows PowerShell:

```powershell
$env:HOST = '0.0.0.0'
$env:PORT = '8080'
python app.py
```

macOS or Linux:

```bash
export HOST="0.0.0.0"
export PORT="8080"
python3 app.py
```

If `certs/cert.pem` and `certs/key.pem` exist in the project root, HTTPS is enabled automatically. Never commit a private key to GitHub.

This project is intended for personal devices or controlled local networks. Do not expose it directly to the public internet without a reverse proxy, trusted HTTPS, backups, and additional access controls.

The registration endpoint allows visitors to create new paired accounts. If public registration is unnecessary, add administrator approval or an invitation-code mechanism before deployment.

## Project structure

- `app.py`: Flask API and static-file serving.
- `init_db.py`: Database schema, migrations, and local initialization.
- `couple-bucket-list.html`: Single-page frontend.
- `images/`: Generic image assets used by the page.
- `tools/test_regressions.py`: Security and business-logic regression tests.
- `start-local-8080.ps1`: Creates the local environment and starts the app on port 8080.
- `start-local-8080.bat`: Double-clickable Windows launcher.
- `start-local-8080.command`: macOS Terminal/Finder launcher.

## License

This project, including its source code and image assets, is licensed under the [MIT License](LICENSE).

You may use, copy, modify, publish, distribute, sublicense, and sell copies of the project, provided that the original copyright notice and MIT permission notice are retained in all copies or substantial portions.
