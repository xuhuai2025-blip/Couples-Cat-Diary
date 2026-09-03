"""
猫猫日记后端 — Flask + SQLite + Token 鉴权
- 同时托管静态文件（HTML / images / fonts）
- 数据同步 API：buckets + scores
- 鉴权：账号密码登录 → 30 天 token
"""
import os
import math
import re
import secrets
import sqlite3
import time
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path
from threading import Lock

from flask import Flask, request, jsonify, send_from_directory, g
from werkzeug.security import check_password_hash, generate_password_hash
import waitress

from init_db import migrate_pair_schema

# === 配置 ===
BASE_DIR = Path(__file__).parent.resolve()
DB_PATH = BASE_DIR / "diary.db"
TOKEN_TTL_HOURS = 24 * 30
HOST = os.environ.get("HOST", "127.0.0.1")  # 安全默认值；确需局域网访问时显式设置 HOST=0.0.0.0 并配置防火墙
PORT = int(os.environ.get("PORT", "8080"))

# === 登录限流 ===
# 按 IP 维度，3 次失败/小时 → 锁 1 小时
# 成功登录会清空该 IP 的失败计数（友好：用户自己输错几次后想起正确密码还能登）
LOGIN_MAX_FAILS = 3
LOGIN_WINDOW_SEC = 3600
login_attempts = defaultdict(list)  # {ip: [timestamp, ...]}
REGISTER_MAX_PER_HOUR = 3
registration_attempts = defaultdict(list)
_schema_ready_paths = set()
_schema_lock = Lock()


def _prune_attempts(ip: str):
    now = time.time()
    login_attempts[ip] = [t for t in login_attempts[ip] if t > now - LOGIN_WINDOW_SEC]


def _is_login_locked(ip: str) -> bool:
    _prune_attempts(ip)
    return len(login_attempts.get(ip, [])) >= LOGIN_MAX_FAILS


def _record_login_failure(ip: str):
    login_attempts[ip].append(time.time())


def _clear_login_attempts(ip: str):
    login_attempts.pop(ip, None)


def gen_id(prefix: str) -> str:
    ts = int(datetime.now().timestamp() * 1000)
    rand = secrets.token_hex(3)
    return f"{prefix}_{ts}_{rand}"


def clean_string(value) -> str:
    """只接受 JSON 字符串，避免对数字/对象调用 strip() 导致 500。"""
    return value.strip() if isinstance(value, str) else ""


app = Flask(__name__, static_folder=None)


@app.before_request
def _handle_options():
    """iOS 18 PNA + CORS 预检：OPTIONS 不进视图，after_request 统一打 CORS/PNA 头。"""
    if request.method == "OPTIONS":
        return ("", 204)


@app.after_request
def _cors_and_no_cache(resp):
    """CORS / PNA 头 + JSON 禁用缓存。

    关键点：iOS 18+ Safari 启用 Private Network Access (PNA)，
    fetch 到 RFC1918 IP（10.x / 172.16-31 / 192.168）时会先发 OPTIONS 预检，
    预检头带 `Access-Control-Request-Private-Network: true`。
    响应不带 `Access-Control-Allow-Private-Network: true` → 整个 fetch 失败。
    错误表现就是 `Network request failed`，没有任何额外信息。
    """
    resp.headers["Access-Control-Allow-Origin"] = "*"
    resp.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, PATCH, DELETE, OPTIONS"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization, X-Requested-With"
    resp.headers["Access-Control-Allow-Private-Network"] = "true"
    if resp.content_type and resp.content_type.startswith("application/json"):
        resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        resp.headers["Pragma"] = "no-cache"
        resp.headers["Expires"] = "0"
    return resp


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
        db_key = str(Path(DB_PATH).resolve())
        if db_key not in _schema_ready_paths:
            with _schema_lock:
                if db_key not in _schema_ready_paths:
                    migrate_pair_schema(g.db)
                    _schema_ready_paths.add(db_key)
    return g.db


@app.teardown_appcontext
def close_db(error):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def auth_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        scheme, separator, token = auth.partition(" ")
        token = token.strip()
        if separator != " " or scheme.lower() != "bearer":
            token = ""
        if not token:
            return jsonify({"error": "missing token"}), 401
        db = get_db()
        row = db.execute(
            "SELECT s.user_id, s.expires_at, u.username, u.display_name, u.pair_id "
            "FROM sessions s JOIN users u ON u.id = s.user_id "
            "WHERE s.token = ?",
            (token,),
        ).fetchone()
        if not row:
            return jsonify({"error": "invalid token"}), 401
        try:
            if datetime.fromisoformat(row["expires_at"]) < datetime.now():
                return jsonify({"error": "token expired"}), 401
        except Exception:
            return jsonify({"error": "token expired"}), 401
        g.user = {
            "id": row["user_id"],
            "username": row["username"],
            "display_name": row["display_name"] or row["username"],
        }
        if not row["pair_id"]:
            return jsonify({"error": "account has no shared space"}), 403
        g.pair_id = row["pair_id"]
        g.auth_token = token
        # 顺便记录 last_seen_at(供 /api/presence 判定"对方是否在线")
        try:
            db.execute("UPDATE users SET last_seen_at=CURRENT_TIMESTAMP WHERE id=?", (g.user["id"],))
            db.commit()
        except Exception:
            pass
        return f(*args, **kwargs)
    return wrapper


@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"ok": True, "service": "cat-diary", "time": datetime.now().isoformat()})


def _validate_registration_account(raw, label):
    if not isinstance(raw, dict):
        return None, f"{label}信息格式无效"
    username = clean_string(raw.get("username"))
    password = raw.get("password") if isinstance(raw.get("password"), str) else ""
    display_name = clean_string(raw.get("displayName")) or username
    if not re.fullmatch(r"[\w.-]{2,32}", username, flags=re.UNICODE):
        return None, f"{label}用户名须为 2-32 位中文、字母、数字、下划线、点或短横线"
    if len(password) < 8 or len(password) > 128:
        return None, f"{label}密码须为 8-128 位"
    if len(display_name) > 24:
        return None, f"{label}昵称最多 24 个字符"
    return {
        "username": username,
        "password_hash": generate_password_hash(password),
        "display_name": display_name,
    }, None


@app.route("/api/auth/register-pair", methods=["POST"])
def register_pair():
    """一次原子创建两个账号；两个账号归属同一个隔离共享空间。"""
    client_ip = request.remote_addr or "unknown"
    now_ts = time.time()
    registration_attempts[client_ip] = [
        t for t in registration_attempts[client_ip] if t > now_ts - LOGIN_WINDOW_SEC
    ]
    if len(registration_attempts[client_ip]) >= REGISTER_MAX_PER_HOUR:
        return jsonify({"error": "该网络本小时注册次数已达上限"}), 429

    data = request.get_json(force=True, silent=True) or {}
    accounts = data.get("accounts")
    if not isinstance(accounts, list) or len(accounts) != 2:
        return jsonify({"error": "必须一次提交两个账号"}), 400
    first, error = _validate_registration_account(accounts[0], "第一个账号")
    if error:
        return jsonify({"error": error}), 400
    second, error = _validate_registration_account(accounts[1], "第二个账号")
    if error:
        return jsonify({"error": error}), 400
    if first["username"].casefold() == second["username"].casefold():
        return jsonify({"error": "两个用户名不能相同"}), 400

    db = get_db()
    existing = db.execute(
        "SELECT username FROM users WHERE lower(username) IN (lower(?), lower(?)) LIMIT 1",
        (first["username"], second["username"]),
    ).fetchone()
    if existing:
        return jsonify({"error": "用户名已存在，请更换后重试"}), 409

    pair_id = gen_id("pair")
    try:
        db.execute("BEGIN IMMEDIATE")
        db.execute("INSERT INTO pairs (id) VALUES (?)", (pair_id,))
        for account in (first, second):
            db.execute(
                "INSERT INTO users (username, password_hash, display_name, pair_id) VALUES (?, ?, ?, ?)",
                (account["username"], account["password_hash"], account["display_name"], pair_id),
            )
        db.execute("INSERT INTO pair_together_settings (pair_id) VALUES (?)", (pair_id,))
        db.execute(
            "INSERT INTO pair_pet_state (pair_id, last_decay_at) VALUES (?, datetime('now', 'localtime'))",
            (pair_id,),
        )
        db.commit()
    except sqlite3.IntegrityError:
        db.rollback()
        return jsonify({"error": "用户名已存在，请更换后重试"}), 409
    except Exception:
        db.rollback()
        raise

    registration_attempts[client_ip].append(now_ts)
    return jsonify({
        "ok": True,
        "accounts": [
            {"username": first["username"], "display_name": first["display_name"]},
            {"username": second["username"], "display_name": second["display_name"]},
        ],
    }), 201


@app.route("/api/presence", methods=["GET"])
@auth_required
def presence():
    """返回所有账号的在线状态（基于 users.last_seen_at + 5 分钟阈值）。

    触发 last_seen_at: 任何 auth_required 请求都会更新（auth_required wrapper 自动）。
    在线判定: now - last_seen_at < 5 分钟 = 在线。
    """
    db = get_db()
    rows = db.execute(
        "SELECT id, username, display_name, last_seen_at FROM users WHERE pair_id=? ORDER BY id",
        (g.pair_id,),
    ).fetchall()
    # SQLite CURRENT_TIMESTAMP 使用无时区 UTC；转换后移除 tzinfo 以保持可比较。
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    threshold = timedelta(minutes=5)
    out = []
    for r in rows:
        last = r["last_seen_at"]
        is_online = False
        if last:
            # sqlite CURRENT_TIMESTAMP 格式 = 'YYYY-MM-DD HH:MM:SS' (带空格)
            # Python 3.11+ 的 fromisoformat 也接受，但用 strptime 更稳
            last_dt = None
            for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f"):
                try:
                    last_dt = datetime.strptime(last, fmt)
                    break
                except (TypeError, ValueError):
                    continue
            if last_dt is not None:
                is_online = (now - last_dt) < threshold
        out.append({
            "user_id": r["id"],
            "username": r["username"],
            "display_name": r["display_name"] or r["username"],
            "last_seen_at": last,
            "online": is_online,
        })
    return jsonify({"users": out, "threshold_minutes": 5})


# === Auth ===
@app.route("/api/auth/login", methods=["POST"])
def login():
    data = request.get_json(force=True, silent=True) or {}
    username = clean_string(data.get("username"))
    password = data.get("password") if isinstance(data.get("password"), str) else ""
    if not username or not password:
        return jsonify({"error": "用户名和密码不能为空"}), 400
    client_ip = request.remote_addr or "unknown"
    # 限流检查
    if _is_login_locked(client_ip):
        oldest = min(login_attempts[client_ip]) if login_attempts[client_ip] else 0
        wait_min = max(1, int((LOGIN_WINDOW_SEC - (time.time() - oldest)) / 60) + 1)
        return jsonify({
            "error": f"尝试次数过多，请 {wait_min} 分钟后再试",
            "retry_after_min": wait_min,
        }), 429
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    if not user or not check_password_hash(user["password_hash"], password):
        _record_login_failure(client_ip)
        n = len(login_attempts[client_ip])
        remaining = max(0, LOGIN_MAX_FAILS - n)
        if remaining > 0:
            return jsonify({
                "error": f"用户名或密码错误（还剩 {remaining} 次机会）",
                "remaining_attempts": remaining,
            }), 401
        return jsonify({
            "error": "用户名或密码错误（已锁定 1 小时）",
            "locked_minutes": 60,
        }), 401
    # 登录成功：清空该 IP 失败计数
    _clear_login_attempts(client_ip)
    token = secrets.token_urlsafe(32)
    expires_at = (datetime.now() + timedelta(hours=TOKEN_TTL_HOURS)).isoformat()
    db.execute(
        "INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)",
        (token, user["id"], expires_at),
    )
    db.commit()
    return jsonify({
        "token": token,
        "expires_at": expires_at,
        "user": {
            "id": user["id"],
            "username": user["username"],
            "display_name": user["display_name"] or user["username"],
        },
    })


@app.route("/api/auth/logout", methods=["POST"])
@auth_required
def logout():
    db = get_db()
    db.execute("DELETE FROM sessions WHERE token = ?", (g.auth_token,))
    db.commit()
    return jsonify({"ok": True})


@app.route("/api/auth/me", methods=["GET"])
@auth_required
def me():
    return jsonify({"user": g.user})


# === Buckets ===
VALID_CATEGORIES = ("food", "movie", "travel", "play")


@app.route("/api/buckets", methods=["GET"])
@auth_required
def list_buckets():
    db = get_db()
    rows = db.execute(
        "SELECT b.id, b.title, b.category, b.cat_key, b.done, b.done_at, b.created_at, b.added_by, "
        "u.username as added_by_name, u.display_name as added_by_display "
        "FROM buckets b LEFT JOIN users u ON u.id = b.added_by "
        "WHERE b.pair_id=? ORDER BY b.created_at DESC",
        (g.pair_id,),
    ).fetchall()
    out = []
    for r in rows:
        out.append({
            "id": r["id"],
            "title": r["title"],
            "category": r["category"],
            "catKey": r["cat_key"],
            "done": bool(r["done"]),
            "doneAt": r["done_at"],
            "createdAt": r["created_at"],
            "addedBy": r["added_by"],
            "addedByName": r["added_by_name"],
            "addedByDisplay": r["added_by_display"],
        })
    return jsonify({"buckets": out})


BUCKET_TITLE_MAX = 16


@app.route("/api/buckets", methods=["POST"])
@auth_required
def create_bucket():
    data = request.get_json(force=True, silent=True) or {}
    title = clean_string(data.get("title"))
    category = clean_string(data.get("category"))
    cat_key = clean_string(data.get("catKey"))
    if not title:
        return jsonify({"error": "title 不能为空"}), 400
    if len(title) > BUCKET_TITLE_MAX:
        return jsonify({
            "error": f"愿望最多 {BUCKET_TITLE_MAX} 字,当前 {len(title)} 字",
            "max_length": BUCKET_TITLE_MAX,
        }), 400
    if category not in VALID_CATEGORIES:
        return jsonify({"error": f"category 必须是 {VALID_CATEGORIES} 之一"}), 400
    bucket_id = gen_id("b")
    now = datetime.now().isoformat()
    db = get_db()
    db.execute(
        "INSERT INTO buckets (id, title, category, cat_key, done, done_at, added_by, created_at, pair_id) "
        "VALUES (?, ?, ?, ?, 0, NULL, ?, ?, ?)",
        (bucket_id, title, category, cat_key, g.user["id"], now, g.pair_id),
    )
    db.commit()
    row = db.execute("SELECT * FROM buckets WHERE id=? AND pair_id=?", (bucket_id, g.pair_id)).fetchone()
    return jsonify({"bucket": _row_to_bucket(row)})


@app.route("/api/buckets/<bucket_id>", methods=["PATCH"])
@auth_required
def update_bucket(bucket_id):
    data = request.get_json(force=True, silent=True) or {}
    db = get_db()
    row = db.execute("SELECT * FROM buckets WHERE id=? AND pair_id=?", (bucket_id, g.pair_id)).fetchone()
    if not row:
        return jsonify({"error": "bucket not found"}), 404
    updates, values = [], []
    if "done" in data:
        if not isinstance(data["done"], bool):
            return jsonify({"error": "done 必须是布尔值"}), 400
        done = data["done"]
        updates += ["done = ?", "done_at = ?"]
        values += [1 if done else 0, datetime.now().isoformat() if done else None]
    if "title" in data:
        title = clean_string(data["title"])
        if not title:
            return jsonify({"error": "title 不能为空"}), 400
        updates.append("title = ?")
        values.append(title)
    if "category" in data:
        if data["category"] not in VALID_CATEGORIES:
            return jsonify({"error": f"category 必须是 {VALID_CATEGORIES} 之一"}), 400
        updates.append("category = ?")
        values.append(data["category"])
    if "catKey" in data:
        updates.append("cat_key = ?")
        values.append(clean_string(data["catKey"]))
    if not updates:
        return jsonify({"error": "没有可更新的字段"}), 400
    updates.append("updated_at = ?")
    values.append(datetime.now().isoformat())
    values.append(bucket_id)
    values.append(g.pair_id)
    db.execute(f"UPDATE buckets SET {', '.join(updates)} WHERE id=? AND pair_id=?", values)
    db.commit()
    row = db.execute("SELECT * FROM buckets WHERE id=? AND pair_id=?", (bucket_id, g.pair_id)).fetchone()
    return jsonify({"bucket": _row_to_bucket(row)})


@app.route("/api/buckets/<bucket_id>", methods=["DELETE"])
@auth_required
def delete_bucket(bucket_id):
    db = get_db()
    db.execute("DELETE FROM buckets WHERE id=? AND pair_id=?", (bucket_id, g.pair_id))
    db.commit()
    return jsonify({"ok": True})


def _row_to_bucket(r):
    return {
        "id": r["id"],
        "title": r["title"],
        "category": r["category"],
        "catKey": r["cat_key"],
        "done": bool(r["done"]),
        "doneAt": r["done_at"],
        "createdAt": r["created_at"],
        "addedBy": r["added_by"],
    }


# === Scores ===
@app.route("/api/scores", methods=["GET"])
@auth_required
def list_scores():
    db = get_db()
    rows = db.execute(
        "SELECT s.id, s.type, s.score, s.emoji, s.text, s.created_at, s.added_by, "
        "u.username as added_by_name, u.display_name as added_by_display "
        "FROM scores s LEFT JOIN users u ON u.id = s.added_by "
        "WHERE s.pair_id=? ORDER BY s.created_at DESC",
        (g.pair_id,),
    ).fetchall()
    out = []
    for r in rows:
        out.append({
            "id": r["id"],
            "type": r["type"],
            "score": r["score"],
            "emoji": r["emoji"],
            "text": r["text"],
            "date": r["created_at"],
            "addedBy": r["added_by"],
            "addedByName": r["added_by_name"],
            "addedByDisplay": r["added_by_display"],
        })
    return jsonify({"scores": out})


@app.route("/api/scores", methods=["POST"])
@auth_required
def create_score():
    data = request.get_json(force=True, silent=True) or {}
    text = clean_string(data.get("text"))
    stype = clean_string(data.get("type") or "plus")
    emoji = clean_string(data.get("emoji")) or ("😺" if stype == "plus" else "😢")
    if not text:
        return jsonify({"error": "text 不能为空"}), 400
    if stype not in ("plus", "minus"):
        return jsonify({"error": "type 必须是 plus/minus"}), 400
    try:
        score = float(data.get("score", 1))
    except (TypeError, ValueError):
        return jsonify({"error": "score 必须是有限数字"}), 400
    if not math.isfinite(score):
        return jsonify({"error": "score 必须是有限数字"}), 400
    if score < 0:
        score = 0.0  # 0 分事件允许（仅有 emoji 标记，无积分变化）
    score_id = gen_id("s")
    # 客户端可以指定 createdAt（用于历史数据导入）；不传则用服务器时间
    custom_date = data.get("date") or data.get("createdAt")
    if custom_date:
        try:
            created_at = datetime.fromisoformat(custom_date).isoformat()
        except (TypeError, ValueError):
            created_at = datetime.now().isoformat()
    else:
        created_at = datetime.now().isoformat()
    db = get_db()
    db.execute(
        "INSERT INTO scores (id, type, score, emoji, text, added_by, created_at, pair_id) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (score_id, stype, score, emoji, text, g.user["id"], created_at, g.pair_id),
    )
    db.commit()
    row = db.execute("SELECT * FROM scores WHERE id=? AND pair_id=?", (score_id, g.pair_id)).fetchone()
    return jsonify({"score": _row_to_score(row)})


@app.route("/api/scores/<score_id>", methods=["DELETE"])
@auth_required
def delete_score(score_id):
    db = get_db()
    db.execute("DELETE FROM scores WHERE id=? AND pair_id=?", (score_id, g.pair_id))
    db.commit()
    return jsonify({"ok": True})


def _row_to_score(r):
    return {
        "id": r["id"],
        "type": r["type"],
        "score": r["score"],
        "emoji": r["emoji"],
        "text": r["text"],
        "date": r["created_at"],
        "addedBy": r["added_by"],
    }


# === 留言簿（硬限 3 条） ===
GUESTBOOK_MAX = 3
GUESTBOOK_CONTENT_MAX = 100


@app.route("/api/guestbook", methods=["GET"])
@auth_required
def list_guestbook():
    db = get_db()
    rows = db.execute(
        "SELECT g.id, g.content, g.created_at, g.author_user_id, "
        "u.username as author_name, u.display_name as author_display "
        "FROM guestbook g LEFT JOIN users u ON u.id = g.author_user_id "
        "WHERE g.pair_id=? ORDER BY g.created_at DESC, g.id DESC LIMIT ?",
        (g.pair_id, GUESTBOOK_MAX),
    ).fetchall()
    out = []
    for r in rows:
        out.append({
            "id": r["id"],
            "content": r["content"],
            "createdAt": r["created_at"],
            "authorUserId": r["author_user_id"],
            "authorName": r["author_name"],
            "authorDisplay": r["author_display"] or r["author_name"],
        })
    return jsonify({"messages": out, "max": GUESTBOOK_MAX})


@app.route("/api/guestbook", methods=["POST"])
@auth_required
def post_guestbook():
    data = request.get_json(force=True, silent=True) or {}
    content = clean_string(data.get("content"))
    if not content:
        return jsonify({"error": "留言不能为空"}), 400
    if len(content) > GUESTBOOK_CONTENT_MAX:
        return jsonify({
            "error": f"留言最多 {GUESTBOOK_CONTENT_MAX} 字,当前 {len(content)} 字",
            "max_length": GUESTBOOK_CONTENT_MAX,
        }), 400
    db = get_db()
    db.execute(
        "INSERT INTO guestbook (author_user_id, content, pair_id) VALUES (?, ?, ?)",
        (g.user["id"], content, g.pair_id),
    )
    # 硬限：保留最新 GUESTBOOK_MAX 条
    db.execute(
        "DELETE FROM guestbook WHERE pair_id=? AND id IN ("
        "  SELECT id FROM guestbook WHERE pair_id=? "
        "  ORDER BY created_at DESC, id DESC LIMIT -1 OFFSET ?"
        ")",
        (g.pair_id, g.pair_id, GUESTBOOK_MAX),
    )
    db.commit()
    # 重新读最新 3 条
    rows = db.execute(
        "SELECT g.id, g.content, g.created_at, g.author_user_id, "
        "u.username as author_name, u.display_name as author_display "
        "FROM guestbook g LEFT JOIN users u ON u.id = g.author_user_id "
        "WHERE g.pair_id=? ORDER BY g.created_at DESC, g.id DESC LIMIT ?",
        (g.pair_id, GUESTBOOK_MAX),
    ).fetchall()
    out = []
    for r in rows:
        out.append({
            "id": r["id"],
            "content": r["content"],
            "createdAt": r["created_at"],
            "authorUserId": r["author_user_id"],
            "authorName": r["author_name"],
            "authorDisplay": r["author_display"] or r["author_name"],
        })
    return jsonify({"messages": out, "max": GUESTBOOK_MAX})


# === 宠物系统常量 ===
SHOP_ITEMS = {
    "cat-treat":   {"name": "猫条",   "emoji": "🍢", "image": "images/items/item-cat-treat.png",  "price": 5,  "hunger": 15, "mood": 15, "energy": 0,  "category": "food"},
    "cat-food":    {"name": "猫粮",   "emoji": "🥫", "image": "images/items/item-cat-food.png",   "price": 10, "hunger": 30, "mood": 0,  "energy": 0,  "category": "food"},
    "cat-can":     {"name": "猫罐罐", "emoji": "🐟", "image": "images/items/item-cat-can.png",    "price": 20, "hunger": 30, "mood": 30, "energy": 15, "category": "food"},
    "feather-toy": {"name": "逗猫棒", "emoji": "🪶", "image": "images/items/item-feather-toy.png", "price": 15, "hunger": 0,  "mood": 30, "energy": 30, "category": "play"},
    "yarn-ball":   {"name": "线团",   "emoji": "🧶", "image": "images/items/item-yarn-ball.png",  "price": 15, "hunger": 0,  "mood": 30, "energy": 30, "category": "play"},
}

PET_CONFIG = {
    "work_gold_per_hour": 5,
    "work_max_hours_per_day": 8,
    "study_gold_per_hour": 1,
    "study_mood_per_hour": 5,
    "study_exp_per_hour": 10,
    "exp_per_level": 100,
    "decay_interval_hours": 4,
    "decay_hunger": 5,    # 调小单次幅度（10→5），避免"突然掉"
    "decay_mood": 3,      # 调小（5→3）
    "decay_energy": 3,    # 调小（5→3）
}

LEVEL_UP_EMOJI = ["🐱", "🐈", "🦁", "🐅", "🐉", "🌟", "✨", "👑"]


def _clamp(val, lo=0, hi=100):
    return max(lo, min(hi, val))


def _today_str() -> str:
    return datetime.now().strftime("%Y-%m-%d")


def _apply_decay(pet_row):
    """如果距离 last_decay_at 超过 decay_interval_hours，按经过的小时数衰减"""
    cfg = PET_CONFIG
    now = datetime.now()
    last = pet_row["last_decay_at"]
    if not last:
        last_dt = now
    else:
        try:
            last_dt = datetime.fromisoformat(last)
        except (TypeError, ValueError):
            last_dt = now
    elapsed_hours = (now - last_dt).total_seconds() / 3600
    if elapsed_hours < cfg["decay_interval_hours"]:
        return  # 还不到衰减时间
    # 每 4h 衰减一次（多次累积）
    steps = int(elapsed_hours // cfg["decay_interval_hours"])
    new_hunger = _clamp(pet_row["hunger"] - steps * cfg["decay_hunger"])
    new_mood = _clamp(pet_row["mood"] - steps * cfg["decay_mood"])
    new_energy = _clamp(pet_row["energy"] - steps * cfg["decay_energy"])
    new_last = (last_dt + __import__("datetime").timedelta(hours=steps * cfg["decay_interval_hours"])).isoformat()
    pet_row["hunger"] = new_hunger
    pet_row["mood"] = new_mood
    pet_row["energy"] = new_energy
    pet_row["last_decay_at"] = new_last


def _pet_sprite_key(pet_row):
    """根据属性决定 cat sprite key：任一数值 < 40% = sad（伤心），否则 = idle（一般状态）"""
    if pet_row["hunger"] < 40 or pet_row["mood"] < 40 or pet_row["energy"] < 40:
        return "sad"
    return "idle"


def _pet_sprite_path(key):
    return {
        "happy":   "images/cat/cat-happy.png",
        "warning": "images/cat/cat-warning.png",
        "sad":     "images/cat/cat-sad.png",
        "idle":    "images/cat/cat-idle-1.png",
    }.get(key, "images/cat/cat-happy.png")


# === Together（纪念日）===
@app.route("/api/together", methods=["GET"])
@auth_required
def get_together():
    db = get_db()
    row = db.execute(
        "SELECT * FROM pair_together_settings WHERE pair_id=?", (g.pair_id,)
    ).fetchone()
    if not row:
        return jsonify({"start_date": None, "anniversaries": []})
    import json as _json
    try:
        anns = _json.loads(row["anniversaries"] or "[]")
    except (TypeError, ValueError):
        anns = []
    return jsonify({
        "start_date": row["start_date"],
        "anniversaries": anns,
        "updated_at": row["updated_at"],
        "updated_by": row["updated_by"],
    })


@app.route("/api/together", methods=["PUT"])
@auth_required
def put_together():
    data = request.get_json(force=True, silent=True) or {}
    raw_start_date = data.get("start_date")
    if raw_start_date is not None and not isinstance(raw_start_date, str):
        return jsonify({"error": "start_date 必须是 YYYY-MM-DD 格式"}), 400
    start_date = clean_string(raw_start_date) or None
    if start_date:
        try:
            datetime.strptime(start_date, "%Y-%m-%d")
        except ValueError:
            return jsonify({"error": "start_date 必须是 YYYY-MM-DD 格式"}), 400
    anniversaries = data.get("anniversaries") or []
    if not isinstance(anniversaries, list):
        return jsonify({"error": "anniversaries 必须是数组"}), 400
    normalized_anniversaries = []
    for anniversary in anniversaries:
        if not isinstance(anniversary, dict):
            return jsonify({"error": "每个纪念日必须是对象"}), 400
        name = anniversary.get("name")
        date_value = anniversary.get("date")
        emoji = anniversary.get("emoji") or "✨"
        recurring = anniversary.get("recurring", False)
        if not isinstance(name, str) or not name.strip():
            return jsonify({"error": "纪念日名称不能为空"}), 400
        if not isinstance(date_value, str):
            return jsonify({"error": "纪念日日期格式无效"}), 400
        if not isinstance(emoji, str) or not isinstance(recurring, bool):
            return jsonify({"error": "纪念日参数格式无效"}), 400
        try:
            datetime.strptime(date_value, "%m-%d" if recurring else "%Y-%m-%d")
        except ValueError:
            return jsonify({"error": "纪念日日期格式无效"}), 400
        normalized_anniversaries.append({
            "name": name.strip(),
            "date": date_value,
            "emoji": emoji.strip() or "✨",
            "recurring": recurring,
        })
    import json as _json
    db = get_db()
    db.execute("""
        UPDATE pair_together_settings
        SET start_date = ?, anniversaries = ?, updated_at = ?, updated_by = ?
        WHERE pair_id = ?
    """, (start_date, _json.dumps(normalized_anniversaries, ensure_ascii=False),
          datetime.now().isoformat(), g.user["id"], g.pair_id))
    db.commit()
    return jsonify({"ok": True})


# === Pet（共享宠物）===
def _get_pet_with_decay():
    db = get_db()
    row = db.execute("SELECT * FROM pair_pet_state WHERE pair_id=?", (g.pair_id,)).fetchone()
    if not row:
        db.execute(
            "INSERT INTO pair_pet_state (pair_id, last_decay_at) VALUES (?, datetime('now', 'localtime'))",
            (g.pair_id,),
        )
        db.commit()
        row = db.execute("SELECT * FROM pair_pet_state WHERE pair_id=?", (g.pair_id,)).fetchone()
    pet = dict(row)
    _apply_decay(pet)
    # 衰减后写回 DB
    db.execute("""UPDATE pair_pet_state SET hunger=?, mood=?, energy=?, last_decay_at=?, updated_at=CURRENT_TIMESTAMP WHERE pair_id=?""",
               (pet["hunger"], pet["mood"], pet["energy"], pet["last_decay_at"], g.pair_id))
    db.commit()
    return pet


@app.route("/api/pet", methods=["GET"])
@auth_required
def get_pet():
    pet = _get_pet_with_decay()
    sprite_key = _pet_sprite_key(pet)
    # 顺便看 pending 数量（共享猫的全局队列）
    pending_row = get_db().execute(
        "SELECT COUNT(*) AS n, MIN(available_at) AS next_avail FROM pet_actions "
        "WHERE status='pending' AND user_id IN (SELECT id FROM users WHERE pair_id=?)",
        (g.pair_id,),
    ).fetchone()
    pending_count = pending_row["n"] if pending_row else 0
    next_avail = pending_row["next_avail"] if pending_row else None
    return jsonify({
        "name": pet["name"],
        "hunger": pet["hunger"],
        "mood": pet["mood"],
        "energy": pet["energy"],
        "gold": pet["gold"],
        "level": pet["level"],
        "exp": pet["exp"],
        "exp_to_next": PET_CONFIG["exp_per_level"] - (pet["exp"] % PET_CONFIG["exp_per_level"]),
        "exp_max": PET_CONFIG["exp_per_level"],  # 升级所需总经验池（用于显示"已积累/总池"）
        "sprite": _pet_sprite_path(sprite_key),
        "sprite_key": sprite_key,
        "pending_count": pending_count,
        "next_available_at": next_avail,
    })


def _today_total_work_hours():
    """两账号合计今日已下单 work 小时（pending + completed 一起算），共享 8h 池。

    业务: 情侣共养一只猫, 打工是猫的体力活, 两人合计不能超过 daily 8h。
    """
    db = get_db()
    row = db.execute(
        """SELECT COALESCE(SUM(hours),0) AS h FROM pet_actions
           WHERE action='work' AND action_date=?
             AND user_id IN (SELECT id FROM users WHERE pair_id=?)""",
        (_today_str(), g.pair_id)
    ).fetchone()
    return float(row["h"] or 0)


def _has_active_job():
    """全局 work/study/sleep 互斥：任一账号排了 pending work/study/sleep 时返回 True。

    业务语义: 情侣共做一份工, 期间另一账号不能再开新工; 睡觉期间全锁定不能摸/喂/玩。
    """
    db = get_db()
    row = db.execute(
        """SELECT 1 FROM pet_actions
           WHERE status='pending' AND action IN ('work','study','sleep')
             AND user_id IN (SELECT id FROM users WHERE pair_id=?) LIMIT 1""",
        (g.pair_id,),
    ).fetchone()
    return row is not None


@app.route("/api/pet/work", methods=["POST"])
@auth_required
def pet_work():
    """打工：排队 N 小时后到账（共享猫的全局队列）"""
    data = request.get_json(force=True, silent=True) or {}
    try:
        hours = float(data.get("hours", 1))
    except (TypeError, ValueError):
        return jsonify({"error": "hours 必须是有限数字"}), 400
    if not math.isfinite(hours) or hours <= 0 or hours > 8:
        return jsonify({"error": "hours 必须在 0-8 之间"}), 400
    user_id = g.user["id"]
    if _has_active_job():
        return jsonify({
            "error": "有任务正在进行中,请先到账或取消后再排新任务",
            "busy": True,
        }), 423
    today_hours = _today_total_work_hours()
    if today_hours + hours > PET_CONFIG["work_max_hours_per_day"]:
        return jsonify({
            "error": f"今天两人合计打工 {today_hours:.1f}h，最多 {PET_CONFIG['work_max_hours_per_day']}h",
            "today_hours": today_hours,
        }), 429
    gold_earned = int(hours * PET_CONFIG["work_gold_per_hour"])
    available_at = (datetime.now() + timedelta(hours=hours)).isoformat()
    db = get_db()
    cur = db.execute(
        """INSERT INTO pet_actions
           (user_id, action, hours, gold_earned, action_date, status, available_at)
           VALUES (?, 'work', ?, ?, ?, 'pending', ?)""",
        (user_id, hours, gold_earned, _today_str(), available_at)
    )
    db.commit()
    return jsonify({
        "ok": True,
        "queued": True,
        "id": cur.lastrowid,
        "action": "work",
        "hours": hours,
        "gold_earned": gold_earned,
        "available_at": available_at,
    })


@app.route("/api/pet/study", methods=["POST"])
@auth_required
def pet_study():
    """学习：排队 N 小时后到账（共享猫的全局队列）"""
    data = request.get_json(force=True, silent=True) or {}
    try:
        hours = float(data.get("hours", 1))
    except (TypeError, ValueError):
        return jsonify({"error": "hours 必须是有限数字"}), 400
    if not math.isfinite(hours) or hours <= 0 or hours > 24:
        return jsonify({"error": "hours 必须在 0-24 之间"}), 400
    user_id = g.user["id"]
    if _has_active_job():
        return jsonify({
            "error": "有任务正在进行中,请先到账或取消后再排新任务",
            "busy": True,
        }), 423
    cfg = PET_CONFIG
    gold_earned = int(hours * cfg["study_gold_per_hour"])
    exp_earned = int(hours * cfg["study_exp_per_hour"])
    mood_delta = int(hours * cfg["study_mood_per_hour"])
    available_at = (datetime.now() + timedelta(hours=hours)).isoformat()
    db = get_db()
    cur = db.execute(
        """INSERT INTO pet_actions
           (user_id, action, hours, gold_earned, exp_earned, mood_delta, action_date, status, available_at)
           VALUES (?, 'study', ?, ?, ?, ?, ?, 'pending', ?)""",
        (user_id, hours, gold_earned, exp_earned, mood_delta, _today_str(), available_at)
    )
    db.commit()
    return jsonify({
        "ok": True,
        "queued": True,
        "id": cur.lastrowid,
        "action": "study",
        "hours": hours,
        "gold_earned": gold_earned,
        "exp_earned": exp_earned,
        "mood_delta": mood_delta,
        "available_at": available_at,
    })


# === Sleep ===
SLEEP_CONFIG = {
    "hours": 0.5,            # 30 分钟
    "mood_delta": 15,         # 醒后 +15 心情
    "energy_delta": 20,       # 醒后 +20 活力
}


@app.route("/api/pet/sleep", methods=["POST"])
@auth_required
def pet_sleep():
    """睡觉: 锁定 30min，期间不能 work/study/pet/feed/play/use-item。醒后 +心情 +活力。"""
    if _has_active_job():
        return jsonify({
            "error": "有任务正在进行中,请先到账或取消后再睡",
            "busy": True,
        }), 423
    cfg = SLEEP_CONFIG
    user_id = g.user["id"]
    available_at = (datetime.now() + timedelta(hours=cfg["hours"])).isoformat()
    db = get_db()
    cur = db.execute(
        """INSERT INTO pet_actions
           (user_id, action, hours, mood_delta, action_date, status, available_at, energy_delta)
           VALUES (?, 'sleep', ?, ?, ?, 'pending', ?, ?)""",
        (user_id, cfg["hours"], cfg["mood_delta"], _today_str(), available_at, cfg["energy_delta"])
    )
    db.commit()
    return jsonify({
        "ok": True,
        "queued": True,
        "id": cur.lastrowid,
        "action": "sleep",
        "hours": cfg["hours"],
        "mood_delta": cfg["mood_delta"],
        "energy_delta": cfg["energy_delta"],
        "available_at": available_at,
    })


@app.route("/api/pet/pending", methods=["GET"])
@auth_required
def pet_pending():
    """查看所有待到账的 work/study/sleep 队列（共享猫的全局队列）"""
    db = get_db()
    rows = db.execute(
        """SELECT id, user_id, action, hours, gold_earned, exp_earned, mood_delta, energy_delta,
                  available_at, created_at
           FROM pet_actions
           WHERE status='pending'
             AND user_id IN (SELECT id FROM users WHERE pair_id=?)
           ORDER BY available_at ASC""",
        (g.pair_id,),
    ).fetchall()
    now = datetime.now()
    out = []
    for r in rows:
        try:
            av = datetime.fromisoformat(r["available_at"])
        except (TypeError, ValueError):
            av = now
        seconds_left = max(0, (av - now).total_seconds())
        out.append({
            "id": r["id"],
            "user_id": r["user_id"],
            "action": r["action"],
            "hours": r["hours"],
            "gold": r["gold_earned"] or 0,
            "exp": r["exp_earned"] or 0,
            "mood": r["mood_delta"] or 0,
            "energy": r["energy_delta"] or 0,
            "available_at": r["available_at"],
            "seconds_left": seconds_left,
            "ready": seconds_left == 0,
        })
    next_avail = out[0]["available_at"] if out else None
    return jsonify({
        "pending": out,
        "count": len(out),
        "next_available_at": next_avail,
    })


@app.route("/api/pet/settle", methods=["POST"])
@auth_required
def pet_settle():
    """扫描所有到期的 pending pet_actions，加 gold/exp/mood 到共享 pet_state，标记 completed。

    并发安全: 用 SQL 端 atomic 累加 + clamp，避免 read-modify-write 丢更新。
    触发方式:
    - 前端 30s 轮询自动调
    - 用户主动
    - cat-diary-ip-watch Mavis cron 也可调
    """
    db = get_db()
    now_iso = datetime.now().isoformat()
    rows = db.execute(
        """SELECT id, action, hours, gold_earned, exp_earned, mood_delta, energy_delta, user_id
           FROM pet_actions
           WHERE status='pending' AND available_at <= ?
             AND user_id IN (SELECT id FROM users WHERE pair_id=?)
           LIMIT 50""",
        (now_iso, g.pair_id)
    ).fetchall()
    if not rows:
        return jsonify({"ok": True, "settled": 0, "details": []})

    cfg = PET_CONFIG
    total_gold = sum(r["gold_earned"] or 0 for r in rows)
    total_exp = sum(r["exp_earned"] or 0 for r in rows)
    total_mood = sum(r["mood_delta"] or 0 for r in rows)
    total_energy = sum(r["energy_delta"] or 0 for r in rows)

    # atomic UPDATE — 单条 SQL 内完成 read-modify-write，不会丢更新
    db.execute(
        """UPDATE pair_pet_state SET
              gold   = MIN(2147483647, gold + ?),
              exp    = MIN(2147483647, exp + ?),
              mood   = MAX(0, MIN(100, mood + ?)),
              energy = MAX(0, MIN(100, energy + ?)),
              updated_at = CURRENT_TIMESTAMP
           WHERE pair_id=?""",
        (total_gold, total_exp, total_mood, total_energy, g.pair_id)
    )

    # 升级：读 exp/level 算新 level，update 写回。
    # 两个并发 settle 各自算升级可能 race，但 gold/exp/mood/energy 是 atomic 已落地，
    # level 升级只会"少升一次"（下一次 level_up 阈值满足时仍会升），不会丢。
    st = db.execute(
        "SELECT exp, level FROM pair_pet_state WHERE pair_id=?", (g.pair_id,)
    ).fetchone()
    new_exp = st["exp"]
    new_level = st["level"]
    while new_exp >= cfg["exp_per_level"]:
        new_exp -= cfg["exp_per_level"]
        new_level += 1
    if new_level != st["level"]:
        db.execute(
            "UPDATE pair_pet_state SET exp=?, level=? WHERE pair_id=?",
            (new_exp, new_level, g.pair_id),
        )

    placeholders = ",".join("?" * len(rows))
    db.execute(
        f"""UPDATE pet_actions SET status='completed', settled_at=?
            WHERE id IN ({placeholders})""",
        [now_iso] + [r["id"] for r in rows]
    )
    db.commit()

    details = [
        {
            "id": r["id"], "user_id": r["user_id"], "action": r["action"],
            "hours": r["hours"], "gold": r["gold_earned"] or 0,
            "exp": r["exp_earned"] or 0, "mood": r["mood_delta"] or 0,
            "energy": r["energy_delta"] or 0,
        } for r in rows
    ]
    return jsonify({
        "ok": True,
        "settled": len(rows),
        "details": details,
        "new_level": new_level,
        "level_up": new_level != st["level"],
    })


# === Shop & Inventory ===
@app.route("/api/pet/shop", methods=["GET"])
@auth_required
def pet_shop():
    items = []
    for k, v in SHOP_ITEMS.items():
        items.append({"key": k, **v})
    return jsonify({"items": items})


def _get_inventory(pair_id):
    db = get_db()
    rows = db.execute(
        "SELECT item_key, quantity FROM pair_inventory WHERE pair_id=?", (pair_id,)
    ).fetchall()
    return {r["item_key"]: r["quantity"] for r in rows}


@app.route("/api/pet/inventory", methods=["GET"])
@auth_required
def get_inventory():
    inv = _get_inventory(g.pair_id)
    # 合并商品详情（含效果字段，前端喂食/玩耍弹窗要显示）
    out = []
    for k, v in SHOP_ITEMS.items():
        out.append({
            "key": k,
            "name": v["name"],
            "emoji": v["emoji"],
            "image": v["image"],
            "category": v["category"],
            "hunger": v["hunger"],
            "mood": v["mood"],
            "energy": v["energy"],
            "price": v["price"],
            "quantity": inv.get(k, 0),
        })
    return jsonify({"items": out, "gold_view": None})


@app.route("/api/pet/buy", methods=["POST"])
@auth_required
def pet_buy():
    data = request.get_json(force=True, silent=True) or {}
    item_key = clean_string(data.get("item_key"))
    try:
        qty = int(data.get("quantity", 1))
    except (TypeError, ValueError):
        qty = 1
    if item_key not in SHOP_ITEMS or qty <= 0 or qty > 99:
        return jsonify({"error": "参数无效"}), 400
    item = SHOP_ITEMS[item_key]
    total_cost = item["price"] * qty
    db = get_db()
    pet = _get_pet_with_decay()
    if pet["gold"] < total_cost:
        return jsonify({"error": f"金币不足（需要 {total_cost}，你有 {pet['gold']}）"}), 400
    new_gold = pet["gold"] - total_cost
    db.execute(
        "UPDATE pair_pet_state SET gold=?, updated_at=CURRENT_TIMESTAMP WHERE pair_id=?",
        (new_gold, g.pair_id),
    )
    # upsert inventory
    cur = db.execute(
        "SELECT quantity FROM pair_inventory WHERE pair_id=? AND item_key=?",
        (g.pair_id, item_key),
    ).fetchone()
    if cur:
        db.execute(
            "UPDATE pair_inventory SET quantity=?, updated_at=CURRENT_TIMESTAMP WHERE pair_id=? AND item_key=?",
            (cur["quantity"] + qty, g.pair_id, item_key),
        )
    else:
        db.execute(
            "INSERT INTO pair_inventory (pair_id, item_key, quantity) VALUES (?, ?, ?)",
            (g.pair_id, item_key, qty),
        )
    db.commit()
    return jsonify({"ok": True, "cost": total_cost, "new_gold": new_gold, "bought": qty})


@app.route("/api/pet/use-item", methods=["POST"])
@auth_required
def pet_use_item():
    if _has_active_job():
        return jsonify({"error": "小猫正在睡觉/工作中,不能喂/玩", "busy": True}), 423
    data = request.get_json(force=True, silent=True) or {}
    item_key = clean_string(data.get("item_key"))
    try:
        qty = int(data.get("quantity", 1))
    except (TypeError, ValueError):
        qty = 1
    if item_key not in SHOP_ITEMS or qty <= 0 or qty > 99:
        return jsonify({"error": "参数无效"}), 400
    db = get_db()
    inv = _get_inventory(g.pair_id)
    if inv.get(item_key, 0) < qty:
        return jsonify({"error": f"道具不足（需要 {qty}，你有 {inv.get(item_key, 0)}）"}), 400
    item = SHOP_ITEMS[item_key]
    pet = _get_pet_with_decay()
    delta_h = item["hunger"] * qty
    delta_m = item["mood"] * qty
    delta_e = item["energy"] * qty
    new_h = _clamp(pet["hunger"] + delta_h)
    new_m = _clamp(pet["mood"] + delta_m)
    new_e = _clamp(pet["energy"] + delta_e)
    db.execute("""UPDATE pair_pet_state SET hunger=?, mood=?, energy=?, updated_at=CURRENT_TIMESTAMP WHERE pair_id=?""",
               (new_h, new_m, new_e, g.pair_id))
    db.execute(
        "UPDATE pair_inventory SET quantity=quantity-?, updated_at=CURRENT_TIMESTAMP WHERE pair_id=? AND item_key=?",
        (qty, g.pair_id, item_key),
    )
    # 记录操作者，展示时按同一账号组合汇总。
    # category=food → 喂食，category=play → 玩耍。一次 use-item 请求 = 一条记录（前端面板也按事件数 +1）
    action_label = "feed" if item["category"] == "food" else "play"
    db.execute("""INSERT INTO pet_actions (user_id, action, hours, gold_earned, exp_earned, mood_delta, action_date)
                  VALUES (?, ?, 0, 0, 0, ?, ?)""",
               (g.user["id"], action_label, new_m - pet["mood"], _today_str()))
    db.commit()
    return jsonify({
        "ok": True,
        "item": item["name"],
        "action": action_label,
        "delta": {"hunger": new_h - pet["hunger"], "mood": new_m - pet["mood"], "energy": new_e - pet["energy"]},
        "new": {"hunger": new_h, "mood": new_m, "energy": new_e},
    })


@app.route("/api/pet/pet", methods=["POST"])
@auth_required
def pet_pet():
    """抚摸 +1 心情（不消耗任何资源）"""
    if _has_active_job():
        return jsonify({"error": "小猫正在睡觉/工作中,不能打扰", "busy": True}), 423
    user_id = g.user["id"]
    pet = _get_pet_with_decay()
    new_m = _clamp(pet["mood"] + 1)
    mood_delta = new_m - pet["mood"]
    db = get_db()
    db.execute(
        "UPDATE pair_pet_state SET mood=?, updated_at=CURRENT_TIMESTAMP WHERE pair_id=?",
        (new_m, g.pair_id),
    )
    # 记录操作者，展示时按同一账号组合汇总。
    db.execute("""INSERT INTO pet_actions (user_id, action, hours, gold_earned, exp_earned, mood_delta, action_date)
                  VALUES (?, 'pet', 0, 0, 0, ?, ?)""",
               (user_id, mood_delta, _today_str()))
    db.commit()
    return jsonify({
        "ok": True,
        "delta": {"mood": mood_delta},
        "new": {"hunger": pet["hunger"], "mood": new_m, "energy": pet["energy"]},
    })


@app.route("/api/pet/stats", methods=["GET"])
@auth_required
def pet_stats():
    """同一账号组合共享的互动次数：抚摸 / 喂食 / 玩耍。"""
    db = get_db()
    rows = db.execute("""SELECT action, COUNT(*) AS n FROM pet_actions
                         WHERE user_id IN (SELECT id FROM users WHERE pair_id=?)
                           AND action IN ('pet', 'feed', 'play')
                         GROUP BY action""", (g.pair_id,)).fetchall()
    counts = {r["action"]: r["n"] for r in rows}
    return jsonify({
        "pet_count":  counts.get("pet", 0),
        "fed_count":  counts.get("feed", 0),
        "play_count": counts.get("play", 0),
    })


# === 静态文件托管 ===
@app.route("/")
def index():
    return send_from_directory(BASE_DIR, "couple-bucket-list.html")


@app.route("/images/<path:filename>")
def image_file(filename):
    """只公开前端实际需要的图片，避免泄露数据库、源码和 TLS 私钥。"""
    return send_from_directory(BASE_DIR / "images", filename)


if __name__ == "__main__":
    cert_dir = BASE_DIR / "certs"
    certfile = cert_dir / "cert.pem"
    keyfile = cert_dir / "key.pem"
    have_tls = certfile.exists() and keyfile.exists()
    scheme = "https" if have_tls else "http"
    print(f"[cat-diary] DB: {DB_PATH}")
    print(f"[cat-diary] Serving on {scheme}://{HOST}:{PORT}")
    print(f"[cat-diary] Open: {scheme}://{HOST}:{PORT}/")
    if have_tls:
        print(f"[cat-diary] TLS cert: {certfile}")
        # 用 hypercorn 跑（waitress 不支持 SSL），Flask WSGI 用 asgiref 包装成 ASGI
        from hypercorn.config import Config
        from hypercorn.asyncio import serve
        from asgiref.wsgi import WsgiToAsgi
        import asyncio
        config = Config()
        config.bind = [f"{HOST}:{PORT}"]
        config.certfile = str(certfile)
        config.keyfile = str(keyfile)
        config.loglevel = "info"
        asyncio.run(serve(WsgiToAsgi(app), config))
    else:
        waitress.serve(app, host=HOST, port=PORT, ident="cat-diary", threads=4)
