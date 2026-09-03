"""
初始化 SQLite 数据库 + 创建默认账号
"""
import argparse
import secrets
import sqlite3
from pathlib import Path

from werkzeug.security import generate_password_hash

BASE_DIR = Path(__file__).parent.resolve()
DB_PATH = BASE_DIR / "diary.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS pairs (
    id TEXT PRIMARY KEY,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    display_name TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen_at TIMESTAMP,
    pair_id TEXT,
    FOREIGN KEY (pair_id) REFERENCES pairs(id)
);

CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS buckets (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    category TEXT NOT NULL,
    cat_key TEXT NOT NULL,
    done INTEGER DEFAULT 0,
    done_at TIMESTAMP,
    added_by INTEGER,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    pair_id TEXT,
    FOREIGN KEY (pair_id) REFERENCES pairs(id),
    FOREIGN KEY (added_by) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS scores (
    id TEXT PRIMARY KEY,
    type TEXT NOT NULL,
    score REAL NOT NULL,
    emoji TEXT,
    text TEXT NOT NULL,
    added_by INTEGER,
    created_at TIMESTAMP NOT NULL,
    pair_id TEXT,
    FOREIGN KEY (pair_id) REFERENCES pairs(id),
    FOREIGN KEY (added_by) REFERENCES users(id)
);

CREATE INDEX IF NOT EXISTS idx_buckets_done ON buckets(done);
CREATE INDEX IF NOT EXISTS idx_buckets_category ON buckets(category);
CREATE INDEX IF NOT EXISTS idx_scores_date ON scores(created_at);

-- 纪念日（全局 1 行）
CREATE TABLE IF NOT EXISTS together_settings (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    start_date TEXT,
    anniversaries TEXT,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_by INTEGER,
    FOREIGN KEY (updated_by) REFERENCES users(id)
);

-- 共享宠物（全局 1 行）
CREATE TABLE IF NOT EXISTS pet_state (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    name TEXT DEFAULT '小本本',
    hunger INTEGER DEFAULT 50,
    mood INTEGER DEFAULT 50,
    energy INTEGER DEFAULT 50,
    gold INTEGER DEFAULT 0,
    level INTEGER DEFAULT 1,
    exp INTEGER DEFAULT 0,
    last_decay_at TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 打工/学习日志
CREATE TABLE IF NOT EXISTS pet_actions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    action TEXT NOT NULL,
    hours REAL NOT NULL,
    gold_earned INTEGER DEFAULT 0,
    exp_earned INTEGER DEFAULT 0,
    mood_delta INTEGER DEFAULT 0,
    energy_delta INTEGER DEFAULT 0,
    action_date TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status TEXT DEFAULT 'completed',
    available_at TIMESTAMP,
    settled_at TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE INDEX IF NOT EXISTS idx_pet_actions_user_date ON pet_actions(user_id, action_date);

-- 仓库（每用户）
CREATE TABLE IF NOT EXISTS inventory (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    item_key TEXT NOT NULL,
    quantity INTEGER DEFAULT 0,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id),
    UNIQUE (user_id, item_key)
);

-- 每对账号共享的仓库
CREATE TABLE IF NOT EXISTS pair_inventory (
    pair_id TEXT NOT NULL,
    item_key TEXT NOT NULL,
    quantity INTEGER DEFAULT 0,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (pair_id, item_key),
    FOREIGN KEY (pair_id) REFERENCES pairs(id)
);

-- 留言簿（硬限 3 条，超出由应用层 DELETE 旧行）
CREATE TABLE IF NOT EXISTS guestbook (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    author_user_id INTEGER NOT NULL,
    content TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    pair_id TEXT,
    FOREIGN KEY (pair_id) REFERENCES pairs(id),
    FOREIGN KEY (author_user_id) REFERENCES users(id)
);

CREATE INDEX IF NOT EXISTS idx_guestbook_created ON guestbook(created_at DESC);

-- 每对账号独立的一套纪念日与共享宠物数据
CREATE TABLE IF NOT EXISTS pair_together_settings (
    pair_id TEXT PRIMARY KEY,
    start_date TEXT,
    anniversaries TEXT,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_by INTEGER,
    FOREIGN KEY (pair_id) REFERENCES pairs(id),
    FOREIGN KEY (updated_by) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS pair_pet_state (
    pair_id TEXT PRIMARY KEY,
    name TEXT DEFAULT '小本本',
    hunger INTEGER DEFAULT 50,
    mood INTEGER DEFAULT 50,
    energy INTEGER DEFAULT 50,
    gold INTEGER DEFAULT 0,
    level INTEGER DEFAULT 1,
    exp INTEGER DEFAULT 0,
    last_decay_at TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (pair_id) REFERENCES pairs(id)
);

-- 初始化 1 行 pet_state
INSERT OR IGNORE INTO pet_state (id, name, hunger, mood, energy, gold, level, exp, last_decay_at)
VALUES (1, '小本本', 50, 50, 50, 0, 1, 0, datetime('now', 'localtime'));

-- 初始化 1 行 together_settings
INSERT OR IGNORE INTO together_settings (id) VALUES (1);
"""

LEGACY_PAIR_ID = "pair_legacy"


def _column_names(conn, table):
    return {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}


def migrate_pair_schema(conn):
    """幂等迁移：保留旧数据，并把旧账号归入同一个共享空间。"""
    conn.execute("PRAGMA foreign_keys = ON")
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS pairs (
            id TEXT PRIMARY KEY,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS pair_together_settings (
            pair_id TEXT PRIMARY KEY,
            start_date TEXT,
            anniversaries TEXT,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_by INTEGER,
            FOREIGN KEY (pair_id) REFERENCES pairs(id),
            FOREIGN KEY (updated_by) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS pair_pet_state (
            pair_id TEXT PRIMARY KEY,
            name TEXT DEFAULT '小本本',
            hunger INTEGER DEFAULT 50,
            mood INTEGER DEFAULT 50,
            energy INTEGER DEFAULT 50,
            gold INTEGER DEFAULT 0,
            level INTEGER DEFAULT 1,
            exp INTEGER DEFAULT 0,
            last_decay_at TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (pair_id) REFERENCES pairs(id)
        );
        CREATE TABLE IF NOT EXISTS pair_inventory (
            pair_id TEXT NOT NULL,
            item_key TEXT NOT NULL,
            quantity INTEGER DEFAULT 0,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (pair_id, item_key),
            FOREIGN KEY (pair_id) REFERENCES pairs(id)
        );
    """)

    additions = {
        "users": (("last_seen_at", "TIMESTAMP"), ("pair_id", "TEXT")),
        "buckets": (("pair_id", "TEXT"),),
        "scores": (("pair_id", "TEXT"),),
        "guestbook": (("pair_id", "TEXT"),),
        "pet_actions": (
            ("status", "TEXT DEFAULT 'completed'"),
            ("available_at", "TIMESTAMP"),
            ("settled_at", "TIMESTAMP"),
            ("energy_delta", "INTEGER DEFAULT 0"),
        ),
    }
    for table, columns in additions.items():
        existing = _column_names(conn, table)
        for name, definition in columns:
            if name not in existing:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {definition}")

    has_unpaired_users = conn.execute(
        "SELECT 1 FROM users WHERE pair_id IS NULL OR pair_id = '' LIMIT 1"
    ).fetchone()
    if has_unpaired_users:
        conn.execute("INSERT OR IGNORE INTO pairs (id) VALUES (?)", (LEGACY_PAIR_ID,))
        conn.execute(
            "UPDATE users SET pair_id=? WHERE pair_id IS NULL OR pair_id=''",
            (LEGACY_PAIR_ID,),
        )
        for table in ("buckets", "scores", "guestbook"):
            conn.execute(
                f"UPDATE {table} SET pair_id=? WHERE pair_id IS NULL OR pair_id=''",
                (LEGACY_PAIR_ID,),
            )
        conn.execute("""
            INSERT OR IGNORE INTO pair_together_settings
                (pair_id, start_date, anniversaries, updated_at, updated_by)
            SELECT ?, start_date, anniversaries, updated_at, updated_by
            FROM together_settings WHERE id=1
        """, (LEGACY_PAIR_ID,))
        conn.execute("""
            INSERT OR IGNORE INTO pair_pet_state
                (pair_id, name, hunger, mood, energy, gold, level, exp, last_decay_at, updated_at)
            SELECT ?, name, hunger, mood, energy, gold, level, exp, last_decay_at, updated_at
            FROM pet_state WHERE id=1
        """, (LEGACY_PAIR_ID,))

    conn.execute("""
        INSERT OR IGNORE INTO pair_together_settings (pair_id)
        SELECT DISTINCT pair_id FROM users WHERE pair_id IS NOT NULL AND pair_id != ''
    """)
    conn.execute("""
        INSERT OR IGNORE INTO pair_pet_state (pair_id, last_decay_at)
        SELECT DISTINCT pair_id, datetime('now', 'localtime')
        FROM users WHERE pair_id IS NOT NULL AND pair_id != ''
    """)
    conn.execute("""
        INSERT OR IGNORE INTO pair_inventory (pair_id, item_key, quantity, updated_at)
        SELECT u.pair_id, i.item_key, SUM(i.quantity), MAX(i.updated_at)
        FROM inventory i JOIN users u ON u.id=i.user_id
        WHERE u.pair_id IS NOT NULL AND u.pair_id != ''
        GROUP BY u.pair_id, i.item_key
    """)
    conn.executescript("""
        CREATE INDEX IF NOT EXISTS idx_users_pair ON users(pair_id);
        CREATE INDEX IF NOT EXISTS idx_buckets_pair_created ON buckets(pair_id, created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_scores_pair_created ON scores(pair_id, created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_guestbook_pair_created ON guestbook(pair_id, created_at DESC);
    """)
    conn.commit()


def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.executescript(SCHEMA)
    migrate_pair_schema(conn)
    conn.commit()
    return conn


def create_user(conn, username, password, display_name=None):
    cur = conn.cursor()
    cur.execute("SELECT id FROM users WHERE username = ?", (username,))
    if cur.fetchone():
        print(f"  - 用户 {username!r} 已存在，跳过")
        return False
    cur.execute(
        "INSERT INTO users (username, password_hash, display_name) VALUES (?, ?, ?)",
        (username, generate_password_hash(password), display_name or username),
    )
    conn.commit()
    print(f"  + 创建用户 {username!r}  (显示名: {display_name or username})")
    return True


def reset_password(conn, username, new_password):
    cur = conn.cursor()
    cur.execute("SELECT id FROM users WHERE username = ?", (username,))
    if not cur.fetchone():
        print(f"  ! 用户 {username!r} 不存在")
        return False
    cur.execute(
        "UPDATE users SET password_hash = ? WHERE username = ?",
        (generate_password_hash(new_password), username),
    )
    conn.commit()
    print(f"  * 已重置 {username!r} 的密码")
    return True


def main():
    parser = argparse.ArgumentParser(description="猫猫日记数据库初始化")
    parser.add_argument("--reset-password", nargs=2, metavar=("USERNAME", "NEW_PASSWORD"))
    parser.add_argument("--user1", default="you")
    parser.add_argument("--name1", default="我")
    parser.add_argument("--pass1", default=None)
    parser.add_argument("--user2", default="ta")
    parser.add_argument("--name2", default="TA")
    parser.add_argument("--pass2", default=None)
    args = parser.parse_args()

    print(f"[init_db] DB: {DB_PATH}")
    conn = init_db()
    print("[init_db] 表结构已就绪")

    if args.reset_password:
        username, new_password = args.reset_password
        reset_password(conn, username, new_password)
        conn.close()
        return

    pass1 = args.pass1 or f"cat-{secrets.token_hex(2)}"
    pass2 = args.pass2 or f"love-{secrets.token_hex(2)}"

    print("\n[init_db] 创建默认账号:")
    create_user(conn, args.user1, pass1, args.name1)
    create_user(conn, args.user2, pass2, args.name2)

    print("\n" + "=" * 60)
    print(" 账号信息（请妥善保存）")
    print("=" * 60)
    print(f"  用户 1: {args.user1:<10} 密码: {pass1:<20} 显示名: {args.name1}")
    print(f"  用户 2: {args.user2:<10} 密码: {pass2:<20} 显示名: {args.name2}")
    print("=" * 60)
    print("\n 改密码: python init_db.py --reset-password <用户名> <新密码>")
    print(" 重新生成: 删 diary.db 后再跑 python init_db.py")
    conn.close()


if __name__ == "__main__":
    main()
