"""数据库层：基于标准库 sqlite3，提供连接、建表与初始化。时间戳为 UTC epoch 秒。"""
import sqlite3
import threading
import time

from config import settings
from security import hash_password

_local = threading.local()

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT UNIQUE NOT NULL,
    display_name  TEXT,
    password_hash TEXT NOT NULL,
    salt          TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'user',   -- superadmin | user
    active        INTEGER NOT NULL DEFAULT 1,
    must_change   INTEGER NOT NULL DEFAULT 0,
    created_at    REAL NOT NULL,
    last_login    REAL
);

CREATE TABLE IF NOT EXISTS sessions (
    token       TEXT PRIMARY KEY,
    user_id     INTEGER NOT NULL,
    created_at  REAL NOT NULL,
    expires_at  REAL NOT NULL,
    ip          TEXT,
    user_agent  TEXT
);

CREATE TABLE IF NOT EXISTS host_groups (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id    INTEGER NOT NULL,
    name        TEXT NOT NULL,
    color       TEXT DEFAULT '#3b82f6',
    description TEXT,
    created_at  REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS hosts (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT NOT NULL,
    address       TEXT,                 -- ip / dns
    ssh_port      INTEGER DEFAULT 22,
    ssh_user      TEXT DEFAULT 'root',
    ssh_auth      TEXT DEFAULT 'password',   -- password | key
    ssh_secret    TEXT,                 -- 加密存储
    owner_id      INTEGER NOT NULL,
    group_id      INTEGER,
    agent_token   TEXT,                 -- 每主机上报令牌
    os            TEXT,
    tags          TEXT,
    description   TEXT,
    created_at    REAL NOT NULL,
    last_seen     REAL,
    -- 最新快照（便于仪表盘快速读取，避免每次聚合）
    last_metrics  TEXT,                 -- json
    risk_level    TEXT DEFAULT 'Unknown',
    composite     REAL DEFAULT 0,
    health        REAL DEFAULT 100
);

CREATE TABLE IF NOT EXISTS host_access (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id    INTEGER NOT NULL,
    user_id    INTEGER NOT NULL,
    permission TEXT NOT NULL DEFAULT 'operate',  -- view | operate | admin
    granted_by INTEGER,
    granted_at REAL NOT NULL,
    UNIQUE(host_id, user_id)
);

CREATE TABLE IF NOT EXISTS metrics (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id   INTEGER NOT NULL,
    ts        REAL NOT NULL,
    data      TEXT NOT NULL            -- json: 全部采集维度
);
CREATE INDEX IF NOT EXISTS idx_metrics_host_ts ON metrics(host_id, ts);

CREATE TABLE IF NOT EXISTS baselines (
    host_id   INTEGER NOT NULL,
    metric    TEXT NOT NULL,
    mean      REAL NOT NULL,
    var       REAL NOT NULL,
    samples   INTEGER NOT NULL,
    updated_at REAL NOT NULL,
    PRIMARY KEY (host_id, metric)
);

CREATE TABLE IF NOT EXISTS anomalies (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id   INTEGER NOT NULL,
    ts        REAL NOT NULL,
    code      TEXT,
    metric    TEXT,
    severity  TEXT,                    -- info | warning | critical
    source    TEXT,                    -- threshold | baseline | log | ai
    message   TEXT,
    value     REAL,
    baseline  REAL,
    zscore    REAL,
    resolved  INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_anom_host_ts ON anomalies(host_id, ts);

CREATE TABLE IF NOT EXISTS audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          REAL NOT NULL,
    user_id     INTEGER,
    username    TEXT,
    action      TEXT NOT NULL,         -- 机器可读动作码
    category    TEXT,                  -- auth | host | group | ssh | admin | ai | system
    target_type TEXT,
    target_id   TEXT,
    target_name TEXT,
    detail      TEXT,                  -- json
    ip          TEXT,
    risk        TEXT DEFAULT 'low',    -- low | medium | high
    ai_summary     TEXT,               -- AI 对该操作的一句话摘要
    ai_explanation TEXT                -- AI 对该操作的细节解释
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts);
CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_log(user_id);

CREATE TABLE IF NOT EXISTS ssh_sessions (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL,
    username   TEXT,
    host_id    INTEGER NOT NULL,
    host_name  TEXT,
    started_at REAL NOT NULL,
    ended_at   REAL,
    status     TEXT DEFAULT 'active',  -- active | closed | error
    cmd_count  INTEGER DEFAULT 0,
    ai_summary TEXT
);

CREATE TABLE IF NOT EXISTS ssh_commands (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  INTEGER NOT NULL,
    ts          REAL NOT NULL,
    command     TEXT,
    output_excerpt TEXT,
    risk_level  TEXT DEFAULT 'safe',   -- safe | caution | dangerous
    source      TEXT DEFAULT 'manual', -- manual | button | ai
    ai_note     TEXT
);
CREATE INDEX IF NOT EXISTS idx_sshcmd_session ON ssh_commands(session_id);

CREATE TABLE IF NOT EXISTS investigations (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id     INTEGER NOT NULL,
    host_name   TEXT,
    user_id     INTEGER,
    created_at  REAL NOT NULL,
    updated_at  REAL,
    status      TEXT DEFAULT 'proposed', -- proposed | approved | running | done | rejected | failed
    trigger     TEXT,
    plan        TEXT,                    -- json: AI 提议的诊断步骤
    transcript  TEXT,                    -- json: 命令->输出 全过程
    findings    TEXT,                    -- AI 根因
    remediation TEXT,                    -- json: 建议修复(需人工二次批准)
    summary     TEXT
);

CREATE TABLE IF NOT EXISTS forecasts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id     INTEGER NOT NULL,
    metric      TEXT,
    created_at  REAL NOT NULL,
    method      TEXT,
    slope       REAL,
    current     REAL,
    eta_seconds REAL,                    -- 距资源耗尽预计秒数 (None=无风险)
    horizon     TEXT,                    -- json: 未来预测点
    confidence  REAL,
    note        TEXT
);

CREATE TABLE IF NOT EXISTS settings_kv (
    k TEXT PRIMARY KEY,
    v TEXT
);
"""


def get_conn() -> sqlite3.Connection:
    conn = getattr(_local, "conn", None)
    if conn is None:
        conn = sqlite3.connect(settings.DB_PATH, timeout=30, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA foreign_keys=ON;")
        conn.execute("PRAGMA busy_timeout=5000;")
        _local.conn = conn
    return conn


def init_db():
    conn = get_conn()
    conn.executescript(SCHEMA)
    conn.commit()
    _bootstrap_admin()


def _bootstrap_admin():
    conn = get_conn()
    row = conn.execute("SELECT COUNT(*) c FROM users WHERE role='superadmin'").fetchone()
    if row["c"] == 0:
        salt, h = hash_password(settings.BOOTSTRAP_ADMIN_PASS)
        conn.execute(
            "INSERT INTO users (username, display_name, password_hash, salt, role, active, must_change, created_at) "
            "VALUES (?,?,?,?,?,1,1,?)",
            (settings.BOOTSTRAP_ADMIN_USER, "超级管理员", h, salt, "superadmin", time.time()),
        )
        conn.commit()
        print(f"[init] 已创建超级管理员: {settings.BOOTSTRAP_ADMIN_USER} / {settings.BOOTSTRAP_ADMIN_PASS} (请尽快修改)")
