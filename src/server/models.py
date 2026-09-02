"""数据访问层：封装 SQL 查询。"""
import json
import time

from database import get_conn
from security import hash_password, encrypt_secret, decrypt_secret, new_token


def _now():
    return time.time()


def _row(r):
    return dict(r) if r else None


def _rows(rs):
    return [dict(r) for r in rs]


# ============================================================ USERS
def create_user(username, password, role="user", display_name=None, must_change=0):
    salt, h = hash_password(password)
    conn = get_conn()
    cur = conn.execute(
        "INSERT INTO users (username, display_name, password_hash, salt, role, active, must_change, created_at) "
        "VALUES (?,?,?,?,?,1,?,?)",
        (username, display_name or username, h, salt, role, must_change, _now()),
    )
    conn.commit()
    return cur.lastrowid


def get_user(user_id):
    return _row(get_conn().execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone())


def get_user_by_name(username):
    return _row(get_conn().execute("SELECT * FROM users WHERE username=?", (username,)).fetchone())


def list_users():
    return _rows(get_conn().execute("SELECT * FROM users ORDER BY id").fetchall())


def update_user(user_id, **fields):
    if not fields:
        return
    if "password" in fields:
        salt, h = hash_password(fields.pop("password"))
        fields["password_hash"] = h
        fields["salt"] = salt
    cols = ", ".join(f"{k}=?" for k in fields)
    conn = get_conn()
    conn.execute(f"UPDATE users SET {cols} WHERE id=?", (*fields.values(), user_id))
    conn.commit()


def delete_user(user_id):
    conn = get_conn()
    conn.execute("DELETE FROM users WHERE id=?", (user_id,))
    conn.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))
    conn.commit()


def touch_login(user_id):
    conn = get_conn()
    conn.execute("UPDATE users SET last_login=? WHERE id=?", (_now(), user_id))
    conn.commit()


def count_users():
    return get_conn().execute("SELECT COUNT(*) c FROM users").fetchone()["c"]


# ============================================================ SESSIONS
def create_session(user_id, ip, user_agent, hours):
    token = new_token()
    now = _now()
    conn = get_conn()
    conn.execute(
        "INSERT INTO sessions (token, user_id, created_at, expires_at, ip, user_agent) VALUES (?,?,?,?,?,?)",
        (token, user_id, now, now + hours * 3600, ip, user_agent),
    )
    conn.commit()
    return token


def get_session(token):
    r = _row(get_conn().execute("SELECT * FROM sessions WHERE token=?", (token,)).fetchone())
    if not r:
        return None
    if r["expires_at"] < _now():
        delete_session(token)
        return None
    return r


def delete_session(token):
    conn = get_conn()
    conn.execute("DELETE FROM sessions WHERE token=?", (token,))
    conn.commit()


# ============================================================ GROUPS
def create_group(owner_id, name, color="#3b82f6", description=""):
    conn = get_conn()
    cur = conn.execute(
        "INSERT INTO host_groups (owner_id, name, color, description, created_at) VALUES (?,?,?,?,?)",
        (owner_id, name, color, description, _now()),
    )
    conn.commit()
    return cur.lastrowid


def list_groups(owner_id):
    return _rows(get_conn().execute(
        "SELECT * FROM host_groups WHERE owner_id=? ORDER BY name", (owner_id,)).fetchall())


def get_group(group_id):
    return _row(get_conn().execute("SELECT * FROM host_groups WHERE id=?", (group_id,)).fetchone())


def update_group(group_id, **fields):
    if not fields:
        return
    cols = ", ".join(f"{k}=?" for k in fields)
    conn = get_conn()
    conn.execute(f"UPDATE host_groups SET {cols} WHERE id=?", (*fields.values(), group_id))
    conn.commit()


def delete_group(group_id):
    conn = get_conn()
    conn.execute("UPDATE hosts SET group_id=NULL WHERE group_id=?", (group_id,))
    conn.execute("DELETE FROM host_groups WHERE id=?", (group_id,))
    conn.commit()


# ============================================================ HOSTS
def create_host(name, owner_id, address="", ssh_port=22, ssh_user="root",
                ssh_auth="password", ssh_secret="", group_id=None, os="", tags="",
                description=""):
    conn = get_conn()
    cur = conn.execute(
        "INSERT INTO hosts (name, address, ssh_port, ssh_user, ssh_auth, ssh_secret, owner_id, "
        "group_id, agent_token, os, tags, description, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (name, address, ssh_port, ssh_user, ssh_auth, encrypt_secret(ssh_secret), owner_id,
         group_id, new_token(16), os, tags, description, _now()),
    )
    conn.commit()
    return cur.lastrowid


def get_host(host_id):
    return _row(get_conn().execute("SELECT * FROM hosts WHERE id=?", (host_id,)).fetchone())


def get_host_by_token(token):
    return _row(get_conn().execute("SELECT * FROM hosts WHERE agent_token=?", (token,)).fetchone())


def get_host_by_name(name):
    return _row(get_conn().execute("SELECT * FROM hosts WHERE name=? ORDER BY id LIMIT 1", (name,)).fetchone())


def host_ssh_secret(host_id):
    h = get_host(host_id)
    return decrypt_secret(h["ssh_secret"]) if h else ""


def update_host(host_id, **fields):
    if "ssh_secret" in fields:
        fields["ssh_secret"] = encrypt_secret(fields["ssh_secret"])
    if not fields:
        return
    cols = ", ".join(f"{k}=?" for k in fields)
    conn = get_conn()
    conn.execute(f"UPDATE hosts SET {cols} WHERE id=?", (*fields.values(), host_id))
    conn.commit()


def delete_host(host_id):
    conn = get_conn()
    # 关联的 SSH 命令需经会话表定位后清理
    conn.execute(
        "DELETE FROM ssh_commands WHERE session_id IN "
        "(SELECT id FROM ssh_sessions WHERE host_id=?)", (host_id,))
    for t in ("metrics", "anomalies", "baselines", "forecasts",
              "ssh_sessions", "investigations"):
        conn.execute(f"DELETE FROM {t} WHERE host_id=?", (host_id,))
    conn.execute("DELETE FROM host_access WHERE host_id=?", (host_id,))
    conn.execute("DELETE FROM hosts WHERE id=?", (host_id,))
    conn.commit()


def list_all_hosts():
    return _rows(get_conn().execute("SELECT * FROM hosts ORDER BY name").fetchall())


def list_hosts_for_user(user_id):
    """用户可见主机 = 自己拥有的 + 被分配的。返回含 permission 字段。"""
    conn = get_conn()
    owned = conn.execute("SELECT *, 'owner' AS permission FROM hosts WHERE owner_id=?", (user_id,)).fetchall()
    shared = conn.execute(
        "SELECT h.*, a.permission AS permission FROM hosts h "
        "JOIN host_access a ON a.host_id=h.id WHERE a.user_id=? AND h.owner_id<>?",
        (user_id, user_id),
    ).fetchall()
    return _rows(owned) + _rows(shared)


def user_host_permission(user_id, host_id, user_role="user"):
    """返回 owner|admin|operate|view|None"""
    if user_role == "superadmin":
        return "admin"
    h = get_host(host_id)
    if not h:
        return None
    if h["owner_id"] == user_id:
        return "owner"
    r = get_conn().execute(
        "SELECT permission FROM host_access WHERE host_id=? AND user_id=?", (host_id, user_id)
    ).fetchone()
    return r["permission"] if r else None


def can_operate(perm):
    return perm in ("owner", "admin", "operate")


# ---- assignment (admin) ----
def grant_access(host_id, user_id, permission, granted_by):
    conn = get_conn()
    conn.execute(
        "INSERT INTO host_access (host_id, user_id, permission, granted_by, granted_at) VALUES (?,?,?,?,?) "
        "ON CONFLICT(host_id, user_id) DO UPDATE SET permission=excluded.permission",
        (host_id, user_id, permission, granted_by, _now()),
    )
    conn.commit()


def revoke_access(host_id, user_id):
    conn = get_conn()
    conn.execute("DELETE FROM host_access WHERE host_id=? AND user_id=?", (host_id, user_id))
    conn.commit()


def list_host_access(host_id):
    return _rows(get_conn().execute(
        "SELECT a.*, u.username, u.display_name FROM host_access a JOIN users u ON u.id=a.user_id "
        "WHERE a.host_id=?", (host_id,)).fetchall())


# ---- 快照更新 ----
def update_host_snapshot(host_id, metrics_dict, risk_level, composite, health):
    conn = get_conn()
    conn.execute(
        "UPDATE hosts SET last_seen=?, last_metrics=?, risk_level=?, composite=?, health=? WHERE id=?",
        (_now(), json.dumps(metrics_dict), risk_level, composite, health, host_id),
    )
    conn.commit()


# ============================================================ METRICS
def insert_metric(host_id, ts, data: dict):
    conn = get_conn()
    conn.execute("INSERT INTO metrics (host_id, ts, data) VALUES (?,?,?)",
                 (host_id, ts, json.dumps(data)))
    conn.commit()


def recent_metrics(host_id, limit=200):
    rs = get_conn().execute(
        "SELECT ts, data FROM metrics WHERE host_id=? ORDER BY ts DESC LIMIT ?", (host_id, limit)
    ).fetchall()
    out = []
    for r in rs:
        d = json.loads(r["data"])
        d["ts"] = r["ts"]
        out.append(d)
    out.reverse()
    return out


def prune_metrics(host_id, keep):
    conn = get_conn()
    conn.execute(
        "DELETE FROM metrics WHERE host_id=? AND id NOT IN "
        "(SELECT id FROM metrics WHERE host_id=? ORDER BY ts DESC LIMIT ?)",
        (host_id, host_id, keep),
    )
    conn.commit()


# ============================================================ BASELINES
def get_baseline(host_id, metric):
    return _row(get_conn().execute(
        "SELECT * FROM baselines WHERE host_id=? AND metric=?", (host_id, metric)).fetchone())


def upsert_baseline(host_id, metric, mean, var, samples):
    conn = get_conn()
    conn.execute(
        "INSERT INTO baselines (host_id, metric, mean, var, samples, updated_at) VALUES (?,?,?,?,?,?) "
        "ON CONFLICT(host_id, metric) DO UPDATE SET mean=excluded.mean, var=excluded.var, "
        "samples=excluded.samples, updated_at=excluded.updated_at",
        (host_id, metric, mean, var, samples, _now()),
    )
    conn.commit()


# ============================================================ ANOMALIES
def insert_anomaly(host_id, code, metric, severity, source, message,
                   value=None, baseline=None, zscore=None, ts=None):
    conn = get_conn()
    cur = conn.execute(
        "INSERT INTO anomalies (host_id, ts, code, metric, severity, source, message, value, baseline, zscore) "
        "VALUES (?,?,?,?,?,?,?,?,?,?)",
        (host_id, ts or _now(), code, metric, severity, source, message, value, baseline, zscore),
    )
    conn.commit()
    return cur.lastrowid


def recent_anomalies(host_id, limit=50):
    return _rows(get_conn().execute(
        "SELECT * FROM anomalies WHERE host_id=? ORDER BY ts DESC LIMIT ?", (host_id, limit)).fetchall())


def anomalies_since(host_id, since_ts):
    return _rows(get_conn().execute(
        "SELECT * FROM anomalies WHERE host_id=? AND ts>=? ORDER BY ts", (host_id, since_ts)).fetchall())


def fleet_anomaly_buckets(host_ids, since_ts, bucket_seconds=300):
    """返回 [(bucket_ts, count, crit_count)] 用于趋势图"""
    if not host_ids:
        return []
    ph = ",".join("?" * len(host_ids))
    rs = get_conn().execute(
        f"SELECT ts, severity FROM anomalies WHERE host_id IN ({ph}) AND ts>=? ORDER BY ts",
        (*host_ids, since_ts),
    ).fetchall()
    buckets = {}
    for r in rs:
        b = int(r["ts"] // bucket_seconds) * bucket_seconds
        if b not in buckets:
            buckets[b] = [0, 0]
        buckets[b][0] += 1
        if r["severity"] == "critical":
            buckets[b][1] += 1
    return [(b, v[0], v[1]) for b, v in sorted(buckets.items())]


# ============================================================ AUDIT
def add_audit(user_id, username, action, category, target_type=None, target_id=None,
              target_name=None, detail=None, ip=None, risk="low",
              ai_summary=None, ai_explanation=None):
    conn = get_conn()
    cur = conn.execute(
        "INSERT INTO audit_log (ts, user_id, username, action, category, target_type, target_id, "
        "target_name, detail, ip, risk, ai_summary, ai_explanation) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (_now(), user_id, username, action, category, target_type,
         str(target_id) if target_id is not None else None, target_name,
         json.dumps(detail, ensure_ascii=False) if detail else None, ip, risk,
         ai_summary, ai_explanation),
    )
    conn.commit()
    return cur.lastrowid


def set_audit_ai(audit_id, ai_summary, ai_explanation):
    conn = get_conn()
    conn.execute("UPDATE audit_log SET ai_summary=?, ai_explanation=? WHERE id=?",
                 (ai_summary, ai_explanation, audit_id))
    conn.commit()


def query_audit(user_id=None, category=None, risk=None, since=None, until=None,
                search=None, limit=200, offset=0, visible_user_ids=None):
    where, params = [], []
    if user_id is not None:
        where.append("user_id=?"); params.append(user_id)
    if visible_user_ids is not None:
        if not visible_user_ids:
            return []
        where.append("user_id IN (%s)" % ",".join("?" * len(visible_user_ids)))
        params.extend(visible_user_ids)
    if category:
        where.append("category=?"); params.append(category)
    if risk:
        where.append("risk=?"); params.append(risk)
    if since:
        where.append("ts>=?"); params.append(since)
    if until:
        where.append("ts<=?"); params.append(until)
    if search:
        where.append("(action LIKE ? OR target_name LIKE ? OR detail LIKE ? OR ai_summary LIKE ?)")
        params.extend([f"%{search}%"] * 4)
    sql = "SELECT * FROM audit_log"
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY ts DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])
    return _rows(get_conn().execute(sql, params).fetchall())


def get_audit(audit_id):
    return _row(get_conn().execute("SELECT * FROM audit_log WHERE id=?", (audit_id,)).fetchone())


# ============================================================ SSH SESSIONS / COMMANDS
def open_ssh_session(user_id, username, host_id, host_name):
    conn = get_conn()
    cur = conn.execute(
        "INSERT INTO ssh_sessions (user_id, username, host_id, host_name, started_at, status) "
        "VALUES (?,?,?,?,?, 'active')",
        (user_id, username, host_id, host_name, _now()),
    )
    conn.commit()
    return cur.lastrowid


def close_ssh_session(session_id, status="closed", ai_summary=None):
    conn = get_conn()
    conn.execute("UPDATE ssh_sessions SET ended_at=?, status=?, ai_summary=COALESCE(?, ai_summary) WHERE id=?",
                 (_now(), status, ai_summary, session_id))
    conn.commit()


def log_ssh_command(session_id, command, output_excerpt="", risk_level="safe",
                    source="manual", ai_note=None):
    conn = get_conn()
    conn.execute(
        "INSERT INTO ssh_commands (session_id, ts, command, output_excerpt, risk_level, source, ai_note) "
        "VALUES (?,?,?,?,?,?,?)",
        (session_id, _now(), command, output_excerpt[:2000], risk_level, source, ai_note),
    )
    conn.execute("UPDATE ssh_sessions SET cmd_count=cmd_count+1 WHERE id=?", (session_id,))
    conn.commit()


def get_ssh_session(session_id):
    return _row(get_conn().execute("SELECT * FROM ssh_sessions WHERE id=?", (session_id,)).fetchone())


def list_ssh_commands(session_id):
    return _rows(get_conn().execute(
        "SELECT * FROM ssh_commands WHERE session_id=? ORDER BY ts", (session_id,)).fetchall())


def list_ssh_sessions(host_id=None, user_id=None, limit=100):
    where, params = [], []
    if host_id:
        where.append("host_id=?"); params.append(host_id)
    if user_id:
        where.append("user_id=?"); params.append(user_id)
    sql = "SELECT * FROM ssh_sessions"
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY started_at DESC LIMIT ?"
    params.append(limit)
    return _rows(get_conn().execute(sql, params).fetchall())


# ============================================================ INVESTIGATIONS
def create_investigation(host_id, host_name, user_id, trigger, plan):
    conn = get_conn()
    cur = conn.execute(
        "INSERT INTO investigations (host_id, host_name, user_id, created_at, updated_at, status, trigger, plan) "
        "VALUES (?,?,?,?,?, 'proposed', ?, ?)",
        (host_id, host_name, user_id, _now(), _now(), trigger, json.dumps(plan, ensure_ascii=False)),
    )
    conn.commit()
    return cur.lastrowid


def get_investigation(inv_id):
    r = _row(get_conn().execute("SELECT * FROM investigations WHERE id=?", (inv_id,)).fetchone())
    if r:
        for f in ("plan", "transcript", "remediation"):
            if r.get(f):
                try:
                    r[f] = json.loads(r[f])
                except (json.JSONDecodeError, TypeError):
                    pass
    return r


def update_investigation(inv_id, **fields):
    for f in ("plan", "transcript", "remediation"):
        if f in fields and not isinstance(fields[f], str):
            fields[f] = json.dumps(fields[f], ensure_ascii=False)
    fields["updated_at"] = _now()
    cols = ", ".join(f"{k}=?" for k in fields)
    conn = get_conn()
    conn.execute(f"UPDATE investigations SET {cols} WHERE id=?", (*fields.values(), inv_id))
    conn.commit()


def list_investigations(host_id=None, limit=50):
    if host_id:
        rs = get_conn().execute(
            "SELECT id, host_id, host_name, created_at, status, trigger, summary FROM investigations "
            "WHERE host_id=? ORDER BY created_at DESC LIMIT ?", (host_id, limit)).fetchall()
    else:
        rs = get_conn().execute(
            "SELECT id, host_id, host_name, created_at, status, trigger, summary FROM investigations "
            "ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
    return _rows(rs)


# ============================================================ FORECASTS
def save_forecast(host_id, metric, method, slope, current, eta_seconds, horizon, confidence, note):
    conn = get_conn()
    conn.execute("DELETE FROM forecasts WHERE host_id=? AND metric=?", (host_id, metric))
    conn.execute(
        "INSERT INTO forecasts (host_id, metric, created_at, method, slope, current, eta_seconds, "
        "horizon, confidence, note) VALUES (?,?,?,?,?,?,?,?,?,?)",
        (host_id, metric, _now(), method, slope, current, eta_seconds,
         json.dumps(horizon), confidence, note),
    )
    conn.commit()


def get_forecasts(host_id):
    rs = get_conn().execute("SELECT * FROM forecasts WHERE host_id=?", (host_id,)).fetchall()
    out = []
    for r in rs:
        d = dict(r)
        if d.get("horizon"):
            try:
                d["horizon"] = json.loads(d["horizon"])
            except (json.JSONDecodeError, TypeError):
                d["horizon"] = []
        out.append(d)
    return out


# =========================================================== 配置 KV（settings_kv）
def get_setting(key, default=None):
    r = get_conn().execute("SELECT v FROM settings_kv WHERE k=?", (key,)).fetchone()
    return r["v"] if r else default


def set_setting(key, value):
    conn = get_conn()
    conn.execute(
        "INSERT INTO settings_kv (k, v) VALUES (?, ?) "
        "ON CONFLICT(k) DO UPDATE SET v=excluded.v", (key, value))
    conn.commit()


def get_ai_rca(host_id):
    raw = get_setting(f"ai_rca:{host_id}")
    if not raw:
        return None
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return None


def set_ai_rca(host_id, data):
    set_setting(f"ai_rca:{host_id}", json.dumps(data, ensure_ascii=False))
