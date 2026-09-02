"""
仪表盘数据 API
- /api/dashboard/global  全局大仪表盘（管理员=全平台，普通用户=自己可见范围）
- /api/dashboard/user    个人小仪表盘
- /api/dashboard/host/{hid}  单机小小仪表盘
"""
import time

from fastapi import APIRouter, Request

import models
import analysis
from auth import current_user, is_admin, visible_host_ids, visible_user_ids

router = APIRouter(prefix="/api/dashboard")

OFFLINE = 60


def _hosts_for(user):
    if is_admin(user):
        return models.list_all_hosts()
    return models.list_hosts_for_user(user["id"])


def _summarize(hosts):
    now = time.time()
    counts = {"total": len(hosts), "online": 0, "offline": 0,
              "Normal": 0, "Warning": 0, "Critical": 0}
    health_sum = 0.0
    health_n = 0
    for h in hosts:
        online = bool(h["last_seen"] and now - h["last_seen"] < OFFLINE)
        counts["online" if online else "offline"] += 1
        lvl = h.get("risk_level") or "Normal"
        counts[lvl] = counts.get(lvl, 0) + 1
        if h.get("health") is not None:
            health_sum += h["health"]; health_n += 1
    counts["avg_health"] = round(health_sum / health_n, 1) if health_n else 100.0
    return counts


@router.get("/global")
async def global_dashboard(request: Request):
    user = current_user(request)
    hosts = _hosts_for(user)
    host_ids = [h["id"] for h in hosts]
    summary = _summarize(hosts)

    # 负载排行（按 composite 倒序）
    top_loaded = sorted(
        [{"id": h["id"], "name": h["name"], "composite": h.get("composite") or 0,
          "health": h.get("health"), "risk_level": h.get("risk_level"),
          "cpu": _m(h, "cpu"), "memory_pct": _m(h, "memory_pct"), "disk_pct": _m(h, "disk_pct")}
         for h in hosts],
        key=lambda x: x["composite"], reverse=True)[:8]

    # 异常趋势（24h）
    trend = analysis.anomaly_trend(host_ids, hours=24, bucket=3600) if host_ids else \
        {"buckets": [], "trend": "flat", "next_estimate": 0}

    # 近期 AI 事件（带 AI 摘要的审计）
    vis = visible_user_ids(user)
    recent_audit = models.query_audit(visible_user_ids=vis, limit=12)
    ai_events = [a for a in recent_audit if a.get("ai_summary")][:6]

    # 风险分布饼图数据
    risk_pie = [
        {"name": "正常", "value": summary.get("Normal", 0), "color": "#22c55e"},
        {"name": "警告", "value": summary.get("Warning", 0), "color": "#f59e0b"},
        {"name": "严重", "value": summary.get("Critical", 0), "color": "#ef4444"},
    ]

    # 用户活跃（仅管理员）
    user_activity = []
    if is_admin(user):
        for u in models.list_users():
            uh = models.list_all_hosts() if u["role"] == "superadmin" else models.list_hosts_for_user(u["id"])
            user_activity.append({"username": u["username"], "role": u["role"],
                                  "hosts": len(uh), "last_login": u["last_login"]})

    return {
        "summary": summary,
        "risk_pie": risk_pie,
        "top_loaded": top_loaded,
        "anomaly_trend": trend,
        "ai_events": [{"ts": a["ts"], "username": a["username"], "action": a["action"],
                       "summary": a["ai_summary"], "risk": a["risk"],
                       "target": a.get("target_name")} for a in ai_events],
        "user_activity": user_activity,
        "is_admin": is_admin(user),
    }


def _m(h, key):
    import json
    raw = h.get("last_metrics")
    if not raw:
        return None
    try:
        return json.loads(raw).get(key)
    except (json.JSONDecodeError, TypeError):
        return None


@router.get("/user")
async def user_dashboard(request: Request):
    """个人小仪表盘：自己拥有/被分配的主机概览 + 自己近期操作。"""
    user = current_user(request)
    hosts = _hosts_for(user)
    summary = _summarize(hosts)
    groups = models.list_groups(user["id"])
    my_audit = models.query_audit(user_id=user["id"], limit=8)
    # 待处理调查（proposed/approved）
    pending_inv = []
    for h in hosts:
        for inv in models.list_investigations(host_id=h["id"], limit=5):
            if inv["status"] in ("proposed", "approved", "running"):
                pending_inv.append(inv)
    return {
        "summary": summary,
        "groups": [{"id": g["id"], "name": g["name"], "color": g["color"]} for g in groups],
        "recent_actions": [{"ts": a["ts"], "action": a["action"], "target": a.get("target_name"),
                            "summary": a.get("ai_summary"), "risk": a["risk"]} for a in my_audit],
        "pending_investigations": pending_inv[:6],
    }


@router.get("/host/{hid}")
async def host_dashboard(request: Request, hid: int):
    """单机小小仪表盘。"""
    from auth import assert_host_visible
    user = current_user(request)
    assert_host_visible(user, hid)
    h = models.get_host(hid)
    metrics = models.recent_metrics(hid, 60)
    last = metrics[-1] if metrics else {}
    spark = {}
    for key in ("cpu", "memory_pct", "disk_pct", "load1", "iowait"):
        spark[key] = [{"t": m["ts"], "v": m.get(key)} for m in metrics if m.get(key) is not None]
    return {
        "host": {"id": h["id"], "name": h["name"], "risk_level": h["risk_level"],
                 "health": h["health"], "composite": h["composite"],
                 "online": bool(h["last_seen"] and time.time() - h["last_seen"] < OFFLINE),
                 "last_seen": h["last_seen"]},
        "current": last,
        "sparklines": spark,
        "anomalies": models.recent_anomalies(hid, 10),
        "forecasts": models.get_forecasts(hid),
    }
