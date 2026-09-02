"""主机与分组管理 API（用户视角：管理自己拥有/被分配的主机与分组）。"""
import time

from fastapi import APIRouter, Request, HTTPException, Depends, BackgroundTasks
from pydantic import BaseModel
from typing import Optional

import models
import analysis
import audit
from routes import report
from auth import current_user, assert_host_visible, assert_host_operable, is_admin

router = APIRouter()


# --------------------------------------------------------------- 分组
class GroupBody(BaseModel):
    name: str
    color: str = "#3b82f6"
    description: str = ""


@router.get("/api/groups")
async def get_groups(request: Request):
    user = current_user(request)
    groups = models.list_groups(user["id"])
    # 统计每组主机数
    hosts = models.list_hosts_for_user(user["id"])
    counts = {}
    for h in hosts:
        counts[h.get("group_id")] = counts.get(h.get("group_id"), 0) + 1
    for g in groups:
        g["host_count"] = counts.get(g["id"], 0)
    return {"groups": groups}


@router.post("/api/groups")
async def add_group(body: GroupBody, request: Request):
    user = current_user(request)
    gid = models.create_group(user["id"], body.name, body.color, body.description)
    audit.record(user, "create_group", "group", target_type="group", target_id=gid,
                 target_name=body.name, ip=audit.client_ip(request), ai=True)
    return {"ok": True, "id": gid}


@router.put("/api/groups/{gid}")
async def edit_group(gid: int, body: GroupBody, request: Request):
    user = current_user(request)
    g = models.get_group(gid)
    if not g or (g["owner_id"] != user["id"] and not is_admin(user)):
        raise HTTPException(status_code=403, detail="无权操作该分组")
    models.update_group(gid, name=body.name, color=body.color, description=body.description)
    audit.record(user, "update_group", "group", target_type="group", target_id=gid,
                 target_name=body.name, ip=audit.client_ip(request))
    return {"ok": True}


@router.delete("/api/groups/{gid}")
async def remove_group(gid: int, request: Request):
    user = current_user(request)
    g = models.get_group(gid)
    if not g or (g["owner_id"] != user["id"] and not is_admin(user)):
        raise HTTPException(status_code=403, detail="无权操作该分组")
    models.delete_group(gid)
    audit.record(user, "delete_group", "group", target_type="group", target_id=gid,
                 target_name=g["name"], ip=audit.client_ip(request), risk="medium", ai=True)
    return {"ok": True}


# --------------------------------------------------------------- 主机
class HostBody(BaseModel):
    name: str
    address: str = ""
    ssh_port: int = 22
    ssh_user: str = "root"
    ssh_auth: str = "password"
    ssh_secret: str = ""
    group_id: Optional[int] = None
    os: str = ""
    tags: str = ""
    description: str = ""


def _host_view(h, perm=None):
    return {
        "id": h["id"], "name": h["name"], "address": h["address"],
        "ssh_port": h["ssh_port"], "ssh_user": h["ssh_user"], "ssh_auth": h["ssh_auth"],
        "group_id": h["group_id"], "os": h["os"], "tags": h["tags"],
        "description": h["description"], "owner_id": h["owner_id"],
        "risk_level": h["risk_level"], "composite": h["composite"], "health": h["health"],
        "last_seen": h["last_seen"], "permission": perm,
        "online": bool(h["last_seen"] and (time.time() - h["last_seen"] < 60)),
        "last_metrics": _safe_json(h.get("last_metrics")),
    }


def _safe_json(s):
    import json
    if not s:
        return {}
    try:
        return json.loads(s)
    except (json.JSONDecodeError, TypeError):
        return {}


@router.get("/api/hosts")
async def get_hosts(request: Request):
    user = current_user(request)
    if is_admin(user):
        hosts = models.list_all_hosts()
        out = [_host_view(h, "admin") for h in hosts]
    else:
        hosts = models.list_hosts_for_user(user["id"])
        out = [_host_view(h, h.get("permission")) for h in hosts]
    return {"hosts": out}


@router.post("/api/hosts")
async def add_host(body: HostBody, request: Request):
    user = current_user(request)
    if body.group_id:
        g = models.get_group(body.group_id)
        if not g or g["owner_id"] != user["id"]:
            raise HTTPException(status_code=400, detail="分组不存在或不属于你")
    hid = models.create_host(body.name, user["id"], body.address, body.ssh_port, body.ssh_user,
                             body.ssh_auth, body.ssh_secret, body.group_id, body.os, body.tags,
                             body.description)
    host = models.get_host(hid)
    audit.record(user, "create_host", "host", target_type="host", target_id=hid,
                 target_name=body.name, detail={"address": body.address}, ip=audit.client_ip(request),
                 ai=True)
    return {"ok": True, "id": hid, "agent_token": host["agent_token"]}


@router.get("/api/hosts/{hid}")
async def host_detail(hid: int, request: Request):
    user = current_user(request)
    perm = assert_host_visible(user, hid)
    h = models.get_host(hid)
    view = _host_view(h, perm)
    view["agent_token"] = h["agent_token"] if models.can_operate(perm) else None
    view["metrics_history"] = models.recent_metrics(hid, 120)
    view["anomalies"] = models.recent_anomalies(hid, 30)
    view["forecasts"] = models.get_forecasts(hid)
    view["ssh_sessions"] = models.list_ssh_sessions(host_id=hid, limit=10)
    view["investigations"] = models.list_investigations(host_id=hid, limit=10)
    view["ai_rca"] = models.get_ai_rca(hid)
    if is_admin(user):
        view["access"] = models.list_host_access(hid)
    return view


@router.put("/api/hosts/{hid}")
async def edit_host(hid: int, body: HostBody, request: Request):
    user = current_user(request)
    assert_host_operable(user, hid)
    fields = dict(name=body.name, address=body.address, ssh_port=body.ssh_port,
                  ssh_user=body.ssh_user, ssh_auth=body.ssh_auth, group_id=body.group_id,
                  os=body.os, tags=body.tags, description=body.description)
    if body.ssh_secret:  # 仅在提供新值时更新凭据
        fields["ssh_secret"] = body.ssh_secret
    models.update_host(hid, **fields)
    audit.record(user, "update_host", "host", target_type="host", target_id=hid,
                 target_name=body.name, ip=audit.client_ip(request), risk="medium")
    return {"ok": True}


@router.delete("/api/hosts/{hid}")
async def remove_host(hid: int, request: Request):
    user = current_user(request)
    h = models.get_host(hid)
    if not h:
        raise HTTPException(status_code=404, detail="主机不存在")
    if h["owner_id"] != user["id"] and not is_admin(user):
        raise HTTPException(status_code=403, detail="仅拥有者或管理员可删除主机")
    models.delete_host(hid)
    audit.record(user, "delete_host", "host", target_type="host", target_id=hid,
                 target_name=h["name"], ip=audit.client_ip(request), risk="high", ai=True)
    return {"ok": True}


@router.post("/api/hosts/{hid}/forecast")
async def refresh_forecast(hid: int, request: Request):
    user = current_user(request)
    assert_host_visible(user, hid)
    out = analysis.refresh_forecasts(hid)
    return {"ok": True, "forecasts": out}


@router.post("/api/hosts/{hid}/analyze")
def analyze_host(hid: int, request: Request, background_tasks: BackgroundTasks):
    user = current_user(request)
    assert_host_visible(user, hid)
    h = models.get_host(hid)
    if not h:
        raise HTTPException(status_code=404, detail="主机不存在")
    cur = models.get_ai_rca(hid)
    if cur and cur.get("status") == "running" and time.time() - cur.get("started_at", 0) < 180:
        return {"status": "running"}
    metrics = _safe_json(h["last_metrics"]) or {}
    anomalies = [a["message"] for a in models.recent_anomalies(hid, 20) if a.get("message")]
    payload = {"hostname": h["name"], "metrics": metrics, "anomalies": anomalies, "logs": ""}
    models.set_ai_rca(hid, {"status": "running", "started_at": time.time(), "hostname": h["name"]})
    background_tasks.add_task(report._ai_analysis_task, hid, h["name"], payload)
    audit.record(user, "ai_incident_analysis", "ai", target_type="host", target_id=hid,
                 target_name=h["name"], ip=audit.client_ip(request))
    return {"status": "running"}
