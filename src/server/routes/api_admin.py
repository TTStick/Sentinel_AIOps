"""
超级管理员 API：管理所有用户 + 主机分配（授予/回收/转移归属）。
所有路由都需要 superadmin 权限，并写入审计。
"""
from fastapi import APIRouter, Request, HTTPException, Depends
from pydantic import BaseModel
from typing import Optional

import models
import audit
from auth import require_admin, current_user

router = APIRouter(prefix="/api/admin", dependencies=[Depends(require_admin)])


# --------------------------------------------------------------- 用户管理
class UserBody(BaseModel):
    username: str
    password: str = ""
    display_name: str = ""
    role: str = "user"            # user | superadmin


class UserEditBody(BaseModel):
    display_name: Optional[str] = None
    role: Optional[str] = None
    active: Optional[int] = None


class ResetPwBody(BaseModel):
    new_password: str


def _user_view(u):
    hosts = models.list_hosts_for_user(u["id"]) if u["role"] != "superadmin" else models.list_all_hosts()
    return {
        "id": u["id"], "username": u["username"], "display_name": u["display_name"],
        "role": u["role"], "active": u["active"], "must_change": u["must_change"],
        "created_at": u["created_at"], "last_login": u["last_login"],
        "host_count": len(hosts),
        "group_count": len(models.list_groups(u["id"])),
    }


@router.get("/users")
async def list_all_users(request: Request):
    return {"users": [_user_view(u) for u in models.list_users()]}


@router.post("/users")
async def create_user(body: UserBody, request: Request):
    admin = current_user(request)
    if models.get_user_by_name(body.username):
        raise HTTPException(status_code=400, detail="用户名已存在")
    if len(body.password) < 6:
        raise HTTPException(status_code=400, detail="初始密码至少 6 位")
    if body.role not in ("user", "superadmin"):
        raise HTTPException(status_code=400, detail="角色非法")
    uid = models.create_user(body.username, body.password, body.role,
                             body.display_name or body.username, must_change=1)
    audit.record(admin, "admin_create_user", "admin", target_type="user", target_id=uid,
                 target_name=body.username, detail={"role": body.role},
                 ip=audit.client_ip(request), risk="medium", ai=True)
    return {"ok": True, "id": uid}


@router.put("/users/{uid}")
async def edit_user(uid: int, body: UserEditBody, request: Request):
    admin = current_user(request)
    u = models.get_user(uid)
    if not u:
        raise HTTPException(status_code=404, detail="用户不存在")
    fields = {}
    if body.display_name is not None:
        fields["display_name"] = body.display_name
    if body.role is not None:
        if body.role not in ("user", "superadmin"):
            raise HTTPException(status_code=400, detail="角色非法")
        fields["role"] = body.role
    if body.active is not None:
        # 不允许停用自己
        if uid == admin["id"] and body.active == 0:
            raise HTTPException(status_code=400, detail="不能停用当前登录的管理员账号")
        fields["active"] = body.active
    if fields:
        models.update_user(uid, **fields)
    audit.record(admin, "admin_update_user", "admin", target_type="user", target_id=uid,
                 target_name=u["username"], detail=fields, ip=audit.client_ip(request),
                 risk="medium", ai=True)
    return {"ok": True}


@router.post("/users/{uid}/reset_password")
async def reset_password(uid: int, body: ResetPwBody, request: Request):
    admin = current_user(request)
    u = models.get_user(uid)
    if not u:
        raise HTTPException(status_code=404, detail="用户不存在")
    if len(body.new_password) < 6:
        raise HTTPException(status_code=400, detail="新密码至少 6 位")
    models.update_user(uid, password=body.new_password, must_change=1)
    audit.record(admin, "admin_reset_password", "admin", target_type="user", target_id=uid,
                 target_name=u["username"], ip=audit.client_ip(request), risk="high", ai=True)
    return {"ok": True}


@router.delete("/users/{uid}")
async def delete_user(uid: int, request: Request):
    admin = current_user(request)
    if uid == admin["id"]:
        raise HTTPException(status_code=400, detail="不能删除当前登录账号")
    u = models.get_user(uid)
    if not u:
        raise HTTPException(status_code=404, detail="用户不存在")
    if u["role"] == "superadmin" and sum(1 for x in models.list_users() if x["role"] == "superadmin") <= 1:
        raise HTTPException(status_code=400, detail="必须保留至少一个超级管理员")
    models.delete_user(uid)
    audit.record(admin, "admin_delete_user", "admin", target_type="user", target_id=uid,
                 target_name=u["username"], ip=audit.client_ip(request), risk="high", ai=True)
    return {"ok": True}


# --------------------------------------------------------------- 主机总览 & 分配
@router.get("/hosts")
async def list_all_hosts(request: Request):
    out = []
    for h in models.list_all_hosts():
        owner = models.get_user(h["owner_id"]) if h["owner_id"] else None
        out.append({
            "id": h["id"], "name": h["name"], "address": h["address"],
            "owner_id": h["owner_id"], "owner": owner["username"] if owner else "(未分配)",
            "group_id": h["group_id"], "risk_level": h["risk_level"],
            "health": h["health"], "last_seen": h["last_seen"],
            "access": models.list_host_access(h["id"]),
        })
    return {"hosts": out}


class AssignBody(BaseModel):
    user_id: int
    permission: str = "operate"   # view | operate | admin


@router.post("/hosts/{hid}/assign")
async def assign_host(hid: int, body: AssignBody, request: Request):
    admin = current_user(request)
    h = models.get_host(hid)
    if not h:
        raise HTTPException(status_code=404, detail="主机不存在")
    u = models.get_user(body.user_id)
    if not u:
        raise HTTPException(status_code=404, detail="用户不存在")
    if body.permission not in ("view", "operate", "admin"):
        raise HTTPException(status_code=400, detail="权限级别非法")
    models.grant_access(hid, body.user_id, body.permission, admin["id"])
    audit.record(admin, "admin_assign_host", "admin", target_type="host", target_id=hid,
                 target_name=h["name"], detail={"to": u["username"], "perm": body.permission},
                 ip=audit.client_ip(request), risk="medium", ai=True)
    return {"ok": True}


@router.post("/hosts/{hid}/revoke")
async def revoke_host(hid: int, body: AssignBody, request: Request):
    admin = current_user(request)
    h = models.get_host(hid)
    if not h:
        raise HTTPException(status_code=404, detail="主机不存在")
    u = models.get_user(body.user_id)
    models.revoke_access(hid, body.user_id)
    audit.record(admin, "admin_revoke_host", "admin", target_type="host", target_id=hid,
                 target_name=h["name"], detail={"from": u["username"] if u else body.user_id},
                 ip=audit.client_ip(request), risk="medium", ai=True)
    return {"ok": True}


class OwnerBody(BaseModel):
    owner_id: int


@router.post("/hosts/{hid}/owner")
async def reassign_owner(hid: int, body: OwnerBody, request: Request):
    admin = current_user(request)
    h = models.get_host(hid)
    if not h:
        raise HTTPException(status_code=404, detail="主机不存在")
    u = models.get_user(body.owner_id)
    if not u:
        raise HTTPException(status_code=404, detail="目标用户不存在")
    models.update_host(hid, owner_id=body.owner_id)
    audit.record(admin, "admin_reassign_owner", "admin", target_type="host", target_id=hid,
                 target_name=h["name"], detail={"new_owner": u["username"]},
                 ip=audit.client_ip(request), risk="high", ai=True)
    return {"ok": True}
