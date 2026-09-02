"""认证与权限：基于会话令牌的 Cookie 鉴权，提供 current_user / require_admin 等依赖。"""
from fastapi import Request, HTTPException, Depends

import models

COOKIE_NAME = "sid"


def optional_user(request: Request):
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        return None
    sess = models.get_session(token)
    if not sess:
        return None
    user = models.get_user(sess["user_id"])
    if not user or not user["active"]:
        return None
    user["_session"] = token
    return user


def current_user(request: Request):
    user = optional_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="未登录")
    return user


def require_admin(user=Depends(current_user)):
    if user["role"] != "superadmin":
        raise HTTPException(status_code=403, detail="需要超级管理员权限")
    return user


def is_admin(user):
    return user and user["role"] == "superadmin"


def assert_host_visible(user, host_id):
    perm = models.user_host_permission(user["id"], host_id, user["role"])
    if not perm:
        raise HTTPException(status_code=403, detail="无权访问该主机")
    return perm


def assert_host_operable(user, host_id):
    perm = assert_host_visible(user, host_id)
    if not models.can_operate(perm):
        raise HTTPException(status_code=403, detail="对该主机只有查看权限")
    return perm


def visible_host_ids(user):
    if is_admin(user):
        return [h["id"] for h in models.list_all_hosts()]
    return [h["id"] for h in models.list_hosts_for_user(user["id"])]


def visible_user_ids(user):
    """用于审计可见范围：管理员可见全部；普通用户仅自己。"""
    if is_admin(user):
        return None
    return [user["id"]]
