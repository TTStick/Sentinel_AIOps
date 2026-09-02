"""认证路由：登录 / 登出 / 修改自身口令。"""
from fastapi import APIRouter, Request, Response, HTTPException
from pydantic import BaseModel

import models
import audit
from security import verify_password
from auth import COOKIE_NAME, current_user
from config import settings

router = APIRouter()


class LoginBody(BaseModel):
    username: str
    password: str


@router.post("/api/login")
async def login(body: LoginBody, request: Request, response: Response):
    user = models.get_user_by_name(body.username)
    if not user or not user["active"] or not verify_password(body.password, user["salt"], user["password_hash"]):
        # 审计失败登录
        models.add_audit(None, body.username, "login_failed", "auth", ip=audit.client_ip(request), risk="medium")
        raise HTTPException(status_code=401, detail="用户名或密码错误")

    token = models.create_session(user["id"], audit.client_ip(request),
                                  request.headers.get("user-agent", "")[:200], settings.SESSION_HOURS)
    models.touch_login(user["id"])
    response.set_cookie(COOKIE_NAME, token, httponly=True, samesite="lax",
                        max_age=settings.SESSION_HOURS * 3600)
    audit.record(user, "login", "auth", ip=audit.client_ip(request),
                 detail={"ua": request.headers.get("user-agent", "")[:120]}, ai=False)
    return {"ok": True, "role": user["role"], "must_change": user["must_change"],
            "display_name": user["display_name"]}


@router.post("/api/logout")
async def logout(request: Request, response: Response):
    user = None
    token = request.cookies.get(COOKIE_NAME)
    if token:
        sess = models.get_session(token)
        if sess:
            user = models.get_user(sess["user_id"])
        models.delete_session(token)
    if user:
        audit.record(user, "logout", "auth", ip=audit.client_ip(request))
    response.delete_cookie(COOKIE_NAME)
    return {"ok": True}


class PwBody(BaseModel):
    old_password: str
    new_password: str


@router.post("/api/me/password")
async def change_password(body: PwBody, request: Request):
    user = current_user(request)
    full = models.get_user(user["id"])
    if not verify_password(body.old_password, full["salt"], full["password_hash"]):
        raise HTTPException(status_code=400, detail="原密码错误")
    if len(body.new_password) < 6:
        raise HTTPException(status_code=400, detail="新密码至少 6 位")
    models.update_user(user["id"], password=body.new_password, must_change=0)
    audit.record(user, "change_password", "auth", ip=audit.client_ip(request), risk="medium")
    return {"ok": True}


@router.get("/api/me")
async def me(request: Request):
    user = current_user(request)
    return {"id": user["id"], "username": user["username"], "display_name": user["display_name"],
            "role": user["role"], "must_change": user["must_change"]}
