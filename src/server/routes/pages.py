"""页面路由：服务端渲染 Jinja 模板，未登录重定向到登录页。"""
from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
import os

from auth import optional_user, is_admin
from config import settings
import llm_config

router = APIRouter()
TEMPLATE_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "templates")
templates = Jinja2Templates(directory=TEMPLATE_DIR)


def _ctx(request, user, **extra):
    base = {
        "user": {"id": user["id"], "username": user["username"],
                 "display_name": user["display_name"], "role": user["role"],
                 "must_change": user["must_change"]},
        "is_admin": is_admin(user),
        "app_name": settings.APP_NAME,
        "app_version": settings.APP_VERSION,
        "llm_provider": llm_config.summary_label(),
    }
    base.update(extra)
    return base


def _guard(request):
    return optional_user(request)


@router.get("/login", response_class=HTMLResponse)
async def page_login(request: Request):
    user = optional_user(request)
    if user:
        return RedirectResponse("/", status_code=302)
    return templates.TemplateResponse(request, "login.html", {"app_name": settings.APP_NAME})


@router.get("/", response_class=HTMLResponse)
async def page_dashboard(request: Request):
    user = _guard(request)
    if not user:
        return RedirectResponse("/login", status_code=302)
    return templates.TemplateResponse(request, "dashboard.html", _ctx(request, user, page="dashboard"))


@router.get("/hosts", response_class=HTMLResponse)
async def page_hosts(request: Request):
    user = _guard(request)
    if not user:
        return RedirectResponse("/login", status_code=302)
    return templates.TemplateResponse(request, "hosts.html", _ctx(request, user, page="hosts"))


@router.get("/hosts/{hid}", response_class=HTMLResponse)
async def page_host_detail(request: Request, hid: int):
    user = _guard(request)
    if not user:
        return RedirectResponse("/login", status_code=302)
    return templates.TemplateResponse(request, "host_detail.html",
                                      _ctx(request, user, page="hosts", host_id=hid))


@router.get("/webssh/{hid}", response_class=HTMLResponse)
async def page_webssh(request: Request, hid: int):
    user = _guard(request)
    if not user:
        return RedirectResponse("/login", status_code=302)
    return templates.TemplateResponse(request, "webssh.html",
                                      _ctx(request, user, page="hosts", host_id=hid))


@router.get("/audit", response_class=HTMLResponse)
async def page_audit(request: Request):
    user = _guard(request)
    if not user:
        return RedirectResponse("/login", status_code=302)
    return templates.TemplateResponse(request, "audit.html", _ctx(request, user, page="audit"))


@router.get("/investigations", response_class=HTMLResponse)
async def page_investigations(request: Request):
    user = _guard(request)
    if not user:
        return RedirectResponse("/login", status_code=302)
    return templates.TemplateResponse(request, "investigations.html",
                                      _ctx(request, user, page="investigations"))


@router.get("/chatops", response_class=HTMLResponse)
async def page_chatops(request: Request):
    user = _guard(request)
    if not user:
        return RedirectResponse("/login", status_code=302)
    return templates.TemplateResponse(request, "chatops.html", _ctx(request, user, page="chatops"))


@router.get("/admin", response_class=HTMLResponse)
async def page_admin(request: Request):
    user = _guard(request)
    if not user:
        return RedirectResponse("/login", status_code=302)
    if not is_admin(user):
        return RedirectResponse("/", status_code=302)
    return templates.TemplateResponse(request, "admin.html", _ctx(request, user, page="admin"))


@router.get("/settings", response_class=HTMLResponse)
async def page_settings(request: Request):
    user = _guard(request)
    if not user:
        return RedirectResponse("/login", status_code=302)
    if not is_admin(user):
        return RedirectResponse("/", status_code=302)
    return templates.TemplateResponse(request, "settings.html", _ctx(request, user, page="settings"))


@router.get("/me", response_class=HTMLResponse)
async def page_me(request: Request):
    user = _guard(request)
    if not user:
        return RedirectResponse("/login", status_code=302)
    return templates.TemplateResponse(request, "me.html", _ctx(request, user, page="me"))
