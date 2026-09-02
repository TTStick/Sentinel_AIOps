"""应用入口：装配路由与中间件，管理后台任务生命周期。"""
import os
import sys
import asyncio
import contextlib

# 允许 `python server/app.py` 直接运行（把 server 目录加入路径）
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException

from config import settings
import database
import models
import analysis
import llm_config

from routes import (auth_routes, report, api_hosts, api_admin, api_audit,
                    api_dashboard, api_ai, api_settings, ssh, pages)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = FastAPI(title=settings.APP_NAME, version=settings.APP_VERSION)

# 静态资源
static_dir = os.path.join(BASE_DIR, "static")
os.makedirs(static_dir, exist_ok=True)
app.mount("/static", StaticFiles(directory=static_dir), name="static")

# 业务路由
app.include_router(pages.router)
app.include_router(auth_routes.router)
app.include_router(report.router)
app.include_router(api_hosts.router)
app.include_router(api_admin.router)
app.include_router(api_audit.router)
app.include_router(api_dashboard.router)
app.include_router(api_ai.router)
app.include_router(api_settings.router)
app.include_router(ssh.router)


# JSON 化的 HTTP 异常（API 友好）
@app.exception_handler(StarletteHTTPException)
async def http_exc_handler(request, exc):
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})


_bg_task = None


async def _forecast_loop():
    """后台定时为所有主机刷新容量/耗尽预测。"""
    while True:
        try:
            await asyncio.sleep(600)   # 每 10 分钟
            for h in models.list_all_hosts():
                try:
                    analysis.refresh_forecasts(h["id"])
                except Exception:  # noqa: BLE001
                    pass
        except asyncio.CancelledError:
            break
        except Exception:  # noqa: BLE001
            await asyncio.sleep(30)


@app.on_event("startup")
async def _startup():
    database.init_db()
    # 载入模型路由配置
    llm_config.bootstrap_from_env()
    llm_config.load()
    global _bg_task
    _bg_task = asyncio.create_task(_forecast_loop())
    print(f"[{settings.APP_NAME} v{settings.APP_VERSION}] 启动完成 "
          f"模型路由={llm_config.summary_label()} 端口={settings.PORT}")
    print(f"  默认管理员: {settings.BOOTSTRAP_ADMIN_USER} / {settings.BOOTSTRAP_ADMIN_PASS} "
          f"(首次登录请立即修改)")


@app.on_event("shutdown")
async def _shutdown():
    global _bg_task
    if _bg_task:
        _bg_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await _bg_task


@app.get("/healthz")
async def healthz():
    return {"status": "ok", "app": settings.APP_NAME, "version": settings.APP_VERSION}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host=settings.HOST, port=settings.PORT, reload=False)
