"""模型设置接口：读取/保存模型路由配置与连接测试（仅超级管理员）。"""
from fastapi import APIRouter, Request, Depends
from pydantic import BaseModel
from typing import Optional

import audit
import llm_config
import llm_engine
from auth import require_admin, current_user

router = APIRouter(prefix="/api/admin/llm", dependencies=[Depends(require_admin)])


@router.get("")
async def get_llm(request: Request):
    return {
        "config": llm_config.get_public(),
        "presets": llm_config.PROVIDER_PRESETS,
        "routing_modes": llm_config.ROUTING_MODES,
    }


class SlotIn(BaseModel):
    provider: Optional[str] = None
    base_url: Optional[str] = None
    model: Optional[str] = None
    enabled: Optional[bool] = None
    api_key: Optional[str] = ""      # 空=沿用；'__CLEAR__'=清空；其它=新值


class LLMConfigIn(BaseModel):
    routing: str = "tiered"
    timeout: int = 40
    fast: SlotIn = SlotIn()
    strong: SlotIn = SlotIn()


@router.put("")
async def put_llm(body: LLMConfigIn, request: Request):
    admin = current_user(request)
    new_cfg = {
        "routing": body.routing,
        "timeout": body.timeout,
        "fast": {k: v for k, v in body.fast.model_dump().items() if v is not None},
        "strong": {k: v for k, v in body.strong.model_dump().items() if v is not None},
    }
    public = llm_config.save(new_cfg)
    # 审计不记录任何 key
    safe_detail = {
        "routing": public["routing"],
        "fast": {"provider": public["fast"]["provider"], "model": public["fast"]["model"],
                 "enabled": public["fast"]["enabled"]},
        "strong": {"provider": public["strong"]["provider"], "model": public["strong"]["model"],
                   "enabled": public["strong"]["enabled"]},
    }
    audit.record(admin, "llm_config_update", "admin", detail=safe_detail,
                 ip=audit.client_ip(request), risk="medium", ai=False)
    return {"ok": True, "config": public, "label": llm_config.summary_label()}


class TestIn(BaseModel):
    slot: Optional[str] = None        # 'fast' | 'strong'：用已保存的 key
    provider: Optional[str] = None
    base_url: str = ""
    model: str = ""
    api_key: Optional[str] = ""


@router.post("/test")
def test_llm(body: TestIn, request: Request):
    admin = current_user(request)
    # 解析要测试的连接参数；api_key 为空且指定了 slot 时，沿用已保存的 key
    key = body.api_key or ""
    base_url = body.base_url
    model = body.model
    provider = body.provider
    if body.slot in ("fast", "strong"):
        saved = llm_config.get_runtime().get(body.slot, {})
        if not key:
            key = saved.get("api_key", "")
        base_url = base_url or saved.get("base_url", "")
        model = model or saved.get("model", "")
        provider = provider or saved.get("provider")

    if not base_url or not model:
        return {"ok": False, "error": "缺少 base_url 或 model"}

    slot = {"provider": provider, "base_url": base_url, "model": model, "api_key": key}
    result = llm_engine.ping(slot)
    audit.record(admin, "llm_config_test", "admin",
                 detail={"provider": provider, "model": model, "ok": result.get("ok")},
                 ip=audit.client_ip(request), risk="low", ai=False)
    return result
