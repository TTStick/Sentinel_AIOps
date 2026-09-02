"""模型路由配置：管理快速/强力两档模型与供应商参数，API Key 加密存储。"""
import json
import copy

import models
import security

# ---- 供应商预设：仅作为 UI 自动填充的“起点”，base_url/model 均可在页面里改 ----
PROVIDER_PRESETS = {
    "deepseek": {
        "label": "DeepSeek（深度求索）",
        "base_url": "https://api.deepseek.com/v1",
        "needs_key": True,
        "models": ["deepseek-chat", "deepseek-reasoner"],
        "hint": "官网申请 API Key；deepseek-chat 适合快速档，deepseek-reasoner 适合强力档。",
    },
    "qwen": {
        "label": "通义千问 Qwen（阿里云百炼）",
        "base_url": "https://dashscope.aliyuncs.com/compatible-mode/v1",
        "needs_key": True,
        "models": ["qwen-plus", "qwen-max", "qwen-turbo", "qwen2.5-72b-instruct"],
        "hint": "使用百炼平台的「OpenAI 兼容模式」Key；qwen-turbo/plus 快，qwen-max 强。",
    },
    "siliconflow": {
        "label": "硅基流动 SiliconFlow",
        "base_url": "https://api.siliconflow.cn/v1",
        "needs_key": True,
        "models": ["Qwen/Qwen2.5-7B-Instruct", "deepseek-ai/DeepSeek-V3", "deepseek-ai/DeepSeek-R1"],
        "hint": "聚合多家开源模型，模型名形如 厂商/模型。小模型走快速档，V3/R1 走强力档。",
    },
    "ollama": {
        "label": "本地 Ollama",
        "base_url": "http://127.0.0.1:11434/v1",
        "needs_key": False,
        "models": ["qwen2.5:7b", "llama3.1:8b", "deepseek-r1:7b"],
        "hint": "本机离线运行，无需 Key。需先 ollama pull 对应模型。",
    },
    "openai": {
        "label": "OpenAI / 兼容网关",
        "base_url": "https://api.openai.com/v1",
        "needs_key": True,
        "models": ["gpt-4o-mini", "gpt-4o"],
        "hint": "任何 OpenAI 兼容网关都可用，填对应的 base_url 与 Key。",
    },
    "custom": {
        "label": "自定义兼容接口",
        "base_url": "",
        "needs_key": True,
        "models": [],
        "hint": "任意兼容 /v1/chat/completions 的服务，自行填写 base_url / model / key。",
    },
    "mock": {
        "label": "离线规则引擎（不接模型）",
        "base_url": "",
        "needs_key": False,
        "models": [],
        "hint": "内置规则化输出，无需任何外部模型，可随时作为兜底。",
    },
}

ROUTING_MODES = {
    "tiered": "智能路由（简单任务用快速模型，复杂任务用强力模型）",
    "strong": "始终使用强力模型",
    "fast": "始终使用快速模型",
    "mock": "离线规则引擎（不调用任何模型）",
}

_KV_KEY = "llm_config"

_DEFAULT = {
    "routing": "mock",
    "timeout": 40,
    "fast":   {"provider": "mock", "base_url": "", "model": "", "enabled": False},
    "strong": {"provider": "mock", "base_url": "", "model": "", "enabled": False},
}

# 运行时缓存（含解密后的明文 key，仅驻留内存）
_cache = None


def _blank_slot():
    return {"provider": "mock", "base_url": "", "model": "", "enabled": False, "api_key": ""}


def load():
    """从数据库载入配置并解密 key 到内存缓存。"""
    global _cache
    raw = models.get_setting(_KV_KEY)
    if not raw:
        _cache = copy.deepcopy(_DEFAULT)
        for s in ("fast", "strong"):
            _cache[s]["api_key"] = ""
        return _cache
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        data = copy.deepcopy(_DEFAULT)

    cfg = {"routing": data.get("routing", "mock"),
           "timeout": int(data.get("timeout", 40) or 40)}
    for slot in ("fast", "strong"):
        s = data.get(slot, {}) or {}
        enc = s.get("api_key_enc", "")
        key = ""
        if enc:
            try:
                key = security.decrypt_secret(enc)
            except Exception:
                key = ""
        cfg[slot] = {
            "provider": s.get("provider", "mock"),
            "base_url": s.get("base_url", ""),
            "model": s.get("model", ""),
            "enabled": bool(s.get("enabled", False)),
            "api_key": key,
        }
    _cache = cfg
    return _cache


def _ensure():
    global _cache
    if _cache is None:
        load()
    return _cache


def get_runtime():
    """内部使用：返回含明文 key 的运行时配置。"""
    return _ensure()


def get_public():
    """对前端暴露：屏蔽明文 key，仅返回 has_key 标记。"""
    cfg = _ensure()
    out = {"routing": cfg["routing"], "timeout": cfg["timeout"]}
    for slot in ("fast", "strong"):
        s = cfg[slot]
        out[slot] = {
            "provider": s["provider"], "base_url": s["base_url"],
            "model": s["model"], "enabled": s["enabled"],
            "has_key": bool(s.get("api_key")),
        }
    return out


def save(new_cfg):
    """
    保存配置。new_cfg 各 slot 的 api_key 规则：
      · 非空字符串      -> 视为新 key，加密保存
      · 空字符串/缺省   -> 保留原有 key
      · 值为 '__CLEAR__' -> 清空该 key
    """
    cur = _ensure()
    store = {
        "routing": new_cfg.get("routing", cur["routing"]),
        "timeout": int(new_cfg.get("timeout", cur["timeout"]) or 40),
    }
    runtime = {"routing": store["routing"], "timeout": store["timeout"]}

    for slot in ("fast", "strong"):
        incoming = new_cfg.get(slot, {}) or {}
        prev = cur.get(slot, _blank_slot())
        provider = incoming.get("provider", prev["provider"])
        base_url = incoming.get("base_url", prev["base_url"])
        model = incoming.get("model", prev["model"])
        enabled = bool(incoming.get("enabled", prev["enabled"]))

        # 决定 key
        raw_key = incoming.get("api_key", "")
        if raw_key == "__CLEAR__":
            key = ""
        elif raw_key:
            key = raw_key
        else:
            key = prev.get("api_key", "")

        store[slot] = {
            "provider": provider, "base_url": base_url, "model": model,
            "enabled": enabled,
            "api_key_enc": security.encrypt_secret(key) if key else "",
        }
        runtime[slot] = {"provider": provider, "base_url": base_url,
                         "model": model, "enabled": enabled, "api_key": key}

    models.set_setting(_KV_KEY, json.dumps(store, ensure_ascii=False))
    global _cache
    _cache = runtime
    return get_public()


def _slot_usable(slot):
    if not slot or not slot.get("enabled"):
        return False
    if slot.get("provider") == "mock":
        return False
    if not slot.get("base_url") or not slot.get("model"):
        return False
    needs_key = PROVIDER_PRESETS.get(slot.get("provider"), {}).get("needs_key", True)
    if needs_key and not slot.get("api_key"):
        return False
    return True


def resolve(tier):
    """
    根据路由模式与任务档位，返回应使用的 slot(含明文 key)；
    返回 None 表示走离线 mock。
    """
    cfg = _ensure()
    mode = cfg.get("routing", "mock")
    if mode == "mock":
        return None

    if mode == "strong":
        pick = cfg["strong"]
    elif mode == "fast":
        pick = cfg["fast"]
    else:  # tiered
        pick = cfg["strong"] if tier == "strong" else cfg["fast"]

    if _slot_usable(pick):
        return pick
    # 兜底：尝试另一档
    other = cfg["fast"] if pick is cfg["strong"] else cfg["strong"]
    if _slot_usable(other):
        return other
    return None


def active(tier):
    return resolve(tier) is not None


_PROV_NAMES = {"deepseek": "DeepSeek", "qwen": "Qwen", "siliconflow": "硅基流动",
               "ollama": "Ollama", "openai": "OpenAI", "custom": "自定义", "mock": "离线"}


def summary_label():
    """侧栏/横幅用的简短标签，反映当前实际生效的模型来源。"""
    cfg = _ensure()
    if cfg.get("routing") == "mock":
        return "离线规则"
    provs = []
    for s in ("fast", "strong"):
        if _slot_usable(cfg[s]):
            name = _PROV_NAMES.get(cfg[s]["provider"], cfg[s]["provider"])
            if name not in provs:
                provs.append(name)
    return " / ".join(provs) if provs else "离线规则"


def bootstrap_from_env():
    """无持久化配置时，从环境变量读取初始模型配置。"""
    if models.get_setting(_KV_KEY):
        return
    try:
        from config import settings
    except Exception:
        return
    prov = getattr(settings, "LLM_PROVIDER", "mock")
    if prov not in ("ollama", "openai"):
        return
    if prov == "ollama":
        slot = {"provider": "ollama", "base_url": "http://127.0.0.1:11434/v1",
                "model": settings.LLM_MODEL, "enabled": True, "api_key": ""}
    else:
        slot = {"provider": "openai", "base_url": settings.OPENAI_BASE,
                "model": settings.LLM_MODEL, "enabled": True,
                "api_key": getattr(settings, "OPENAI_KEY", "")}
    save({"routing": "strong", "timeout": getattr(settings, "LLM_TIMEOUT", 40),
          "fast": dict(slot), "strong": dict(slot)})
