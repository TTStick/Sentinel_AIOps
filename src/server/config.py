"""全局配置：集中管理可调参数，支持环境变量覆盖。"""
import os
import secrets

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def _env(key: str, default: str) -> str:
    return os.environ.get(key, default)


def _env_bool(key: str, default: bool) -> bool:
    v = os.environ.get(key)
    if v is None:
        return default
    return v.lower() in ("1", "true", "yes", "on")


class Settings:
    # ---- 基础 ----
    APP_NAME = "AIZ Ops Platform"
    APP_VERSION = "4.0"
    HOST = _env("SENTINEL_HOST", "0.0.0.0")
    PORT = int(_env("SENTINEL_PORT", "8000"))

    # ---- 数据库 ----
    DB_PATH = _env("SENTINEL_DB", os.path.join(BASE_DIR, "sentinel.db"))

    # ---- 安全 ----
    # SECRET_KEY 用于加密 SSH 凭据(Fernet) 与签名。生产环境务必通过环境变量固定。
    SECRET_KEY = _env("SENTINEL_SECRET", "")
    # Agent 上报令牌（旧 Agent 兼容；新 Agent 使用每主机令牌）
    GLOBAL_AGENT_TOKEN = _env("SENTINEL_AGENT_TOKEN", "sk-secure-token-123456")
    SESSION_HOURS = int(_env("SENTINEL_SESSION_HOURS", "12"))

    # 初始超级管理员（仅首次初始化时创建）
    BOOTSTRAP_ADMIN_USER = _env("SENTINEL_ADMIN_USER", "admin")
    BOOTSTRAP_ADMIN_PASS = _env("SENTINEL_ADMIN_PASS", "admin123")

    # ---- LLM 引擎 ----
    # provider: mock | ollama | openai
    LLM_PROVIDER = _env("SENTINEL_LLM_PROVIDER", "mock")
    LLM_MODEL = _env("SENTINEL_LLM_MODEL", "qwen2.5:7b")
    OLLAMA_URL = _env("SENTINEL_OLLAMA_URL", "http://127.0.0.1:11434/api/generate")
    OPENAI_BASE = _env("SENTINEL_OPENAI_BASE", "https://api.openai.com/v1")
    OPENAI_KEY = _env("SENTINEL_OPENAI_KEY", "")
    LLM_TIMEOUT = int(_env("SENTINEL_LLM_TIMEOUT", "40"))

    # ---- 异常检测 ----
    # 统计基线检测的 z-score 触发阈值
    ZSCORE_WARN = float(_env("SENTINEL_ZSCORE_WARN", "2.5"))
    ZSCORE_CRIT = float(_env("SENTINEL_ZSCORE_CRIT", "3.5"))
    EWMA_ALPHA = float(_env("SENTINEL_EWMA_ALPHA", "0.15"))
    # 历史数据保留条数（每主机）
    METRIC_RETENTION = int(_env("SENTINEL_METRIC_RETENTION", "2000"))

    OFFLINE_SECONDS = int(_env("SENTINEL_OFFLINE_SECONDS", "60"))

    def __init__(self):
        if not self.SECRET_KEY:
            # 自动生成并持久化一个密钥，避免重启后无法解密已存凭据
            key_file = os.path.join(BASE_DIR, ".secret_key")
            if os.path.exists(key_file):
                with open(key_file) as f:
                    self.SECRET_KEY = f.read().strip()
            else:
                self.SECRET_KEY = secrets.token_urlsafe(48)
                try:
                    with open(key_file, "w") as f:
                        f.write(self.SECRET_KEY)
                    os.chmod(key_file, 0o600)
                except OSError:
                    pass


settings = Settings()
