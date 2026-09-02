"""审计：记录操作日志，可选地异步生成摘要与说明。"""
import concurrent.futures

import models
import llm_engine

# 后台线程池：AI 摘要生成不占用请求/事件循环
_EXEC = concurrent.futures.ThreadPoolExecutor(max_workers=2, thread_name_prefix="audit-ai")


def record(request_user, action, category, *, target_type=None, target_id=None,
           target_name=None, detail=None, ip=None, risk="low", ai=False):
    """request_user 可为 dict(user) 或 None(系统/匿名)。返回 audit_id。"""
    uid = request_user["id"] if request_user else None
    uname = request_user["username"] if request_user else "system"
    audit_id = models.add_audit(uid, uname, action, category, target_type, target_id,
                                target_name, detail, ip, risk)
    if ai:
        _EXEC.submit(enrich, audit_id, action, detail, uname)
    return audit_id


def enrich(audit_id, action, detail, username):
    """生成 AI 摘要/解释，在后台线程执行。失败时静默跳过。"""
    try:
        out = llm_engine.explain_operation(action, detail or {}, username)
        models.set_audit_ai(audit_id, out.get("summary"), out.get("explanation"))
    except Exception:  # noqa: BLE001
        pass


def client_ip(request):
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else "?"
