"""
审计回溯 API（回溯页面后端）
- 查询审计日志（支持用户/类别/风险/时间/搜索过滤，受可见范围限制）
- 审计明细
- SSH 会话回放（逐条命令 + AI 摘要）
- 触发 AI 会话总结
普通用户仅能看自己；超级管理员可见全部。
"""
from fastapi import APIRouter, Request, HTTPException
from pydantic import BaseModel
from typing import Optional

import models
import llm_engine
import audit
from auth import current_user, is_admin, visible_user_ids, assert_host_visible

router = APIRouter(prefix="/api/audit")


@router.get("")
async def list_audit(request: Request,
                     category: Optional[str] = None,
                     risk: Optional[str] = None,
                     user_id: Optional[int] = None,
                     since: Optional[float] = None,
                     until: Optional[float] = None,
                     search: Optional[str] = None,
                     limit: int = 200,
                     offset: int = 0):
    user = current_user(request)
    vis = visible_user_ids(user)            # None=全部(管理员)，否则限定列表
    # 普通用户即使传 user_id 也只能查自己
    if vis is not None and user_id is not None and user_id not in vis:
        raise HTTPException(status_code=403, detail="无权查看该用户审计")
    rows = models.query_audit(user_id=user_id, category=category, risk=risk,
                              since=since, until=until, search=search,
                              limit=min(limit, 500), offset=offset, visible_user_ids=vis)
    return {"items": rows, "count": len(rows)}


@router.get("/categories")
async def categories(request: Request):
    current_user(request)
    return {"categories": ["auth", "host", "group", "admin", "ssh", "ai", "investigation", "system"],
            "risks": ["low", "medium", "high", "critical"]}


@router.get("/entry/{audit_id}")
async def audit_entry(audit_id: int, request: Request):
    user = current_user(request)
    row = models.get_audit(audit_id)
    if not row:
        raise HTTPException(status_code=404, detail="审计记录不存在")
    vis = visible_user_ids(user)
    if vis is not None and row["user_id"] not in vis:
        raise HTTPException(status_code=403, detail="无权查看")
    return row


# --------------------------------------------------------------- SSH 会话回放
@router.get("/ssh_sessions")
async def ssh_sessions(request: Request, host_id: Optional[int] = None, limit: int = 100):
    user = current_user(request)
    if host_id:
        assert_host_visible(user, host_id)
        rows = models.list_ssh_sessions(host_id=host_id, limit=limit)
    elif is_admin(user):
        rows = models.list_ssh_sessions(limit=limit)
    else:
        rows = models.list_ssh_sessions(user_id=user["id"], limit=limit)
    return {"sessions": rows}


@router.get("/ssh_sessions/{sid}")
async def ssh_session_replay(sid: int, request: Request):
    user = current_user(request)
    sess = models.get_ssh_session(sid)
    if not sess:
        raise HTTPException(status_code=404, detail="会话不存在")
    if not is_admin(user) and sess["user_id"] != user["id"]:
        # 也允许对该主机有可见权限者回放
        assert_host_visible(user, sess["host_id"])
    commands = models.list_ssh_commands(sid)
    return {"session": sess, "commands": commands}


@router.post("/ssh_sessions/{sid}/summarize")
def summarize_ssh_session(sid: int, request: Request):
    user = current_user(request)
    sess = models.get_ssh_session(sid)
    if not sess:
        raise HTTPException(status_code=404, detail="会话不存在")
    if not is_admin(user) and sess["user_id"] != user["id"]:
        assert_host_visible(user, sess["host_id"])
    commands = models.list_ssh_commands(sid)
    summary = llm_engine.summarize_session(sess["host_name"], commands)
    models.close_ssh_session(sid, status=sess["status"], ai_summary=summary)
    audit.record(user, "ssh_session_summarize", "ai", target_type="ssh_session", target_id=sid,
                 target_name=sess["host_name"], ip=audit.client_ip(request))
    return {"ok": True, "summary": summary}
