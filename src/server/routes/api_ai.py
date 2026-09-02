"""AI 功能接口：AI 调查员（人工批准的只读诊断）与 ChatOps。"""
import time

from fastapi import APIRouter, Request, HTTPException, BackgroundTasks
from pydantic import BaseModel
from typing import Optional, List

import models
import analysis
import llm_engine
import cmd_guard
import webssh
import audit
from auth import current_user, assert_host_visible, assert_host_operable, is_admin, visible_host_ids

router = APIRouter(prefix="/api/ai")


# =========================================================== AI 调查员
@router.post("/investigate/{hid}/propose")
def propose(hid: int, request: Request):
    user = current_user(request)
    assert_host_visible(user, hid)
    h = models.get_host(hid)
    anomalies = models.recent_anomalies(hid, 15)
    metrics = models.recent_metrics(hid, 1)
    last = metrics[-1] if metrics else {}
    plan = llm_engine.propose_investigation(h["name"], anomalies, last)

    # 双保险：剔除任何非只读命令
    steps = []
    for s in plan.get("steps", []):
        cmd = (s.get("cmd") or "").strip()
        if cmd and cmd_guard.is_readonly(cmd):
            steps.append({"cmd": cmd, "purpose": s.get("purpose", "")})
    plan["steps"] = steps[:12]

    inv_id = models.create_investigation(hid, h["name"], user["id"],
                                          trigger="manual", plan=plan)
    audit.record(user, "ai_investigate_propose", "investigation", target_type="host",
                 target_id=hid, target_name=h["name"],
                 detail={"hypothesis": plan.get("hypothesis"), "steps": len(steps)},
                 ip=audit.client_ip(request), ai=True)
    return {"ok": True, "investigation_id": inv_id, "plan": plan,
            "note": "诊断命令均为只读；需人工批准后才会在目标主机执行。"}


def _run_investigation(inv_id: int, host: dict, secret: str):
    """后台执行只读诊断并让 AI 得出结论。"""
    inv = models.get_investigation(inv_id)
    plan = inv.get("plan") or {}
    transcript = []
    try:
        for step in plan.get("steps", []):
            cmd = step["cmd"]
            if not cmd_guard.is_readonly(cmd):     # 运行前再次校验
                transcript.append({"cmd": cmd, "purpose": step.get("purpose"),
                                   "output": "[已拦截：非只读命令]", "blocked": True})
                continue
            res = webssh.run_command(host, secret, cmd, timeout=20)
            out = (res.get("stdout") or "") + (("\n" + res["stderr"]) if res.get("stderr") else "")
            transcript.append({"cmd": cmd, "purpose": step.get("purpose"),
                               "output": out[:2000], "exit_code": res.get("exit_code")})
            models.update_investigation(inv_id, transcript=transcript)

        concl = llm_engine.conclude_investigation(host["name"], transcript)
        models.update_investigation(
            inv_id, status="done", transcript=transcript,
            findings=concl.get("root_cause", ""), summary=concl.get("summary", ""),
            remediation=concl.get("remediation", []))
    except Exception as e:  # noqa: BLE001
        models.update_investigation(inv_id, status="failed",
                                    transcript=transcript, summary=f"执行失败：{e}")


@router.post("/investigate/{inv_id}/approve")
async def approve(inv_id: int, request: Request, background: BackgroundTasks):
    """人工批准 → 后台执行只读诊断。需要 operate 权限。"""
    user = current_user(request)
    inv = models.get_investigation(inv_id)
    if not inv:
        raise HTTPException(status_code=404, detail="调查不存在")
    assert_host_operable(user, inv["host_id"])
    if inv["status"] != "proposed":
        raise HTTPException(status_code=400, detail=f"当前状态不可批准：{inv['status']}")

    host = models.get_host(inv["host_id"])
    secret = models.host_ssh_secret(inv["host_id"])
    models.update_investigation(inv_id, status="running")
    audit.record(user, "ai_investigate_approve", "investigation", target_type="host",
                 target_id=inv["host_id"], target_name=inv["host_name"],
                 ip=audit.client_ip(request), risk="medium", ai=True)
    background.add_task(_run_investigation, inv_id, host, secret)
    return {"ok": True, "status": "running"}


@router.post("/investigate/{inv_id}/reject")
async def reject(inv_id: int, request: Request):
    user = current_user(request)
    inv = models.get_investigation(inv_id)
    if not inv:
        raise HTTPException(status_code=404, detail="调查不存在")
    assert_host_visible(user, inv["host_id"])
    models.update_investigation(inv_id, status="rejected")
    audit.record(user, "ai_investigate_reject", "investigation", target_type="host",
                 target_id=inv["host_id"], target_name=inv["host_name"],
                 ip=audit.client_ip(request))
    return {"ok": True}


@router.get("/investigate/{inv_id}")
async def get_inv(inv_id: int, request: Request):
    user = current_user(request)
    inv = models.get_investigation(inv_id)
    if not inv:
        raise HTTPException(status_code=404, detail="调查不存在")
    assert_host_visible(user, inv["host_id"])
    return inv


class RemediateBody(BaseModel):
    cmd: str


@router.post("/investigate/{inv_id}/remediate")
def remediate(inv_id: int, body: RemediateBody, request: Request):
    """对 AI 建议的修复命令做二次人工批准后执行。需要 operate 权限。"""
    user = current_user(request)
    inv = models.get_investigation(inv_id)
    if not inv:
        raise HTTPException(status_code=404, detail="调查不存在")
    assert_host_operable(user, inv["host_id"])

    # 必须是该调查 AI 给出的修复命令之一
    allowed = {(r.get("cmd") or "").strip() for r in (inv.get("remediation") or [])}
    if body.cmd.strip() not in allowed:
        raise HTTPException(status_code=400, detail="该命令不在本次调查的修复建议中")

    verdict = cmd_guard.assess(body.cmd, use_ai=True)
    host = models.get_host(inv["host_id"])
    secret = models.host_ssh_secret(inv["host_id"])
    res = webssh.run_command(host, secret, body.cmd, timeout=30)

    audit.record(user, "ai_investigate_remediate", "investigation", target_type="host",
                 target_id=inv["host_id"], target_name=inv["host_name"],
                 detail={"cmd": body.cmd, "risk": verdict["risk"], "exit": res.get("exit_code")},
                 ip=audit.client_ip(request), risk="high", ai=True)
    return {"ok": res.get("ok"), "risk": verdict, "result": res}


@router.get("/investigations")
async def list_inv(request: Request, host_id: Optional[int] = None):
    user = current_user(request)
    if host_id:
        assert_host_visible(user, host_id)
        return {"investigations": models.list_investigations(host_id=host_id, limit=50)}
    # 汇总用户可见主机
    out = []
    for hid in visible_host_ids(user):
        out.extend(models.list_investigations(host_id=hid, limit=20))
    out.sort(key=lambda x: x["created_at"], reverse=True)
    return {"investigations": out[:50]}


# =========================================================== ChatOps
class ChatBody(BaseModel):
    question: str


@router.post("/chatops")
def chatops(body: ChatBody, request: Request):
    """自然语言机群查询：先用规则检索结构化证据，再交给 LM 表述。"""
    user = current_user(request)
    host_ids = visible_host_ids(user)
    hosts = [models.get_host(i) for i in host_ids]
    now = time.time()

    evidence = {"host_count": len(hosts), "hosts": [], "recent_anomalies": []}
    for h in hosts:
        if not h:
            continue
        evidence["hosts"].append({
            "name": h["name"], "risk": h["risk_level"], "health": h["health"],
            "online": bool(h["last_seen"] and now - h["last_seen"] < 60),
            "metrics": _last_metrics(h),
        })
    # 最近异常（跨可见主机）
    for hid in host_ids[:30]:
        for a in models.recent_anomalies(hid, 5):
            evidence["recent_anomalies"].append(
                {"host": a.get("host_id"), "metric": a.get("metric"),
                 "severity": a.get("severity"), "message": a.get("message")})
    evidence["recent_anomalies"] = evidence["recent_anomalies"][:25]

    answer = llm_engine.chatops_answer(body.question, evidence)
    audit.record(user, "chatops_query", "ai", detail={"q": body.question[:200]},
                 ip=audit.client_ip(request))
    return {"answer": answer, "evidence_hosts": len(evidence["hosts"]),
            "evidence_anomalies": len(evidence["recent_anomalies"])}


def _last_metrics(h):
    import json
    raw = h.get("last_metrics")
    if not raw:
        return {}
    try:
        m = json.loads(raw)
        return {k: m.get(k) for k in ("cpu", "memory_pct", "disk_pct", "load1", "iowait")}
    except (json.JSONDecodeError, TypeError):
        return {}


# =========================================================== WebSSH AI 提示
class SuggestBody(BaseModel):
    context: str = ""
    goal: str = ""


@router.post("/ssh_suggest/{hid}")
def ssh_suggest(hid: int, body: SuggestBody, request: Request):
    user = current_user(request)
    assert_host_visible(user, hid)
    h = models.get_host(hid)
    out = llm_engine.suggest_commands(h["name"], body.context, body.goal)
    # 给每条建议命令补充本地风险判定
    for c in out.get("commands", []):
        v = cmd_guard.static_check(c.get("cmd", ""))
        c["risk"] = v["risk"]
        c["reason"] = c.get("why") or v.get("reason")
    audit.record(user, "ssh_ai_suggest", "ai", target_type="host", target_id=hid,
                 target_name=h["name"], ip=audit.client_ip(request))
    return out


# =========================================================== 命令风险评估（按钮/手动预检）
class GuardBody(BaseModel):
    cmd: str
    use_ai: bool = False


@router.post("/guard")
def guard(body: GuardBody, request: Request):
    current_user(request)
    return cmd_guard.assess(body.cmd, use_ai=body.use_ai)
