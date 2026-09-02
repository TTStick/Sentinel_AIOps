"""指标上报接口：接收 Agent 数据，做异常检测与评分。"""
import time

from fastapi import APIRouter, Header, HTTPException, BackgroundTasks
from pydantic import BaseModel
from typing import List, Optional

from config import settings
import models
import analysis
import llm_engine

router = APIRouter()


class RichMetrics(BaseModel):
    cpu: float = 0.0
    memory_pct: float = 0.0
    swap_pct: float = 0.0
    disk_pct: float = 0.0
    iowait: float = 0.0
    load1: float = 0.0
    load5: float = 0.0
    load15: float = 0.0
    net_sent: int = 0
    net_recv: int = 0
    net_sent_rate: float = 0.0
    net_recv_rate: float = 0.0
    proc_total: int = 0
    proc_running: int = 0
    proc_zombie: int = 0
    tcp_estab: int = 0
    fd_used: int = 0
    fd_max: int = 0
    uptime: float = 0.0
    temperature: float = 0.0
    top_cpu_proc: Optional[str] = ""
    top_mem_proc: Optional[str] = ""


class AgentReport(BaseModel):
    hostname: str
    timestamp: float = 0.0
    metrics: RichMetrics
    logs: Optional[str] = ""
    anomalies: List[str] = []
    is_danger: bool = False


def _resolve_host(token: str, hostname: str):
    # 1) 每主机令牌优先
    host = models.get_host_by_token(token)
    if host:
        return host
    # 按 hostname 匹配既有主机
    if token == settings.GLOBAL_AGENT_TOKEN:
        host = models.get_host_by_name(hostname)
        if host:
            return host
        # 3) 自动登记为“未分配”主机，归属第一个超级管理员，待后台分配
        admin = next((u for u in models.list_users() if u["role"] == "superadmin"), None)
        if admin:
            hid = models.create_host(hostname, admin["id"], description="Agent 自动登记，待分配")
            return models.get_host(hid)
    return None


def _ai_analysis_task(host_id, hostname, payload):
    models.set_ai_rca(host_id, {"status": "running", "started_at": time.time(),
                                "hostname": hostname})
    result = llm_engine.analyze_incident(payload)
    models.set_ai_rca(host_id, {
        "status": "done", "finished_at": time.time(), "hostname": hostname,
        "risk_level": result.get("risk_level"), "summary": result.get("summary"),
        "root_cause": result.get("root_cause"), "solutions": result.get("solutions", []),
        "need_human": result.get("need_human"),
    })
    models.insert_anomaly(host_id, "ai_rca", None,
                          "critical" if result.get("risk_level") == "High" else "warning",
                          "ai", f"AI根因: {result.get('summary')} | {result.get('root_cause','')}")
    models.add_audit(None, "system", "ai_incident_analysis", "ai",
                     target_type="host", target_id=host_id, target_name=hostname,
                     detail={"risk": result.get("risk_level"), "solutions": result.get("solutions")},
                     ai_summary=result.get("summary"),
                     ai_explanation=result.get("root_cause"))
    analysis.refresh_forecasts(host_id)


@router.post("/api/report")
def receive_report(report: AgentReport, background_tasks: BackgroundTasks,
                         authorization: str = Header(None)):
    token = (authorization or "").replace("Bearer ", "").strip()
    if not token:
        raise HTTPException(status_code=403, detail="缺少令牌")
    host = _resolve_host(token, report.hostname)
    if not host:
        raise HTTPException(status_code=403, detail="无效令牌或未登记主机")

    host_id = host["id"]
    m = report.metrics.model_dump()
    ts = report.timestamp or time.time()

    models.insert_metric(host_id, ts, m)
    if int(ts) % 7 == 0:  # 偶尔修剪，控制库体积
        models.prune_metrics(host_id, settings.METRIC_RETENTION)

    found = analysis.detect_anomalies(host_id, m, report.anomalies, report.logs or "")
    severities = [f["severity"] for f in found]
    comp = analysis.composite_score(m)
    health = analysis.health_score(m, severities)
    risk = analysis.risk_from_signals(severities, health)
    models.update_host_snapshot(host_id, m, risk, comp, health)

    if report.is_danger or risk == "Critical":
        background_tasks.add_task(_ai_analysis_task, host_id, report.hostname, {
            "hostname": report.hostname, "metrics": m,
            "anomalies": report.anomalies + [f["message"] for f in found],
            "logs": report.logs, "is_danger": True,
        })

    return {"status": "received", "host_id": host_id, "risk": risk,
            "health": health, "anomalies": len(found)}
