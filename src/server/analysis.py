"""分析引擎：自适应基线异常检测、健康度评分与容量预测。"""
import math
import time

from config import settings
import models

# 参与统计基线检测的核心指标及其“越大越危险”的方向
BASELINE_METRICS = {
    "cpu": "high",
    "memory_pct": "high",
    "swap_pct": "high",
    "disk_pct": "high",
    "iowait": "high",
    "load1": "high",
    "net_recv_rate": "high",
    "net_sent_rate": "high",
    "proc_zombie": "high",
    "tcp_estab": "high",
    "fd_used": "high",
    "temperature": "high",
}

# 安全护栏：无论基线如何，这些绝对红线一律告警
HARD_GUARDS = {
    "disk_pct": (95, "critical", "磁盘使用率超过 95%，存在写满风险"),
    "memory_pct": (97, "critical", "内存使用率超过 97%"),
    "swap_pct": (90, "warning", "Swap 使用率过高，系统可能颠簸"),
}

METRIC_LABELS = {
    "cpu": "CPU", "memory_pct": "内存", "swap_pct": "Swap", "disk_pct": "磁盘",
    "iowait": "IO等待", "load1": "1分钟负载", "net_recv_rate": "下行带宽",
    "net_sent_rate": "上行带宽", "proc_zombie": "僵尸进程", "tcp_estab": "TCP连接",
    "fd_used": "文件句柄", "temperature": "温度",
}


# --------------------------------------------------------------- 基线 (EWMA)
def update_baseline(host_id, metric, value, alpha=None):
    """
    指数加权移动平均/方差。返回 (mean, std, zscore, samples)，
    其中 mean/std/z 均针对“纳入本值之前”的历史基线计算，避免当前异常值自我稀释。
    同时对纳入基线的样本做 winsorize 截断，防止单个尖峰污染基线。
    """
    alpha = alpha or settings.EWMA_ALPHA
    bl = models.get_baseline(host_id, metric)
    if bl is None:
        models.upsert_baseline(host_id, metric, value, 0.0, 1)
        return value, 0.0, 0.0, 1

    mean, var, samples = bl["mean"], bl["var"], bl["samples"]
    std = math.sqrt(var) if var > 0 else 0.0
    # 1) 先用旧基线给当前值打分
    z = (value - mean) / std if std > 1e-6 else 0.0

    # 2) winsorize：把纳入基线的值限制在 ±4σ 内，避免尖峰拉高方差
    upd_value = value
    if std > 1e-6:
        upd_value = min(max(value, mean - 4 * std), mean + 4 * std)

    diff = upd_value - mean
    new_mean = mean + alpha * diff
    new_var = (1 - alpha) * (var + alpha * diff * diff)
    models.upsert_baseline(host_id, metric, new_mean, new_var, samples + 1)
    return mean, std, z, samples + 1


# --------------------------------------------------------------- 健康度评分
def composite_score(m: dict) -> float:
    """综合负载分(越高越忙)，保留旧权重并纳入 iowait/load。"""
    cpu = m.get("cpu", 0) or 0
    mem = m.get("memory_pct", 0) or 0
    swap = m.get("swap_pct", 0) or 0
    disk = m.get("disk_pct", 0) or 0
    iow = m.get("iowait", 0) or 0
    score = cpu * 0.34 + mem * 0.26 + swap * 0.15 + disk * 0.10 + iow * 0.15
    return round(min(score, 100.0), 1)


def health_score(m: dict, anomaly_severities: list) -> float:
    """0-100 健康分(越高越健康)，从满分按各维度压力扣分。"""
    score = 100.0
    for key, weight in (("cpu", 0.25), ("memory_pct", 0.25), ("disk_pct", 0.2),
                        ("swap_pct", 0.15), ("iowait", 0.15)):
        v = m.get(key, 0) or 0
        if v > 70:
            score -= (v - 70) / 30 * 100 * weight
    for sev in anomaly_severities:
        score -= {"critical": 18, "warning": 7, "info": 2}.get(sev, 0)
    return round(max(0.0, min(100.0, score)), 1)


def risk_from_signals(anomaly_severities: list, health: float) -> str:
    if "critical" in anomaly_severities or health < 40:
        return "Critical"
    if "warning" in anomaly_severities or health < 70:
        return "Warning"
    return "Normal"


# --------------------------------------------------------------- 异常检测主流程
def detect_anomalies(host_id, metrics: dict, agent_anomalies: list, logs: str = "") -> list:
    """
    返回本次检测出的异常列表 [{code, metric, severity, source, message, value, baseline, zscore}]
    并写入 anomalies 表。融合三类信号：硬护栏 / 统计基线 / Agent上报(日志正则等)。
    """
    found = []

    # 1) 硬护栏（绝对红线）
    for metric, (limit, severity, msg) in HARD_GUARDS.items():
        v = metrics.get(metric)
        if v is not None and v >= limit:
            found.append(dict(code=f"guard_{metric}", metric=metric, severity=severity,
                              source="threshold", message=f"{msg}（当前 {v}%）",
                              value=v, baseline=None, zscore=None))

    # 自适应统计基线：相对自身历史判定异常
    for metric, direction in BASELINE_METRICS.items():
        v = metrics.get(metric)
        if v is None:
            continue
        mean, std, z, samples = update_baseline(host_id, metric, v)
        if samples < 12:  # 样本太少不下结论，先学习
            continue
        # 仅关注“变高”方向的异常
        if direction == "high" and z >= settings.ZSCORE_WARN and v > mean:
            severity = "critical" if z >= settings.ZSCORE_CRIT else "warning"
            label = METRIC_LABELS.get(metric, metric)
            found.append(dict(
                code=f"baseline_{metric}", metric=metric, severity=severity, source="baseline",
                message=f"{label}异常偏离基线：当前 {round(v,1)}，基线 {round(mean,1)}±{round(std,1)} (z={round(z,1)})",
                value=v, baseline=round(mean, 2), zscore=round(z, 2)))

    # 3) Agent 侧上报的语义异常（日志正则、内核检测等）
    for a in agent_anomalies or []:
        txt = str(a).lower()
        sev = "critical" if any(k in txt for k in ("brute", "oom", "deadlock", "refused", "critical")) else "warning"
        found.append(dict(code="agent", metric=None, severity=sev, source="log",
                          message=str(a), value=None, baseline=None, zscore=None))

    # 去重（同一 code 一次只记一条最严重的）
    dedup = {}
    for f in found:
        key = f["code"]
        if key not in dedup or _sev_rank(f["severity"]) > _sev_rank(dedup[key]["severity"]):
            dedup[key] = f
    final = list(dedup.values())

    for f in final:
        models.insert_anomaly(host_id, f["code"], f["metric"], f["severity"], f["source"],
                              f["message"], f.get("value"), f.get("baseline"), f.get("zscore"))
    return final


def _sev_rank(s):
    return {"info": 1, "warning": 2, "critical": 3}.get(s, 0)


# --------------------------------------------------------------- 趋势/容量预测
def _linreg(points):
    """最小二乘线性回归。points=[(x,y)] -> (slope, intercept, r2)"""
    n = len(points)
    if n < 3:
        return 0.0, points[-1][1] if points else 0.0, 0.0
    sx = sum(p[0] for p in points)
    sy = sum(p[1] for p in points)
    sxx = sum(p[0] * p[0] for p in points)
    sxy = sum(p[0] * p[1] for p in points)
    denom = n * sxx - sx * sx
    if abs(denom) < 1e-9:
        return 0.0, sy / n, 0.0
    slope = (n * sxy - sx * sy) / denom
    intercept = (sy - slope * sx) / n
    mean_y = sy / n
    ss_tot = sum((p[1] - mean_y) ** 2 for p in points)
    ss_res = sum((p[1] - (slope * p[0] + intercept)) ** 2 for p in points)
    r2 = 1 - ss_res / ss_tot if ss_tot > 1e-9 else 0.0
    return slope, intercept, max(0.0, r2)


def forecast_capacity(host_id, metric="disk_pct", limit_value=100.0, horizon_points=6):
    """
    线性外推预测某指标的耗尽时间。返回 dict 或 None。
    slope 单位：每秒变化。eta_seconds：距达到 limit 的秒数。
    """
    history = models.recent_metrics(host_id, limit=300)
    series = [(h["ts"], h.get(metric)) for h in history if h.get(metric) is not None]
    if len(series) < 5:
        return None
    t0 = series[0][0]
    pts = [(t - t0, v) for t, v in series]
    slope, intercept, r2 = _linreg(pts)
    current = series[-1][1]
    now_x = series[-1][0] - t0

    eta = None
    if slope > 1e-9 and current < limit_value:
        eta = (limit_value - current) / slope  # 秒

    step = max(3600, (pts[-1][0] - pts[0][0]) / max(len(pts), 1))
    horizon = []
    for i in range(1, horizon_points + 1):
        fx = now_x + step * i
        fy = slope * fx + intercept
        horizon.append({"t": round(time.time() + step * i), "v": round(max(0.0, min(fy, 150.0)), 1)})

    note = "趋势平稳"
    if eta is not None:
        days = eta / 86400
        if days < 1:
            note = f"⚠ 预计 {round(eta/3600,1)} 小时内逼近上限"
        elif days < 7:
            note = f"⚠ 预计 {round(days,1)} 天后逼近上限"
        else:
            note = f"按当前趋势约 {round(days)} 天后达到上限"
    elif slope < 0:
        note = "占用呈下降趋势"

    models.save_forecast(host_id, metric, "linear", round(slope * 86400, 4), round(current, 1),
                         eta, horizon, round(r2, 2), note)
    return {"metric": metric, "slope_per_day": round(slope * 86400, 3), "current": round(current, 1),
            "eta_seconds": eta, "r2": round(r2, 2), "note": note, "horizon": horizon}


def anomaly_trend(host_ids, hours=24, bucket=3600):
    """异常频率趋势预测：按桶统计 + 线性外推下一桶。"""
    since = time.time() - hours * 3600
    buckets = models.fleet_anomaly_buckets(host_ids, since, bucket)
    if not buckets:
        return {"buckets": [], "trend": "flat", "next_estimate": 0}
    pts = [(i, b[1]) for i, b in enumerate(buckets)]
    slope, intercept, _ = _linreg(pts) if len(pts) >= 3 else (0.0, pts[-1][1], 0.0)
    nxt = max(0, round(slope * len(pts) + intercept))
    trend = "rising" if slope > 0.5 else ("falling" if slope < -0.5 else "flat")
    return {
        "buckets": [{"t": b[0], "count": b[1], "crit": b[2]} for b in buckets],
        "trend": trend, "slope": round(slope, 2), "next_estimate": nxt,
    }


def refresh_forecasts(host_id):
    """对一台主机刷新所有关心的预测。"""
    out = {}
    for metric in ("disk_pct", "memory_pct", "swap_pct"):
        f = forecast_capacity(host_id, metric)
        if f:
            out[metric] = f
    return out
