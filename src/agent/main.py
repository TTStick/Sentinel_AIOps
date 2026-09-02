#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
主机 Agent：采集系统指标与日志异常并定时上报中心服务端。

采集维度：
  · CPU / 内存 / Swap / 磁盘 / IOWait
  · 1/5/15 分钟负载
  · 网络累计字节与实时速率
  · 进程总数 / 运行中 / 僵尸数
  · ESTABLISHED TCP 连接数
  · 文件描述符使用 / 上限
  · 运行时长、CPU 温度
  · CPU / 内存占用最高的进程
  · 日志型异常：SSH 爆破、僵尸进程、应用层关键字

依赖：psutil、requests
"""
import time
import json
import socket
import logging
import os
import re
import subprocess

import requests

try:
    import psutil
except ImportError:
    raise SystemExit("缺少依赖 psutil，请先执行：pip install psutil requests")

# ====================== 配置区（部署时修改） ======================
SERVER_URL = os.environ.get("AIZ_SERVER_URL", "http://YOUR_SERVER_IP:8000/api/report")
# 推荐：在网页端为每台主机生成「专属 agent_token」填到此处；
# 支持主机专属 token 或全局 token 上报。
API_TOKEN = os.environ.get("AIZ_AGENT_TOKEN", "sk-secure-token-123456")
HOSTNAME = os.environ.get("AIZ_HOSTNAME", socket.gethostname())
INTERVAL = int(os.environ.get("AIZ_INTERVAL", "10"))     # 采集上报间隔（秒）
DISK_PATH = os.environ.get("AIZ_DISK_PATH", "/")

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s - %(levelname)s - %(message)s")

# 用于计算网络速率的上一次采样
_last_net = {"ts": None, "sent": 0, "recv": 0}


# ------------------------------------------------------------------ 日志型检测
def get_logs(lines=30):
    try:
        out = subprocess.check_output(
            ["journalctl", "-n", str(lines), "--no-pager", "--output", "short"],
            stderr=subprocess.STDOUT, timeout=4)
        return out.decode("utf-8", errors="ignore")
    except Exception as e:
        return f"(无法读取系统日志: {e})"


def check_security_logs():
    issues = []
    try:
        logs = subprocess.check_output(
            ["journalctl", "-u", "ssh", "-n", "80", "--no-pager", "--output", "cat"],
            stderr=subprocess.DEVNULL, timeout=4).decode("utf-8", errors="ignore")
        fails = len(re.findall(r"Failed password", logs))
        if fails > 5:
            issues.append(f"SSH 爆破告警：近期日志出现 {fails} 次登录失败")
    except Exception:
        pass
    return issues


def check_app_logs(text):
    patterns = [
        (r"connection refused", "连接被拒绝（服务可能已宕）"),
        (r"connection timed out", "网络连接超时"),
        (r"slow query", "数据库慢查询"),
        (r"deadlock", "数据库死锁"),
        (r"out of memory|oom-kill", "OOM 内存耗尽"),
        (r"segfault", "进程段错误 segfault"),
        (r"i/o error|read-only file system", "磁盘 I/O 错误"),
    ]
    low = (text or "").lower()
    return [desc for pat, desc in patterns if re.search(pat, low)]


# ------------------------------------------------------------------ 指标采集
def _top_proc(by):
    """返回占用最高的进程：'name(pid) 12.3%'"""
    best = None
    best_val = -1.0
    for p in psutil.process_iter(["name", "pid", "cpu_percent", "memory_percent"]):
        try:
            val = p.info["cpu_percent"] if by == "cpu" else p.info["memory_percent"]
            if val is None:
                continue
            if val > best_val:
                best_val = val
                best = f"{p.info['name']}({p.info['pid']}) {val:.1f}%"
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return best or ""


def _fd_usage():
    used = 0
    fmax = 0
    try:
        with open("/proc/sys/fs/file-nr") as f:
            parts = f.read().split()
            used = int(parts[0])
            fmax = int(parts[2])
    except Exception:
        pass
    return used, fmax


def _temperature():
    try:
        temps = psutil.sensors_temperatures()
        for _name, entries in (temps or {}).items():
            for e in entries:
                if e.current:
                    return float(e.current)
    except Exception:
        pass
    return 0.0


def _tcp_established():
    try:
        return sum(1 for c in psutil.net_connections(kind="tcp")
                   if c.status == psutil.CONN_ESTABLISHED)
    except Exception:
        return 0


def _proc_counts():
    total = running = zombie = 0
    for p in psutil.process_iter(["status"]):
        try:
            total += 1
            st = p.info["status"]
            if st == psutil.STATUS_RUNNING:
                running += 1
            elif st == psutil.STATUS_ZOMBIE:
                zombie += 1
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return total, running, zombie


def collect():
    cput = psutil.cpu_times_percent(interval=1)
    cpu_pct = psutil.cpu_percent(interval=0)
    mem = psutil.virtual_memory()
    swap = psutil.swap_memory()
    disk = psutil.disk_usage(DISK_PATH)
    net = psutil.net_io_counters()

    try:
        load1, load5, load15 = os.getloadavg()
    except OSError:
        load1 = load5 = load15 = 0.0

    # 网络速率
    now = time.time()
    sent_rate = recv_rate = 0.0
    if _last_net["ts"] is not None:
        dt = max(now - _last_net["ts"], 1e-6)
        sent_rate = max(net.bytes_sent - _last_net["sent"], 0) / dt
        recv_rate = max(net.bytes_recv - _last_net["recv"], 0) / dt
    _last_net.update(ts=now, sent=net.bytes_sent, recv=net.bytes_recv)

    proc_total, proc_running, proc_zombie = _proc_counts()
    fd_used, fd_max = _fd_usage()

    try:
        uptime = now - psutil.boot_time()
    except Exception:
        uptime = 0.0

    metrics = {
        "cpu": round(cpu_pct, 2),
        "memory_pct": round(mem.percent, 2),
        "swap_pct": round(swap.percent, 2),
        "disk_pct": round(disk.percent, 2),
        "iowait": round(getattr(cput, "iowait", 0.0), 2),
        "load1": round(load1, 2), "load5": round(load5, 2), "load15": round(load15, 2),
        "net_sent": net.bytes_sent, "net_recv": net.bytes_recv,
        "net_sent_rate": round(sent_rate, 1), "net_recv_rate": round(recv_rate, 1),
        "proc_total": proc_total, "proc_running": proc_running, "proc_zombie": proc_zombie,
        "tcp_estab": _tcp_established(),
        "fd_used": fd_used, "fd_max": fd_max,
        "uptime": round(uptime, 1),
        "temperature": round(_temperature(), 1),
        "top_cpu_proc": _top_proc("cpu"),
        "top_mem_proc": _top_proc("mem"),
    }

    # Agent 侧只做“信号型”检测（日志/僵尸），数值型异常交给服务端自适应基线
    anomalies = []
    if proc_zombie > 5:
        anomalies.append(f"僵尸进程堆积：{proc_zombie} 个")
    if metrics["iowait"] > 25:
        anomalies.append(f"IO Wait 偏高（{metrics['iowait']}%），磁盘可能瓶颈")
    anomalies.extend(check_security_logs())

    raw_logs = get_logs(30)
    anomalies.extend(check_app_logs(raw_logs))

    return {
        "hostname": HOSTNAME,
        "timestamp": now,
        "metrics": metrics,
        "logs": raw_logs if anomalies else "",
        "anomalies": anomalies,
        "is_danger": bool(anomalies),
    }


def run():
    logging.info("AIZ Agent 启动 · 主机=%s · 上报=%s · 间隔=%ss",
                 HOSTNAME, SERVER_URL, INTERVAL)
    # 预热 cpu_percent / 进程 cpu 采样
    psutil.cpu_percent(interval=None)
    for p in psutil.process_iter():
        try:
            p.cpu_percent(None)
        except Exception:
            pass

    headers = {"Authorization": f"Bearer {API_TOKEN}"}
    while True:
        try:
            data = collect()
            r = requests.post(SERVER_URL, json=data, headers=headers, timeout=6)
            if r.status_code == 200:
                tag = data["anomalies"] if data["anomalies"] else "OK"
                logging.info("已上报 · %s", tag)
            else:
                logging.error("服务端返回 %s: %s", r.status_code, r.text[:200])
        except Exception as e:
            logging.error("上报失败：%s", e)
        time.sleep(INTERVAL)


if __name__ == "__main__":
    run()
