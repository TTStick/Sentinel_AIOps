"""WebSSH WebSocket 路由：浏览器与目标主机 PTY 的实时通道。"""
import asyncio
import json

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Request

import models
import llm_engine
import audit
import webssh
from auth import current_user, assert_host_operable, is_admin

router = APIRouter()


# 傻瓜式命令按钮（封装常用只读/低风险运维指令）
COMMAND_BUTTONS = [
    {"group": "系统概览", "items": [
        {"label": "系统负载", "cmd": "uptime"},
        {"label": "内存使用", "cmd": "free -h"},
        {"label": "磁盘空间", "cmd": "df -h"},
        {"label": "CPU/进程 Top", "cmd": "top -bn1 | head -20"},
        {"label": "登录用户", "cmd": "who"},
        {"label": "系统信息", "cmd": "uname -a"},
    ]},
    {"group": "进程与资源", "items": [
        {"label": "占用CPU最高", "cmd": "ps aux --sort=-%cpu | head -11"},
        {"label": "占用内存最高", "cmd": "ps aux --sort=-%mem | head -11"},
        {"label": "僵尸进程", "cmd": "ps aux | awk '$8 ~ /Z/'"},
        {"label": "打开文件数", "cmd": "lsof 2>/dev/null | wc -l"},
    ]},
    {"group": "网络", "items": [
        {"label": "监听端口", "cmd": "ss -tlnp"},
        {"label": "连接统计", "cmd": "ss -s"},
        {"label": "网卡信息", "cmd": "ip -br addr"},
        {"label": "路由表", "cmd": "ip route"},
    ]},
    {"group": "日志与诊断", "items": [
        {"label": "内核日志(尾)", "cmd": "dmesg | tail -30"},
        {"label": "系统日志(尾)", "cmd": "journalctl -n 40 --no-pager"},
        {"label": "登录失败", "cmd": "journalctl _COMM=sshd | grep -i fail | tail -20"},
        {"label": "OOM 记录", "cmd": "dmesg | grep -i oom | tail -10"},
    ]},
    {"group": "服务(需确认)", "items": [
        {"label": "服务状态", "cmd": "systemctl list-units --type=service --state=running --no-pager | head -20"},
        {"label": "失败的服务", "cmd": "systemctl --failed --no-pager"},
    ]},
]


@router.get("/api/ssh/buttons")
async def ssh_buttons(request: Request):
    current_user(request)
    return {"buttons": COMMAND_BUTTONS}


@router.websocket("/ws/ssh/{host_id}")
async def ws_ssh(websocket: WebSocket, host_id: int):
    await websocket.accept()

    # --- cookie 鉴权 ---
    token = websocket.cookies.get("sid")
    sess = models.get_session(token) if token else None
    user = models.get_user(sess["user_id"]) if sess else None
    if not user or not user["active"]:
        await websocket.send_text(json.dumps({"type": "error", "msg": "未登录或会话失效"}))
        await websocket.close()
        return

    # --- 权限校验：必须可操作 ---
    perm = models.user_host_permission(user["id"], host_id, user["role"])
    if not perm or not models.can_operate(perm):
        await websocket.send_text(json.dumps({"type": "error", "msg": "无该主机操作权限"}))
        await websocket.close()
        return

    host = models.get_host(host_id)
    if not host or not host["address"]:
        await websocket.send_text(json.dumps({"type": "error", "msg": "主机不存在或未配置地址"}))
        await websocket.close()
        return

    secret = models.host_ssh_secret(host_id)
    db_sid = models.open_ssh_session(user["id"], user["username"], host_id, host["name"])
    ip = websocket.client.host if websocket.client else "?"
    audit.record(user, "ssh_open", "ssh", target_type="host", target_id=host_id,
                 target_name=host["name"], ip=ip, risk="medium", ai=True)

    loop = asyncio.get_event_loop()

    async def send_output(data: str):
        try:
            await websocket.send_text(json.dumps({"type": "output", "data": data}))
        except Exception:  # noqa: BLE001
            pass

    bridge = webssh.SSHBridge(host, secret, db_sid, send_output, loop)
    try:
        await asyncio.to_thread(bridge.connect)
        await websocket.send_text(json.dumps({"type": "ready", "session_id": db_sid}))
    except Exception as e:  # noqa: BLE001
        await websocket.send_text(json.dumps({"type": "error", "msg": f"SSH 连接失败：{e}"}))
        models.close_ssh_session(db_sid, status="failed")
        await websocket.close()
        return

    try:
        while True:
            raw = await websocket.receive_text()
            try:
                msg = json.loads(raw)
            except json.JSONDecodeError:
                continue
            mtype = msg.get("type")
            if mtype == "input":
                bridge.write(msg.get("data", ""))
            elif mtype == "exec":     # 按钮 / AI 下发整条命令
                bridge.exec_button(msg.get("cmd", ""), source=msg.get("source", "button"))
            elif mtype == "resize":
                bridge.resize(int(msg.get("cols", 120)), int(msg.get("rows", 32)))
            elif mtype == "ping":
                await websocket.send_text(json.dumps({"type": "pong"}))
    except WebSocketDisconnect:
        pass
    except Exception:  # noqa: BLE001
        pass
    finally:
        bridge.close()
        # AI 摘要总结本次会话
        commands = models.list_ssh_commands(db_sid)
        try:
            summary = await asyncio.to_thread(llm_engine.summarize_session, host["name"], commands)
        except Exception:  # noqa: BLE001
            summary = None
        models.close_ssh_session(db_sid, status="closed", ai_summary=summary)
        audit.record(user, "ssh_close", "ssh", target_type="host", target_id=host_id,
                     target_name=host["name"], detail={"cmd_count": len(commands)},
                     ip=ip, ai=False)
