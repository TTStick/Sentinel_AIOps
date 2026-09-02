"""命令风险护栏：静态规则研判命令风险，标记 safe / caution / dangerous。"""
import re

import llm_engine

# (正则, 风险等级, 中文说明)
RULES = [
    (r"rm\s+(-[a-z]*r[a-z]*f|-[a-z]*f[a-z]*r)\s+(/|/\*|\$HOME|~|\.)\s*$", "dangerous", "递归强删根/家目录"),
    (r"\brm\s+-rf\s+/", "dangerous", "递归强删根路径"),
    (r"\bmkfs\b", "dangerous", "格式化文件系统"),
    (r"\bdd\b.*\bof=/dev/", "dangerous", "向块设备写入(可能抹盘)"),
    (r">\s*/dev/sd[a-z]", "dangerous", "重定向写入磁盘设备"),
    (r":\(\)\s*\{.*\}\s*;\s*:", "dangerous", "Fork 炸弹"),
    (r"\b(shutdown|poweroff|halt|reboot|init\s+0|init\s+6)\b", "dangerous", "关机/重启系统"),
    (r"\b(chmod|chown)\s+-R\s+.*\s+/(?:\s|$)", "dangerous", "对根目录递归改权限/属主"),
    (r"\bmv\s+/\s", "dangerous", "移动根目录"),
    (r"\b>\s*/etc/(passwd|shadow|fstab)", "dangerous", "覆盖关键系统文件"),
    (r"\bcurl\b.*\|\s*(sudo\s+)?(ba)?sh", "dangerous", "下载脚本直接执行(供应链风险)"),
    (r"\bwget\b.*\|\s*(sudo\s+)?(ba)?sh", "dangerous", "下载脚本直接执行(供应链风险)"),
    (r"\biptables\s+-F\b", "caution", "清空防火墙规则"),
    (r"\b(systemctl|service)\s+(stop|restart|disable)\b", "caution", "停止/重启/禁用服务"),
    (r"\bkill(all)?\s+-9\b", "caution", "强杀进程"),
    (r"\bpkill\b", "caution", "按名杀进程"),
    (r"\bmv\b|\brm\b|\btruncate\b", "caution", "存在删除/移动/截断操作"),
    (r"\b(apt|apt-get|yum|dnf)\s+(remove|purge|autoremove)\b", "caution", "卸载软件包"),
    (r"\bgit\s+reset\s+--hard\b", "caution", "丢弃未提交改动"),
    (r"\b(passwd|usermod|userdel|useradd)\b", "caution", "修改账号"),
]

READONLY_HINTS = re.compile(
    r"^\s*(ls|cat|less|more|tail|head|grep|df|du|free|top|htop|ps|ss|netstat|uptime|"
    r"who|w|id|uname|hostname|date|dmesg|journalctl|stat|find|wc|echo|pwd|whoami|"
    r"systemctl\s+status|iostat|vmstat|mpstat|sar|lsof|ip\s+a|ip\s+addr|nproc)\b"
)


def static_check(cmd: str) -> dict:
    c = cmd.strip()
    for pattern, level, desc in RULES:
        if re.search(pattern, c, re.IGNORECASE):
            return {"risk": level, "reason": desc, "matched": pattern}
    if READONLY_HINTS.match(c):
        return {"risk": "safe", "reason": "只读巡检命令", "matched": None}
    return {"risk": "caution", "reason": "未识别命令，建议人工确认", "matched": None}


def assess(cmd: str, use_ai: bool = False) -> dict:
    """综合静态规则(优先)与可选 AI 语义判断。"""
    base = static_check(cmd)
    if base["risk"] == "dangerous" or not use_ai:
        return base
    try:
        ai = llm_engine.classify_command_risk(cmd)
        order = {"safe": 0, "caution": 1, "dangerous": 2}
        if order.get(ai.get("risk"), 0) > order.get(base["risk"], 0):
            return {"risk": ai["risk"], "reason": ai.get("reason", base["reason"]),
                    "matched": base.get("matched")}
    except Exception:  # noqa: BLE001
        pass
    return base


def is_readonly(cmd: str) -> bool:
    """用于 AI 调查员：确保提议命令为只读(双重保险)。"""
    c = cmd.strip()
    if static_check(c)["risk"] == "dangerous":
        return False
    # 拆分管道/分号，逐段判断
    for part in re.split(r"[;|&]+", c):
        part = part.strip()
        if not part:
            continue
        if not READONLY_HINTS.match(part):
            return False
    return True
