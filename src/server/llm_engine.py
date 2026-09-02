"""LLM 引擎：以 OpenAI 兼容接口调用模型，按任务档位路由，异常时回退离线规则。"""
import json
import re
import time

import requests

import llm_config


# ----------------------------------------------------------------- 底层调用
def _chat(slot, system, prompt, json_mode):
    url = slot["base_url"].rstrip("/") + "/chat/completions"
    headers = {"Content-Type": "application/json"}
    if slot.get("api_key"):
        headers["Authorization"] = "Bearer " + slot["api_key"]
    body = {
        "model": slot["model"],
        "messages": [{"role": "system", "content": system},
                     {"role": "user", "content": prompt}],
        "temperature": 0.2,
        "stream": False,
    }
    if json_mode:
        body["response_format"] = {"type": "json_object"}
    timeout = llm_config.get_runtime().get("timeout", 40)
    r = requests.post(url, headers=headers, json=body, timeout=timeout)
    r.raise_for_status()
    return r.json()["choices"][0]["message"]["content"]


def llm_available(tier="fast"):
    """该任务档位是否有可用的真实模型。"""
    return llm_config.active(tier)


def raw_complete(system, prompt, json_mode=False, tier="fast"):
    """统一文本补全入口：按任务档位路由模型，失败降级 mock。"""
    slot = llm_config.resolve(tier)
    if slot is None:
        return _MOCK.complete(system, prompt, json_mode)
    try:
        return _chat(slot, system, prompt, json_mode)
    except Exception as e:  # noqa: BLE001 - 任意网络/模型错误都降级
        return _MOCK.complete(system, prompt, json_mode, error=str(e))


def ping(slot, timeout=12):
    """连接测试：发一条极短请求验证 base_url / key / model 是否可用。"""
    t0 = time.time()
    try:
        url = slot["base_url"].rstrip("/") + "/chat/completions"
        headers = {"Content-Type": "application/json"}
        if slot.get("api_key"):
            headers["Authorization"] = "Bearer " + slot["api_key"]
        body = {"model": slot["model"],
                "messages": [{"role": "user", "content": "请只回复两个字：在线"}],
                "temperature": 0, "max_tokens": 16, "stream": False}
        r = requests.post(url, headers=headers, json=body, timeout=timeout)
        latency = int((time.time() - t0) * 1000)
        if r.status_code != 200:
            return {"ok": False, "latency_ms": latency,
                    "error": f"HTTP {r.status_code}: {r.text[:200]}"}
        reply = r.json()["choices"][0]["message"]["content"]
        return {"ok": True, "latency_ms": latency, "reply": (reply or "").strip()[:80]}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "latency_ms": int((time.time() - t0) * 1000), "error": str(e)}


def _extract_json(text):
    if not text:
        return None
    text = text.strip()
    text = re.sub(r"^```(json)?", "", text).strip()
    text = re.sub(r"```$", "", text).strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        m = re.search(r"\{.*\}", text, re.DOTALL)
        if m:
            try:
                return json.loads(m.group(0))
            except json.JSONDecodeError:
                return None
    return None


# ===========================================================================
# 高层 AIOps 能力（标注任务档位：strong=复杂推理 / fast=轻量）
# ===========================================================================
def analyze_incident(report: dict) -> dict:
    """对一次危险上报做根因分析，返回结构化 JSON。【strong】"""
    system = (
        "你是资深 Linux SRE。根据服务器指标/异常/日志做根因分析。"
        "只输出严格 JSON，字段：risk_level(High/Medium/Low)、root_cause、summary(一句话)、"
        "solutions(数组)、need_human(bool)。不要 markdown。"
    )
    m = report.get("metrics", {})
    prompt = (
        f"主机: {report.get('hostname')}\n"
        f"CPU:{m.get('cpu')}% 内存:{m.get('memory_pct')}% Swap:{m.get('swap_pct')}% "
        f"磁盘:{m.get('disk_pct')}% IOwait:{m.get('iowait')}% Load:{m.get('load1')}\n"
        f"异常: {report.get('anomalies')}\n"
        f"日志:\n{(report.get('logs') or '')[:1500]}\n"
    )
    out = _extract_json(raw_complete(system, prompt, json_mode=True, tier="strong"))
    if not out:
        out = _MOCK.analyze(report)
    out.setdefault("risk_level", "Medium")
    out.setdefault("summary", "AI 分析完成")
    out.setdefault("solutions", [])
    out.setdefault("need_human", True)
    return out


def explain_operation(action: str, detail: dict, username: str) -> dict:
    """为审计日志生成 一句话摘要 + 细节解释。【fast】"""
    if not llm_available("fast"):
        return _MOCK.explain_operation(action, detail, username)
    system = (
        "你是运维审计助手。把一条平台操作翻译成中文：summary(一句话，给管理者快速浏览)、"
        "explanation(2-4句，解释这步在做什么、影响、需注意什么)。只输出 JSON。"
    )
    prompt = f"操作者:{username}\n动作:{action}\n详情:{json.dumps(detail, ensure_ascii=False)[:800]}"
    out = _extract_json(raw_complete(system, prompt, json_mode=True, tier="fast"))
    return out or _MOCK.explain_operation(action, detail, username)


def summarize_session(host_name: str, commands: list) -> str:
    """对一次 WebSSH 会话做 AI 摘要总结。【fast】"""
    if not commands:
        return "本次会话未执行任何命令。"
    if not llm_available("fast"):
        return _MOCK.summarize_session(host_name, commands)
    system = "你是运维审计助手。用 3-5 句中文总结这次 SSH 运维会话：做了什么、是否有风险操作、结果。"
    body = "\n".join(f"$ {c['command']}\n{(c.get('output_excerpt') or '')[:200]}" for c in commands[:40])
    return raw_complete(system, f"主机:{host_name}\n操作记录:\n{body}", tier="fast").strip() or \
        _MOCK.summarize_session(host_name, commands)


def suggest_commands(host_name: str, context: str, goal: str = "") -> dict:
    """WebSSH 内的 AI 提示：根据当前上下文给出建议命令。【fast】"""
    if not llm_available("fast"):
        return _MOCK.suggest_commands(host_name, context, goal)
    system = (
        "你是 Linux 终端助手。根据用户在终端的近期输出，给出下一步建议。"
        "只输出 JSON：advice(中文一段)、commands(数组，每项 {cmd, why, risk(safe/caution/dangerous)})。"
        "命令默认只读、安全；危险命令必须标 dangerous 并在 why 中提示。"
    )
    ctx = context if isinstance(context, str) else str(context or "")
    prompt = f"主机:{host_name}\n目标:{goal or '辅助排障'}\n终端近况:\n{ctx[:1500]}"
    out = _extract_json(raw_complete(system, prompt, json_mode=True, tier="fast"))
    return out or _MOCK.suggest_commands(host_name, context, goal)


def propose_investigation(host_name: str, anomalies: list, metrics: dict) -> dict:
    """AI 调查员：提议一组只读诊断命令(待人工批准)。【strong】"""
    if not llm_available("strong"):
        return _MOCK.propose_investigation(host_name, anomalies, metrics)
    system = (
        "你是 SRE 自动化排障代理。针对给定异常，提出一份只读诊断计划。"
        "只输出 JSON：hypothesis(中文)、steps(数组，每项 {cmd, purpose})。"
        "命令必须是只读、非破坏性的(如 top -bn1, df -h, ss -s, dmesg|tail)。禁止任何写/删/重启操作。"
    )
    prompt = f"主机:{host_name}\n异常:{anomalies}\n指标:{json.dumps(metrics, ensure_ascii=False)}"
    out = _extract_json(raw_complete(system, prompt, json_mode=True, tier="strong"))
    return out or _MOCK.propose_investigation(host_name, anomalies, metrics)


def conclude_investigation(host_name: str, transcript: list) -> dict:
    """AI 调查员：根据命令执行结果给出根因与修复建议(修复需另行人工批准)。【strong】"""
    if not llm_available("strong"):
        return _MOCK.conclude_investigation(host_name, transcript)
    system = (
        "你是 SRE。根据诊断命令的真实输出，给出结论。只输出 JSON："
        "root_cause(中文)、summary(一句话)、confidence(0-1)、"
        "remediation(数组，每项 {cmd, why, risk})。修复命令可能有风险，需人工二次确认。"
    )
    body = "\n".join(f"$ {t['cmd']}\n{(t.get('output') or '')[:400]}" for t in transcript[:20])
    out = _extract_json(raw_complete(system, f"主机:{host_name}\n诊断输出:\n{body}", json_mode=True, tier="strong"))
    return out or _MOCK.conclude_investigation(host_name, transcript)


def classify_command_risk(cmd: str) -> dict:
    """命令风险护栏的 AI 增强(在规则判定之外补充语义判断)。【fast】"""
    if not llm_available("fast"):
        return _MOCK.classify_command_risk(cmd)
    system = ("你是命令安全审查器。判断一条 shell 命令风险。只输出 JSON："
              "risk(safe/caution/dangerous)、reason(中文一句)。")
    out = _extract_json(raw_complete(system, f"命令:{cmd}", json_mode=True, tier="fast"))
    return out or _MOCK.classify_command_risk(cmd)


def chatops_answer(question: str, evidence: dict) -> str:
    """ChatOps：把检索到的结构化证据转成自然语言回答。【fast】"""
    if not llm_available("fast"):
        return _MOCK.chatops_answer(question, evidence)
    system = "你是运维数据助手。依据提供的 JSON 证据，用中文简洁回答问题，不要编造证据外的信息。"
    prompt = f"问题:{question}\n证据:{json.dumps(evidence, ensure_ascii=False)[:2000]}"
    return raw_complete(system, prompt, tier="fast").strip() or _MOCK.chatops_answer(question, evidence)


# ===========================================================================
# 离线规则引擎
# ===========================================================================
class _MockEngine:
    def complete(self, system, prompt, json_mode, error=None):
        if json_mode:
            return json.dumps({"summary": "（离线规则引擎）", "note": error or ""}, ensure_ascii=False)
        return "（当前运行于离线规则引擎模式，未连接大模型）"

    def analyze(self, report):
        m = report.get("metrics", {})
        an = report.get("anomalies", [])
        causes, sols = [], []
        if (m.get("disk_pct") or 0) > 90:
            causes.append("根分区磁盘接近写满")
            sols.append("清理 /var/log 与临时文件，或扩容磁盘")
        if (m.get("memory_pct") or 0) > 90 or (m.get("swap_pct") or 0) > 50:
            causes.append("内存压力大，已动用 Swap")
            sols.append("用 ps --sort=-%mem 定位高内存进程，评估是否内存泄漏")
        if (m.get("iowait") or 0) > 20:
            causes.append("磁盘 I/O 成为瓶颈(高 iowait)")
            sols.append("用 iostat/iotop 定位高 I/O 进程")
        if (m.get("cpu") or 0) > 90:
            causes.append("CPU 持续高负载")
            sols.append("用 top 定位高 CPU 进程，检查是否死循环")
        if any("brute" in str(a).lower() for a in an):
            causes.append("检测到 SSH 暴力破解尝试")
            sols.append("启用 fail2ban / 限制来源 IP / 改用密钥登录")
        if not causes:
            causes.append("存在异常信号，但资源指标尚在可控范围")
            sols.append("结合日志进一步确认")
        risk = "High" if report.get("is_danger") and len(an) >= 2 else ("Medium" if an else "Low")
        return {
            "risk_level": risk,
            "root_cause": "；".join(causes),
            "summary": f"{report.get('hostname')}: {causes[0]}",
            "solutions": sols,
            "need_human": risk == "High",
        }

    def explain_operation(self, action, detail, username):
        templates = {
            "login": "用户登录平台",
            "logout": "用户登出平台",
            "create_host": "新增了一台受管主机",
            "delete_host": "删除了一台受管主机",
            "assign_host": "将主机分配给某用户",
            "create_user": "创建了新用户账号",
            "ssh_open": "发起了一次 WebSSH 远程会话",
            "ssh_command": "在远程主机执行了一条命令",
            "ai_investigate": "触发了一次 AI 自动诊断",
            "approve_investigation": "人工批准了 AI 诊断计划",
        }
        base = templates.get(action, action)
        d = json.dumps(detail, ensure_ascii=False)[:300] if detail else ""
        return {
            "summary": f"{username} {base}",
            "explanation": f"该操作类别为「{action}」。{base}。相关参数：{d or '无'}。"
                           f"此记录已纳入审计，可在回溯页面追踪上下文。",
        }

    def summarize_session(self, host_name, commands):
        n = len(commands)
        risky = [c for c in commands if c.get("risk_level") == "dangerous"]
        cmds = "、".join(c["command"].split()[0] for c in commands[:6] if c.get("command"))
        s = f"对主机 {host_name} 共执行 {n} 条命令，涉及 {cmds} 等。"
        s += f"其中 {len(risky)} 条被标记为高风险，请重点复核。" if risky else "未发现高风险操作。"
        return s

    def suggest_commands(self, host_name, context, goal):
        low = (context if isinstance(context, str) else str(context or "")).lower()
        cmds = []
        if "permission denied" in low:
            cmds.append({"cmd": "ls -l", "why": "确认文件权限与属主", "risk": "safe"})
        if "no such file" in low:
            cmds.append({"cmd": "pwd && ls -la", "why": "确认当前目录与文件是否存在", "risk": "safe"})
        if "disk" in low or "no space" in low:
            cmds.append({"cmd": "df -h", "why": "查看各分区使用率", "risk": "safe"})
            cmds.append({"cmd": "du -sh /var/log/* | sort -h | tail", "why": "定位日志占用", "risk": "safe"})
        if not cmds:
            cmds = [
                {"cmd": "top -bn1 | head -20", "why": "查看实时负载与高占用进程", "risk": "safe"},
                {"cmd": "df -h", "why": "查看磁盘使用率", "risk": "safe"},
                {"cmd": "free -m", "why": "查看内存与 Swap", "risk": "safe"},
            ]
        return {"advice": f"针对 {host_name} 的{goal or '排障'}，建议先做只读巡检确认现状：", "commands": cmds}

    def propose_investigation(self, host_name, anomalies, metrics):
        steps = [
            {"cmd": "uptime", "purpose": "确认负载均值与运行时长"},
            {"cmd": "top -bn1 | head -15", "purpose": "定位高 CPU/内存进程"},
            {"cmd": "df -h", "purpose": "检查磁盘使用率"},
            {"cmd": "free -m", "purpose": "检查内存与 Swap"},
        ]
        txt = " ".join(str(a).lower() for a in anomalies)
        if "io" in txt:
            steps.append({"cmd": "iostat -x 1 2 || vmstat 1 2", "purpose": "确认磁盘 I/O 压力"})
        if "brute" in txt or "ssh" in txt:
            steps.append({"cmd": "journalctl -u ssh -n 50 --no-pager", "purpose": "复核 SSH 登录失败来源"})
        if "memory" in txt or "oom" in txt:
            steps.append({"cmd": "dmesg | grep -i oom | tail", "purpose": "检查是否触发 OOM Killer"})
        return {"hypothesis": f"{host_name} 出现 {anomalies or '异常信号'}，先做只读取证以定位根因。",
                "steps": steps}

    def conclude_investigation(self, host_name, transcript):
        joined = "\n".join((t.get("output") or "") for t in transcript).lower()
        cause, rem = "未发现明确单一根因，建议结合业务日志进一步确认。", []
        if "oom" in joined:
            cause = "系统曾触发 OOM Killer，存在内存不足导致进程被杀。"
            rem = [{"cmd": "systemctl restart <service>", "why": "重启被 OOM 影响的服务", "risk": "caution"}]
        elif re.search(r"\b(9[0-9]|100)%", joined) and "use%" in joined:
            cause = "某分区磁盘使用率过高，逼近写满。"
            rem = [{"cmd": "journalctl --vacuum-size=200M", "why": "清理系统日志释放空间", "risk": "caution"}]
        return {"root_cause": cause, "summary": cause[:30],
                "confidence": 0.55, "remediation": rem}

    def classify_command_risk(self, cmd):
        return {"risk": "safe", "reason": "离线规则未发现明显风险（仅做了基础静态匹配）"}

    def chatops_answer(self, question, evidence):
        n = evidence.get("count", 0)
        items = evidence.get("items", [])
        if not items:
            return f"未检索到与「{question}」匹配的记录。"
        head = "、".join(str(i.get("name") or i.get("host_name") or i) for i in items[:5])
        return f"共匹配到 {n} 条记录，例如：{head}。详见下方明细。"


_MOCK = _MockEngine()
