"""WebSSH 桥接：基于 paramiko 提供交互式 PTY 与非交互命令执行。"""
import asyncio
import threading
import time

import paramiko

import models
import cmd_guard

CONNECT_TIMEOUT = 12


def _build_client(host: dict, secret: str) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    kwargs = dict(
        hostname=host["address"],
        port=host.get("ssh_port") or 22,
        username=host.get("ssh_user") or "root",
        timeout=CONNECT_TIMEOUT,
        banner_timeout=CONNECT_TIMEOUT,
        auth_timeout=CONNECT_TIMEOUT,
        look_for_keys=False,
        allow_agent=False,
    )
    if host.get("ssh_auth") == "key":
        from io import StringIO
        pkey = None
        for cls in (paramiko.RSAKey, paramiko.Ed25519Key, paramiko.ECDSAKey):
            try:
                pkey = cls.from_private_key(StringIO(secret))
                break
            except Exception:  # noqa: BLE001
                continue
        if pkey is None:
            raise ValueError("无法解析提供的私钥")
        kwargs["pkey"] = pkey
    else:
        kwargs["password"] = secret
    client.connect(**kwargs)
    return client


def run_command(host: dict, secret: str, command: str, timeout: int = 25) -> dict:
    """非交互式执行，返回 {ok, stdout, stderr, exit_code}。"""
    client = None
    try:
        client = _build_client(host, secret)
        stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
        out = stdout.read().decode("utf-8", "ignore")
        err = stderr.read().decode("utf-8", "ignore")
        code = stdout.channel.recv_exit_status()
        return {"ok": True, "stdout": out, "stderr": err, "exit_code": code}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "stdout": "", "stderr": str(e), "exit_code": -1}
    finally:
        if client:
            client.close()


class SSHBridge:
    """一个浏览器 WebSSH 会话 <-> 一个 paramiko PTY 通道。"""

    def __init__(self, host: dict, secret: str, db_session_id: int, on_output, loop):
        self.host = host
        self.secret = secret
        self.db_session_id = db_session_id
        self.on_output = on_output            # async callback(str)
        self.loop = loop
        self.client = None
        self.channel = None
        self._reader = None
        self._alive = False
        self._line = ""                        # 服务端行缓冲(用于审计)

    def connect(self):
        self.client = _build_client(self.host, self.secret)
        self.channel = self.client.invoke_shell(term="xterm-256color", width=120, height=32)
        self.channel.settimeout(0.0)
        self._alive = True
        self._reader = threading.Thread(target=self._read_loop, daemon=True)
        self._reader.start()

    def _read_loop(self):
        while self._alive:
            try:
                if self.channel.recv_ready():
                    data = self.channel.recv(4096).decode("utf-8", "ignore")
                    if data:
                        asyncio.run_coroutine_threadsafe(self.on_output(data), self.loop)
                elif self.channel.exit_status_ready():
                    break
                else:
                    time.sleep(0.02)
            except Exception:  # noqa: BLE001
                time.sleep(0.05)
        self._alive = False
        asyncio.run_coroutine_threadsafe(self.on_output("\r\n\x1b[33m[连接已关闭]\x1b[0m\r\n"), self.loop)

    # -------- 来自浏览器的输入 --------
    def write(self, data: str):
        """原始键入(PTY)。同时维护行缓冲用于审计。"""
        if not self.channel:
            return
        for ch in data:
            if ch in ("\r", "\n"):
                self._flush_line(source="manual")
            elif ch in ("\x7f", "\b"):
                self._line = self._line[:-1]
            elif ch == "\x03":   # Ctrl-C
                self._line = ""
            elif ch.isprintable():
                self._line += ch
        self.channel.send(data)

    def exec_button(self, cmd: str, source="button"):
        """按钮/AI 下发的整条命令：先记录审计，再送入 PTY。"""
        risk = cmd_guard.static_check(cmd)
        models.log_ssh_command(self.db_session_id, cmd, "", risk["risk"], source,
                               ai_note=risk["reason"])
        if self.channel:
            self.channel.send(cmd + "\n")

    def _flush_line(self, source="manual"):
        line = self._line.strip()
        self._line = ""
        if not line:
            return
        risk = cmd_guard.static_check(line)
        models.log_ssh_command(self.db_session_id, line, "", risk["risk"], source,
                               ai_note=risk["reason"])
        if risk["risk"] == "dangerous":
            asyncio.run_coroutine_threadsafe(
                self.on_output(f"\r\n\x1b[41m[风险护栏] 该命令被判定为高危: {risk['reason']}\x1b[0m\r\n"),
                self.loop,
            )

    def resize(self, cols: int, rows: int):
        if self.channel:
            try:
                self.channel.resize_pty(width=cols, height=rows)
            except Exception:  # noqa: BLE001
                pass

    def close(self):
        self._alive = False
        try:
            if self.channel:
                self.channel.close()
        finally:
            if self.client:
                self.client.close()
