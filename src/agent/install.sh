#!/bin/bash
# ============================================================================
# AIZ Ops Platform —— 主机 Agent 安装脚本
# 用法：
#   sudo AIZ_SERVER_URL="http://你的服务器IP:8000/api/report" \
#        AIZ_AGENT_TOKEN="主机专属token或全局token" \
#        bash install.sh
# 不传环境变量时会使用 main.py 中的默认值，安装后可再编辑 service 文件。
# ============================================================================
set -e
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'

echo -e "${GREEN}[*] 开始安装 AIZ Ops Agent...${NC}"

if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}请使用 sudo 运行此脚本${NC}"; exit 1
fi

TARGET_DIR="/opt/aiz-ops/agent"
PYBIN="$(command -v python3 || echo /usr/bin/python3)"

echo -e "${GREEN}[*] 创建部署目录: ${TARGET_DIR}${NC}"
mkdir -p "$TARGET_DIR"
cp -r ./main.py "$TARGET_DIR/" 2>/dev/null || true
[ -d ./service ] && cp -r ./service "$TARGET_DIR/" || true

echo -e "${GREEN}[*] 安装 Python 依赖 (psutil requests)...${NC}"
pip3 install --quiet psutil requests || pip3 install --break-system-packages --quiet psutil requests

# ---- 生成 systemd 服务文件（注入环境变量）----
SERVICE_PATH="/etc/systemd/system/aiz-agent.service"
SERVER_URL="${AIZ_SERVER_URL:-http://YOUR_SERVER_IP:8000/api/report}"
AGENT_TOKEN="${AIZ_AGENT_TOKEN:-sk-secure-token-123456}"
INTERVAL="${AIZ_INTERVAL:-10}"

echo -e "${GREEN}[*] 写入 systemd 服务: ${SERVICE_PATH}${NC}"
cat > "$SERVICE_PATH" <<EOF
[Unit]
Description=AIZ Ops Platform Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Environment=AIZ_SERVER_URL=${SERVER_URL}
Environment=AIZ_AGENT_TOKEN=${AGENT_TOKEN}
Environment=AIZ_INTERVAL=${INTERVAL}
ExecStart=${PYBIN} ${TARGET_DIR}/main.py
Restart=always
RestartSec=5s
CPUQuota=10%
MemoryMax=200M
StandardOutput=journal
StandardError=journal
SyslogIdentifier=aiz-agent

[Install]
WantedBy=multi-user.target
EOF

chmod 644 "$SERVICE_PATH"
systemctl daemon-reload
systemctl enable --now aiz-agent.service

echo -e "${GREEN}[SUCCESS] Agent 已安装并启动！${NC}"
echo -e "  服务器地址 : ${SERVER_URL}"
echo -e "  令牌       : ${AGENT_TOKEN}"
echo    "  查看状态   : systemctl status aiz-agent"
echo    "  查看日志   : journalctl -u aiz-agent -f"
if [ "$AGENT_TOKEN" = "sk-secure-token-123456" ]; then
  echo -e "${YELLOW}[提示] 当前使用全局默认令牌，建议在网页端为每台主机生成专属 token 后重装。${NC}"
fi
