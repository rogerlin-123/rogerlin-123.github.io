#!/bin/bash

# --- 設定變數 ---
SERVICE_NAME="ses-safe"
PROJECT_DIR=$(pwd)
USER_NAME=$(whoami)
PYTHON_PATH="$PROJECT_DIR/venv/bin/python3"
MAIN_SCRIPT="web.py"
SYSTEMD_PATH="/etc/systemd/system/$SERVICE_NAME.service"

echo "=== Secure-Encrypted-Safe (SES) Systemd 安裝程式 ==="

# 1. 檢查虛擬環境是否存在
if [ ! -f "$PYTHON_PATH" ]; then
    echo "錯誤: 找不到虛擬環境於 $PYTHON_PATH"
    echo "請先執行 python3 -m venv venv 並安裝依賴套件。"
    exit 1
fi

# 2. 建立 Systemd Service 檔案
echo "正在產生服務設定檔..."

sudo bash -c "cat > $SYSTEMD_PATH" <<EOF
[Unit]
Description=Secure-Encrypted-Safe Web Service
After=network.target

[Service]
User=$USER_NAME
WorkingDirectory=$PROJECT_DIR
ExecStart=$PYTHON_PATH $MAIN_SCRIPT
Restart=always
RestartSec=5
# 設定環境變數防止 Python 緩衝日誌
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
EOF

# 3. 載入並啟動服務
echo "正在載入並啟動服務..."
sudo systemctl daemon-reload
sudo systemctl enable $SERVICE_NAME
sudo systemctl start $SERVICE_NAME

# 4. 檢查狀態
echo "------------------------------------------------"
if systemctl is-active --quiet $SERVICE_NAME; then
    echo "成功: $SERVICE_NAME 服務已啟動並設定為開機自動執行！"
    echo "您的加密保險箱現在應該運行在: https://your-ip:8888"
else
    echo "警告: 服務啟動失敗，請執行 'sudo journalctl -u $SERVICE_NAME' 查看日誌。"
fi
echo "------------------------------------------------"