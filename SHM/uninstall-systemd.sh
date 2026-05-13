#!/usr/bin/env bash
# =============================================================================
# System Health Monitor — Linux systemd 服務移除
# 對應 Windows uninstall-as-service.bat
#
# 預設不刪資料(config.yaml / users.json / monitor.log 等)。
# 完全清乾淨請手動 rm -rf 整個資料夾 + .venv。
# =============================================================================
set -u

SERVICE_NAME="system-health-monitor"
UNIT_FILE="/etc/systemd/system/${SERVICE_NAME}.service"

if [ "$EUID" -ne 0 ]; then
    echo "[ERROR] 需要 root 權限"
    echo "        sudo ./uninstall-systemd.sh"
    exit 1
fi

echo "============================================"
echo "  System Health Monitor — 移除 systemd 服務"
echo "============================================"

# --- 1. 服務存在? ---
if ! systemctl list-unit-files | grep -q "^${SERVICE_NAME}\.service"; then
    echo "[INFO] 服務 $SERVICE_NAME 沒安裝,什麼都不用做"
    exit 0
fi

# --- 2. 停 + disable + remove unit ---
echo "[INFO] systemctl stop $SERVICE_NAME"
systemctl stop "$SERVICE_NAME" 2>/dev/null || true

echo "[INFO] systemctl disable $SERVICE_NAME"
systemctl disable "$SERVICE_NAME" 2>/dev/null || true

if [ -f "$UNIT_FILE" ]; then
    echo "[INFO] 刪除 $UNIT_FILE"
    rm -f "$UNIT_FILE"
fi

systemctl daemon-reload
systemctl reset-failed 2>/dev/null || true

# --- 3. 驗證 ---
if systemctl list-unit-files | grep -q "^${SERVICE_NAME}\.service"; then
    echo "[WARN] 服務看起來還在 list 裡,可能要重開機才完全消失"
else
    echo ""
    echo "[OK]  服務已移除。"
    echo ""
    echo "  資料檔保留在原資料夾(config.yaml / users.json / monitor.log 等)。"
    echo "  要完全清乾淨可 rm -rf 整個資料夾 + .venv。"
    echo ""
fi
