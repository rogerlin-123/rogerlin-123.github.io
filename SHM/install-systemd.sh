#!/usr/bin/env bash
# =============================================================================
# System Health Monitor — Linux systemd 服務安裝
#
# 對應 Windows install-as-service.bat。把當前資料夾的 SHM 註冊成系統服務,
# 開機自動啟動、當機自動重啟、可用 systemctl / journalctl 管理。
#
# 預設行為:
#   · 服務名稱:system-health-monitor
#   · 安裝路徑:就地(即本 run-linux/ 所在的 project root)
#   · 服務帳號:呼叫本腳本的使用者(可用 SERVICE_USER 環境變數覆寫)
#   · unit 寫到:/etc/systemd/system/system-health-monitor.service
#
# 用法:
#   sudo ./install-systemd.sh
#
# 移除:./uninstall-systemd.sh
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# 自動偵測 layout 找 project root(同 run.sh)
if [ -f "$SCRIPT_DIR/monitor.py" ]; then
    ROOT_DIR="$SCRIPT_DIR"
elif [ -f "$SCRIPT_DIR/../monitor.py" ]; then
    ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
else
    echo "[ERROR] 找不到 monitor.py(已嘗試 $SCRIPT_DIR 與 $SCRIPT_DIR/..)"
    exit 1
fi

SERVICE_NAME="system-health-monitor"
UNIT_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
TEMPLATE="$SCRIPT_DIR/systemd/${SERVICE_NAME}.service.template"
VENV="$ROOT_DIR/.venv"

# --- 1. 確認 root ---
if [ "$EUID" -ne 0 ]; then
    echo ""
    echo "[ERROR] 需要 root 權限寫 $UNIT_FILE"
    echo "        重試:sudo ./install-systemd.sh"
    echo ""
    exit 1
fi

# --- 2. 決定服務帳號 ---
# 預設用「呼叫 sudo 的原使用者」;若直接以 root 跑且沒 SUDO_USER,fallback root
INVOKE_USER="${SUDO_USER:-${USER:-root}}"
SERVICE_USER="${SERVICE_USER:-$INVOKE_USER}"
SERVICE_GROUP="${SERVICE_GROUP:-$(id -gn "$SERVICE_USER" 2>/dev/null || echo "$SERVICE_USER")}"

# --- 3. 檢查 template ---
if [ ! -f "$TEMPLATE" ]; then
    echo "[ERROR] 找不到 systemd unit template: $TEMPLATE"
    exit 1
fi

echo "============================================"
echo "  System Health Monitor — 安裝為 systemd 服務"
echo "  install dir : $ROOT_DIR"
echo "  service     : $SERVICE_NAME"
echo "  user/group  : $SERVICE_USER / $SERVICE_GROUP"
echo "  unit file   : $UNIT_FILE"
echo "============================================"

# --- 4. Python 檢查 + venv ---
if ! command -v python3 >/dev/null 2>&1; then
    echo "[ERROR] 找不到 python3,請先安裝"
    echo "        Ubuntu/Debian: apt install python3 python3-venv"
    echo "        RHEL/Fedora:    dnf install python3 python3-pip"
    exit 1
fi

if [ ! -x "$VENV/bin/python3" ]; then
    echo ""
    echo "[INFO] venv 不存在,以 $SERVICE_USER 身分建立 + 裝依賴..."
    sudo -u "$SERVICE_USER" python3 -m venv "$VENV" || {
        echo "[ERROR] 建 venv 失敗(Ubuntu/Debian 可能要先 apt install python3-venv)"
        exit 1
    }
    sudo -u "$SERVICE_USER" "$VENV/bin/pip" install --upgrade pip >/dev/null
    sudo -u "$SERVICE_USER" "$VENV/bin/pip" install -r "$ROOT_DIR/requirements.txt" || {
        echo "[ERROR] pip install 失敗"
        exit 1
    }

    # hauman_radius(選配)
    HAUMAN_WHL="${HAUMAN_RADIUS_WHL:-}"
    if [ -z "$HAUMAN_WHL" ]; then
        for p in "$ROOT_DIR/hauman_radius" "/home/$SERVICE_USER/Downloads"; do
            if [ -d "$p" ]; then
                CANDIDATE=$(ls -1 "$p"/hauman_radius-*.whl 2>/dev/null | head -1)
                [ -n "$CANDIDATE" ] && HAUMAN_WHL="$CANDIDATE" && break
            fi
        done
    fi
    if [ -n "$HAUMAN_WHL" ] && [ -f "$HAUMAN_WHL" ]; then
        echo "[INFO] 安裝 hauman_radius: $HAUMAN_WHL"
        sudo -u "$SERVICE_USER" "$VENV/bin/pip" install "$HAUMAN_WHL" || \
            echo "[WARN] hauman_radius 裝失敗,RADIUS 認證會停用"
    else
        echo "[WARN] 找不到 hauman_radius wheel,RADIUS 功能會停用(其他正常)"
    fi
else
    echo "[INFO] venv 已存在: $VENV"
    # 確認關鍵依賴在
    if ! sudo -u "$SERVICE_USER" "$VENV/bin/python3" -c "import yaml, flask, requests, dns.resolver" 2>/dev/null; then
        echo "[WARN] venv 依賴缺失,補裝..."
        sudo -u "$SERVICE_USER" "$VENV/bin/pip" install -r "$ROOT_DIR/requirements.txt"
    fi
fi

# --- 5. 修權限(讓 SERVICE_USER 能讀寫 ROOT_DIR)---
echo "[INFO] 設定 $ROOT_DIR 擁有者為 $SERVICE_USER"
chown -R "$SERVICE_USER:$SERVICE_GROUP" "$ROOT_DIR"

# --- 6. 寫入 unit file(替換 template 的佔位符)---
echo "[INFO] 產生 $UNIT_FILE"
sed \
    -e "s#__SERVICE_USER__#$SERVICE_USER#g" \
    -e "s#__SERVICE_GROUP__#$SERVICE_GROUP#g" \
    -e "s#__INSTALL_DIR__#$ROOT_DIR#g" \
    "$TEMPLATE" > "$UNIT_FILE"
chmod 644 "$UNIT_FILE"

# --- 7. systemd reload + enable + start ---
echo "[INFO] systemctl daemon-reload"
systemctl daemon-reload

echo "[INFO] 啟用開機自啟 (systemctl enable)"
systemctl enable "$SERVICE_NAME"

echo "[INFO] 啟動服務 (systemctl start)"
systemctl restart "$SERVICE_NAME"  # restart 而非 start,既有就先停再起

sleep 3

# --- 8. 驗證 ---
if systemctl is-active --quiet "$SERVICE_NAME"; then
    echo ""
    echo "============================================"
    echo "  服務安裝成功!"
    echo "============================================"
    PORT=$(awk '
        /^[[:space:]]*web_port[[:space:]]*:/ {
            gsub(/[^0-9]/, "", $2); print $2; exit
        }
    ' "$ROOT_DIR/config.yaml")
    PORT="${PORT:-5192}"

    HOSTIP=$(hostname -I 2>/dev/null | awk '{print $1}')
    echo ""
    echo "  Web UI:  http://127.0.0.1:${PORT}"
    [ -n "$HOSTIP" ] && echo "           http://${HOSTIP}:${PORT}  (區網)"
    echo ""
    echo "  常用指令:"
    echo "    sudo systemctl status  $SERVICE_NAME      # 看狀態"
    echo "    sudo systemctl restart $SERVICE_NAME      # 重啟"
    echo "    sudo systemctl stop    $SERVICE_NAME      # 停止"
    echo "    sudo journalctl -u $SERVICE_NAME -f       # 即時 log"
    echo "    tail -f $ROOT_DIR/monitor.log             # 程式 log"
    echo ""
    echo "  防火牆放行(若要區網連):"
    echo "    sudo ufw allow ${PORT}/tcp                # Ubuntu/Debian"
    echo "    sudo firewall-cmd --permanent --add-port=${PORT}/tcp && sudo firewall-cmd --reload"
    echo ""
    echo "  移除服務:./uninstall-systemd.sh"
    echo ""
else
    echo ""
    echo "[ERROR] 服務啟動失敗。看 log:"
    echo "          sudo journalctl -u $SERVICE_NAME --no-pager -n 50"
    echo ""
    systemctl status "$SERVICE_NAME" --no-pager || true
    exit 1
fi
