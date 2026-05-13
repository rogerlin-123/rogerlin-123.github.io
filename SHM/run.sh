#!/usr/bin/env bash
# =============================================================================
# System Health Monitor — Linux 從原始碼直接執行(對應 Windows run.bat)
# 不需要編譯,直接跑 python3 monitor.py
#
# 支援兩種 layout:
#   (A) 腳本在 run-linux/ 子資料夾,monitor.py 在 ../ (dev 環境)
#   (B) 腳本與 monitor.py 在同資料夾 (給 Linux 使用者的打包版)
#
# 首次執行會自動建 .venv 並安裝依賴;偵測到依賴缺失時會自動重裝。
# 互動模式啟動,要長期常駐請改用 ./install-systemd.sh 安裝成系統服務。
# =============================================================================
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# 自動偵測 project root
if [ -f "$SCRIPT_DIR/monitor.py" ]; then
    ROOT_DIR="$SCRIPT_DIR"
elif [ -f "$SCRIPT_DIR/../monitor.py" ]; then
    ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
else
    echo "[ERROR] 找不到 monitor.py(已嘗試 $SCRIPT_DIR 與 $SCRIPT_DIR/..)"
    exit 1
fi
cd "$ROOT_DIR"

echo "============================================"
echo "  System Health Monitor — 從原始碼啟動 (Linux)"
echo "  project root: $ROOT_DIR"
echo "============================================"

# --- 1. 系統 Python 檢查 ---
if ! command -v python3 >/dev/null 2>&1; then
    echo ""
    echo "[ERROR] 找不到 python3"
    echo ""
    echo "  Ubuntu/Debian:  sudo apt install python3 python3-venv python3-pip"
    echo "  RHEL/Fedora:    sudo dnf install python3 python3-pip"
    echo "  Arch:           sudo pacman -S python python-pip"
    echo ""
    exit 1
fi
PY_VER=$(python3 -c "import sys; print('%d.%d' % (sys.version_info.major, sys.version_info.minor))")
echo "[INFO] 系統 Python $PY_VER"

# 提醒(不阻擋)
PY_MAJOR=$(python3 -c "import sys; print(sys.version_info.major)")
PY_MINOR=$(python3 -c "import sys; print(sys.version_info.minor)")
if [ "$PY_MAJOR" -lt 3 ] || { [ "$PY_MAJOR" -eq 3 ] && [ "$PY_MINOR" -lt 10 ]; }; then
    echo "[WARN] Python $PY_VER < 3.10,truststore 等套件可能裝不起來(其他功能正常)"
fi

# --- 2. 建立(或修復)venv + 安裝依賴 ---
VENV="$ROOT_DIR/.venv"

install_dependencies() {
    echo "[INFO] 升級 pip..."
    python3 -m pip install --upgrade pip 2>&1 | tail -3 || true
    if [ ! -f "$ROOT_DIR/requirements.txt" ]; then
        echo "[ERROR] 找不到 requirements.txt"
        return 1
    fi
    echo "[INFO] 安裝 requirements.txt..."
    if ! python3 -m pip install -r "$ROOT_DIR/requirements.txt"; then
        echo ""
        echo "[ERROR] pip install 失敗,可能原因:"
        echo "        · 沒有網路連線"
        echo "        · 公司 proxy 擋 pypi(試 export HTTPS_PROXY=...)"
        echo "        · python3-venv 沒裝(sudo apt install python3-venv)"
        return 1
    fi

    # hauman_radius(內部 wheel,選配)
    if [ -n "${HAUMAN_RADIUS_WHL:-}" ] && [ -f "$HAUMAN_RADIUS_WHL" ]; then
        echo "[INFO] 安裝 hauman_radius: $HAUMAN_RADIUS_WHL"
        python3 -m pip install "$HAUMAN_RADIUS_WHL" || \
            echo "[WARN] hauman_radius 裝失敗(RADIUS 認證功能會停用)"
    else
        for p in \
            "$ROOT_DIR/hauman_radius" \
            "$HOME/hauman_radius" \
            "$HOME/Downloads/hauman_radius/dist" \
            "$HOME/Downloads"
        do
            if [ -d "$p" ]; then
                CANDIDATE=$(ls -1 "$p"/hauman_radius-*.whl 2>/dev/null | head -1)
                if [ -n "$CANDIDATE" ]; then
                    echo "[INFO] 找到 hauman_radius: $CANDIDATE"
                    python3 -m pip install "$CANDIDATE" || true
                    break
                fi
            fi
        done
    fi
    echo "[OK]   依賴安裝完成"
    return 0
}

if [ ! -x "$VENV/bin/python3" ]; then
    echo ""
    echo "[INFO] 首次啟動 — 建立 virtualenv 與安裝依賴(約 30 秒)"
    if ! python3 -m venv "$VENV" 2>/dev/null; then
        echo "[ERROR] python3 -m venv 失敗 — Ubuntu/Debian 可能要先裝:"
        echo "          sudo apt install python3-venv"
        exit 1
    fi
    # shellcheck disable=SC1091
    source "$VENV/bin/activate"
    install_dependencies || exit 1
else
    # shellcheck disable=SC1091
    source "$VENV/bin/activate"
    if ! python3 -c "import yaml, flask, requests, dns.resolver" 2>/dev/null; then
        echo ""
        echo "[WARN] venv 偵測到依賴缺失,重新安裝..."
        install_dependencies || {
            echo ""
            echo "       若問題持續,可完全重來:"
            echo "       rm -rf '$VENV' 後再跑本腳本"
            exit 1
        }
    fi
fi
echo "[INFO] 使用 venv python: $(which python3)"

# --- 3. 檢查 config.yaml ---
if [ ! -f "$ROOT_DIR/config.yaml" ]; then
    echo "[ERROR] 找不到 config.yaml"
    exit 1
fi

# --- 4. 驗證 config.yaml 語法 ---
if ! python3 -c "import yaml; yaml.safe_load(open('$ROOT_DIR/config.yaml','r',encoding='utf-8'))" 2>/tmp/shm_startup_err; then
    echo "[ERROR] config.yaml 格式錯誤:"
    cat /tmp/shm_startup_err
    rm -f /tmp/shm_startup_err
    exit 1
fi

# --- 5. 停掉既有 instance ---
if [ -f "$ROOT_DIR/monitor.pid" ]; then
    PID=$(cat "$ROOT_DIR/monitor.pid" 2>/dev/null | tr -d '[:space:]')
    if [ -n "$PID" ] && kill -0 "$PID" 2>/dev/null; then
        echo "[INFO] 終止舊 PID $PID"
        kill "$PID" 2>/dev/null || true
        sleep 1
        kill -0 "$PID" 2>/dev/null && kill -9 "$PID" 2>/dev/null
    fi
    rm -f "$ROOT_DIR/monitor.pid"
fi
pkill -f "python.*monitor\.py" 2>/dev/null || true

# --- 6. 解析 web_port ---
PORT=$(awk '
    /^[[:space:]]*web_port[[:space:]]*:/ {
        gsub(/[^0-9]/, "", $2); print $2; exit
    }
' "$ROOT_DIR/config.yaml")
PORT="${PORT:-5192}"

# --- 7. 背景啟動 monitor.py ---
echo "[INFO] 啟動 monitor.py..."
nohup python3 "$ROOT_DIR/monitor.py" > "$ROOT_DIR/monitor.log" 2>&1 &
MAIN_PID=$!
disown 2>/dev/null || true
echo "[INFO] PID = $MAIN_PID"

# --- 8. 等 Flask 就緒(最多 20 秒)---
echo "[INFO] 等 Web 伺服器就緒(最多 20 秒)..."
for i in $(seq 1 20); do
    sleep 1
    if curl -s -o /dev/null -m 1 "http://127.0.0.1:${PORT}/" ; then
        echo "[OK]   Web 就緒"
        break
    fi
    if [ $i -eq 20 ]; then
        echo "[ERROR] 20 秒內沒回應,看 monitor.log:"
        tail -20 "$ROOT_DIR/monitor.log" 2>/dev/null
        exit 1
    fi
done

# --- 9. 開瀏覽器(若有 GUI 環境) ---
URL="http://127.0.0.1:${PORT}"
echo ""
echo "    URL: ${URL}"
echo ""
if [ -n "${DISPLAY:-}${WAYLAND_DISPLAY:-}" ] && command -v xdg-open >/dev/null 2>&1; then
    echo "[INFO] 嘗試打開瀏覽器 (xdg-open)..."
    xdg-open "${URL}" >/dev/null 2>&1 &
elif command -v gnome-open >/dev/null 2>&1; then
    gnome-open "${URL}" >/dev/null 2>&1 &
else
    echo "[INFO] (無 GUI 環境,請從別台機器用瀏覽器連 http://<this-server-ip>:${PORT})"
fi

echo ""
echo "[INFO] monitor.py 持續在背景執行。要停止:./stop.sh"
echo "[INFO] 即時 log:tail -f monitor.log"
echo ""
echo "[INFO] 要設成「開機自動啟動 + 當機自動重啟」,改用:"
echo "         sudo ./install-systemd.sh"
echo ""
