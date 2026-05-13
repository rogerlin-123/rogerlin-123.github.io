#!/usr/bin/env bash
# =============================================================================
# System Health Monitor — Linux 前景除錯模式(對應 Windows run-debug.bat)
# 即時看所有輸出、Ctrl+C 結束。適合排查啟動問題。
# 與 run.sh 一樣會自動建 venv 與補裝缺失依賴。
# =============================================================================
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ -f "$SCRIPT_DIR/monitor.py" ]; then
    ROOT_DIR="$SCRIPT_DIR"
elif [ -f "$SCRIPT_DIR/../monitor.py" ]; then
    ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
else
    echo "[ERROR] 找不到 monitor.py"
    exit 1
fi
cd "$ROOT_DIR"

echo "============================================"
echo "  前景除錯模式 — monitor.py (Linux)"
echo "  Ctrl+C 可隨時結束"
echo "============================================"
echo ""

if ! command -v python3 >/dev/null 2>&1; then
    echo "[ERROR] 找不到 python3"
    echo "        Ubuntu/Debian: sudo apt install python3 python3-venv"
    exit 1
fi

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
        echo "[ERROR] pip install 失敗"
        return 1
    fi
    for p in \
        "$ROOT_DIR/hauman_radius" \
        "$HOME/hauman_radius" \
        "$HOME/Downloads/hauman_radius/dist" \
        "$HOME/Downloads"
    do
        if [ -d "$p" ]; then
            CANDIDATE=$(ls -1 "$p"/hauman_radius-*.whl 2>/dev/null | head -1)
            if [ -n "$CANDIDATE" ]; then
                python3 -m pip install "$CANDIDATE" || true
                break
            fi
        fi
    done
    echo "[OK]   依賴安裝完成"
    return 0
}

if [ ! -x "$VENV/bin/python3" ]; then
    echo "[INFO] 首次執行 — 建立 virtualenv..."
    if ! python3 -m venv "$VENV" 2>/dev/null; then
        echo "[ERROR] python3 -m venv 失敗 — Ubuntu/Debian 試:"
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
        echo "[WARN] venv 依賴缺失,補裝中..."
        install_dependencies || {
            echo ""
            echo "       可試 rm -rf '$VENV' 後再試"
            exit 1
        }
    fi
fi
echo "[INFO] 使用 venv python: $(which python3)"

if [ ! -f "$ROOT_DIR/config.yaml" ]; then
    echo "[ERROR] 找不到 config.yaml"
    exit 1
fi

# 避免跟背景版搶 port
pkill -f "python.*monitor\.py" 2>/dev/null || true
sleep 1

echo ""
echo "--------------------------------------------"
python3 "$ROOT_DIR/monitor.py"

echo ""
echo "=== monitor.py 已結束 ==="
