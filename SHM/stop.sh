#!/usr/bin/env bash
# =============================================================================
# System Health Monitor — 停止從原始碼執行的 monitor.py(對應 Windows stop.bat)
# 兩階段:讀 monitor.pid 殺 → pkill 掃殘留
#
# 注意:這只停 ./run.sh 啟動的互動模式 instance。
#       如果是 systemd 服務模式,改用:sudo systemctl stop system-health-monitor
# =============================================================================
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ -f "$SCRIPT_DIR/monitor.py" ]; then
    ROOT_DIR="$SCRIPT_DIR"
elif [ -f "$SCRIPT_DIR/../monitor.py" ]; then
    ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
else
    echo "[ERROR] 找不到 monitor.py 的位置"
    exit 1
fi
cd "$ROOT_DIR"

STOPPED_ANY=0

# --- 1. 從 monitor.pid 殺 ---
if [ -f monitor.pid ]; then
    PID=$(cat monitor.pid 2>/dev/null | tr -d '[:space:]')
    if [ -n "$PID" ] && kill -0 "$PID" 2>/dev/null; then
        echo "[INFO] 終止 PID $PID"
        kill "$PID" 2>/dev/null || true
        sleep 1
        kill -0 "$PID" 2>/dev/null && kill -9 "$PID" 2>/dev/null
        STOPPED_ANY=1
    fi
    rm -f monitor.pid
fi

# --- 2. 保險:掃過所有命令列含 monitor.py 的 python ---
if pgrep -f "python.*monitor\.py" >/dev/null 2>&1; then
    echo "[INFO] 掃除殘留 python monitor.py 程序"
    pkill -f "python.*monitor\.py" 2>/dev/null || true
    sleep 1
    pgrep -f "python.*monitor\.py" >/dev/null 2>&1 && \
        pkill -9 -f "python.*monitor\.py" 2>/dev/null || true
    STOPPED_ANY=1
fi

if [ $STOPPED_ANY -eq 1 ]; then
    echo "[OK]   已停止"
else
    echo "[INFO] 沒找到執行中的 monitor.py(若是 systemd 服務,用 sudo systemctl stop system-health-monitor)"
fi
