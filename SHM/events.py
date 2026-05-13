"""監控事件紀錄 — 記錄狀態變化(UP / DOWN / 首次 UP)供 UI 回查。

與 monitor.log 的差別:
- monitor.log 是人讀的日誌,輪替(5MB × 3)可能被覆蓋
- monitor_events.jsonl 是結構化 JSONL,只記狀態變化事件,保留時間較長
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from paths import data_dir
BASE_DIR = data_dir()
EVENTS_PATH = BASE_DIR / "monitor_events.jsonl"

log = logging.getLogger(__name__)


def _now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def log_event(target: str, check: dict, event: str, **extra) -> None:
    """寫一筆事件。event ∈ {'up', 'down', 'first_up'}"""
    from checker import check_address  # 避免循環匯入
    entry = {
        "ts": _now_iso(),
        "target": target,
        "type": check.get("type", "tcp"),
        "address": check_address(check),
        "event": event,
    }
    for k, v in extra.items():
        if v is not None and v != "":
            entry[k] = v
    try:
        with EVENTS_PATH.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except OSError as e:
        log.warning("無法寫入 monitor_events: %s", e)


def read_events(limit: int = 500) -> list[dict]:
    if not EVENTS_PATH.exists():
        return []
    out: list[dict] = []
    try:
        with EVENTS_PATH.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    except OSError:
        return []
    return out[-limit:][::-1]  # 最新在前


def clear_events() -> int:
    """清空事件紀錄,回傳原本筆數。"""
    if not EVENTS_PATH.exists():
        return 0
    try:
        with EVENTS_PATH.open("r", encoding="utf-8") as f:
            count = sum(1 for line in f if line.strip())
    except OSError:
        count = 0
    try:
        EVENTS_PATH.unlink()
    except OSError as e:
        log.warning("無法刪除 monitor_events: %s", e)
        raise
    return count
