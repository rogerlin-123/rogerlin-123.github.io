"""Telegram Bot notifier — 支援多通道廣播。"""
from __future__ import annotations

import logging
import time
from typing import Any

import requests

log = logging.getLogger(__name__)


def normalize_telegram(raw: Any) -> list[dict]:
    """將 config 中的 telegram 區塊正規化成 channel 清單。
    支援兩種輸入格式:
      1) 舊版單通道:  {bot_token, chat_id}
      2) 新版多通道:  [{name, bot_token, chat_id, enabled}, ...]
    """
    if not raw:
        return []

    # 舊格式:單一 dict
    if isinstance(raw, dict):
        if raw.get("bot_token") and raw.get("chat_id"):
            return [{
                "name": str(raw.get("name", "default")),
                "bot_token": str(raw["bot_token"]),
                "chat_id": str(raw["chat_id"]),
                "enabled": True,
            }]
        return []

    # 新格式:list
    if isinstance(raw, list):
        out = []
        for c in raw:
            if not isinstance(c, dict):
                continue
            token = str(c.get("bot_token", "")).strip()
            chat_id = str(c.get("chat_id", "")).strip()
            if not token or not chat_id:
                continue
            out.append({
                "name": str(c.get("name", "")).strip() or "unnamed",
                "bot_token": token,
                "chat_id": chat_id,
                "enabled": bool(c.get("enabled", True)),
            })
        return out

    return []


class TelegramNotifier:
    API_BASE = "https://api.telegram.org"

    def __init__(self, channels: list[dict], timeout: float = 10.0):
        self.channels: list[dict] = list(channels or [])
        self.timeout = timeout

    def update_channels(self, channels: list[dict]) -> None:
        """Hot swap 通道清單 — 使用者在 UI 改 Telegram 設定時呼叫。"""
        self.channels = list(channels or [])

    def enabled_count(self) -> int:
        return sum(1 for c in self.channels if c.get("enabled", True))

    def send(self, text: str, parse_mode: str = "Markdown") -> bool:
        """廣播到所有啟用的通道。只要任何一個成功就回 True。
        通道為空時靜默返回 False,讓監控流程照跑(使用者可能不需要 Telegram)。
        """
        if not self.channels:
            return False

        sent_any = False
        for ch in self.channels:
            if not ch.get("enabled", True):
                continue
            ok = self._send_one(
                ch["bot_token"], ch["chat_id"], text, parse_mode, ch.get("name", "")
            )
            if ok:
                sent_any = True
        if not sent_any:
            log.error("所有 Telegram 通道都傳送失敗")
        return sent_any

    def send_to(self, bot_token: str, chat_id: str, text: str,
                parse_mode: str = "Markdown") -> bool:
        """指定單一通道發送(用於 UI 逐一測試)。"""
        return self._send_one(bot_token, str(chat_id), text, parse_mode, "test")

    def _send_one(self, bot_token: str, chat_id: str, text: str,
                  parse_mode: str, name: str = "") -> bool:
        url = f"{self.API_BASE}/bot{bot_token}/sendMessage"
        payload = {
            "chat_id": chat_id,
            "text": text,
            "parse_mode": parse_mode,
            "disable_web_page_preview": True,
        }
        tag = f"[{name}] " if name else ""
        for attempt in range(1, 4):
            try:
                r = requests.post(url, json=payload, timeout=self.timeout)
                if r.status_code == 200 and r.json().get("ok"):
                    return True
                log.warning("%sTelegram 回應非 200 (attempt %d): %s %s",
                            tag, attempt, r.status_code, r.text[:200])
            except requests.RequestException as e:
                log.warning("%sTelegram 請求失敗 (attempt %d): %s", tag, attempt, e)
            if attempt < 3:
                time.sleep(2 ** attempt)
        log.error("%sTelegram 通道傳送失敗,已放棄 (3 次重試)", tag)
        return False
