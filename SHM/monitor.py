"""TCP 服務監控主程式。"""
from __future__ import annotations

import atexit
import json
import logging
import logging.handlers
import os
import signal
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

import yaml

import auth
import events
from checker import (
    check,
    check_address,
    check_key,
    migrate_state_keys,
    normalize_targets,
)
from notifier import TelegramNotifier, normalize_telegram
from web import start_web_server

from paths import data_dir
BASE_DIR = data_dir()
CONFIG_PATH = BASE_DIR / "config.yaml"
STATE_PATH = BASE_DIR / "state.json"
LOG_PATH = BASE_DIR / "monitor.log"
PID_PATH = BASE_DIR / "monitor.pid"

log = logging.getLogger("tcp_monitor")


def setup_logging() -> None:
    log.setLevel(logging.INFO)
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")

    fh = logging.handlers.RotatingFileHandler(
        LOG_PATH, maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8"
    )
    fh.setFormatter(fmt)
    log.addHandler(fh)

    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(fmt)
    log.addHandler(sh)


def ensure_config_yaml() -> None:
    """若使用者目錄沒有 config.yaml,從 bundle 內預設範本複製一份出來。
    這讓單獨拿到 exe 的使用者也能跑(會在 exe 同層自動產生 config.yaml,
    之後使用者可直接編輯)。
    """
    if CONFIG_PATH.exists():
        return
    try:
        from paths import bundle_dir
        default_src = bundle_dir() / "config.yaml"
        if default_src.exists():
            import shutil
            shutil.copy(default_src, CONFIG_PATH)
            log.info("已從 bundle 預設範本建立 config.yaml: %s", CONFIG_PATH)
        else:
            log.warning("bundle 內沒有預設 config.yaml(可能是舊版打包),"
                        "需手動建立 %s", CONFIG_PATH)
    except Exception as e:
        log.warning("展開預設 config.yaml 失敗: %s", e)


def load_config() -> dict:
    ensure_config_yaml()
    if not CONFIG_PATH.exists():
        log.error("找不到設定檔: %s", CONFIG_PATH)
        sys.exit(1)
    with CONFIG_PATH.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def load_state() -> dict:
    if not STATE_PATH.exists():
        return {}
    try:
        with STATE_PATH.open("r", encoding="utf-8") as f:
            raw = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        log.warning("state.json 讀取失敗,重置為空: %s", e)
        return {}
    # 遷移舊 key 格式(name@host:port → name::tcp:host:port)以保留計數
    migrated = migrate_state_keys(raw)
    if migrated.keys() != raw.keys():
        log.info("state.json key 已從舊格式遷移到新格式 (%d 筆)", len(migrated))
    return migrated


def save_state(state: dict) -> None:
    tmp = STATE_PATH.with_suffix(".json.tmp")
    with tmp.open("w", encoding="utf-8") as f:
        json.dump(state, f, ensure_ascii=False, indent=2)
    tmp.replace(STATE_PATH)


def write_pid_file() -> None:
    try:
        PID_PATH.write_text(str(os.getpid()), encoding="ascii")
        atexit.register(_remove_pid_file)
    except OSError as e:
        log.warning("無法寫入 PID 檔: %s", e)


def _remove_pid_file() -> None:
    try:
        if PID_PATH.exists():
            PID_PATH.unlink()
    except OSError:
        pass


def now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def fmt_now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def fmt_duration(seconds: float) -> str:
    seconds = int(seconds)
    if seconds < 60:
        return f"{seconds} 秒"
    m, s = divmod(seconds, 60)
    if m < 60:
        return f"{m} 分 {s} 秒"
    h, m = divmod(m, 60)
    if h < 24:
        return f"{h} 小時 {m} 分"
    d, h = divmod(h, 24)
    return f"{d} 天 {h} 小時"


def _type_label(c: dict) -> str:
    return (c.get("type") or "tcp").upper()


def build_down_message(target_name: str, check: dict, error: str) -> str:
    return (
        f"🔴 *服務異常*\n"
        f"目標: {target_name}\n"
        f"檢查: [{_type_label(check)}] `{check_address(check)}`\n"
        f"錯誤: {error}\n"
        f"時間: {fmt_now()}"
    )


def build_up_message(target_name: str, check: dict, down_since_iso: str,
                     latency_ms: float) -> str:
    try:
        down_since = datetime.fromisoformat(down_since_iso)
        duration = (datetime.now(down_since.tzinfo) - down_since).total_seconds()
        dur_text = fmt_duration(duration)
    except (TypeError, ValueError):
        dur_text = "未知"

    return (
        f"✅ *服務恢復*\n"
        f"目標: {target_name}\n"
        f"檢查: [{_type_label(check)}] `{check_address(check)}`\n"
        f"中斷: {dur_text}\n"
        f"延遲: {latency_ms} ms\n"
        f"時間: {fmt_now()}"
    )


def build_reminder_message(target_name: str, check: dict,
                           down_since_iso: str) -> str:
    try:
        down_since = datetime.fromisoformat(down_since_iso)
        duration = (datetime.now(down_since.tzinfo) - down_since).total_seconds()
        dur_text = fmt_duration(duration)
    except (TypeError, ValueError):
        dur_text = "未知"

    return (
        f"⚠️ *服務仍未恢復*\n"
        f"目標: {target_name}\n"
        f"檢查: [{_type_label(check)}] `{check_address(check)}`\n"
        f"累計中斷: {dur_text}\n"
        f"時間: {fmt_now()}"
    )


_running = True


def _handle_signal(signum, frame):
    global _running
    log.info("收到訊號 %s,準備結束...", signum)
    _running = False


def run() -> None:
    setup_logging()
    write_pid_file()
    log.info("TCP 監控程式啟動 (PID=%s)", os.getpid())

    # 首次啟動:若 users.json 不存在,建立 admin/admin 與 viewer/viewer
    auth.ensure_default_users()

    cfg = load_config()
    channels = normalize_telegram(cfg.get("telegram"))
    settings = cfg.get("settings", {})
    targets = normalize_targets(cfg.get("targets", []))

    # Telegram 允許空 — 沒設就純粹不發告警,但監控 / UI 照跑
    if not targets:
        log.error("config.yaml 未設定任何 targets")
        sys.exit(1)

    interval = int(settings.get("check_interval_seconds", 30))
    timeout = float(settings.get("tcp_timeout_seconds", 5))
    fail_threshold = int(settings.get("failure_threshold", 3))
    recover_threshold = int(settings.get("recovery_threshold", 1))
    reminder_minutes = int(settings.get("reminder_interval_minutes", 60))
    events_cfg = settings.get("events") or {}
    log_every_fail = bool(events_cfg.get("log_every_fail", True))
    log_every_success = bool(events_cfg.get("log_every_success", False))
    web_port = int(settings.get("web_port", 5192))
    web_host = str(settings.get("web_host", "127.0.0.1"))

    notifier = TelegramNotifier(channels)
    if channels:
        log.info("Telegram 已啟用 %d 個通道 (總共 %d)", notifier.enabled_count(), len(channels))
    else:
        log.info("Telegram 未設定任何通道 — 告警不會推播,僅記錄到 monitor.log 與事件紀錄")
    state = load_state()

    # Shared state between monitor loop and web UI (同一把鎖保護)
    # config_changed: 由 web UI 在增刪目標後 set(),讓迴圈提早喚醒並重新檢查
    shared = {
        "state": state,
        "targets": list(targets),
        "settings": dict(settings),
        "notifier": notifier,
        "lock": threading.Lock(),
        "config_changed": threading.Event(),
    }

    web_thread = threading.Thread(
        target=start_web_server,
        args=(web_host, web_port, shared),
        name="WebUI",
        daemon=True,
    )
    web_thread.start()

    total_checks = sum(len(t["checks"]) for t in targets)
    target_lines = []
    for i, t in enumerate(targets, 1):
        target_lines.append(f"  {i}. {t['name']} ({len(t['checks'])} 項檢查)")
        for c in t["checks"]:
            target_lines.append(f"     [{_type_label(c)}] `{check_address(c)}`")
    target_lines = "\n".join(target_lines)

    # 啟動摘要只寫進 monitor.log,不發 Telegram(避免每次重啟洗版)
    log.info(
        "監控就緒:目標 %d 個 / 共 %d 項檢查 · 通道 %d 啟用 / %d 總 · "
        "間隔 %ds · 門檻 %d",
        len(targets), total_checks,
        notifier.enabled_count(), len(notifier.channels),
        interval, fail_threshold,
    )
    # 若綁 0.0.0.0 → 把本機所有可達 IP 列出來,方便同網段使用者知道連哪
    if web_host in ("0.0.0.0", "::"):
        log.info("面板對外開放 (監聽 %s:%d)", web_host, web_port)
        try:
            import socket as _s
            hostname = _s.gethostname()
            ips = set()
            for info in _s.getaddrinfo(hostname, None):
                ip = info[4][0]
                if ip and not ip.startswith("169.254") and ":" not in ip:
                    ips.add(ip)
            for ip in sorted(ips):
                log.info("  → http://%s:%d", ip, web_port)
            log.info("  → http://127.0.0.1:%d (本機)", web_port)
        except Exception as e:
            log.debug("偵測本機 IP 失敗: %s", e)
    else:
        log.info("面板: http://%s:%d", web_host, web_port)

    for line in target_lines.split("\n"):
        log.info(line)

    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    # 兜底 wrapper — 確保告警 / 事件紀錄的 exception 不會穿透到主迴圈讓服務死掉
    def _safe_notify(msg: str) -> None:
        try:
            notifier.send(msg)
        except Exception:
            log.exception("notifier.send 失敗,忽略後繼續")

    def _safe_event(target_name: str, check_obj: dict, event_type: str, **extra) -> None:
        try:
            events.log_event(target_name, check_obj, event_type, **extra)
        except Exception:
            log.exception("events.log_event 失敗,忽略後繼續 (event=%s)", event_type)

    while _running:
        cycle_start = time.time()

        # --- 熱重載:每輪重新讀 config,UI 新增/移除的目標會立即生效 ---
        try:
            fresh_cfg = load_config()
            settings = fresh_cfg.get("settings", settings) or settings
            targets = normalize_targets(fresh_cfg.get("targets", []))
            interval = int(settings.get("check_interval_seconds", interval))
            timeout = float(settings.get("tcp_timeout_seconds", timeout))
            fail_threshold = int(settings.get("failure_threshold", fail_threshold))
            recover_threshold = int(settings.get("recovery_threshold", recover_threshold))
            reminder_minutes = int(settings.get("reminder_interval_minutes", reminder_minutes))
            events_cfg = settings.get("events") or {}
            log_every_fail = bool(events_cfg.get("log_every_fail", True))
            log_every_success = bool(events_cfg.get("log_every_success", False))
        except Exception as e:
            log.error("config.yaml 熱重載失敗,沿用上次設定: %s", e)

        # 清掉 state 中已從 config 移除的 check,避免 UI 出現殘影
        current_keys = {
            check_key(t["name"], c) for t in targets for c in t["checks"]
        }
        for stale_key in [k for k in state.keys() if k not in current_keys]:
            state.pop(stale_key, None)
            log.info("檢查已從 config 移除: %s", stale_key)

        with shared["lock"]:
            shared["targets"] = list(targets)
            shared["settings"] = dict(settings)

        for t in targets:
            tname = t["name"]
            for c in t["checks"]:
                key = check_key(tname, c)
                s = state.setdefault(key, {
                    "status": "unknown",
                    "consecutive_failures": 0,
                    "consecutive_successes": 0,
                    "down_since": None,
                    "last_reminder": None,
                    "last_error": "",
                })

                # 停用的 check:完全跳過檢查 & 告警,保留上次計數,在 UI 顯示「已暫停」
                if c.get("enabled", True) is False:
                    s["paused"] = True
                    with shared["lock"]:
                        shared["state"][key] = dict(s)
                    continue
                else:
                    # 從暫停→啟用 的過渡:清旗標、清殘留錯誤、重設連續計數
                    # 避免顯示「連續失敗 N 次但現在是正常」這種矛盾
                    if s.get("paused"):
                        s["paused"] = False
                        s["consecutive_failures"] = 0
                        s["consecutive_successes"] = 0
                        s["last_error"] = ""

                # 個別 check 覆寫 — 沒填就沿用全域
                eff_interval = int(c.get("check_interval_seconds") or interval)
                eff_timeout = float(c.get("tcp_timeout_seconds") or timeout)
                eff_fail_threshold = int(c.get("failure_threshold") or fail_threshold)
                eff_recover_threshold = int(c.get("recovery_threshold") or recover_threshold)
                eff_reminder_minutes = int(
                    c["reminder_interval_minutes"]
                    if "reminder_interval_minutes" in c
                    else reminder_minutes
                )

                # 以 last_check_ts 節流:只在距離上次檢查已滿 interval 才跑
                # (主迴圈 tick 會依最小 eff_interval 自動變快,見下方 sleep)
                now_ts = time.time()
                last_ts = s.get("last_check_ts", 0)
                if (now_ts - last_ts) < eff_interval - 0.2:
                    continue

                s["last_check_ts"] = now_ts
                # 兜底:check 內部理論上自己處理掉所有 exception,但保險起見,
                # 任何穿透出來的例外都當成 DOWN 處理,絕對不能讓主迴圈 break。
                try:
                    result = check(c, eff_timeout)
                except BaseException as _check_exc:
                    log.exception("check() 拋出非預期例外,當成失敗處理: %s", key)
                    from checker import CheckResult as _CR
                    result = _CR(False, 0.0, f"internal: {type(_check_exc).__name__}: {_check_exc}")

                if result.ok:
                    s["consecutive_failures"] = 0
                    s["consecutive_successes"] += 1
                    # 這次通了 → 清掉殘留錯誤訊息,避免 UI 出現「正常」卻掛著舊錯誤的矛盾
                    s["last_error"] = ""

                    is_transition_to_up = (s["status"] != "up"
                                            and s["consecutive_successes"] >= eff_recover_threshold)

                    if is_transition_to_up:
                        was_down = s["status"] == "down"
                        prev_status = s["status"]
                        s["status"] = "up"
                        if was_down:
                            msg = build_up_message(tname, c, s.get("down_since"), result.latency_ms)
                            log.info("[UP] %s 恢復 (latency=%sms)", key, result.latency_ms)
                            _safe_notify(msg)
                            duration = None
                            try:
                                ds = s.get("down_since")
                                if ds:
                                    duration = int((datetime.now(datetime.fromisoformat(ds).tzinfo)
                                                     - datetime.fromisoformat(ds)).total_seconds())
                            except (TypeError, ValueError):
                                pass
                            # 恢復事件:無論 log_every_success 如何,狀態變化一定記錄
                            _safe_event(tname, c, "up",
                                             latency_ms=result.latency_ms,
                                             down_duration_sec=duration)
                        else:
                            log.info("[UP] %s 首次確認上線 (prev=%s)", key, prev_status)
                            _safe_event(tname, c, "first_up",
                                             latency_ms=result.latency_ms)
                        s["down_since"] = None
                        s["last_reminder"] = None
                    elif log_every_success:
                        # 連續成功紀錄(使用者啟用「每次成功都記」時)
                        _safe_event(tname, c, "up",
                                         latency_ms=result.latency_ms)
                else:
                    s["consecutive_successes"] = 0
                    s["consecutive_failures"] += 1
                    s["last_error"] = result.error

                    is_transition_to_down = (s["status"] != "down"
                                              and s["consecutive_failures"] >= eff_fail_threshold)

                    # 只有在「每次失敗都記」啟用 或 剛好這次達到告警門檻 時才寫事件
                    if log_every_fail or is_transition_to_down:
                        _safe_event(
                            tname, c, "down",
                            error=result.error,
                            consecutive_failures=s["consecutive_failures"],
                        )

                    if is_transition_to_down:
                        s["status"] = "down"
                        s["down_since"] = now_iso()
                        s["last_reminder"] = now_iso()
                        msg = build_down_message(tname, c, result.error)
                        log.warning("[DOWN] %s (%s)", key, result.error)
                        _safe_notify(msg)
                    elif s["status"] == "down" and eff_reminder_minutes > 0:
                        last = s.get("last_reminder")
                        try:
                            last_dt = datetime.fromisoformat(last) if last else None
                        except ValueError:
                            last_dt = None
                        if last_dt is None or (
                            datetime.now(last_dt.tzinfo) - last_dt
                        ).total_seconds() >= eff_reminder_minutes * 60:
                            msg = build_reminder_message(tname, c, s.get("down_since"))
                            log.info("[REMIND] %s 仍 DOWN", key)
                            _safe_notify(msg)
                            s["last_reminder"] = now_iso()

                # 每檢查完一項就更新共享狀態,UI 能看到漸進變化
                s["last_check"] = now_iso()
                s["last_latency_ms"] = result.latency_ms if result.ok else None
                with shared["lock"]:
                    shared["state"][key] = dict(s)

        try:
            save_state(state)
        except OSError as e:
            log.error("state.json 寫入失敗: %s", e)

        # Tick 動態取「有啟用的 check 中最短 interval」,floor 1 秒
        # 這樣 per-check interval 覆寫比全域短也能真正生效
        fastest = interval
        for t in targets:
            for c in t["checks"]:
                if c.get("enabled", True) is False:
                    continue
                ci = int(c.get("check_interval_seconds") or interval)
                if ci < fastest:
                    fastest = ci
        tick = max(1, fastest)

        elapsed = time.time() - cycle_start
        sleep_for = max(0.0, tick - elapsed)
        # 用 Event.wait 取代單純 sleep,UI 新增/移除目標可提前喚醒迴圈
        end = time.time() + sleep_for
        while _running and time.time() < end:
            remaining = end - time.time()
            if remaining <= 0:
                break
            if shared["config_changed"].wait(timeout=min(1.0, remaining)):
                shared["config_changed"].clear()
                log.info("偵測到設定變更,提前進入下一輪檢查")
                break

    log.info("TCP 監控程式結束")


def _write_startup_error(exc: BaseException) -> None:
    """把啟動階段的例外寫到 startup_error.log — 在 console=False 模式下必備。"""
    import traceback
    try:
        err_path = BASE_DIR / "startup_error.log"
        with err_path.open("w", encoding="utf-8") as fh:
            fh.write(datetime.now().isoformat() + "\n")
            fh.write("sys.executable = " + sys.executable + "\n")
            fh.write("sys.frozen = " + str(getattr(sys, "frozen", False)) + "\n")
            fh.write("BASE_DIR = " + str(BASE_DIR) + "\n\n")
            traceback.print_exception(exc, file=fh)
    except Exception:
        pass  # 最後一道防線,連寫檔都失敗就放棄


if __name__ == "__main__":
    try:
        run()
    except SystemExit:
        raise
    except BaseException as exc:
        try:
            log.exception("未處理例外,程式終止")
        except Exception:
            pass
        _write_startup_error(exc)
        raise
