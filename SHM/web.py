"""Flask Web UI:目標 CRUD + 即時狀態檢視。"""
from __future__ import annotations

import logging
import re
import sys
import threading
from datetime import timedelta
from functools import wraps
from pathlib import Path
from typing import Any

import yaml
from flask import Flask, Response, jsonify, request, session

import auth
import events
from checker import check_key, normalize_targets
from notifier import normalize_telegram

log = logging.getLogger(__name__)

from paths import data_dir, bundle_dir
BASE_DIR = data_dir()
CONFIG_PATH = BASE_DIR / "config.yaml"

# Populated by monitor.run() via start_web_server()
_shared: dict[str, Any] = {
    "state": {},
    "targets": [],
    "settings": {},
    "notifier": None,
    "lock": threading.Lock(),
}

app = Flask(__name__, static_folder=str(bundle_dir() / "static"))
app.secret_key = auth.ensure_session_key()
app.permanent_session_lifetime = timedelta(days=7)


# ---------- Auth middleware ----------

def _client_ip() -> str:
    # X-Forwarded-For 優先(若後面有反向代理),否則取 remote_addr
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr or "-"


def current_user() -> dict | None:
    u = session.get("user")
    if u and u.get("username") and u.get("role") in auth.ROLES:
        return u
    return None


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if current_user() is None:
            return jsonify({"error": "未登入", "code": "NOT_AUTHENTICATED"}), 401
        return fn(*args, **kwargs)
    return wrapper


def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        u = current_user()
        if u is None:
            return jsonify({"error": "未登入", "code": "NOT_AUTHENTICATED"}), 401
        if u.get("role") != "admin":
            return jsonify({"error": "需要 admin 權限", "code": "FORBIDDEN"}), 403
        return fn(*args, **kwargs)
    return wrapper


def _read_config() -> dict:
    with CONFIG_PATH.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def _write_config(cfg: dict) -> None:
    tmp = CONFIG_PATH.with_suffix(".yaml.tmp")
    with tmp.open("w", encoding="utf-8") as f:
        yaml.dump(cfg, f, allow_unicode=True, sort_keys=False, default_flow_style=False)
    tmp.replace(CONFIG_PATH)


# ---------- Routes ----------

@app.route("/")
def index() -> Response:
    return Response(INDEX_HTML, mimetype="text/html; charset=utf-8")


DEFAULT_LATENCY_THRESHOLDS = {
    "tcp":  [50, 200, 500],       # TCP 單次握手,門檻緊
    "icmp": [50, 200, 500],       # ICMP 單次 round-trip
    "http": [500, 1500, 3500],    # 放寬 — HTTP 含 DNS+TLS+請求,內部網站可能偏慢
    "dns":  [50, 150, 500],       # DNS 查詢通常快;逾時例外
}


def _get_latency_thresholds() -> dict:
    """從 config 讀出延遲門檻,缺少則用預設值補。
    回傳格式 {tcp: [t1,t2,t3], icmp: [...], http: [...]}
    """
    try:
        cfg = _read_config()
    except Exception:
        cfg = {}
    raw = (cfg.get("settings") or {}).get("latency_thresholds") or {}
    out: dict = {}
    for ttype, default in DEFAULT_LATENCY_THRESHOLDS.items():
        v = raw.get(ttype) if isinstance(raw, dict) else None
        if isinstance(v, list) and len(v) == 3 and all(isinstance(x, (int, float)) and x > 0 for x in v):
            # 確保單調遞增
            if v[0] < v[1] < v[2]:
                out[ttype] = [float(x) for x in v]
                continue
        out[ttype] = list(default)
    return out


def _get_radius_cfg_from_config() -> dict:
    """從 config.yaml 讀 radius 區塊,轉成 hauman_radius 能吃的格式。"""
    try:
        cfg = _read_config()
    except Exception:
        return {}
    r = cfg.get("radius") or {}
    if not isinstance(r, dict):
        return {}
    return r


def _radius_enabled() -> bool:
    r = _get_radius_cfg_from_config()
    return bool(r.get("enabled")
                and str(r.get("server", "")).strip()
                and str(r.get("secret", "")).strip())


@app.route("/api/login-info")
def api_login_info():
    """公開端點 — 告訴登入頁 RADIUS 是否可用、以及 RADIUS 在下拉裡該顯示的文字。"""
    r = _get_radius_cfg_from_config()
    name = str(r.get("display_name", "") or "").strip() or "外部認證"
    return jsonify({
        "radius_enabled": _radius_enabled(),
        "radius_display_name": name,
    })


@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", ""))
    mode = str(data.get("auth_mode", "local")).strip() or "local"
    ip = _client_ip()
    ua = request.headers.get("User-Agent", "")

    if not username or not password:
        auth.log_login_event(username or "-", ip, False, ua,
                             "empty_credentials", auth_mode=mode)
        return jsonify({"error": "請輸入帳號密碼"}), 400

    radius_cfg = None
    default_role = "readonly"
    if mode == "radius":
        if not _radius_enabled():
            auth.log_login_event(username, ip, False, ua,
                                 "radius_disabled", auth_mode=mode)
            return jsonify({"error": "外部認證未啟用,請改用本地認證"}), 400
        r = _get_radius_cfg_from_config()
        radius_cfg = {
            "server": r.get("server"),
            "secret": r.get("secret"),
            "port": int(r.get("port", 1812)),
            "timeout": int(r.get("timeout", 5)),
        }
        default_role = r.get("default_role", "readonly")

    user, reason = auth.verify_login(username, password, mode=mode,
                                     radius_cfg=radius_cfg,
                                     default_role=default_role)
    if user is None:
        auth.log_login_event(username, ip, False, ua, reason, auth_mode=mode)
        # 統一錯誤訊息避免洩露哪個通道失敗
        if reason == "username_conflict_with_local":
            return jsonify({"error": "此帳號已存在於本地認證,請切換為本地認證登入"}), 401
        if reason == "local_login_forbidden_for_radius_user":
            return jsonify({"error": "此帳號綁定外部認證,請切換認證方式"}), 401
        return jsonify({"error": "帳號或密碼錯誤"}), 401

    session.permanent = True
    session["user"] = user
    auth.log_login_event(username, ip, True, ua, auth_mode=mode)
    log.info("登入成功: %s [%s] (%s) from %s",
             username, user["role"], user.get("auth_source", "local"), ip)
    return jsonify({"ok": True, "user": user})


@app.route("/api/logout", methods=["POST"])
def api_logout():
    u = current_user()
    if u:
        log.info("登出: %s from %s", u["username"], _client_ip())
    session.pop("user", None)
    return jsonify({"ok": True})


@app.route("/api/me")
def api_me():
    u = current_user()
    if u is None:
        return jsonify({"authenticated": False}), 401
    return jsonify({"authenticated": True, "user": u})


# ---------- User management (admin only) ----------

@app.route("/api/auth/users", methods=["GET"])
@admin_required
def api_list_users():
    return jsonify({"users": auth.list_users()})


@app.route("/api/auth/users", methods=["POST"])
@admin_required
def api_add_user():
    data = request.get_json(silent=True) or {}
    err = auth.add_user(
        str(data.get("username", "")),
        str(data.get("password", "")),
        str(data.get("role", "readonly")),
        str(data.get("auth_source", "local")),
    )
    if err:
        return jsonify({"error": err}), 400
    log.info("新增帳號: %s [%s/%s] by %s",
             data.get("username"), data.get("role"),
             data.get("auth_source", "local"), current_user()["username"])
    return jsonify({"ok": True})


@app.route("/api/auth/users", methods=["DELETE"])
@admin_required
def api_remove_user():
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip()
    # 禁止刪除自己
    if username == current_user()["username"]:
        return jsonify({"error": "不能刪除自己目前登入的帳號"}), 400
    err = auth.remove_user(username)
    if err:
        return jsonify({"error": err}), 400
    log.info("移除帳號: %s by %s", username, current_user()["username"])
    return jsonify({"ok": True})


@app.route("/api/auth/users/role", methods=["POST"])
@admin_required
def api_change_role():
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip()
    role = str(data.get("role", "")).strip()
    if username == current_user()["username"] and role != "admin":
        return jsonify({"error": "不能把自己降為 readonly"}), 400
    err = auth.change_role(username, role)
    if err:
        return jsonify({"error": err}), 400
    log.info("調整角色: %s → %s by %s", username, role, current_user()["username"])
    return jsonify({"ok": True})


@app.route("/api/auth/change-password", methods=["POST"])
@login_required
def api_change_password():
    """使用者變自己的密碼;admin 可用 target_user 變別人的密碼。"""
    data = request.get_json(silent=True) or {}
    me = current_user()
    target = str(data.get("target_user", "")).strip() or me["username"]
    new_pw = str(data.get("new_password", ""))

    # 改別人的密碼需要 admin 權限
    if target != me["username"] and me["role"] != "admin":
        return jsonify({"error": "需要 admin 權限"}), 403

    # 變自己密碼需驗證舊密碼
    if target == me["username"]:
        old_pw = str(data.get("old_password", ""))
        if not auth.verify_login(me["username"], old_pw):
            return jsonify({"error": "舊密碼錯誤"}), 400

    err = auth.change_password(target, new_pw)
    if err:
        return jsonify({"error": err}), 400
    log.info("密碼變更: %s (由 %s 執行)", target, me["username"])
    return jsonify({"ok": True})


@app.route("/api/reset", methods=["POST"])
@admin_required
def api_reset():
    """清空監控狀態(state.json 連續成功/失敗計數、上次延遲等)。
    config.yaml 的 targets 不動,下一輪檢查會重新建立狀態。
    """
    with _shared["lock"]:
        cleared_count = len(_shared["state"])
        _shared["state"].clear()
    try:
        state_path = BASE_DIR / "state.json"
        state_path.write_text("{}", encoding="utf-8")
    except OSError as e:
        return jsonify({"error": f"寫入 state.json 失敗: {e}"}), 500
    # 喚醒 monitor 迴圈立即跑新一輪檢查
    evt = _shared.get("config_changed")
    if evt is not None:
        evt.set()

    log.warning("Web UI: 清空監控狀態 by %s (原 %d 筆)",
                current_user()["username"], cleared_count)
    return jsonify({"ok": True, "cleared": cleared_count})


@app.route("/api/latency-thresholds", methods=["GET"])
@admin_required
def api_get_latency_thresholds():
    return jsonify({
        "thresholds": _get_latency_thresholds(),
        "defaults": DEFAULT_LATENCY_THRESHOLDS,
    })


@app.route("/api/latency-thresholds", methods=["POST"])
@admin_required
def api_set_latency_thresholds():
    """body: {tcp:[t1,t2,t3], icmp:[...], http:[...]}  缺少或 null = 回到預設"""
    data = request.get_json(silent=True) or {}
    clean: dict = {}
    for ttype in ("tcp", "icmp", "http"):
        v = data.get(ttype)
        if v in (None, ""):
            continue  # 不寫入 = 沿用預設
        if not isinstance(v, list) or len(v) != 3:
            return jsonify({"error": f"{ttype} 必須是 3 個數字的陣列 [fast, ok, slow]"}), 400
        try:
            nums = [float(x) for x in v]
        except (TypeError, ValueError):
            return jsonify({"error": f"{ttype} 必須是數字"}), 400
        if not all(x > 0 for x in nums):
            return jsonify({"error": f"{ttype} 的值必須大於 0"}), 400
        if not (nums[0] < nums[1] < nums[2]):
            return jsonify({"error": f"{ttype} 須遞增 (fast < ok < slow)"}), 400
        # 存成整數讓 YAML 乾淨
        clean[ttype] = [int(round(x)) if x == int(x) else x for x in nums]

    try:
        cfg = _read_config()
    except yaml.YAMLError as e:
        return jsonify({"error": f"config.yaml 讀取錯誤: {e}"}), 500

    settings = cfg.setdefault("settings", {})
    if clean:
        settings["latency_thresholds"] = clean
    else:
        # 沒有任何設定 → 移除欄位,使用預設
        settings.pop("latency_thresholds", None)

    try:
        _write_config(cfg)
    except OSError as e:
        return jsonify({"error": f"寫入 config.yaml 失敗: {e}"}), 500

    log.info("Web UI: 延遲門檻已更新 by %s", current_user()["username"])
    return jsonify({"ok": True, "thresholds": _get_latency_thresholds()})


@app.route("/api/events/config", methods=["GET"])
@admin_required
def api_get_events_config():
    try:
        cfg = _read_config()
    except Exception:
        cfg = {}
    s = cfg.get("settings") or {}
    e = s.get("events") or {}
    return jsonify({
        "log_every_fail": bool(e.get("log_every_fail", True)),
        "log_every_success": bool(e.get("log_every_success", False)),
    })


@app.route("/api/events/config", methods=["POST"])
@admin_required
def api_set_events_config():
    data = request.get_json(silent=True) or {}
    try:
        cfg = _read_config()
    except yaml.YAMLError as e:
        return jsonify({"error": f"config.yaml 讀取錯誤: {e}"}), 500

    settings = cfg.setdefault("settings", {})
    settings.setdefault("events", {})
    settings["events"]["log_every_fail"] = bool(data.get("log_every_fail", True))
    settings["events"]["log_every_success"] = bool(data.get("log_every_success", False))

    try:
        _write_config(cfg)
    except OSError as e:
        return jsonify({"error": f"寫入 config.yaml 失敗: {e}"}), 500

    # 通知 monitor 迴圈馬上重讀設定
    evt = _shared.get("config_changed")
    if evt is not None:
        evt.set()

    log.info("Web UI: 事件紀錄設定更新 (fail=%s, success=%s) by %s",
             settings["events"]["log_every_fail"],
             settings["events"]["log_every_success"],
             current_user()["username"])
    return jsonify({"ok": True})


@app.route("/api/events")
@login_required
def api_events():
    """讀取監控狀態變化事件(UP / DOWN / first_up)。"""
    limit = int(request.args.get("limit", 500))
    limit = max(1, min(limit, 5000))
    return jsonify({"events": events.read_events(limit)})


@app.route("/api/events/export")
@login_required
def api_events_export():
    """匯出事件為 CSV。查詢參數:
    - limit  (default 5000, max 50000)
    - type   (tcp / icmp / http)
    - event  (down / up / first_up / up:recovery / up:ok)
    - q      (比對 target / address / error)
    """
    import csv
    import io
    from datetime import datetime as _dt

    limit = int(request.args.get("limit", 5000))
    limit = max(1, min(limit, 50000))
    ftype = (request.args.get("type") or "").strip().lower()
    fevent = (request.args.get("event") or "").strip().lower()
    q = (request.args.get("q") or "").strip().lower()

    rows = events.read_events(limit)

    def keep(ev: dict) -> bool:
        if ftype and (ev.get("type") or "tcp") != ftype:
            return False
        if fevent:
            if fevent == "up:recovery":
                if not (ev.get("event") == "up" and ev.get("down_duration_sec") is not None):
                    return False
            elif fevent == "up:ok":
                if not (ev.get("event") == "up" and ev.get("down_duration_sec") is None):
                    return False
            elif ev.get("event") != fevent:
                return False
        if q:
            hay = " ".join(str(ev.get(k, "")) for k in
                           ("target", "address", "error", "event", "type")).lower()
            if q not in hay:
                return False
        return True

    filtered = [e for e in rows if keep(e)]

    # 建立 CSV(UTF-8 with BOM,讓 Excel 正確顯示中文)
    buf = io.StringIO()
    writer = csv.writer(buf, quoting=csv.QUOTE_MINIMAL)
    writer.writerow([
        "時間", "事件", "目標", "類型", "位址", "錯誤訊息",
        "延遲(ms)", "連續失敗次數", "中斷時長(秒)",
    ])
    for ev in filtered:
        ev_type = ev.get("event", "")
        # 把 up+down_duration_sec 標記為 recovery
        if ev_type == "up" and ev.get("down_duration_sec") is not None:
            ev_label = "up_recovery"
        elif ev_type == "up":
            ev_label = "up_ok"
        else:
            ev_label = ev_type
        writer.writerow([
            ev.get("ts", ""),
            ev_label,
            ev.get("target", ""),
            (ev.get("type") or "tcp").upper(),
            ev.get("address", ""),
            ev.get("error", ""),
            ev.get("latency_ms", ""),
            ev.get("consecutive_failures", ""),
            ev.get("down_duration_sec", ""),
        ])

    csv_body = buf.getvalue()
    # BOM + content
    payload = "\ufeff" + csv_body
    fname = _dt.now().strftime("monitor_events_%Y%m%d_%H%M%S.csv")
    return Response(
        payload,
        mimetype="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
    )


@app.route("/api/events", methods=["DELETE"])
@admin_required
def api_clear_events():
    try:
        n = events.clear_events()
    except OSError as e:
        return jsonify({"error": f"清空失敗: {e}"}), 500
    log.warning("Web UI: 清空監控事件紀錄 by %s (原 %d 筆)",
                current_user()["username"], n)
    return jsonify({"ok": True, "cleared": n})


@app.route("/api/radius", methods=["GET"])
@admin_required
def api_get_radius():
    r = _get_radius_cfg_from_config()
    return jsonify({
        "enabled": bool(r.get("enabled", False)),
        "server": str(r.get("server", "")),
        "port": int(r.get("port", 1812)),
        "secret": str(r.get("secret", "")),
        "timeout": int(r.get("timeout", 5)),
        "default_role": str(r.get("default_role", "readonly")),
        "display_name": str(r.get("display_name", "")),
    })


@app.route("/api/radius", methods=["POST"])
@admin_required
def api_set_radius():
    data = request.get_json(silent=True) or {}
    server = str(data.get("server", "")).strip()
    secret = str(data.get("secret", "")).strip()
    try:
        port = int(data.get("port", 1812))
        timeout = int(data.get("timeout", 5))
    except (TypeError, ValueError):
        return jsonify({"error": "port / timeout 必須是整數"}), 400
    enabled = bool(data.get("enabled"))
    default_role = str(data.get("default_role", "readonly"))
    if default_role not in ("admin", "readonly"):
        return jsonify({"error": "default_role 必須是 admin 或 readonly"}), 400
    display_name = str(data.get("display_name", "")).strip()
    if len(display_name) > 40:
        return jsonify({"error": "顯示名稱最長 40 字"}), 400

    if enabled:
        if not server:
            return jsonify({"error": "啟用 RADIUS 需要填寫 server"}), 400
        if not secret:
            return jsonify({"error": "啟用 RADIUS 需要填寫 secret"}), 400
        if not (1 <= port <= 65535):
            return jsonify({"error": "port 須介於 1-65535"}), 400
        if not (1 <= timeout <= 60):
            return jsonify({"error": "timeout 須介於 1-60 秒"}), 400

    try:
        cfg = _read_config()
    except yaml.YAMLError as e:
        return jsonify({"error": f"config.yaml 讀取錯誤: {e}"}), 500

    cfg["radius"] = {
        "enabled": enabled,
        "server": server,
        "port": port,
        "secret": secret,
        "timeout": timeout,
        "default_role": default_role,
    }
    if display_name:
        cfg["radius"]["display_name"] = display_name
    try:
        _write_config(cfg)
    except OSError as e:
        return jsonify({"error": f"寫入 config.yaml 失敗: {e}"}), 500
    log.info("Web UI: RADIUS 設定已更新 (enabled=%s, server=%s, default_role=%s) by %s",
             enabled, server, default_role, current_user()["username"])
    return jsonify({"ok": True})


@app.route("/api/tools/radius-test", methods=["POST"])
@admin_required
def api_tool_radius_test():
    """RADIUS 認證測試 — 輸入帳密直接 verify。body: {server, secret, port, timeout, username, password}"""
    data = request.get_json(silent=True) or {}
    server = str(data.get("server", "")).strip()
    secret = str(data.get("secret", "")).strip()
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", ""))
    try:
        port = int(data.get("port", 1812))
        timeout_s = int(data.get("timeout", 5))
    except (TypeError, ValueError):
        return jsonify({"error": "port / timeout 必須是整數"}), 400
    if not server or not secret:
        return jsonify({"error": "需填 server 與 secret"}), 400
    if not username:
        return jsonify({"error": "需填測試帳號"}), 400

    try:
        from hauman_radius import verify_radius
    except ImportError:
        return jsonify({"error": "hauman_radius 未安裝"}), 500

    import time as _t
    t0 = _t.perf_counter()
    try:
        ok = verify_radius(username, password, {
            "server": server, "secret": secret, "port": port, "timeout": timeout_s,
        })
    except Exception as e:
        return jsonify({
            "ok": False,
            "authenticated": False,
            "elapsed_ms": int((_t.perf_counter() - t0) * 1000),
            "message": f"{type(e).__name__}: {str(e)[:200]}",
        })
    elapsed = int((_t.perf_counter() - t0) * 1000)
    log.info("Web UI tool: RADIUS 測試 %s@%s:%s -> %s (%dms) by %s",
             username, server, port, ok, elapsed, current_user()["username"])
    return jsonify({
        "ok": True,
        "authenticated": bool(ok),
        "elapsed_ms": elapsed,
        "message": "認證成功" if ok else "認證失敗:帳號或密碼錯誤",
    })


@app.route("/api/tools/ad-test", methods=["POST"])
@admin_required
def api_tool_ad_test():
    """AD / LDAP simple bind 測試。body: {server, port, use_ssl, bind_dn, password}"""
    data = request.get_json(silent=True) or {}
    server = str(data.get("server", "")).strip()
    bind_dn = str(data.get("bind_dn", "")).strip()
    password = str(data.get("password", ""))
    use_ssl = bool(data.get("use_ssl", False))
    try:
        port = int(data.get("port", 636 if use_ssl else 389))
    except (TypeError, ValueError):
        return jsonify({"error": "port 必須是整數"}), 400
    if not server or not bind_dn:
        return jsonify({"error": "需填 server 與 bind_dn"}), 400

    try:
        import ssl as _ssl
        from ldap3 import Server, Connection, ALL, Tls
    except ImportError:
        return jsonify({"error": "ldap3 未安裝"}), 500

    import time as _t
    t0 = _t.perf_counter()
    try:
        tls = None
        if use_ssl:
            # 寬鬆 — 測試工具允許自簽;正式使用應改為 verify + trust store
            tls = Tls(validate=_ssl.CERT_NONE)
        srv = Server(server, port=port, use_ssl=use_ssl, get_info=None, tls=tls,
                     connect_timeout=5)
        conn = Connection(srv, user=bind_dn, password=password,
                          auto_bind=False, raise_exceptions=False,
                          receive_timeout=8)
        bound = conn.bind()
        elapsed = int((_t.perf_counter() - t0) * 1000)

        if bound:
            who = conn.extend.standard.who_am_i() if conn.bound else None
            conn.unbind()
            return jsonify({
                "ok": True, "authenticated": True,
                "elapsed_ms": elapsed,
                "message": "Bind 成功",
                "who_am_i": who or "",
            })
        else:
            err = conn.result or {}
            return jsonify({
                "ok": True, "authenticated": False,
                "elapsed_ms": elapsed,
                "message": f"Bind 失敗: {err.get('description','?')} {err.get('message','')}".strip(),
            })
    except Exception as e:
        return jsonify({
            "ok": False, "authenticated": False,
            "elapsed_ms": int((_t.perf_counter() - t0) * 1000),
            "message": f"{type(e).__name__}: {str(e)[:200]}",
        })


@app.route("/api/tools/traceroute", methods=["POST"])
@admin_required
def api_tool_traceroute():
    """Traceroute 測試。body: {host, max_hops}"""
    import subprocess
    import re as _re

    data = request.get_json(silent=True) or {}
    host = str(data.get("host", "")).strip()
    try:
        max_hops = int(data.get("max_hops", 30))
    except (TypeError, ValueError):
        max_hops = 30
    max_hops = max(1, min(max_hops, 64))

    if not host:
        return jsonify({"error": "需填目標 host / IP"}), 400
    # 防呆:禁止空白、特殊字元
    if not _re.match(r"^[A-Za-z0-9][A-Za-z0-9\-\.:]*$", host):
        return jsonify({"error": "host 格式不正確"}), 400

    is_windows = sys.platform.startswith("win")
    if is_windows:
        cmd = ["tracert", "-d", "-h", str(max_hops), "-w", "2000", host]
        creationflags = 0x08000000  # CREATE_NO_WINDOW
    else:
        cmd = ["traceroute", "-n", "-m", str(max_hops), "-w", "2", host]
        creationflags = 0

    try:
        # 最多等 max_hops * 2s + buffer
        overall_timeout = max_hops * 3 + 5
        proc = subprocess.run(cmd, capture_output=True,
                              timeout=overall_timeout,
                              creationflags=creationflags)
    except subprocess.TimeoutExpired:
        return jsonify({"error": f"traceroute 整體逾時 ({overall_timeout}s)"}), 500
    except FileNotFoundError:
        return jsonify({"error": "找不到 traceroute/tracert 指令"}), 500

    raw = proc.stdout + proc.stderr
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        try:
            text = raw.decode("cp950", errors="replace")
        except Exception:
            text = raw.decode("latin-1", errors="replace")

    log.info("Web UI tool: traceroute %s by %s", host, current_user()["username"])
    return jsonify({
        "ok": True,
        "host": host,
        "output": text,
        "return_code": proc.returncode,
    })


@app.route("/api/radius/test", methods=["POST"])
@admin_required
def api_test_radius():
    """測試 RADIUS 伺服器是否可達(以 POST body 的設定)。"""
    data = request.get_json(silent=True) or {}
    server = str(data.get("server", "")).strip()
    secret = str(data.get("secret", "")).strip()
    try:
        port = int(data.get("port", 1812))
        timeout = int(data.get("timeout", 5))
    except (TypeError, ValueError):
        return jsonify({"error": "port / timeout 必須是整數"}), 400
    if not server or not secret:
        return jsonify({"error": "請填寫 server 與 secret"}), 400

    try:
        from hauman_radius import test_reachable
    except ImportError:
        return jsonify({"error": "hauman_radius 套件未安裝"}), 500

    try:
        result = test_reachable({
            "server": server,
            "secret": secret,
            "port": port,
            "timeout": timeout,
        })
    except Exception as e:
        return jsonify({"error": f"測試失敗: {type(e).__name__}: {e}"}), 500

    return jsonify(result)


@app.route("/api/auth/history/export")
@admin_required
def api_login_history_export():
    """匯出登入紀錄為 CSV。"""
    import csv
    import io
    from datetime import datetime as _dt

    limit = int(request.args.get("limit", 2000))
    limit = max(1, min(limit, 50000))
    rows = auth.read_login_history(limit)

    buf = io.StringIO()
    w = csv.writer(buf, quoting=csv.QUOTE_MINIMAL)
    w.writerow(["時間", "結果", "帳號", "認證方式", "IP", "失敗原因", "User Agent"])
    for ev in rows:
        w.writerow([
            ev.get("ts", ""),
            "成功" if ev.get("success") else "失敗",
            ev.get("user", ""),
            "RADIUS" if ev.get("auth_mode") == "radius" else "本地",
            ev.get("ip", ""),
            ev.get("reason", ""),
            ev.get("user_agent", ""),
        ])

    payload = "\ufeff" + buf.getvalue()
    fname = _dt.now().strftime("login_history_%Y%m%d_%H%M%S.csv")
    return Response(
        payload,
        mimetype="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
    )


@app.route("/api/auth/history")
@admin_required
def api_login_history():
    limit = int(request.args.get("limit", 200))
    limit = max(1, min(limit, 1000))
    return jsonify({"history": auth.read_login_history(limit)})


# ---------- Monitoring state & config ----------

@app.route("/api/state")
@login_required
def api_state():
    with _shared["lock"]:
        # 回傳已正規化的 targets (都有 checks 陣列),前端不用再做格式判斷
        settings_out = dict(_shared["settings"])
        payload = {
            "targets": [
                {"name": t["name"], "checks": list(t["checks"])}
                for t in _shared["targets"]
            ],
            "state": dict(_shared["state"]),
            "settings": settings_out,
        }
    payload["latency_thresholds"] = _get_latency_thresholds()
    return jsonify(payload)


def _validate_check(data: dict) -> tuple[dict | None, str | None]:
    """回 (check, error)。error 非 None 即代表驗證失敗。"""
    ttype = (str(data.get("type", "tcp")).strip() or "tcp").lower()
    if ttype not in ("tcp", "icmp", "http", "dns"):
        return None, "type 必須是 tcp / icmp / http / dns"

    if ttype == "tcp":
        host = str(data.get("host", "")).strip()
        try:
            port = int(data.get("port"))
        except (TypeError, ValueError):
            return None, "port 必須是整數"
        if not host:
            return None, "Host 不可為空"
        if not (1 <= port <= 65535):
            return None, "Port 須介於 1-65535"
        return {"type": "tcp", "host": host, "port": port}, None

    if ttype == "icmp":
        host = str(data.get("host", "")).strip()
        if not host:
            return None, "Host 不可為空"
        return {"type": "icmp", "host": host}, None

    if ttype == "http":
        url = str(data.get("url", "")).strip()
        if not url:
            return None, "URL 不可為空"
        if not re.match(r"^https?://", url, re.IGNORECASE):
            return None, "URL 必須以 http:// 或 https:// 開頭"
        check = {"type": "http", "url": url}
        expect = data.get("expect_status")
        if expect not in (None, "", 0):
            try:
                es = int(expect)
                if not (100 <= es <= 599):
                    raise ValueError
                check["expect_status"] = es
            except (TypeError, ValueError):
                return None, "expect_status 必須是 100-599 的整數"
        if data.get("verify_ssl") is False:
            check["verify_ssl"] = False
        return check, None

    # dns
    hostname = str(data.get("hostname", "")).strip()
    if not hostname:
        return None, "Hostname 不可為空"
    if not re.match(r"^[A-Za-z0-9]([A-Za-z0-9\-\.]*[A-Za-z0-9])?$", hostname):
        return None, "Hostname 格式不正確"
    check = {"type": "dns", "hostname": hostname}
    rtype = str(data.get("record_type", "A")).strip().upper() or "A"
    valid_types = ("A", "AAAA", "CNAME", "MX", "TXT", "NS", "PTR")
    if rtype not in valid_types:
        return None, f"record_type 必須是 {' / '.join(valid_types)}"
    if rtype != "A":
        check["record_type"] = rtype
    dns_server = str(data.get("dns_server", "")).strip()
    if dns_server:
        # 粗略驗:IPv4 或 IPv6 的合理字元
        if not re.match(r"^[0-9a-fA-F:.]+$", dns_server):
            return None, "dns_server 必須是合法的 IP 位址"
        check["dns_server"] = dns_server
    expect_ip = str(data.get("expect_ip", "")).strip()
    if expect_ip:
        if rtype not in ("A", "AAAA"):
            return None, "expect_ip 僅在 A / AAAA 查詢時才能使用"
        if not re.match(r"^[0-9a-fA-F:.]+$", expect_ip):
            return None, "expect_ip 必須是合法的 IP 位址"
        check["expect_ip"] = expect_ip
    return check, None


def _check_duplicate(checks: list, new_check: dict) -> str | None:
    """檢查 new_check 是否跟既有 checks 重複。回 error 訊息或 None。"""
    for c in checks:
        if c.get("type") != new_check["type"]:
            continue
        if new_check["type"] == "tcp":
            if c.get("host") == new_check["host"] and int(c.get("port", 0)) == new_check["port"]:
                return f"已有相同 TCP 檢查: {new_check['host']}:{new_check['port']}"
        elif new_check["type"] == "icmp":
            if c.get("host") == new_check["host"]:
                return f"已有相同 ICMP 檢查: {new_check['host']}"
        elif new_check["type"] == "http":
            if c.get("url") == new_check["url"]:
                return f"已有相同 HTTP 檢查: {new_check['url']}"
        elif new_check["type"] == "dns":
            if (c.get("hostname") == new_check["hostname"]
                    and c.get("record_type", "A") == new_check.get("record_type", "A")
                    and c.get("dns_server", "") == new_check.get("dns_server", "")):
                return (f"已有相同 DNS 檢查: {new_check['hostname']} "
                        f"[{new_check.get('record_type','A')}]"
                        + (f" @ {new_check.get('dns_server')}" if new_check.get('dns_server') else ""))
    return None


@app.route("/api/targets", methods=["POST"])
@admin_required
def api_add_target():
    """兩種模式:
    1) 只傳 {name} → 建立空目標(使用者之後再往這個目標加檢查)
    2) 傳 {name, type, ...} → 新增一筆檢查
       - name 不存在 → 建 target 並放入這個 check
       - name 已存在 → 附加 check 到該 target
    """
    data = request.get_json(silent=True) or {}
    name = str(data.get("name", "")).strip()
    if not name:
        return jsonify({"error": "名稱不可為空"}), 400

    has_check_fields = any(k in data for k in ("type", "host", "port", "url"))

    try:
        cfg = _read_config()
    except yaml.YAMLError as e:
        return jsonify({"error": f"config.yaml 讀取錯誤: {e}"}), 500

    targets_norm = normalize_targets(cfg.get("targets", []) or [])
    existing = next((t for t in targets_norm if t["name"] == name), None)

    if not has_check_fields:
        # --- Mode 1: 建立空目標 ---
        if existing:
            return jsonify({"error": f"目標「{name}」已存在"}), 400
        targets_norm.append({"name": name, "checks": []})
        action = "created_target"
        new_check = None
    else:
        # --- Mode 2: 新增檢查 ---
        new_check, err = _validate_check(data)
        if err:
            return jsonify({"error": err}), 400

        if existing:
            dup = _check_duplicate(existing["checks"], new_check)
            if dup:
                return jsonify({"error": dup}), 400
            existing["checks"].append(new_check)
            action = "added_check"
        else:
            targets_norm.append({"name": name, "checks": [new_check]})
            action = "created_target_with_check"

    cfg["targets"] = targets_norm

    try:
        _write_config(cfg)
    except OSError as e:
        return jsonify({"error": f"寫入 config.yaml 失敗: {e}"}), 500

    with _shared["lock"]:
        _shared["targets"] = list(targets_norm)
        if new_check is not None:
            key = check_key(name, new_check)
            _shared["state"].setdefault(key, {
                "status": "unknown",
                "consecutive_failures": 0,
                "consecutive_successes": 0,
                "down_since": None,
                "last_reminder": None,
                "last_error": "",
                "last_check": None,
                "last_latency_ms": None,
            })

    evt = _shared.get("config_changed")
    if evt is not None:
        evt.set()

    if new_check:
        log.info("Web UI: %s [%s] → %s", action, new_check["type"].upper(), name)
    else:
        log.info("Web UI: %s → %s", action, name)
    return jsonify({"ok": True, "action": action})


@app.route("/api/targets/settings", methods=["POST"])
@admin_required
def api_set_check_settings():
    """更新某個 check 的個別設定覆寫。
    body: {name, check_key, settings: {...}}
    settings 可包含下列任一(null 或空字串 = 清除該覆寫、沿用全域):
      - check_interval_seconds (int, ≥1)
      - tcp_timeout_seconds    (float, >0)
      - failure_threshold      (int, ≥1)
      - recovery_threshold     (int, ≥1)
      - reminder_interval_minutes (int, ≥0)
    """
    data = request.get_json(silent=True) or {}
    name = str(data.get("name", "")).strip()
    ck_key = str(data.get("check_key", "")).strip()
    overrides = data.get("settings") or {}
    if not name or not ck_key:
        return jsonify({"error": "缺少 name 或 check_key"}), 400
    if not isinstance(overrides, dict):
        return jsonify({"error": "settings 必須是物件"}), 400

    allowed_fields = {
        "check_interval_seconds":     (int,   lambda v: v >= 1, "須為 ≥1 的整數"),
        "tcp_timeout_seconds":        (float, lambda v: v > 0,  "須為正數"),
        "failure_threshold":          (int,   lambda v: v >= 1, "須為 ≥1 的整數"),
        "recovery_threshold":         (int,   lambda v: v >= 1, "須為 ≥1 的整數"),
        "reminder_interval_minutes":  (int,   lambda v: v >= 0, "須為 ≥0 的整數(0=關閉提醒)"),
    }

    cleaned: dict = {}
    clear_fields: set = set()
    for fld, val in overrides.items():
        if fld not in allowed_fields:
            return jsonify({"error": f"未知設定欄位: {fld}"}), 400
        caster, predicate, hint = allowed_fields[fld]
        if val in (None, ""):
            clear_fields.add(fld)
            continue
        try:
            v = caster(val)
        except (TypeError, ValueError):
            return jsonify({"error": f"{fld}: {hint}"}), 400
        if not predicate(v):
            return jsonify({"error": f"{fld}: {hint}"}), 400
        cleaned[fld] = v

    try:
        cfg = _read_config()
    except yaml.YAMLError as e:
        return jsonify({"error": f"config.yaml 讀取錯誤: {e}"}), 500

    targets_norm = normalize_targets(cfg.get("targets", []) or [])
    target = next((t for t in targets_norm if t["name"] == name), None)
    if target is None:
        return jsonify({"error": f"找不到「{name}」"}), 404

    matched = None
    for c in target["checks"]:
        if check_key(name, c) == ck_key:
            matched = c
            break
    if matched is None:
        return jsonify({"error": f"找不到檢查: {ck_key}"}), 404

    for f in clear_fields:
        matched.pop(f, None)
    for f, v in cleaned.items():
        matched[f] = v

    cfg["targets"] = targets_norm
    try:
        _write_config(cfg)
    except OSError as e:
        return jsonify({"error": f"寫入 config.yaml 失敗: {e}"}), 500

    with _shared["lock"]:
        _shared["targets"] = list(targets_norm)

    evt = _shared.get("config_changed")
    if evt is not None:
        evt.set()

    log.info("Web UI: 更新檢查設定 %s / %s (寫入 %d 欄、清除 %d 欄)",
             name, ck_key, len(cleaned), len(clear_fields))
    return jsonify({"ok": True, "set": cleaned, "cleared": list(clear_fields)})


@app.route("/api/targets/reorder", methods=["POST"])
@admin_required
def api_reorder_targets():
    """接受 {names: [...]} 重新排列目標。必須涵蓋所有現有目標。"""
    data = request.get_json(silent=True) or {}
    order = data.get("names")
    if not isinstance(order, list) or not all(isinstance(x, str) for x in order):
        return jsonify({"error": "names 必須是字串陣列"}), 400

    try:
        cfg = _read_config()
    except yaml.YAMLError as e:
        return jsonify({"error": f"config.yaml 讀取錯誤: {e}"}), 500

    targets_norm = normalize_targets(cfg.get("targets", []) or [])
    by_name = {t["name"]: t for t in targets_norm}

    missing = [n for n in order if n not in by_name]
    extra = [n for n in by_name.keys() if n not in order]
    if missing or extra:
        return jsonify({
            "error": "名稱清單與現有目標不一致",
            "missing": missing,
            "extra": extra,
        }), 400
    # 同名重複也擋(避免 by_name 先前吞掉了)
    if len(set(order)) != len(order):
        return jsonify({"error": "名稱清單有重複"}), 400

    reordered = [by_name[n] for n in order]
    cfg["targets"] = reordered
    try:
        _write_config(cfg)
    except OSError as e:
        return jsonify({"error": f"寫入 config.yaml 失敗: {e}"}), 500

    with _shared["lock"]:
        _shared["targets"] = list(reordered)

    log.info("Web UI: 重排目標順序 (%d 個)", len(reordered))
    return jsonify({"ok": True})


@app.route("/api/targets", methods=["PATCH"])
@admin_required
def api_patch_check():
    """切換/更新單一 check 的屬性(目前只支援 enabled)。
    body: {name, check_key, enabled: bool}
    """
    data = request.get_json(silent=True) or {}
    name = str(data.get("name", "")).strip()
    ck_key = str(data.get("check_key", "")).strip()
    if not name or not ck_key:
        return jsonify({"error": "缺少 name 或 check_key"}), 400
    if "enabled" not in data:
        return jsonify({"error": "缺少 enabled 欄位"}), 400
    new_enabled = bool(data.get("enabled"))

    try:
        cfg = _read_config()
    except yaml.YAMLError as e:
        return jsonify({"error": f"config.yaml 讀取錯誤: {e}"}), 500

    targets_norm = normalize_targets(cfg.get("targets", []) or [])
    target = next((t for t in targets_norm if t["name"] == name), None)
    if target is None:
        return jsonify({"error": f"找不到「{name}」"}), 404

    matched_check = None
    for c in target["checks"]:
        if check_key(name, c) == ck_key:
            matched_check = c
            break
    if matched_check is None:
        return jsonify({"error": f"找不到檢查: {ck_key}"}), 404

    if new_enabled:
        # 啟用 = 移除 enabled 欄位(以預設 true 為準,YAML 比較乾淨)
        matched_check.pop("enabled", None)
    else:
        matched_check["enabled"] = False

    cfg["targets"] = targets_norm
    try:
        _write_config(cfg)
    except OSError as e:
        return jsonify({"error": f"寫入 config.yaml 失敗: {e}"}), 500

    with _shared["lock"]:
        _shared["targets"] = list(targets_norm)

    evt = _shared.get("config_changed")
    if evt is not None:
        evt.set()

    log.info("Web UI: %s 檢查 [%s] (%s)",
             "啟用" if new_enabled else "暫停", ck_key, name)
    return jsonify({"ok": True, "enabled": new_enabled})


@app.route("/api/targets", methods=["DELETE"])
@admin_required
def api_delete_target():
    """刪除一個 target(整個移除)或單一 check。
    - body: {name}                              → 移除整個 target (所有 checks)
    - body: {name, check_key: "..."}            → 只移除那一個 check
    """
    data = request.get_json(silent=True) or {}
    name = str(data.get("name", "")).strip()
    ck_key = str(data.get("check_key", "")).strip()
    if not name:
        return jsonify({"error": "缺少 name"}), 400

    try:
        cfg = _read_config()
    except yaml.YAMLError as e:
        return jsonify({"error": f"config.yaml 讀取錯誤: {e}"}), 500

    targets_norm = normalize_targets(cfg.get("targets", []) or [])
    target = next((t for t in targets_norm if t["name"] == name), None)
    if target is None:
        return jsonify({"error": f"找不到「{name}」"}), 404

    removed_keys: list[str] = []
    if ck_key:
        # 只刪那個 check
        before = len(target["checks"])
        target["checks"] = [c for c in target["checks"] if check_key(name, c) != ck_key]
        if len(target["checks"]) == before:
            return jsonify({"error": f"找不到檢查: {ck_key}"}), 404
        removed_keys.append(ck_key)
        # 如果這個 target 沒剩任何 check,整個移除
        if not target["checks"]:
            targets_norm = [t for t in targets_norm if t["name"] != name]
    else:
        # 整個 target 的所有 check 都要刪
        for c in target["checks"]:
            removed_keys.append(check_key(name, c))
        targets_norm = [t for t in targets_norm if t["name"] != name]

    cfg["targets"] = targets_norm
    try:
        _write_config(cfg)
    except OSError as e:
        return jsonify({"error": f"寫入 config.yaml 失敗: {e}"}), 500

    with _shared["lock"]:
        _shared["targets"] = list(targets_norm)
        for k in removed_keys:
            _shared["state"].pop(k, None)

    evt = _shared.get("config_changed")
    if evt is not None:
        evt.set()

    log.info("Web UI: 移除 %s (%d 個檢查)", name, len(removed_keys))
    return jsonify({"ok": True, "removed": len(removed_keys)})


@app.route("/api/test-notify", methods=["POST"])
@admin_required
def api_test_notify():
    notifier = _shared.get("notifier")
    if notifier is None:
        return jsonify({"error": "Notifier 未初始化"}), 500
    if not notifier.channels or notifier.enabled_count() == 0:
        return jsonify({"error": "尚未設定任何啟用的 Telegram 通道"}), 400
    ok = notifier.send("🔔 *Telegram 測試訊息*\n從 Web UI 發送,若你看到這則訊息代表告警通道正常。")
    if ok:
        return jsonify({"ok": True})
    return jsonify({"error": "傳送失敗,請檢查 monitor.log"}), 500


@app.route("/api/telegram", methods=["GET"])
@admin_required
def api_get_telegram():
    try:
        cfg = _read_config()
    except yaml.YAMLError as e:
        return jsonify({"error": f"config.yaml 讀取錯誤: {e}"}), 500
    return jsonify({"channels": normalize_telegram(cfg.get("telegram"))})


@app.route("/api/telegram", methods=["POST"])
@admin_required
def api_set_telegram():
    import re
    data = request.get_json(silent=True) or {}
    channels_in = data.get("channels")
    if not isinstance(channels_in, list):
        return jsonify({"error": "channels 必須是陣列"}), 400

    clean: list[dict] = []
    token_pat = re.compile(r"^\d{6,}:[A-Za-z0-9_\-]{20,}$")
    chat_pat = re.compile(r"^-?\d+$")

    for i, ch in enumerate(channels_in, 1):
        if not isinstance(ch, dict):
            return jsonify({"error": f"第 {i} 個通道格式不對"}), 400
        name = str(ch.get("name", "")).strip() or f"通道 {i}"
        bot_token = str(ch.get("bot_token", "")).strip()
        chat_id = str(ch.get("chat_id", "")).strip()
        enabled = bool(ch.get("enabled", True))

        if not bot_token:
            return jsonify({"error": f"[{name}] bot_token 不可為空"}), 400
        if not token_pat.match(bot_token):
            return jsonify({"error": f"[{name}] bot_token 格式不對 (應為 123456789:AAE... 形式)"}), 400
        if not chat_id:
            return jsonify({"error": f"[{name}] chat_id 不可為空"}), 400
        if not chat_pat.match(chat_id):
            return jsonify({"error": f"[{name}] chat_id 必須是數字 (群組 id 可為負數)"}), 400

        clean.append({
            "name": name,
            "bot_token": bot_token,
            "chat_id": chat_id,
            "enabled": enabled,
        })

    # 允許 clean 為空(使用者不需要 Telegram 告警)— 照樣存

    try:
        cfg = _read_config()
    except yaml.YAMLError as e:
        return jsonify({"error": f"config.yaml 讀取錯誤: {e}"}), 500

    cfg["telegram"] = clean

    try:
        _write_config(cfg)
    except OSError as e:
        return jsonify({"error": f"寫入 config.yaml 失敗: {e}"}), 500

    notifier = _shared.get("notifier")
    if notifier is not None and hasattr(notifier, "update_channels"):
        notifier.update_channels(clean)

    log.info("Web UI: Telegram 通道已更新 (%d 個,%d 啟用)",
             len(clean), sum(1 for c in clean if c["enabled"]))
    return jsonify({"ok": True})


@app.route("/api/telegram/test", methods=["POST"])
@admin_required
def api_test_single_channel():
    """測試單一通道(不需事先存檔),用於設定介面的逐筆驗證。"""
    import re
    data = request.get_json(silent=True) or {}
    bot_token = str(data.get("bot_token", "")).strip()
    chat_id = str(data.get("chat_id", "")).strip()

    if not re.match(r"^\d{6,}:[A-Za-z0-9_\-]{20,}$", bot_token):
        return jsonify({"error": "bot_token 格式不對"}), 400
    if not re.match(r"^-?\d+$", chat_id):
        return jsonify({"error": "chat_id 必須是數字"}), 400

    notifier = _shared.get("notifier")
    if notifier is None or not hasattr(notifier, "send_to"):
        return jsonify({"error": "Notifier 未初始化"}), 500

    ok = notifier.send_to(bot_token, chat_id,
                          "🔔 *通道測試*\n這則訊息用來驗證此 Telegram 通道可用。")
    if ok:
        return jsonify({"ok": True})
    return jsonify({"error": "傳送失敗,請檢查 bot_token / chat_id / 網路"}), 500


# ---------- Server bootstrap ----------

def start_web_server(host: str, port: int, shared: dict) -> None:
    """在背景執行緒中啟動 Flask。"""
    global _shared
    _shared = shared

    # 降低 Flask/Werkzeug 本身的 INFO 噪音
    logging.getLogger("werkzeug").setLevel(logging.WARNING)

    log.info("Web UI 啟動: http://%s:%d", host, port)
    try:
        app.run(
            host=host,
            port=port,
            threaded=True,
            use_reloader=False,
            debug=False,
        )
    except OSError as e:
        log.error("Web UI 啟動失敗 (port %d 被佔用?): %s", port, e)


# ---------- HTML ----------

INDEX_HTML = r"""<!doctype html>
<html lang="zh-TW">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>System Health Monitor</title>
<link rel="icon" type="image/x-icon" href="/static/favicon.ico">
<style>
/* === Hauman CRM 風格 (取樣自客戶專案資料管理系統) === */
:root {
  --brand:        #541b86;
  --brand-dark:   #3f1364;
  --brand-soft:   #ede6f6;
  --accent:       #ffdd12;
  --accent-dark:  #8a6b00;
  --border:       #e5e7eb;
  --border-soft:  #f3f4f6;
  --muted:        #6b7280;
  --text:         #1f2937;
  --text-sub:     #374151;
  --text-faint:   #9ca3af;
  --bg:           #f3f4f6;
  --surface:      #ffffff;
  --danger:       #dc2626;
  --danger-soft:  #fee2e2;
  --danger-hover: #b91c1c;
  --success:      #16a34a;
  --success-soft: #dcfce7;
  --warn:         #d97706;
  --warn-soft:    #fef3c7;
  --mono:         "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace;
}

* { box-sizing: border-box; }
html, body { margin: 0; padding: 0; height: 100%; }
body {
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "Microsoft JhengHei", "PingFang TC", "Heiti TC", sans-serif;
  color: var(--text);
  background: var(--bg);
  font-size: 14px;
  line-height: 1.5;
  -webkit-font-smoothing: antialiased;
}

/* === Topbar (紫色主條) === */
.site-header {
  background: var(--brand);
  color: #fff;
  padding: 0 20px;
  height: 60px;
  display: flex;
  align-items: center;
  gap: 12px;
  flex-shrink: 0;
}
.site-header .logo-link {
  display: inline-flex;
  align-items: center;
  background: #fff;
  border-radius: 6px;
  padding: 3px 8px;
  box-shadow: 0 1px 2px rgba(0,0,0,.1);
  flex-shrink: 0;
  transition: opacity .15s;
}
.site-header .logo-link:hover { opacity: .9; }
.site-header .logo-img { height: 32px; display: block; }
.site-header .divider {
  width: 1px; height: 28px;
  background: rgba(255,255,255,.3);
  flex-shrink: 0;
}
.site-header h1 {
  margin: 0;
  font-size: 18px;
  font-weight: 600;
  color: #fff;
  display: flex;
  align-items: center;
  gap: 10px;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  min-width: 0;
}
.site-header h1 .sub {
  font-weight: 400;
  color: #d6c9e5;
  font-size: 14px;
}
.site-header .spacer { flex: 1; }
.site-header .h-actions { display: flex; gap: 8px; flex-shrink: 0; }
.site-header .btn-h {
  background: transparent;
  color: #fff;
  border: 1px solid rgba(255,255,255,.3);
  padding: 7px 14px;
  border-radius: 6px;
  font-size: 14px;
  font-weight: 500;
  cursor: pointer;
  font-family: inherit;
  transition: background .15s, border-color .15s;
}
.site-header .btn-h:hover { background: rgba(255,255,255,.1); }
.site-header .btn-h.accent {
  background: var(--accent);
  color: var(--brand);
  border-color: var(--accent);
  font-weight: 600;
}
.site-header .btn-h.accent:hover { background: #ffe85a; border-color: #ffe85a; }

/* === Main container === */
.wrap { padding: 20px 24px 40px; max-width: 1440px; margin: 0 auto; }

/* === Stats === */
.bar { display: flex; gap: 12px; margin-bottom: 20px; flex-wrap: wrap; }
.stat {
  background: var(--surface);
  padding: 14px 18px;
  border-radius: 8px;
  border: 1px solid var(--border);
  min-width: 130px;
  flex: 0 0 auto;
}
.stat .label {
  font-size: 12px;
  color: var(--muted);
  font-weight: 500;
  letter-spacing: .3px;
  text-transform: uppercase;
}
.stat .num {
  font-size: 28px;
  font-weight: 700;
  line-height: 1.1;
  color: var(--text);
  margin-top: 2px;
}
.stat.total .num { color: var(--brand); }
.stat.up .num    { color: var(--success); }
.stat.down .num  { color: var(--danger); }
.stat.unknown .num { color: var(--muted); }
.spacer { flex: 1; }

/* === Buttons (通用) === */
.btn {
  padding: 8px 16px;
  background: var(--brand);
  color: #fff;
  border: 1px solid var(--brand);
  border-radius: 6px;
  cursor: pointer;
  font-size: 14px;
  font-weight: 500;
  font-family: inherit;
  transition: background .15s, border-color .15s;
}
.btn:hover { background: var(--brand-dark); border-color: var(--brand-dark); }
.btn.secondary {
  background: #fff;
  color: var(--text-sub);
  border-color: var(--border);
}
.btn.secondary:hover { background: #f9fafb; border-color: #9ca3af; }
.btn.ghost {
  background: transparent;
  color: var(--muted);
  border-color: transparent;
}
.btn.ghost:hover { background: var(--border-soft); color: var(--text); }

/* === Add form === */
.add-form {
  background: var(--surface);
  padding: 14px 16px;
  border-radius: 8px;
  border: 1px solid var(--border);
  margin-bottom: 18px;
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
  align-items: center;
}
.add-form input,
.add-form select {
  padding: 8px 12px;
  border: 1px solid var(--border);
  border-radius: 6px;
  font-size: 14px;
  font-family: inherit;
  background: #fff;
  color: var(--text);
  transition: border-color .15s, box-shadow .15s;
}
.add-form input:focus,
.add-form select:focus {
  outline: none;
  border-color: var(--brand);
  box-shadow: 0 0 0 3px rgba(84, 27, 134, .1);
}
.add-form input[name="name"] { flex: 2; min-width: 180px; }
.add-form input[name="host"] { flex: 2; min-width: 160px; }
.add-form input[name="port"] { width: 100px; }

/* === Grid === */
.grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(340px, 1fr)); gap: 14px; }

/* === Cards === */
.card {
  background: var(--surface);
  border-radius: 8px;
  border: 1px solid var(--border);
  padding: 14px 16px;
  position: relative;
  border-left: 3px solid var(--muted);
  transition: box-shadow .15s, border-color .15s, transform .15s;
}
.card:hover { box-shadow: 0 2px 6px rgba(0,0,0,.05); }
.card:hover .drag-handle { opacity: 1; }
.card.dragging {
  opacity: 0.4;
  box-shadow: 0 10px 25px rgba(84, 27, 134, .15);
}
.card.drop-before {
  box-shadow: -4px 0 0 0 var(--brand);
}
.card.drop-after {
  box-shadow: 4px 0 0 0 var(--brand);
}
.drag-handle {
  position: absolute;
  top: 10px;
  left: 8px;
  color: var(--text-faint);
  font-size: 14px;
  letter-spacing: -1px;
  line-height: 1;
  cursor: grab;
  user-select: none;
  opacity: 0;
  transition: opacity .15s, color .15s;
  padding: 4px 6px;
}
.drag-handle:hover { color: var(--brand); }
.drag-handle:active { cursor: grabbing; }
/* 位移 h3 讓 drag-handle 不被擋住 */
.card h3 { padding-left: 20px; }
.card.up     { border-left-color: var(--success); }
.card.down   { border-left-color: var(--danger); }
.card.unknown{ border-left-color: var(--muted); }
.card.paused { border-left-color: var(--muted); background: #fafafa; }
.card h3 {
  margin: 0 0 12px;
  font-size: 16px;
  font-weight: 600;
  color: var(--text);
  padding-right: 28px;
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 8px;
  line-height: 1.3;
}
.counts { color: var(--text-faint); font-size: 12px; font-weight: 400; margin-left: auto; }
.remove {
  position: absolute; top: 10px; right: 10px;
  background: transparent; border: none;
  color: var(--text-faint); cursor: pointer;
  font-size: 18px; line-height: 1;
  padding: 2px 8px; border-radius: 4px;
  transition: all .15s;
}
.remove:hover { color: var(--danger); background: var(--danger-soft); }

/* === Badges === */
.badge {
  display: inline-block;
  padding: 2px 8px;
  font-size: 11px;
  border-radius: 10px;
  font-weight: 600;
  letter-spacing: .3px;
  vertical-align: middle;
}
.badge.up      { background: var(--success-soft); color: var(--success); }
.badge.down    { background: var(--danger-soft);  color: var(--danger); }
.badge.unknown { background: var(--border-soft);  color: var(--muted); }
.badge.paused  { background: var(--border-soft);  color: var(--muted); }

/* === Type tag === */
.type-tag {
  display: inline-block;
  padding: 2px 8px;
  font-size: 11px;
  border-radius: 4px;
  font-weight: 600;
  letter-spacing: .3px;
  font-family: var(--mono);
}
.type-tag.tcp  { background: var(--brand-soft); color: var(--brand); }
.type-tag.icmp { background: var(--warn-soft);  color: #8a6300; }
.type-tag.http { background: var(--success-soft); color: var(--success); }
.type-tag.dns  { background: #e0e7ff; color: #3730a3; }

/* === Check row === */
.check-row { border-top: 1px solid var(--border-soft); padding-top: 10px; margin-top: 10px; }
.check-row:first-of-type { border-top: none; padding-top: 4px; margin-top: 0; }
.check-row.paused { opacity: 0.55; }
.check-head { display: flex; align-items: center; gap: 6px; font-size: 13px; }
.check-head .spacer { flex: 1; }
.check-head button {
  background: transparent; border: none;
  color: var(--text-faint); cursor: pointer;
  font-size: 12px; line-height: 1;
  padding: 4px 8px; border-radius: 4px;
  font-family: inherit;
  transition: all .15s;
}
.check-head .toggle-ck:hover { background: var(--brand-soft); color: var(--brand); }
.check-head .settings-ck { font-size: 14px; padding: 2px 8px; }
.check-head .settings-ck:hover { background: var(--brand-soft); color: var(--brand); }
.check-head .settings-ck.has-override { color: var(--brand); font-weight: 700; }
.check-head .remove-ck { color: #bbb; font-size: 16px; }
.check-head .remove-ck:hover { color: var(--danger); background: var(--danger-soft); }

.addr { font-family: var(--mono); font-size: 12px; color: var(--muted); margin-top: 6px; word-break: break-all; }
.check-meta { font-size: 12px; color: var(--muted); line-height: 1.6; margin-top: 6px; }
.check-meta .k { color: var(--text-faint); font-weight: 500; }

.err {
  color: var(--danger-hover);
  font-size: 12px;
  margin-top: 6px;
  padding: 6px 10px;
  background: var(--danger-soft);
  border-radius: 4px;
  word-break: break-all;
}

/* === Latency pill === */
.latency {
  display: inline-block;
  padding: 1px 8px;
  font-size: 11px;
  border-radius: 10px;
  font-family: var(--mono);
  font-weight: 600;
}
.latency.fast { background: var(--success-soft); color: var(--success); }
.latency.ok   { background: var(--brand-soft);   color: var(--brand); }
.latency.slow { background: var(--warn-soft);    color: var(--warn); }
.latency.bad  { background: var(--danger-soft);  color: var(--danger); }
.latency.none { background: var(--border-soft);  color: var(--muted); }

/* === Toast === */
.toast {
  position: fixed; bottom: 24px; right: 24px;
  background: var(--text);
  color: #fff;
  padding: 12px 18px;
  border-radius: 6px;
  opacity: 0;
  transition: opacity .2s, transform .2s;
  transform: translateY(8px);
  pointer-events: none;
  max-width: 400px;
  box-shadow: 0 10px 20px rgba(0,0,0,.15);
  font-size: 14px;
}
.toast.show { opacity: 1; transform: translateY(0); }
.toast.err { background: var(--danger); }

/* === Footer === */
.foot {
  margin-top: 28px;
  padding-top: 16px;
  border-top: 1px solid var(--border);
  font-size: 12px;
  color: var(--text-faint);
  text-align: center;
  letter-spacing: .2px;
}
.foot-status { margin-bottom: 8px; }
.foot-sign { font-size: 12px; color: var(--text-faint); }
.foot-sign a { color: var(--brand); text-decoration: none; }
.foot-sign a:hover { text-decoration: underline; }

.hidden { display: none !important; }

/* === Login view === */
.login-view {
  position: fixed; inset: 0;
  background: var(--bg);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 200;
}
.login-card {
  background: #fff;
  border-radius: 12px;
  padding: 36px 32px;
  width: 360px;
  max-width: calc(100% - 32px);
  box-shadow: 0 20px 40px rgba(0,0,0,.15);
  display: flex;
  flex-direction: column;
  gap: 14px;
}
.login-card .login-logo { height: 40px; margin: 0 auto 4px; display: block; }
.login-card h1 {
  font-size: 20px;
  margin: 0 0 2px;
  text-align: center;
  color: var(--text);
  font-weight: 600;
}
.login-card .login-sub {
  font-size: 13px;
  color: var(--muted);
  text-align: center;
  margin: 0 0 8px;
}
.login-card label {
  display: flex;
  flex-direction: column;
  gap: 4px;
  font-size: 13px;
  color: var(--text-sub);
  font-weight: 500;
}
.login-card input,
.login-card select {
  padding: 10px 12px;
  border: 1px solid var(--border);
  border-radius: 6px;
  font-size: 14px;
  font-family: inherit;
  background: #fff;
  transition: border-color .15s, box-shadow .15s;
}
.login-card input:focus,
.login-card select:focus {
  outline: none;
  border-color: var(--brand);
  box-shadow: 0 0 0 3px rgba(84, 27, 134, .1);
}
.login-card button[type="submit"] {
  margin-top: 6px;
  padding: 11px;
  background: var(--brand);
  color: #fff;
  border: none;
  border-radius: 6px;
  cursor: pointer;
  font-size: 15px;
  font-weight: 600;
  font-family: inherit;
  transition: background .15s;
}
.login-card button[type="submit"]:hover { background: var(--brand-dark); }
.login-error { color: var(--danger); font-size: 13px; min-height: 18px; text-align: center; }
.login-foot {
  position: absolute;
  bottom: 18px;
  left: 0; right: 0;
  text-align: center;
  font-size: 12px;
  color: var(--text-faint);
  letter-spacing: .2px;
  padding: 0 20px;
}
.login-foot a { color: var(--brand); text-decoration: none; }
.login-foot a:hover { text-decoration: underline; }

/* === User area in topbar === */
.user-area { display: flex; align-items: center; gap: 10px; flex-shrink: 0; }
.user-label { color: #fff; font-size: 13px; }
.role-pill {
  background: rgba(255,255,255,.15);
  color: #fff;
  border: 1px solid rgba(255,255,255,.3);
  padding: 2px 8px;
  border-radius: 10px;
  font-size: 11px;
  font-weight: 600;
  letter-spacing: .3px;
}
.role-pill.admin { background: var(--accent); color: var(--brand); border-color: var(--accent); }

/* readonly 下隱藏寫入 UI */
body.readonly #add-form,
body.readonly .remove,
body.readonly .add-check-btn-small,
body.readonly .toggle-ck,
body.readonly .remove-ck,
body.readonly .drag-handle,
body.readonly #btn-settings,
body.readonly #btn-test,
body.readonly #btn-admin,
body.readonly #btn-tools,
body.readonly #ev-clear { display: none !important; }

/* RADIUS 使用者:密碼由外部管理,隱藏本地的改密碼按鈕 */
body.radius-user #btn-password { display: none !important; }
body.readonly .card { cursor: default !important; }

/* === User / history tables === */
.users-table, .history-table { width: 100%; border-collapse: collapse; font-size: 13px; }
.users-table th, .users-table td, .history-table th, .history-table td {
  text-align: left; padding: 8px 10px;
  border-bottom: 1px solid var(--border-soft);
}
.users-table th, .history-table th {
  color: var(--muted); font-weight: 600; font-size: 11px;
  text-transform: uppercase; letter-spacing: .3px;
  background: #fafafa; position: sticky; top: 0;
}
.history-table { font-family: var(--mono); font-size: 12px; }
.history-table th { font-family: inherit; }
.role-chip {
  display: inline-block;
  padding: 2px 8px;
  border-radius: 10px;
  font-size: 11px;
  font-weight: 600;
}
.role-chip.admin { background: var(--brand-soft); color: var(--brand); }
.role-chip.readonly { background: var(--border-soft); color: var(--muted); }
.row-btns button {
  background: transparent;
  border: 1px solid var(--border);
  padding: 4px 10px;
  border-radius: 4px;
  cursor: pointer;
  font-size: 12px;
  color: var(--text-sub);
  margin-left: 4px;
  font-family: inherit;
}
.row-btns button:hover { background: var(--brand-soft); color: var(--brand); border-color: var(--brand); }
.row-btns button.danger:hover { background: var(--danger-soft); color: var(--danger); border-color: var(--danger); }
.history-table tr.fail td { color: var(--danger); }

/* === Modal === */
.modal-bg {
  position: fixed; inset: 0;
  background: rgba(17, 24, 39, .5);
  display: none;
  align-items: center;
  justify-content: center;
  z-index: 100;
}
.modal-bg.show { display: flex; }
.modal {
  background: #fff;
  border-radius: 10px;
  width: 560px;
  max-width: calc(100% - 40px);
  max-height: calc(100vh - 40px);
  overflow: hidden;
  display: flex;
  flex-direction: column;
  box-shadow: 0 20px 50px rgba(0,0,0,.2);
}
.modal h2 {
  margin: 0;
  font-size: 18px;
  font-weight: 600;
  padding: 18px 22px 14px;
  border-bottom: 1px solid var(--border);
  color: var(--text);
}
.modal .body { padding: 18px 22px; overflow-y: auto; flex: 1; }
.modal .row { margin-bottom: 14px; }
.modal label { display: block; font-size: 13px; color: var(--text-sub); margin-bottom: 5px; font-weight: 500; }
.modal input[type="text"], .modal input[type="password"], .modal input:not([type]) {
  width: 100%;
  padding: 9px 12px;
  border: 1px solid var(--border);
  border-radius: 6px;
  font-size: 14px;
  font-family: var(--mono);
  color: var(--text);
  transition: border-color .15s, box-shadow .15s;
}
.modal input:focus { outline: none; border-color: var(--brand); box-shadow: 0 0 0 3px rgba(84, 27, 134, .1); }
.modal .hint { font-size: 12px; color: var(--text-faint); margin-top: 4px; line-height: 1.5; }
.modal .actions { display: flex; justify-content: flex-end; gap: 8px; padding: 14px 22px; border-top: 1px solid var(--border); background: #f9fafb; }

.token-wrap { position: relative; }
.token-wrap button {
  position: absolute; right: 6px; top: 50%; transform: translateY(-50%);
  background: none; border: none; cursor: pointer;
  font-size: 14px; color: var(--text-faint); padding: 4px 6px;
}
.token-wrap button:hover { color: var(--brand); }

.channel {
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 12px 14px;
  margin-bottom: 10px;
  background: #fafafa;
}
.channel.disabled { opacity: .5; }
.ch-head { display: flex; align-items: center; gap: 8px; margin-bottom: 10px; }
.ch-head input[type="checkbox"] { width: 16px; height: 16px; margin: 0; cursor: pointer; flex-shrink: 0; accent-color: var(--brand); }
.ch-head input.ch-name { flex: 1; font-family: inherit; }
.ch-actions { display: flex; gap: 6px; flex-shrink: 0; }
.ch-actions button {
  background: #fff;
  border: 1px solid var(--border);
  border-radius: 5px;
  padding: 6px 12px;
  cursor: pointer;
  font-size: 12px;
  color: var(--text-sub);
  font-family: inherit;
  transition: all .15s;
}
.ch-actions button:hover { background: var(--brand-soft); color: var(--brand); border-color: var(--brand); }
.ch-actions button.ch-remove:hover { background: var(--danger-soft); border-color: var(--danger); color: var(--danger); }

.add-ch-btn {
  width: 100%;
  padding: 10px;
  background: #fff;
  border: 1px dashed var(--border);
  border-radius: 6px;
  cursor: pointer;
  color: var(--muted);
  font-size: 13px;
  font-family: inherit;
  transition: all .15s;
}
.add-ch-btn:hover { border-color: var(--brand); color: var(--brand); background: var(--brand-soft); border-style: solid; }

/* === Admin center page === */
.admin-head {
  background: var(--surface);
  border: 1px solid var(--border);
  border-left: 3px solid var(--brand);
  padding: 18px 22px;
  border-radius: 8px;
  margin-bottom: 18px;
}
.admin-head h2 { margin: 0; font-size: 20px; font-weight: 700; color: var(--brand); }
.admin-sub { font-size: 13px; color: var(--muted); margin-top: 4px; }
.admin-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(260px, 1fr));
  gap: 14px;
}
.admin-card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 20px 22px;
  cursor: pointer;
  text-align: left;
  font-family: inherit;
  transition: border-color .15s, box-shadow .15s, transform .05s;
}
.admin-card:hover {
  border-color: var(--brand);
  box-shadow: 0 4px 12px rgba(84, 27, 134, .08);
}
.admin-card:active { transform: translateY(1px); }
.admin-card.danger:hover { border-color: var(--danger); box-shadow: 0 4px 12px rgba(208, 30, 61, .1); }
.admin-card .ac-icon { font-size: 28px; line-height: 1; margin-bottom: 10px; }
.admin-card .ac-title {
  font-size: 16px;
  font-weight: 700;
  color: var(--text);
  margin-bottom: 4px;
}
.admin-card.danger .ac-title { color: var(--danger); }
.admin-card .ac-desc {
  font-size: 13px;
  color: var(--muted);
  line-height: 1.5;
}

/* === Empty state === */
.empty {
  grid-column: 1/-1;
  text-align: center;
  color: var(--muted);
  padding: 60px 20px;
  background: var(--surface);
  border-radius: 8px;
  border: 1px dashed var(--border);
}
.empty strong { display: block; color: var(--text-sub); font-size: 15px; margin-bottom: 4px; }

.card-empty {
  color: var(--text-faint);
  font-size: 13px;
  padding: 14px 6px;
  text-align: center;
}
.card-foot {
  margin-top: 10px;
  padding-top: 10px;
  border-top: 1px dashed var(--border);
}
.add-check-btn-small {
  width: 100%;
  padding: 8px 12px;
  background: transparent;
  border: 1px dashed var(--border);
  border-radius: 6px;
  cursor: pointer;
  color: var(--muted);
  font-size: 13px;
  font-family: inherit;
  font-weight: 500;
  transition: all .15s;
}
.add-check-btn-small:hover {
  border-color: var(--brand);
  color: var(--brand);
  background: var(--brand-soft);
  border-style: solid;
}
</style>
</head>
<body>
<!-- Login 畫面 -->
<div class="login-view hidden" id="login-view">
  <form class="login-card" id="login-form" autocomplete="on">
    <img class="login-logo" src="/static/logo.png" alt="Hauman">
    <h1>System Health Monitor</h1>
    <p class="login-sub">請登入以繼續</p>
    <label id="auth-mode-label" class="hidden">認證方式
      <select name="auth_mode">
        <option value="radius" selected>外部認證</option>
        <option value="local">本地認證</option>
      </select>
    </label>
    <label>帳號 <input name="username" type="text" required autofocus autocomplete="username"></label>
    <label>密碼 <input name="password" type="password" required autocomplete="current-password"></label>
    <button type="submit">登入</button>
    <div id="login-error" class="login-error"></div>
  </form>
  <div class="login-foot">
    Planning &amp; Design by Timmy (<a href="mailto:timmyc@hauman.com.tw">timmyc@hauman.com.tw</a>) &nbsp;|&nbsp; 豪勉科技 Hauman Technologies Corporation &nbsp;|&nbsp; Ver.2026.05.12.23.39
  </div>
</div>

<!-- 主畫面(登入後才顯示) -->
<div id="app-view" class="hidden">
<header class="site-header">
  <a href="https://www.hauman.com.tw/" target="_blank" rel="noopener" class="logo-link" title="前往 Hauman 官網">
    <img src="/static/logo.png" alt="Hauman" class="logo-img">
  </a>
  <div class="divider"></div>
  <h1>System Health Monitor</h1>
  <div class="spacer"></div>
  <div class="h-actions">
    <button class="btn-h" id="btn-events">監控事件</button>
    <button class="btn-h" id="btn-tools">🛠 測試工具</button>
    <button class="btn-h accent" id="btn-admin">⚙ 管理中心</button>
    <button class="btn-h hidden" id="btn-back">← 回到監控</button>
  </div>
  <div class="user-area">
    <span class="user-label" id="user-label"></span>
    <span class="role-pill" id="role-pill"></span>
    <button class="btn-h" id="btn-password">改密碼</button>
    <button class="btn-h" id="btn-logout">登出</button>
  </div>
</header>
<div class="wrap" id="view-monitor">
<div class="bar">
  <div class="stat total"><div class="label">總目標</div><div class="num" id="stat-total">-</div></div>
  <div class="stat up"><div class="label">正常</div><div class="num" id="stat-up">-</div></div>
  <div class="stat down"><div class="label">異常</div><div class="num" id="stat-down">-</div></div>
  <div class="stat unknown"><div class="label">未知</div><div class="num" id="stat-unknown">-</div></div>
</div>



<form class="add-form" id="add-form">
  <select name="type" id="f-type" style="padding:8px 12px; border:1px solid var(--border); border-radius:6px; font-size:14px; background:#fff;">
    <option value="tcp">TCP</option>
    <option value="icmp">ICMP (ping)</option>
    <option value="http">HTTP GET</option>
    <option value="dns">DNS</option>
  </select>
  <input name="name" placeholder="目標名稱 (同名視為同目標、附加為新檢查)" required list="existing-names" style="flex:1.5; min-width:200px;">
  <datalist id="existing-names"></datalist>
  <input name="host" placeholder="Host 或 IP(選填)" data-for="tcp,icmp" style="flex:1.5; min-width:160px;">
  <input name="port" type="number" min="1" max="65535" placeholder="Port" data-for="tcp" style="width:100px;">
  <input name="url" placeholder="https://example.com/health(選填)" data-for="http" style="flex:2; min-width:220px;">
  <input name="expect_status" type="number" min="100" max="599" placeholder="預期狀態碼" data-for="http" style="width:130px;">
  <label data-for="http" style="display:flex; align-items:center; gap:4px; font-size:13px; color:var(--muted); padding:0 6px; white-space:nowrap;">
    <input name="verify_ssl" type="checkbox" checked style="width:14px; height:14px; accent-color: var(--brand);"> 驗證 SSL
  </label>
  <input name="hostname" placeholder="hostname 要查的網域 (例: example.com)" data-for="dns" style="flex:2; min-width:200px;">
  <select name="record_type" data-for="dns" style="padding:8px 12px; border:1px solid var(--border); border-radius:6px; font-size:14px; background:#fff;">
    <option value="A">A</option>
    <option value="AAAA">AAAA</option>
    <option value="CNAME">CNAME</option>
    <option value="MX">MX</option>
    <option value="TXT">TXT</option>
    <option value="NS">NS</option>
  </select>
  <input name="dns_server" placeholder="DNS 伺服器 IP(選填,空=系統)" data-for="dns" style="width:180px;">
  <button type="submit" class="btn">+ 新增</button>
  <div style="flex-basis:100%; font-size:12px; color:var(--muted); margin-top:4px;">
    💡 一次填完 → 建立目標並附第一個檢查;只填名稱 → 建立空目標,稍後到卡片裡加檢查。同名可附加多個檢查。
  </div>
</form>















<div class="grid" id="grid"></div>

<div class="foot">
  <div class="foot-status">每 3 秒自動刷新 · 最後更新: <span id="updated">-</span></div>
  <div class="foot-sign">Planning &amp; Design by Timmy (<a href="mailto:timmyc@hauman.com.tw">timmyc@hauman.com.tw</a>) &nbsp;|&nbsp; 豪勉科技 Hauman Technologies Corporation &nbsp;|&nbsp; Ver.2026.05.12.23.39</div>
</div>
</div><!-- /#view-monitor -->

<!-- ===== 管理中心(admin-only) ===== -->
<div class="wrap hidden" id="view-admin">
  <div class="admin-head">
    <h2>管理中心</h2>
    <div class="admin-sub">設定 · 使用者 · 紀錄 · 維護操作</div>
  </div>
  <div class="admin-grid">
    <button class="admin-card" data-open="settings">
      <div class="ac-icon">📢</div>
      <div class="ac-title">Telegram 通道</div>
      <div class="ac-desc">設定告警推播通道(可多個)並測試</div>
    </button>
    <button class="admin-card" data-open="radius">
      <div class="ac-icon">🔐</div>
      <div class="ac-title">外部認證 (RADIUS)</div>
      <div class="ac-desc">設定 RADIUS 認證伺服器</div>
    </button>
    <button class="admin-card" data-open="users">
      <div class="ac-icon">👥</div>
      <div class="ac-title">使用者管理</div>
      <div class="ac-desc">新增 / 刪除 / 調整角色 / 重設密碼</div>
    </button>
    <button class="admin-card" data-open="history">
      <div class="ac-icon">📋</div>
      <div class="ac-title">登入紀錄</div>
      <div class="ac-desc">查看最近 200 筆登入(含 RADIUS / 本地)</div>
    </button>
    <button class="admin-card" data-open="evconfig">
      <div class="ac-icon">📝</div>
      <div class="ac-title">事件紀錄設定</div>
      <div class="ac-desc">決定 UP / DOWN 是否持續記錄</div>
    </button>
    <button class="admin-card" data-open="latency">
      <div class="ac-icon">⏱</div>
      <div class="ac-title">延遲門檻</div>
      <div class="ac-desc">調整卡片延遲徽章的快 / 正常 / 慢 / 異常判定</div>
    </button>
    <button class="admin-card danger" data-open="reset">
      <div class="ac-icon">🗑</div>
      <div class="ac-title">清空監控狀態</div>
      <div class="ac-desc">重置所有計數器(不刪除監控目標)</div>
    </button>
  </div>
</div><!-- /#view-admin -->

<!-- ===== 測試工具(admin-only) ===== -->
<div class="wrap hidden" id="view-tools">
  <div class="admin-head">
    <h2>🛠 測試工具</h2>
    <div class="admin-sub">網路 / 認證的即時診斷工具 — 執行結果只在本次顯示,不保留紀錄</div>
  </div>
  <div class="admin-grid">
    <button class="admin-card" data-tool="radius">
      <div class="ac-icon">🔐</div>
      <div class="ac-title">RADIUS 認證測試</div>
      <div class="ac-desc">用任意帳密驗證 RADIUS 伺服器</div>
    </button>
    <button class="admin-card" data-tool="ad">
      <div class="ac-icon">🏢</div>
      <div class="ac-title">AD 認證測試</div>
      <div class="ac-desc">Active Directory / LDAP simple bind 連通測試</div>
    </button>
    <button class="admin-card" data-tool="traceroute">
      <div class="ac-icon">🗺</div>
      <div class="ac-title">Traceroute</div>
      <div class="ac-desc">列出封包到目的地經過的每一跳路由器</div>
    </button>
  </div>
</div><!-- /#view-tools -->

<!-- 使用者管理 modal (admin only) -->
<div class="modal-bg" id="users-modal-bg">
  <div class="modal" style="width: 720px;">
    <h2>使用者管理</h2>
    <div class="body">
      <div style="border: 1px solid var(--border); border-radius: 8px; padding: 14px 16px; margin-bottom: 18px; background: #fafafa;">
        <div style="font-weight: 600; margin-bottom: 10px;">新增使用者</div>
        <div style="display: flex; gap: 8px; flex-wrap: wrap; align-items: center;">
          <select id="nu-source" style="padding: 8px 12px; border: 1px solid var(--border); border-radius: 6px; font-size: 14px; background: #fff;">
            <option value="local">本地認證</option>
            <option value="radius">外部認證 (RADIUS)</option>
          </select>
          <input id="nu-username" type="text" placeholder="帳號" style="flex: 1; min-width: 140px; padding: 8px 12px; border: 1px solid var(--border); border-radius: 6px; font-size: 14px;">
          <input id="nu-password" type="password" placeholder="密碼 (至少 4 字;RADIUS 忽略)" style="flex: 1; min-width: 140px; padding: 8px 12px; border: 1px solid var(--border); border-radius: 6px; font-size: 14px;">
          <select id="nu-role" style="padding: 8px 12px; border: 1px solid var(--border); border-radius: 6px; font-size: 14px; background: #fff;">
            <option value="readonly">readonly</option>
            <option value="admin">admin</option>
          </select>
          <button class="btn" type="button" id="nu-add">+ 新增</button>
        </div>
      </div>
      <div style="overflow-x: auto;">
        <table class="users-table">
          <thead><tr><th>帳號</th><th>角色</th><th>認證來源</th><th>建立時間</th><th>上次登入</th><th style="text-align:right">操作</th></tr></thead>
          <tbody id="users-tbody"></tbody>
        </table>
      </div>
    </div>
    <div class="actions">
      <button class="btn ghost" type="button" id="um-close">關閉</button>
    </div>
  </div>
</div>

<!-- 登入紀錄 modal (admin only) -->
<div class="modal-bg" id="history-modal-bg">
  <div class="modal" style="width: 820px;">
    <h2 style="display: flex; align-items: center; gap: 10px;">
      登入紀錄
      <span style="font-size: 13px; font-weight: normal; color: var(--muted);">(最近 200 筆,最新在前)</span>
      <span class="spacer" style="flex: 1;"></span>
      <button id="hm-export" class="btn ghost" style="font-size: 12px; padding: 5px 12px;">⬇ 匯出 CSV</button>
    </h2>
    <div class="body" style="padding: 0;">
      <div style="overflow: auto; max-height: 60vh;">
        <table class="history-table">
          <thead><tr><th style="width: 50px">結果</th><th>時間</th><th>帳號</th><th style="width: 80px">認證</th><th>IP</th><th>備註</th></tr></thead>
          <tbody id="history-tbody"></tbody>
        </table>
      </div>
    </div>
    <div class="actions">
      <button class="btn ghost" type="button" id="hm-close">關閉</button>
    </div>
  </div>
</div>

<!-- 改密碼 modal -->
<div class="modal-bg" id="pw-modal-bg">
  <div class="modal">
    <h2>變更密碼</h2>
    <div class="body">
      <div class="row">
        <label>舊密碼</label>
        <input id="pw-old" type="password" autocomplete="current-password">
      </div>
      <div class="row">
        <label>新密碼(至少 4 字元)</label>
        <input id="pw-new" type="password" autocomplete="new-password">
      </div>
      <div class="row">
        <label>再輸入一次新密碼</label>
        <input id="pw-new2" type="password" autocomplete="new-password">
      </div>
    </div>
    <div class="actions">
      <button class="btn ghost" type="button" id="pw-cancel">取消</button>
      <button class="btn" type="button" id="pw-submit">變更</button>
    </div>
  </div>
</div>

<!-- ===== 測試工具:RADIUS 認證測試 modal ===== -->
<div class="modal-bg" id="tool-radius-modal-bg">
  <div class="modal" style="width: 560px;">
    <h2>🔐 RADIUS 認證測試</h2>
    <div class="body">
      <div class="hint" style="margin-bottom: 14px;">
        直接用指定的 server/secret + 帳密驗證,**不會**修改任何設定。<br>
        欲預設帶入目前管理中心的 RADIUS 設定,點「載入現有設定」。
      </div>
      <div class="row" style="display:flex; gap:10px;">
        <div style="flex:3;">
          <label>Server</label>
          <input id="trd-server" type="text" placeholder="IP 或 hostname">
        </div>
        <div style="width:100px;">
          <label>Port</label>
          <input id="trd-port" type="number" min="1" max="65535" value="1812">
        </div>
      </div>
      <div class="row">
        <label>Shared Secret</label>
        <div class="token-wrap">
          <input id="trd-secret" type="password">
          <button type="button" id="trd-secret-toggle" title="顯示/隱藏">👁</button>
        </div>
      </div>
      <div class="row" style="display:flex; gap:10px;">
        <div style="flex:1;">
          <label>測試帳號</label>
          <input id="trd-username" type="text" autocomplete="off">
        </div>
        <div style="flex:1;">
          <label>測試密碼</label>
          <input id="trd-password" type="password" autocomplete="off">
        </div>
        <div style="width:80px;">
          <label>Timeout</label>
          <input id="trd-timeout" type="number" min="1" max="60" value="5">
        </div>
      </div>
      <div id="trd-result" style="margin-top: 14px; display:none; padding: 12px 14px; border-radius: 6px; font-size: 13px; line-height: 1.6;"></div>
    </div>
    <div class="actions">
      <button class="btn ghost" type="button" id="trd-load">載入現有設定</button>
      <span class="spacer" style="flex:1;"></span>
      <button class="btn ghost" type="button" id="trd-close">關閉</button>
      <button class="btn" type="button" id="trd-run">執行測試</button>
    </div>
  </div>
</div>

<!-- ===== 測試工具:AD 認證測試 modal ===== -->
<div class="modal-bg" id="tool-ad-modal-bg">
  <div class="modal" style="width: 580px;">
    <h2>🏢 AD 認證測試</h2>
    <div class="body">
      <div class="hint" style="margin-bottom: 14px;">
        對 Active Directory / LDAP 進行 <strong>Simple Bind</strong> 驗證。<br>
        <code>bind_dn</code> 常見格式:<code>user@company.local</code> 或 <code>DOMAIN\\user</code> 或完整 DN。
      </div>
      <div class="row" style="display:flex; gap:10px;">
        <div style="flex:3;">
          <label>Server(DC hostname 或 IP)</label>
          <input id="tad-server" type="text" placeholder="例: dc01.company.local">
        </div>
        <div style="width:100px;">
          <label>Port</label>
          <input id="tad-port" type="number" min="1" max="65535" value="389">
        </div>
      </div>
      <div class="row">
        <label style="display:flex; gap:8px; align-items:center;">
          <input id="tad-ssl" type="checkbox" style="width:16px; height:16px; accent-color: var(--brand);">
          <span>使用 LDAPS(port 自動切 636)</span>
        </label>
      </div>
      <div class="row">
        <label>Bind DN / 使用者</label>
        <input id="tad-binddn" type="text" autocomplete="off" placeholder="user@company.local">
      </div>
      <div class="row">
        <label>密碼</label>
        <input id="tad-password" type="password" autocomplete="off">
      </div>
      <div id="tad-result" style="margin-top: 14px; display:none; padding: 12px 14px; border-radius: 6px; font-size: 13px; line-height: 1.6;"></div>
    </div>
    <div class="actions">
      <span class="spacer" style="flex:1;"></span>
      <button class="btn ghost" type="button" id="tad-close">關閉</button>
      <button class="btn" type="button" id="tad-run">執行測試</button>
    </div>
  </div>
</div>

<!-- ===== 測試工具:Traceroute modal ===== -->
<div class="modal-bg" id="tool-tracert-modal-bg">
  <div class="modal" style="width: 720px;">
    <h2>🗺 Traceroute</h2>
    <div class="body">
      <div class="hint" style="margin-bottom: 14px;">
        列出封包到目的地經過的每一跳路由器。Windows 用 <code>tracert</code>,其他系統用 <code>traceroute</code>。<br>
        完整 30 跳可能需要 1 分鐘以上,請耐心等候。
      </div>
      <div class="row" style="display:flex; gap:10px;">
        <div style="flex:2;">
          <label>目標(hostname 或 IP)</label>
          <input id="ttr-host" type="text" placeholder="例: www.google.com / 172.31.66.221">
        </div>
        <div style="width:120px;">
          <label>最大跳數</label>
          <input id="ttr-hops" type="number" min="1" max="64" value="30">
        </div>
      </div>
      <div id="ttr-status" style="font-size: 12px; color: var(--muted); margin-top: 8px;"></div>
      <pre id="ttr-output" style="display:none; margin-top: 12px; background: #1a1d20; color: #d4d4d4; padding: 14px; border-radius: 6px; font-family: var(--mono); font-size: 12px; line-height: 1.5; max-height: 50vh; overflow: auto; white-space: pre-wrap; word-break: break-all;"></pre>
    </div>
    <div class="actions">
      <span class="spacer" style="flex:1;"></span>
      <button class="btn ghost" type="button" id="ttr-close">關閉</button>
      <button class="btn" type="button" id="ttr-run">執行</button>
    </div>
  </div>
</div>

<!-- RADIUS 設定 modal (admin only) -->
<div class="modal-bg" id="radius-modal-bg">
  <div class="modal">
    <h2>RADIUS 外部認證設定</h2>
    <div class="body">
      <div class="hint" style="margin-bottom: 14px;">
        啟用後,登入頁會出現「認證方式」下拉,使用者可選「外部認證」。<br>
        首次成功登入的使用者會自動建立帳號,角色套用下方「新使用者預設角色」。
      </div>
      <div class="row">
        <label style="display: flex; gap: 8px; align-items: center; cursor: pointer;">
          <input id="rd-enabled" type="checkbox" style="width: 16px; height: 16px; accent-color: var(--brand);">
          <span style="font-weight: 600;">啟用 RADIUS 外部認證</span>
        </label>
      </div>
      <div class="row">
        <label>登入頁顯示名稱</label>
        <input id="rd-display-name" type="text" maxlength="40" placeholder="例: 技術部無線網路認證(留空=外部認證)">
        <div class="hint">登入頁「認證方式」下拉裡這個選項要顯示的文字。</div>
      </div>
      <div class="row" style="display: flex; gap: 10px;">
        <div style="flex: 3;">
          <label>Server (IP 或 hostname)</label>
          <input id="rd-server" type="text" placeholder="例: 192.168.1.100">
        </div>
        <div style="width: 110px;">
          <label>Port</label>
          <input id="rd-port" type="number" min="1" max="65535" placeholder="1812">
        </div>
      </div>
      <div class="row">
        <label>Shared Secret</label>
        <div class="token-wrap">
          <input id="rd-secret" type="password" placeholder="shared secret">
          <button type="button" id="rd-secret-toggle" title="顯示/隱藏">👁</button>
        </div>
      </div>
      <div class="row" style="display: flex; gap: 10px;">
        <div style="width: 140px;">
          <label>Timeout(秒)</label>
          <input id="rd-timeout" type="number" min="1" max="60" placeholder="5">
        </div>
        <div style="flex: 1;">
          <label>新使用者預設角色</label>
          <select id="rd-default-role" style="width: 100%; padding: 9px 12px; border: 1px solid var(--border); border-radius: 6px; font-size: 14px; background: #fff; font-family: inherit;">
            <option value="readonly">readonly(唯讀)</option>
            <option value="admin">admin(管理員)</option>
          </select>
        </div>
      </div>
    </div>
    <div class="actions">
      <button class="btn ghost" type="button" id="rd-test">測試連線</button>
      <button class="btn ghost" type="button" id="rd-cancel">取消</button>
      <button class="btn" type="button" id="rd-save">儲存</button>
    </div>
  </div>
</div>

<!-- 延遲門檻 modal (admin only) -->
<div class="modal-bg" id="lat-modal-bg">
  <div class="modal" style="width: 680px;">
    <h2>延遲門檻</h2>
    <div class="body">
      <div class="hint" style="margin-bottom: 14px;">
        三個門檻依序是 <strong>快(🟢) / 正常(🟣) / 慢(🟡)</strong> 的**上限**(ms)。<br>
        超過最後一個 = <strong>異常(🔴)</strong>。數值必須遞增 <code>fast &lt; ok &lt; slow</code>。<br>
        只影響卡片徽章顏色,<strong>不影響告警判定</strong>。
      </div>
      <table style="width:100%; border-collapse: collapse; font-size: 13px;">
        <thead>
          <tr style="border-bottom: 1px solid var(--border);">
            <th style="padding: 8px; text-align: left; color: var(--muted); font-weight: 600;">類型</th>
            <th style="padding: 8px; text-align: center; color: var(--muted); font-weight: 600;">快 &lt; (ms)</th>
            <th style="padding: 8px; text-align: center; color: var(--muted); font-weight: 600;">正常 &lt; (ms)</th>
            <th style="padding: 8px; text-align: center; color: var(--muted); font-weight: 600;">慢 &lt; (ms)</th>
            <th style="padding: 8px; text-align: center; color: var(--muted); font-weight: 600;">預設</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td style="padding: 10px 8px;"><span class="type-tag tcp">TCP</span></td>
            <td><input id="lat-tcp-1" type="number" min="1" style="width:100%; padding:6px 8px; border:1px solid var(--border); border-radius:4px;"></td>
            <td><input id="lat-tcp-2" type="number" min="1" style="width:100%; padding:6px 8px; border:1px solid var(--border); border-radius:4px;"></td>
            <td><input id="lat-tcp-3" type="number" min="1" style="width:100%; padding:6px 8px; border:1px solid var(--border); border-radius:4px;"></td>
            <td style="text-align:center; color: var(--muted); font-size: 12px;"><span id="lat-tcp-default"></span></td>
          </tr>
          <tr>
            <td style="padding: 10px 8px;"><span class="type-tag icmp">ICMP</span></td>
            <td><input id="lat-icmp-1" type="number" min="1" style="width:100%; padding:6px 8px; border:1px solid var(--border); border-radius:4px;"></td>
            <td><input id="lat-icmp-2" type="number" min="1" style="width:100%; padding:6px 8px; border:1px solid var(--border); border-radius:4px;"></td>
            <td><input id="lat-icmp-3" type="number" min="1" style="width:100%; padding:6px 8px; border:1px solid var(--border); border-radius:4px;"></td>
            <td style="text-align:center; color: var(--muted); font-size: 12px;"><span id="lat-icmp-default"></span></td>
          </tr>
          <tr>
            <td style="padding: 10px 8px;"><span class="type-tag http">HTTP</span></td>
            <td><input id="lat-http-1" type="number" min="1" style="width:100%; padding:6px 8px; border:1px solid var(--border); border-radius:4px;"></td>
            <td><input id="lat-http-2" type="number" min="1" style="width:100%; padding:6px 8px; border:1px solid var(--border); border-radius:4px;"></td>
            <td><input id="lat-http-3" type="number" min="1" style="width:100%; padding:6px 8px; border:1px solid var(--border); border-radius:4px;"></td>
            <td style="text-align:center; color: var(--muted); font-size: 12px;"><span id="lat-http-default"></span></td>
          </tr>
          <tr>
            <td style="padding: 10px 8px;"><span class="type-tag dns">DNS</span></td>
            <td><input id="lat-dns-1" type="number" min="1" style="width:100%; padding:6px 8px; border:1px solid var(--border); border-radius:4px;"></td>
            <td><input id="lat-dns-2" type="number" min="1" style="width:100%; padding:6px 8px; border:1px solid var(--border); border-radius:4px;"></td>
            <td><input id="lat-dns-3" type="number" min="1" style="width:100%; padding:6px 8px; border:1px solid var(--border); border-radius:4px;"></td>
            <td style="text-align:center; color: var(--muted); font-size: 12px;"><span id="lat-dns-default"></span></td>
          </tr>
        </tbody>
      </table>
      <div class="hint" style="margin-top: 14px; padding: 10px 12px; background: var(--brand-soft); border-radius: 6px;">
        💡 儲存後**立刻生效**,下一次卡片刷新(3 秒內)就會套新門檻。
      </div>
    </div>
    <div class="actions">
      <button class="btn ghost" type="button" id="lat-reset">回到預設</button>
      <span class="spacer" style="flex: 1;"></span>
      <button class="btn ghost" type="button" id="lat-cancel">取消</button>
      <button class="btn" type="button" id="lat-save">儲存</button>
    </div>
  </div>
</div>

<!-- 事件紀錄設定 modal (admin only) -->
<div class="modal-bg" id="evc-modal-bg">
  <div class="modal" style="width: 520px;">
    <h2>事件紀錄設定</h2>
    <div class="body">
      <div class="hint" style="margin-bottom: 14px;">
        決定哪些檢查結果會寫入 <code>monitor_events.jsonl</code>。<br>
        <strong>狀態變化(DOWN 告警 / UP 恢復 / 首次上線)永遠會被紀錄</strong>,這兩個開關影響的是「持續紀錄」。
      </div>

      <label style="display: flex; gap: 10px; align-items: flex-start; padding: 12px; border: 1px solid var(--border); border-radius: 6px; margin-bottom: 10px; cursor: pointer;">
        <input id="evc-fail" type="checkbox" style="width: 18px; height: 18px; margin-top: 2px; accent-color: var(--brand);">
        <div>
          <div style="font-weight: 600; color: var(--text);">每次失敗(DOWN)都記錄</div>
          <div style="font-size: 12px; color: var(--muted); margin-top: 2px; line-height: 1.6;">
            即使還沒達到告警門檻,每次 check 失敗都寫入一筆事件,帶 <code>consecutive_failures</code>。<br>
            <strong style="color: var(--success);">推薦開啟</strong> — 可精確追溯抖動時間。
          </div>
        </div>
      </label>

      <label style="display: flex; gap: 10px; align-items: flex-start; padding: 12px; border: 1px solid var(--border); border-radius: 6px; cursor: pointer;">
        <input id="evc-success" type="checkbox" style="width: 18px; height: 18px; margin-top: 2px; accent-color: var(--brand);">
        <div>
          <div style="font-weight: 600; color: var(--text);">每次成功(UP)都記錄</div>
          <div style="font-size: 12px; color: var(--muted); margin-top: 2px; line-height: 1.6;">
            每次 check 成功就寫入一筆事件,包含延遲數值。<br>
            <strong style="color: var(--danger);">⚠ 會讓事件檔快速變大</strong> —
            1 個 check × 30s 間隔 × 1 天 ≈ 2880 筆;多 check 會倍增。<br>
            只在需要完整歷史(如稽核、績效分析)時啟用。
          </div>
        </div>
      </label>

      <div class="hint" style="margin-top: 12px; padding: 10px 12px; background: var(--brand-soft); border-radius: 6px;">
        💡 兩個都關 → 只記錄狀態變化(最乾淨,預設建議)<br>
        💡 設定變更即時生效,不需重啟
      </div>
    </div>
    <div class="actions">
      <button class="btn ghost" type="button" id="evc-cancel">取消</button>
      <button class="btn" type="button" id="evc-save">儲存</button>
    </div>
  </div>
</div>

<!-- 清空監控狀態 modal (admin only) -->
<div class="modal-bg" id="reset-modal-bg">
  <div class="modal" style="width: 460px;">
    <h2 style="color: var(--danger);">⚠ 清空監控狀態</h2>
    <div class="body">
      <div style="font-size: 14px; color: var(--text-sub); line-height: 1.6;">
        此動作會將 <code>state.json</code> 內所有檢查的<strong>連續成功/失敗計數、延遲紀錄、DOWN 時間</strong>歸零。
      </div>
      <ul style="font-size: 13px; color: var(--muted); margin: 12px 0; padding-left: 22px; line-height: 1.8;">
        <li><strong>不會</strong>刪除任何監控目標(<code>config.yaml</code> 的 targets 保留)</li>
        <li><strong>不會</strong>清空監控事件紀錄(<code>monitor_events.jsonl</code>)</li>
        <li>下一輪檢查會立即重新建立狀態</li>
      </ul>
      <div style="font-size: 13px; color: var(--danger); padding: 10px 12px; background: var(--danger-soft); border-radius: 6px;">
        ⚠ 無法還原
      </div>
    </div>
    <div class="actions">
      <button class="btn ghost" type="button" id="rs-cancel">取消</button>
      <button class="btn" type="button" id="rs-submit" style="background: var(--danger); border-color: var(--danger);">確定清空</button>
    </div>
  </div>
</div>

<!-- 監控事件 modal -->
<div class="modal-bg" id="events-modal-bg">
  <div class="modal" style="width: 960px;">
    <h2 style="display: flex; align-items: center; gap: 10px;">
      監控事件
      <span id="ev-count" style="font-size: 13px; font-weight: normal; color: var(--muted);"></span>
      <span class="spacer" style="flex: 1;"></span>
      <span id="ev-last" style="font-size: 11px; color: var(--text-faint);"></span>
      <label style="font-size: 12px; color: var(--muted); display: flex; align-items: center; gap: 4px; cursor: pointer;">
        <input type="checkbox" id="ev-auto" checked style="margin: 0; accent-color: var(--brand);"> 自動刷新
      </label>
      <button id="ev-reload" class="btn ghost" style="font-size: 12px; padding: 5px 12px;">⟳ 重新載入</button>
      <button id="ev-export" class="btn ghost" style="font-size: 12px; padding: 5px 12px;">⬇ 匯出 CSV</button>
      <button id="ev-clear" class="btn ghost" style="font-size: 12px; padding: 5px 12px; color: var(--danger); border-color: var(--border);">清空紀錄</button>
    </h2>
    <div class="body" style="padding: 12px 22px 0;">
      <div style="display: flex; gap: 8px; margin-bottom: 10px; align-items: center;">
        <input id="ev-search" type="search" placeholder="🔍 搜尋:目標名稱、位址、錯誤訊息..." style="flex: 1; padding: 8px 12px; border: 1px solid var(--border); border-radius: 6px; font-size: 14px; font-family: inherit;">
        <select id="ev-filter-type" style="padding: 8px 12px; border: 1px solid var(--border); border-radius: 6px; font-size: 14px; background: #fff; font-family: inherit;">
          <option value="">全部類型</option>
          <option value="tcp">TCP</option>
          <option value="icmp">ICMP</option>
          <option value="http">HTTP</option>
          <option value="dns">DNS</option>
        </select>
        <select id="ev-filter-event" style="padding: 8px 12px; border: 1px solid var(--border); border-radius: 6px; font-size: 14px; background: #fff; font-family: inherit;">
          <option value="">全部事件</option>
          <option value="down">🔴 DOWN</option>
          <option value="up:recovery">✅ UP 恢復</option>
          <option value="up:ok">🟢 UP (連續成功)</option>
          <option value="first_up">🟢 首次上線</option>
        </select>
      </div>
      <div style="overflow: auto; max-height: 55vh; border-top: 1px solid var(--border);">
        <table class="history-table">
          <thead>
            <tr>
              <th style="width: 110px">事件</th>
              <th style="width: 150px">時間</th>
              <th>目標</th>
              <th style="width: 60px">類型</th>
              <th>位址</th>
              <th>詳細</th>
            </tr>
          </thead>
          <tbody id="events-tbody"></tbody>
        </table>
      </div>
    </div>
    <div class="actions">
      <button class="btn ghost" type="button" id="ev-close">關閉</button>
    </div>
  </div>
</div>

<!-- 個別檢查設定覆寫 modal (admin only) -->
<div class="modal-bg" id="cks-modal-bg">
  <div class="modal" style="width: 560px;">
    <h2 id="cks-title">檢查設定覆寫</h2>
    <div class="body">
      <div class="hint" style="margin-bottom: 14px;">
        留空即<strong>沿用全域預設</strong>。下方括號內是目前的全域值,供對照。
      </div>
      <div class="row" style="display: flex; gap: 10px; align-items: center;">
        <label style="flex: 1;">
          檢查間隔(秒)
          <input id="cks-interval" type="number" min="1" placeholder="留空=繼承">
        </label>
        <span id="cks-g-interval" style="font-size: 12px; color: var(--muted); white-space: nowrap; margin-top: 16px;"></span>
      </div>
      <div class="row" style="display: flex; gap: 10px; align-items: center;">
        <label style="flex: 1;">
          連線 / 讀取逾時(秒)
          <input id="cks-timeout" type="number" min="1" step="0.5" placeholder="留空=繼承">
        </label>
        <span id="cks-g-timeout" style="font-size: 12px; color: var(--muted); white-space: nowrap; margin-top: 16px;"></span>
      </div>
      <div class="row" style="display: flex; gap: 10px; align-items: center;">
        <label style="flex: 1;">
          連續失敗門檻(DOWN 告警)
          <input id="cks-fail" type="number" min="1" placeholder="留空=繼承">
        </label>
        <span id="cks-g-fail" style="font-size: 12px; color: var(--muted); white-space: nowrap; margin-top: 16px;"></span>
      </div>
      <div class="row" style="display: flex; gap: 10px; align-items: center;">
        <label style="flex: 1;">
          連續成功門檻(UP 恢復)
          <input id="cks-recover" type="number" min="1" placeholder="留空=繼承">
        </label>
        <span id="cks-g-recover" style="font-size: 12px; color: var(--muted); white-space: nowrap; margin-top: 16px;"></span>
      </div>
      <div class="row" style="display: flex; gap: 10px; align-items: center;">
        <label style="flex: 1;">
          DOWN 期間提醒頻率(分鐘,0 = 關)
          <input id="cks-reminder" type="number" min="0" placeholder="留空=繼承">
        </label>
        <span id="cks-g-reminder" style="font-size: 12px; color: var(--muted); white-space: nowrap; margin-top: 16px;"></span>
      </div>
      <div class="hint" style="margin-top: 14px; padding: 10px 12px; background: var(--brand-soft); border-radius: 6px;">
        💡 <strong>檢查間隔</strong>下限 1 秒,可比全域(<span id="cks-g-interval-inline">-</span>)更快或更慢,主迴圈會自動依最短間隔為節奏。<br>
        💡 <strong>提醒頻率 0</strong> = 服務 DOWN 期間不重複提醒。<br>
        ⚠ 多個 check 同時用很短的間隔時,實際頻率會被單輪的總執行時間限制。
      </div>
    </div>
    <div class="actions">
      <button class="btn ghost" type="button" id="cks-clear">全部清除(沿用全域)</button>
      <span class="spacer" style="flex: 1;"></span>
      <button class="btn ghost" type="button" id="cks-cancel">取消</button>
      <button class="btn" type="button" id="cks-save">儲存</button>
    </div>
  </div>
</div>

<!-- 新增檢查 modal -->
<div class="modal-bg" id="check-modal-bg">
  <div class="modal">
    <h2 id="ck-modal-title">新增檢查</h2>
    <div class="body">
      <div class="row">
        <label>檢查類型</label>
        <select id="ck-type" style="width:100%; padding:9px 12px; border:1px solid var(--border); border-radius:6px; font-size:14px; background:#fff;">
          <option value="tcp">TCP — socket 連線</option>
          <option value="icmp">ICMP — ping 主機可達性</option>
          <option value="http">HTTP GET — 請求並檢查回應</option>
          <option value="dns">DNS — 網域名稱解析</option>
        </select>
      </div>
      <div class="row" data-ck-for="tcp,icmp">
        <label>Host 或 IP</label>
        <input id="ck-host" type="text" placeholder="例: 172.31.66.221 或 example.com">
      </div>
      <div class="row" data-ck-for="tcp">
        <label>Port</label>
        <input id="ck-port" type="number" min="1" max="65535" placeholder="例: 80、443、6218">
      </div>
      <div class="row" data-ck-for="http">
        <label>URL</label>
        <input id="ck-url" type="text" placeholder="https://example.com/health">
      </div>
      <div class="row" data-ck-for="http">
        <label>預期狀態碼(選填,空白 = 接受 2xx/3xx)</label>
        <input id="ck-expect" type="number" min="100" max="599" placeholder="例: 200">
      </div>
      <div class="row" data-ck-for="http">
        <label style="display:flex; align-items:center; gap:6px; cursor:pointer;">
          <input id="ck-verify-ssl" type="checkbox" checked style="width:16px; height:16px; accent-color: var(--brand);">
          <span>驗證 SSL 憑證</span>
        </label>
        <div class="hint">使用系統憑證庫(含 TWCA 等區域 CA)。若仍失敗可取消勾選。</div>
      </div>
      <div class="row" data-ck-for="dns">
        <label>要查的網域(hostname)</label>
        <input id="ck-hostname" type="text" placeholder="例: www.google.com / company.local">
      </div>
      <div class="row" data-ck-for="dns" style="display:flex; gap:10px;">
        <div style="width:140px;">
          <label>記錄類型</label>
          <select id="ck-record-type" style="width:100%; padding:9px 12px; border:1px solid var(--border); border-radius:6px; font-size:14px; background:#fff;">
            <option value="A">A (IPv4)</option>
            <option value="AAAA">AAAA (IPv6)</option>
            <option value="CNAME">CNAME</option>
            <option value="MX">MX</option>
            <option value="TXT">TXT</option>
            <option value="NS">NS</option>
          </select>
        </div>
        <div style="flex:1;">
          <label>DNS 伺服器(選填,空=系統預設)</label>
          <input id="ck-dns-server" type="text" placeholder="例: 8.8.8.8 / 192.168.1.1">
        </div>
      </div>
      <div class="row" data-ck-for="dns">
        <label>期望 IP(選填,僅 A / AAAA)</label>
        <input id="ck-expect-ip" type="text" placeholder="例: 172.31.66.221">
        <div class="hint">填了就會驗證:回應中必須包含這個 IP 才算 OK</div>
      </div>
    </div>
    <div class="actions">
      <button class="btn ghost" type="button" id="ck-cancel">取消</button>
      <button class="btn" type="button" id="ck-submit">新增檢查</button>
    </div>
  </div>
</div>

<div class="modal-bg" id="modal-bg">
  <div class="modal">
    <h2>Telegram 通道設定</h2>
    <div class="body">
      <div class="hint" style="margin-bottom:14px">每個通道可獨立啟用/停用。告警觸發時會同時廣播到所有啟用的通道。</div>
      <div id="channels-list"></div>
      <button class="add-ch-btn" type="button" id="f-add">+ 新增通道</button>
    </div>
    <div class="actions">
      <button class="btn secondary" id="f-test-all">儲存並測試全部</button>
      <button class="btn ghost" type="button" id="f-cancel">取消</button>
      <button class="btn" id="f-save">儲存</button>
    </div>
  </div>
</div>

</div><!-- /#app-view -->
<div class="toast" id="toast"></div>

<script>
function esc(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g, c => ({
    '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'
  })[c]);
}

function fmtDuration(sec) {
  sec = Math.floor(sec);
  if (sec < 60) return sec + ' 秒';
  const m = Math.floor(sec / 60), s = sec % 60;
  if (m < 60) return m + ' 分 ' + s + ' 秒';
  const h = Math.floor(m / 60), mm = m % 60;
  if (h < 24) return h + ' 小時 ' + mm + ' 分';
  const d = Math.floor(h / 24), hh = h % 24;
  return d + ' 天 ' + hh + ' 小時';
}

function toast(msg, isErr) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.className = 'toast show' + (isErr ? ' err' : '');
  clearTimeout(t._timer);
  t._timer = setTimeout(() => t.className = 'toast', 2800);
}

function typeOf(c) { return (c.type || 'tcp').toLowerCase(); }

function checkKey(targetName, c) {
  const tp = typeOf(c);
  if (tp === 'icmp') return targetName + '::icmp:' + (c.host || '');
  if (tp === 'http') return targetName + '::http:' + (c.url || '');
  if (tp === 'dns') {
    return targetName + '::dns:' + (c.hostname || '') + '/' +
           (c.record_type || 'A') +
           (c.dns_server ? '@' + c.dns_server : '');
  }
  return targetName + '::tcp:' + (c.host || '') + ':' + (c.port || '');
}

function addrOf(c) {
  const tp = typeOf(c);
  if (tp === 'icmp') return c.host || '?';
  if (tp === 'http') return c.url || '?';
  if (tp === 'dns') {
    return (c.hostname || '?') + ' [' + (c.record_type || 'A') + ']' +
           (c.dns_server ? ' @ ' + c.dns_server : '');
  }
  return (c.host || '?') + ':' + (c.port || '?');
}

async function refresh() {
  try {
    const r = await fetch('/api/state', { cache: 'no-store' });
    if (r.status === 401) { showLoginView(); return; }
    if (!r.ok) throw new Error('HTTP ' + r.status);
    render(await r.json());
  } catch (e) {
    console.error(e);
    document.getElementById('updated').textContent = '讀取失敗';
  }
}

// 依檢查類型分別的延遲門檻(ms):[fast <, ok <, slow <, 其餘=bad]
// 實際值由 /api/state 推送來(管理中心可調);伺服器下不來時用這份當 fallback
let LATENCY_THRESHOLDS = {
  tcp:  [50, 200, 500],
  icmp: [50, 200, 500],
  http: [500, 1500, 3500],
  dns:  [50, 150, 500],
};

function renderCheckRow(targetName, c, s) {
  const isPaused = c.enabled === false;
  const rawStatus = (s && s.status) || 'unknown';
  // UI 狀態:暫停時一律顯示 paused,不看上次 status
  const displayStatus = isPaused ? 'paused' : rawStatus;
  const statusTxt = { up: '正常', down: '異常', unknown: '未知', paused: '已暫停' }[displayStatus] || displayStatus;
  const tp = typeOf(c);
  const typeTxt = { tcp: 'TCP', icmp: 'ICMP', http: 'HTTP', dns: 'DNS' }[tp] || tp.toUpperCase();

  let latencyHtml;
  if (isPaused || rawStatus === 'down' || !s || s.last_latency_ms == null) {
    latencyHtml = '<span class="latency none">—</span>';
  } else {
    const ms = s.last_latency_ms;
    const [t1, t2, t3] = LATENCY_THRESHOLDS[tp] || LATENCY_THRESHOLDS.tcp;
    let cls = 'fast';
    if (ms >= t3) cls = 'bad';
    else if (ms >= t2) cls = 'slow';
    else if (ms >= t1) cls = 'ok';
    latencyHtml = '<span class="latency ' + cls + '" title="' + tp.toUpperCase() + ' 門檻: <' + t1 + '/' + t2 + '/' + t3 + 'ms">' + ms.toFixed(1) + ' ms</span>';
  }

  let lastCheckTxt = '—';
  if (s && s.last_check) {
    const dt = new Date(s.last_check);
    if (!isNaN(dt)) lastCheckTxt = dt.toLocaleTimeString();
  }

  let extra = '';
  if (!isPaused && s && rawStatus === 'down' && s.down_since) {
    const secs = (Date.now() - new Date(s.down_since).getTime()) / 1000;
    if (secs >= 0) extra += '<div><span class="k">中斷:</span> ' + esc(fmtDuration(secs)) + '</div>';
  }
  if (!isPaused && s && s.last_error) extra += '<div class="err">' + esc(s.last_error) + '</div>';

  const key = checkKey(targetName, c);
  let ckSuffix = '';
  if (tp === 'http') {
    if (c.expect_status) ckSuffix += ' · 預期 ' + c.expect_status;
    if (c.verify_ssl === false) ckSuffix += ' · 不驗證 SSL';
  }

  const toggleLabel = isPaused ? '▶ 啟用' : '⏸ 暫停';
  const toggleTitle = isPaused ? '啟用此檢查' : '暫停此檢查(保留設定,不跑檢查、不發告警)';
  // 若有任何覆寫,⚙ 顯示紫色粗體
  const overrideFields = ['check_interval_seconds','tcp_timeout_seconds','failure_threshold','recovery_threshold','reminder_interval_minutes'];
  const hasOverride = overrideFields.some(f => c[f] != null);

  return (
    '<div class="check-row ' + displayStatus + (isPaused ? ' paused' : '') + '">' +
      '<div class="check-head">' +
        '<span class="type-tag ' + tp + '">' + esc(typeTxt) + '</span>' +
        '<span class="badge ' + displayStatus + '">' + esc(statusTxt) + '</span>' +
        '<span class="spacer"></span>' +
        '<button class="toggle-ck" title="' + esc(toggleTitle) + '" data-ck="' + esc(key) + '" data-name="' + esc(targetName) + '" data-enabled="' + (isPaused ? '0' : '1') + '">' + toggleLabel + '</button>' +
        '<button class="settings-ck' + (hasOverride ? ' has-override' : '') + '" title="個別設定覆寫" data-ck="' + esc(key) + '" data-name="' + esc(targetName) + '">⚙</button>' +
        '<button class="remove-ck" title="移除此檢查" data-ck="' + esc(key) + '" data-name="' + esc(targetName) + '">×</button>' +
      '</div>' +
      '<div class="addr">' + esc(addrOf(c)) + esc(ckSuffix) + '</div>' +
      '<div class="check-meta">' +
        '<div><span class="k">延遲:</span> ' + latencyHtml + ' &nbsp;<span class="k">最後檢查:</span> ' + esc(lastCheckTxt) + '</div>' +
        '<div><span class="k">連續成功:</span> ' + ((s && s.consecutive_successes) || 0) + ' · <span class="k">連續失敗:</span> ' + ((s && s.consecutive_failures) || 0) + '</div>' +
        extra +
      '</div>' +
    '</div>'
  );
}

function render(data) {
  const { targets, state } = data;
  // 若 server 回傳了新的門檻,動態採用
  if (data.latency_thresholds) LATENCY_THRESHOLDS = data.latency_thresholds;
  const grid = document.getElementById('grid');
  grid.innerHTML = '';

  // 填入名稱 autocomplete
  const dl = document.getElementById('existing-names');
  if (dl) dl.innerHTML = targets.map(t => '<option value="' + esc(t.name) + '">').join('');

  if (targets.length === 0) {
    grid.innerHTML = '<div class="empty"><strong>尚無監控目標</strong>請在上方輸入目標名稱後點「+ 新增監控目標」,再到卡片中加入檢查項目。</div>';
  }

  // stats:rollup 只看「啟用中」的 check;全部被暫停的 target 算 paused
  const stats = { total: targets.length, up: 0, down: 0, unknown: 0, paused: 0,
                  checks: 0, cDown: 0, cPaused: 0 };

  for (const t of targets) {
    const checksHtml = [];
    let anyDown = false, activeCount = 0, allUp = true;

    for (const c of t.checks) {
      stats.checks++;
      const s = state[checkKey(t.name, c)];
      if (c.enabled === false) {
        stats.cPaused++;
      } else {
        activeCount++;
        const st = (s && s.status) || 'unknown';
        if (st === 'down') { anyDown = true; allUp = false; stats.cDown++; }
        else if (st !== 'up') { allUp = false; }
      }
      checksHtml.push(renderCheckRow(t.name, c, s));
    }

    // 目標狀態判斷:空 target → unknown;有啟用的且都 up → up;任一 down → down
    let tStatus;
    if (t.checks.length === 0) {
      tStatus = 'unknown';
    } else if (activeCount === 0) {
      tStatus = 'paused';
    } else if (anyDown) {
      tStatus = 'down';
    } else if (allUp) {
      tStatus = 'up';
    } else {
      tStatus = 'unknown';
    }
    stats[tStatus]++;

    const tStatusTxt = { up: '正常', down: '異常', unknown: t.checks.length === 0 ? '尚未設檢查' : '未知', paused: '全部暫停' }[tStatus];
    const enabledCnt = t.checks.length - (t.checks.filter(c => c.enabled === false).length);
    let countsTxt;
    if (t.checks.length === 0) countsTxt = '0 項檢查';
    else if (enabledCnt === t.checks.length) countsTxt = t.checks.length + ' 項檢查';
    else countsTxt = enabledCnt + ' / ' + t.checks.length + ' 啟用';

    // 卡片內容 — 有 check 就 render,沒有就顯示空提示
    const body = t.checks.length === 0
      ? '<div class="card-empty">尚未設定檢查項目,請點下方按鈕新增。</div>'
      : checksHtml.join('');

    const addBtn =
      '<div class="card-foot">' +
        '<button class="add-check-btn-small" data-target="' + esc(t.name) + '">+ 新增檢查</button>' +
      '</div>';

    const card = document.createElement('div');
    card.className = 'card ' + tStatus;
    card.setAttribute('draggable', 'true');
    card.setAttribute('data-name', t.name);
    card.innerHTML =
      '<span class="drag-handle" title="拖曳調整順序">⋮⋮</span>' +
      '<button class="remove" title="移除整個目標(含所有檢查)" data-name="' + esc(t.name) + '">×</button>' +
      '<h3>' + esc(t.name) +
        '<span class="badge ' + tStatus + '">' + esc(tStatusTxt) + '</span>' +
        '<span class="counts">' + countsTxt + '</span>' +
      '</h3>' +
      body +
      addBtn;
    grid.appendChild(card);
  }

  document.getElementById('stat-total').textContent = stats.total;
  document.getElementById('stat-up').textContent = stats.up;
  document.getElementById('stat-down').textContent = stats.down;
  document.getElementById('stat-unknown').textContent = stats.unknown + (stats.paused ? ' (' + stats.paused + ' 暫停)' : '');
  document.getElementById('updated').textContent = new Date().toLocaleTimeString() +
    ' · ' + stats.checks + ' 項檢查' +
    (stats.cDown ? ' (' + stats.cDown + ' 異常' + (stats.cPaused ? ', ' + stats.cPaused + ' 暫停' : '') + ')' :
     (stats.cPaused ? ' (' + stats.cPaused + ' 暫停)' : ''));
}

// ----- 頂部表單:type-aware 欄位顯示 + 快速新增 / 建立空目標 -----
function syncAddFormFields() {
  const tp = document.getElementById('f-type').value;
  document.querySelectorAll('#add-form [data-for]').forEach(el => {
    const show = el.getAttribute('data-for').split(',').includes(tp);
    el.classList.toggle('hidden', !show);
  });
}
document.getElementById('f-type').addEventListener('change', syncAddFormFields);
syncAddFormFields();

document.getElementById('add-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  const name = (fd.get('name') || '').trim();
  if (!name) return;
  const tp = fd.get('type');

  // 判斷是否有填入檢查欄位
  let payload = { name };
  let hasCheck = false;

  if (tp === 'tcp') {
    const host = (fd.get('host') || '').trim();
    const port = (fd.get('port') || '').trim();
    if (host || port) {
      if (!host) { toast('Host 不可為空', true); return; }
      if (!port) { toast('Port 不可為空', true); return; }
      const p = parseInt(port, 10);
      if (!p || p < 1 || p > 65535) { toast('Port 須介於 1-65535', true); return; }
      payload = { name, type: 'tcp', host, port: p };
      hasCheck = true;
    }
  } else if (tp === 'icmp') {
    const host = (fd.get('host') || '').trim();
    if (host) {
      payload = { name, type: 'icmp', host };
      hasCheck = true;
    }
  } else if (tp === 'http') {
    const url = (fd.get('url') || '').trim();
    if (url) {
      payload = { name, type: 'http', url };
      const es = (fd.get('expect_status') || '').trim();
      if (es) payload.expect_status = parseInt(es, 10);
      payload.verify_ssl = document.querySelector('#add-form input[name="verify_ssl"]').checked;
      hasCheck = true;
    }
  } else if (tp === 'dns') {
    const hostname = (fd.get('hostname') || '').trim();
    if (hostname) {
      payload = { name, type: 'dns', hostname };
      const rtype = (fd.get('record_type') || 'A').trim();
      if (rtype && rtype !== 'A') payload.record_type = rtype;
      const dnsSrv = (fd.get('dns_server') || '').trim();
      if (dnsSrv) payload.dns_server = dnsSrv;
      hasCheck = true;
    }
  }

  try {
    const r = await fetch('/api/targets', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    const data = await r.json();
    if (r.ok) {
      toast(hasCheck ? '目標與檢查已新增,即將執行檢查' : '空目標「' + name + '」已建立 · 點卡片中「+ 新增檢查」加入項目');
      e.target.reset();
      syncAddFormFields();
      refresh();
    } else {
      toast(data.error || '新增失敗', true);
    }
  } catch (err) {
    toast('網路錯誤', true);
  }
});

// ----- 新增檢查 Modal -----
const ckModal = document.getElementById('check-modal-bg');
let ckTargetName = null;   // 目前開著 modal 的目標名

function syncCheckModalFields() {
  const tp = document.getElementById('ck-type').value;
  document.querySelectorAll('#check-modal-bg [data-ck-for]').forEach(el => {
    const show = el.getAttribute('data-ck-for').split(',').includes(tp);
    el.classList.toggle('hidden', !show);
  });
}
document.getElementById('ck-type').addEventListener('change', syncCheckModalFields);

function openCheckModal(targetName) {
  ckTargetName = targetName;
  document.getElementById('ck-modal-title').textContent = '新增檢查 — ' + targetName;
  document.getElementById('ck-type').value = 'tcp';
  document.getElementById('ck-host').value = '';
  document.getElementById('ck-port').value = '';
  document.getElementById('ck-url').value = '';
  document.getElementById('ck-expect').value = '';
  document.getElementById('ck-verify-ssl').checked = true;
  document.getElementById('ck-hostname').value = '';
  document.getElementById('ck-record-type').value = 'A';
  document.getElementById('ck-dns-server').value = '';
  document.getElementById('ck-expect-ip').value = '';
  syncCheckModalFields();
  ckModal.classList.add('show');
  setTimeout(() => document.getElementById('ck-host').focus(), 50);
}
function closeCheckModal() { ckModal.classList.remove('show'); ckTargetName = null; }

async function submitCheck() {
  if (!ckTargetName) return;
  const tp = document.getElementById('ck-type').value;
  const payload = { name: ckTargetName, type: tp };

  if (tp === 'tcp') {
    payload.host = document.getElementById('ck-host').value.trim();
    const port = parseInt(document.getElementById('ck-port').value, 10);
    if (!payload.host) { toast('Host 不可為空', true); return; }
    if (!port || port < 1 || port > 65535) { toast('Port 須介於 1-65535', true); return; }
    payload.port = port;
  } else if (tp === 'icmp') {
    payload.host = document.getElementById('ck-host').value.trim();
    if (!payload.host) { toast('Host 不可為空', true); return; }
  } else if (tp === 'http') {
    payload.url = document.getElementById('ck-url').value.trim();
    if (!payload.url) { toast('URL 不可為空', true); return; }
    const es = document.getElementById('ck-expect').value.trim();
    if (es) payload.expect_status = parseInt(es, 10);
    payload.verify_ssl = document.getElementById('ck-verify-ssl').checked;
  } else if (tp === 'dns') {
    payload.hostname = document.getElementById('ck-hostname').value.trim();
    if (!payload.hostname) { toast('Hostname 不可為空', true); return; }
    const rtype = document.getElementById('ck-record-type').value;
    if (rtype && rtype !== 'A') payload.record_type = rtype;
    const dnsSrv = document.getElementById('ck-dns-server').value.trim();
    if (dnsSrv) payload.dns_server = dnsSrv;
    const expIp = document.getElementById('ck-expect-ip').value.trim();
    if (expIp) payload.expect_ip = expIp;
  }

  try {
    const r = await fetch('/api/targets', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    const data = await r.json();
    if (r.ok) {
      toast('檢查已新增,下一輪執行');
      closeCheckModal();
      refresh();
    } else {
      toast(data.error || '新增失敗', true);
    }
  } catch (err) {
    toast('網路錯誤', true);
  }
}

document.getElementById('ck-cancel').addEventListener('click', closeCheckModal);
document.getElementById('ck-submit').addEventListener('click', submitCheck);
ckModal.addEventListener('click', (e) => { if (e.target === ckModal) closeCheckModal(); });
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape' && ckModal.classList.contains('show')) closeCheckModal();
});

document.getElementById('grid').addEventListener('click', async (e) => {
  // 新增檢查 → 開 modal
  const btnAdd = e.target.closest('.add-check-btn-small');
  if (btnAdd) {
    openCheckModal(btnAdd.dataset.target);
    return;
  }

  // 個別檢查設定覆寫 (⚙)
  const btnCks = e.target.closest('.settings-ck');
  if (btnCks) {
    openCheckSettingsModal(btnCks.dataset.name, btnCks.dataset.ck);
    return;
  }

  // 暫停 / 啟用 單一檢查
  const btnToggle = e.target.closest('.toggle-ck');
  if (btnToggle) {
    const name = btnToggle.dataset.name;
    const ckKey = btnToggle.dataset.ck;
    const curEnabled = btnToggle.dataset.enabled === '1';
    const newEnabled = !curEnabled;
    try {
      const r = await fetch('/api/targets', {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, check_key: ckKey, enabled: newEnabled }),
      });
      const data = await r.json();
      if (r.ok) { toast(newEnabled ? '已啟用' : '已暫停'); refresh(); }
      else { toast(data.error || '切換失敗', true); }
    } catch (err) {
      toast('網路錯誤', true);
    }
    return;
  }

  // 移除整個目標(卡片右上角 ×)
  const btnAll = e.target.closest('.remove');
  // 移除單一檢查(check row 右邊 ×)
  const btnOne = e.target.closest('.remove-ck');
  if (!btnAll && !btnOne) return;

  const name = (btnAll || btnOne).dataset.name;
  let payload, prompt;
  if (btnOne) {
    payload = { name, check_key: btnOne.dataset.ck };
    prompt = '確定要移除這個檢查?';
  } else {
    payload = { name };
    prompt = '確定要移除整個目標「' + name + '」? (含所有檢查)';
  }
  if (!confirm(prompt)) return;

  try {
    const r = await fetch('/api/targets', {
      method: 'DELETE',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    const data = await r.json();
    if (r.ok) { toast('已移除' + (data.removed ? (' (' + data.removed + ' 項檢查)') : '')); refresh(); }
    else { toast(data.error || '移除失敗', true); }
  } catch (err) {
    toast('網路錯誤', true);
  }
});

// (btn-test 已移至管理中心,由 admin-card [data-action="test"] 觸發)

// ----- Settings Modal (多通道) -----
const modal = document.getElementById('modal-bg');
const chList = document.getElementById('channels-list');

function renderChannel(ch) {
  const row = document.createElement('div');
  row.className = 'channel' + (ch.enabled === false ? ' disabled' : '');
  row.innerHTML =
    '<div class="ch-head">' +
      '<input type="checkbox" class="ch-enabled" title="啟用/停用" ' + (ch.enabled !== false ? 'checked' : '') + '>' +
      '<input type="text" class="ch-name" placeholder="通道名稱 (例: 工作群組)" value="' + esc(ch.name || '') + '">' +
      '<div class="ch-actions">' +
        '<button type="button" class="ch-test" title="測試此通道">測試</button>' +
        '<button type="button" class="ch-remove" title="移除">✕ 移除</button>' +
      '</div>' +
    '</div>' +
    '<div class="row">' +
      '<label>Bot Token</label>' +
      '<div class="token-wrap">' +
        '<input type="password" class="ch-token" placeholder="123456789:AAE..." value="' + esc(ch.bot_token || '') + '">' +
        '<button type="button" class="ch-toggle" title="顯示/隱藏">👁</button>' +
      '</div>' +
    '</div>' +
    '<div class="row">' +
      '<label>Chat ID</label>' +
      '<input type="text" class="ch-chat" placeholder="例: 8190460394 或 -100123... (群組)" value="' + esc(ch.chat_id || '') + '">' +
    '</div>';

  // 啟用狀態切換時改外觀
  row.querySelector('.ch-enabled').addEventListener('change', (e) => {
    row.classList.toggle('disabled', !e.target.checked);
  });
  // 顯示 / 隱藏 token
  row.querySelector('.ch-toggle').addEventListener('click', () => {
    const inp = row.querySelector('.ch-token');
    inp.type = inp.type === 'password' ? 'text' : 'password';
  });
  // 移除通道(允許刪到空:等於不使用 Telegram)
  row.querySelector('.ch-remove').addEventListener('click', () => {
    row.remove();
  });
  // 測試單一通道
  row.querySelector('.ch-test').addEventListener('click', async () => {
    const payload = {
      bot_token: row.querySelector('.ch-token').value.trim(),
      chat_id: row.querySelector('.ch-chat').value.trim(),
    };
    try {
      const r = await fetch('/api/telegram/test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      const d = await r.json();
      if (r.ok) toast('測試成功 — 請確認 Telegram 收到訊息');
      else toast(d.error || '測試失敗', true);
    } catch (err) {
      toast('網路錯誤', true);
    }
  });

  chList.appendChild(row);
}

function collectChannels() {
  return Array.from(chList.querySelectorAll('.channel')).map(row => ({
    name: row.querySelector('.ch-name').value.trim(),
    bot_token: row.querySelector('.ch-token').value.trim(),
    chat_id: row.querySelector('.ch-chat').value.trim(),
    enabled: row.querySelector('.ch-enabled').checked,
  }))
  // 沒有 token 也沒有 chat_id 的列視為空白殘留,直接丟掉(允許存空、不使用 Telegram)
  .filter(c => c.bot_token || c.chat_id);
}

async function openSettings() {
  chList.innerHTML = '';
  try {
    const r = await fetch('/api/telegram');
    const data = await r.json();
    if (r.ok) {
      const channels = data.channels || [];
      // 空清單 → 不自動塞空白列。使用者若要 Telegram,自己按「+ 新增通道」
      channels.forEach(renderChannel);
    } else {
      toast(data.error || '讀取設定失敗', true);
    }
  } catch (err) {
    toast('網路錯誤', true);
  }
  modal.classList.add('show');
}

function closeSettings() { modal.classList.remove('show'); }

async function saveSettings(andTest) {
  const payload = { channels: collectChannels() };
  try {
    const r = await fetch('/api/telegram', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    const data = await r.json();
    if (!r.ok) {
      toast(data.error || '儲存失敗', true);
      return;
    }
    const ch = payload.channels || [];
    if (ch.length === 0) {
      toast('已儲存(無通道 — Telegram 告警已停用)');
    } else {
      toast('已儲存,熱更新已套用');
    }
    closeSettings();
    if (andTest && ch.length > 0) {
      const r2 = await fetch('/api/test-notify', { method: 'POST' });
      const d2 = await r2.json();
      if (r2.ok) toast('測試訊息已送往所有啟用的通道');
      else toast(d2.error || '測試失敗', true);
    }
  } catch (err) {
    toast('網路錯誤', true);
  }
}

// (btn-settings 已移至管理中心)
document.getElementById('f-cancel').addEventListener('click', closeSettings);
document.getElementById('f-save').addEventListener('click', () => saveSettings(false));
document.getElementById('f-test-all').addEventListener('click', () => saveSettings(true));
document.getElementById('f-add').addEventListener('click', () => {
  renderChannel({ name: '', enabled: true });
  const last = chList.lastElementChild;
  if (last) last.querySelector('.ch-name').focus();
});
modal.addEventListener('click', (e) => { if (e.target === modal) closeSettings(); });
document.addEventListener('keydown', (e) => { if (e.key === 'Escape' && modal.classList.contains('show')) closeSettings(); });

// Refresh 可被暫停(拖曳中避免 grid 重繪中斷操作)
let refreshPaused = false;
let currentUser = null;

async function refreshAuthAware() {
  if (refreshPaused || !currentUser) return;
  try {
    const r = await fetch('/api/state', { cache: 'no-store' });
    if (r.status === 401) {
      showLoginView();
      return;
    }
    if (!r.ok) return;
    const data = await r.json();
    render(data);
  } catch (_) {}
}

// ===== Auth bootstrap =====
function applyRole(user) {
  currentUser = user;
  document.body.classList.toggle('readonly', user.role !== 'admin');
  // RADIUS 使用者的密碼由外部系統管理,藏起本地的「改密碼」按鈕
  document.body.classList.toggle('radius-user', user.auth_source === 'radius');
  document.getElementById('user-label').textContent = user.username;
  const pill = document.getElementById('role-pill');
  pill.textContent = user.role === 'admin' ? 'ADMIN' : 'READ ONLY';
  pill.className = 'role-pill' + (user.role === 'admin' ? ' admin' : '');
  // 登入/切換後,一律回到監控視圖
  showMonitorView();
}

async function showLoginView() {
  currentUser = null;
  document.getElementById('login-view').classList.remove('hidden');
  document.getElementById('app-view').classList.add('hidden');
  document.getElementById('login-error').textContent = '';
  // 查 RADIUS 是否啟用 → 決定要不要顯示認證方式下拉
  try {
    const r = await fetch('/api/login-info');
    const data = await r.json();
    const lbl = document.getElementById('auth-mode-label');
    if (lbl) lbl.classList.toggle('hidden', !data.radius_enabled);
    // 客製顯示名稱
    const radOpt = document.querySelector('#login-form select[name="auth_mode"] option[value="radius"]');
    if (radOpt) radOpt.textContent = data.radius_display_name || '外部認證';
  } catch (_) {}
  setTimeout(() => {
    const u = document.querySelector('#login-form [name="username"]');
    if (u) u.focus();
  }, 50);
}

function showAppView() {
  document.getElementById('login-view').classList.add('hidden');
  document.getElementById('app-view').classList.remove('hidden');
}

// ===== View switching (monitor / admin / tools) =====
function showMonitorView() {
  document.getElementById('view-monitor').classList.remove('hidden');
  document.getElementById('view-admin').classList.add('hidden');
  document.getElementById('view-tools').classList.add('hidden');
  document.getElementById('btn-admin').classList.remove('hidden');
  document.getElementById('btn-tools').classList.remove('hidden');
  document.getElementById('btn-back').classList.add('hidden');
}
function showAdminView() {
  if (!currentUser || currentUser.role !== 'admin') {
    toast('需要 admin 權限', true); return;
  }
  document.getElementById('view-monitor').classList.add('hidden');
  document.getElementById('view-admin').classList.remove('hidden');
  document.getElementById('view-tools').classList.add('hidden');
  document.getElementById('btn-admin').classList.add('hidden');
  document.getElementById('btn-tools').classList.add('hidden');
  document.getElementById('btn-back').classList.remove('hidden');
}
function showToolsView() {
  if (!currentUser || currentUser.role !== 'admin') {
    toast('需要 admin 權限', true); return;
  }
  document.getElementById('view-monitor').classList.add('hidden');
  document.getElementById('view-admin').classList.add('hidden');
  document.getElementById('view-tools').classList.remove('hidden');
  document.getElementById('btn-admin').classList.add('hidden');
  document.getElementById('btn-tools').classList.add('hidden');
  document.getElementById('btn-back').classList.remove('hidden');
}
document.getElementById('btn-admin').addEventListener('click', showAdminView);
document.getElementById('btn-tools').addEventListener('click', showToolsView);
document.getElementById('btn-back').addEventListener('click', showMonitorView);
// 工具卡片分派
document.getElementById('view-tools').addEventListener('click', (e) => {
  const card = e.target.closest('.admin-card');
  if (!card) return;
  const tool = card.dataset.tool;
  if (tool === 'radius') openToolRadius();
  else if (tool === 'ad') openToolAD();
  else if (tool === 'traceroute') openToolTracert();
});

// Admin 卡片分派
document.getElementById('view-admin').addEventListener('click', (e) => {
  const card = e.target.closest('.admin-card');
  if (!card) return;
  const open = card.dataset.open;
  if (open === 'settings')    openSettings();
  else if (open === 'radius') openRadiusModal();
  else if (open === 'users')  openUsersModal();
  else if (open === 'history') openHistoryModal();
  else if (open === 'evconfig') openEvConfigModal();
  else if (open === 'latency')  openLatencyModal();
  else if (open === 'reset')  openResetModal();
});

async function bootAuth() {
  try {
    const r = await fetch('/api/me');
    if (r.status === 401) { showLoginView(); return; }
    const data = await r.json();
    applyRole(data.user);
    showAppView();
    refresh();
  } catch (_) {
    showLoginView();
  }
}

document.getElementById('login-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  const err = document.getElementById('login-error');
  err.textContent = '';
  // 若下拉隱藏代表 RADIUS 不可用,一律 local
  const modeEl = document.querySelector('#auth-mode-label');
  const authMode = (modeEl && !modeEl.classList.contains('hidden'))
    ? (fd.get('auth_mode') || 'local') : 'local';
  try {
    const r = await fetch('/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: fd.get('username'),
        password: fd.get('password'),
        auth_mode: authMode,
      }),
    });
    const data = await r.json();
    if (r.ok) {
      applyRole(data.user);
      showAppView();
      e.target.reset();
      refresh();
    } else {
      err.textContent = data.error || '登入失敗';
    }
  } catch (_) {
    err.textContent = '網路錯誤';
  }
});

document.getElementById('btn-logout').addEventListener('click', async () => {
  if (!confirm('確定要登出?')) return;
  try { await fetch('/api/logout', { method: 'POST' }); } catch (_) {}
  showLoginView();
});

// ===== 改密碼 modal =====
const pwModal = document.getElementById('pw-modal-bg');
function openPwModal() {
  document.getElementById('pw-old').value = '';
  document.getElementById('pw-new').value = '';
  document.getElementById('pw-new2').value = '';
  pwModal.classList.add('show');
  setTimeout(() => document.getElementById('pw-old').focus(), 50);
}
function closePwModal() { pwModal.classList.remove('show'); }
document.getElementById('btn-password').addEventListener('click', openPwModal);
document.getElementById('pw-cancel').addEventListener('click', closePwModal);
document.getElementById('pw-submit').addEventListener('click', async () => {
  const oldPw = document.getElementById('pw-old').value;
  const newPw = document.getElementById('pw-new').value;
  const new2  = document.getElementById('pw-new2').value;
  if (!oldPw || !newPw) { toast('請填寫完整', true); return; }
  if (newPw !== new2) { toast('兩次新密碼不一致', true); return; }
  try {
    const r = await fetch('/api/auth/change-password', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ old_password: oldPw, new_password: newPw }),
    });
    const data = await r.json();
    if (r.ok) { toast('密碼已變更'); closePwModal(); }
    else { toast(data.error || '變更失敗', true); }
  } catch (_) { toast('網路錯誤', true); }
});
pwModal.addEventListener('click', (e) => { if (e.target === pwModal) closePwModal(); });

// ===== 使用者管理 modal (admin) =====
const umModal = document.getElementById('users-modal-bg');
async function openUsersModal() {
  try {
    const r = await fetch('/api/auth/users');
    const data = await r.json();
    if (!r.ok) { toast(data.error || '讀取失敗', true); return; }
    renderUsersTable(data.users || []);
    umModal.classList.add('show');
  } catch (_) { toast('網路錯誤', true); }
}
function closeUmModal() { umModal.classList.remove('show'); }

function renderUsersTable(users) {
  const tbody = document.getElementById('users-tbody');
  tbody.innerHTML = '';
  users.forEach(u => {
    const tr = document.createElement('tr');
    const created = u.created_at ? new Date(u.created_at).toLocaleDateString() : '—';
    const lastLogin = u.last_login ? new Date(u.last_login).toLocaleString() : '—';
    const roleChipCls = u.role === 'admin' ? 'admin' : 'readonly';
    const roleNew = u.role === 'admin' ? 'readonly' : 'admin';
    const roleBtnText = u.role === 'admin' ? '降為 readonly' : '升為 admin';
    const source = u.auth_source || 'local';
    const sourceChipCls = source === 'radius' ? 'admin' : 'readonly';
    const sourceText = source === 'radius' ? 'RADIUS' : '本地';
    // RADIUS 使用者沒有本地密碼可重設,隱藏該按鈕
    const resetBtn = source === 'radius'
      ? '<button disabled title="由 RADIUS 系統管理密碼" style="opacity: .5; cursor: not-allowed;">重設密碼</button>'
      : '<button data-act="reset" data-user="' + esc(u.username) + '">重設密碼</button>';
    tr.innerHTML =
      '<td><strong>' + esc(u.username) + '</strong></td>' +
      '<td><span class="role-chip ' + roleChipCls + '">' + esc(u.role) + '</span></td>' +
      '<td><span class="role-chip ' + sourceChipCls + '">' + sourceText + '</span></td>' +
      '<td>' + esc(created) + '</td>' +
      '<td>' + esc(lastLogin) + '</td>' +
      '<td class="row-btns" style="text-align:right; white-space:nowrap;">' +
        resetBtn +
        '<button data-act="role" data-user="' + esc(u.username) + '" data-role="' + roleNew + '">' + roleBtnText + '</button>' +
        '<button class="danger" data-act="delete" data-user="' + esc(u.username) + '">刪除</button>' +
      '</td>';
    tbody.appendChild(tr);
  });
}

document.getElementById('users-tbody').addEventListener('click', async (e) => {
  const btn = e.target.closest('button[data-act]');
  if (!btn) return;
  const act = btn.dataset.act;
  const user = btn.dataset.user;

  if (act === 'delete') {
    if (!confirm('確定刪除帳號「' + user + '」?')) return;
    const r = await fetch('/api/auth/users', {
      method: 'DELETE',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: user }),
    });
    const d = await r.json();
    if (r.ok) { toast('已刪除'); openUsersModal(); }
    else toast(d.error || '刪除失敗', true);
  } else if (act === 'role') {
    const role = btn.dataset.role;
    const r = await fetch('/api/auth/users/role', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: user, role }),
    });
    const d = await r.json();
    if (r.ok) { toast('角色已更新'); openUsersModal(); }
    else toast(d.error || '更新失敗', true);
  } else if (act === 'reset') {
    const pw = prompt('為「' + user + '」設定新密碼(至少 4 字):');
    if (!pw) return;
    const r = await fetch('/api/auth/change-password', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target_user: user, new_password: pw }),
    });
    const d = await r.json();
    if (r.ok) toast('密碼已重設');
    else toast(d.error || '重設失敗', true);
  }
});

document.getElementById('nu-add').addEventListener('click', async () => {
  const source = document.getElementById('nu-source').value;
  const username = document.getElementById('nu-username').value.trim();
  const password = document.getElementById('nu-password').value;
  const role = document.getElementById('nu-role').value;
  if (!username) { toast('帳號不可為空', true); return; }
  if (source === 'local' && !password) { toast('本地帳號需填密碼', true); return; }
  const r = await fetch('/api/auth/users', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password, role, auth_source: source }),
  });
  const d = await r.json();
  if (r.ok) {
    toast('已新增');
    document.getElementById('nu-username').value = '';
    document.getElementById('nu-password').value = '';
    openUsersModal();
  } else toast(d.error || '新增失敗', true);
});

// (btn-users 已移至管理中心)
document.getElementById('um-close').addEventListener('click', closeUmModal);
umModal.addEventListener('click', (e) => { if (e.target === umModal) closeUmModal(); });

// ===== 登入紀錄 modal =====
const hmModal = document.getElementById('history-modal-bg');
async function openHistoryModal() {
  try {
    const r = await fetch('/api/auth/history?limit=200');
    const data = await r.json();
    if (!r.ok) { toast(data.error || '讀取失敗', true); return; }
    const tbody = document.getElementById('history-tbody');
    tbody.innerHTML = '';
    (data.history || []).forEach(ev => {
      const tr = document.createElement('tr');
      tr.className = ev.success ? 'ok' : 'fail';
      const ts = ev.ts ? new Date(ev.ts).toLocaleString() : '—';
      const mark = ev.success ? '✓' : '✗';
      const mode = ev.auth_mode === 'radius' ? 'RADIUS' : '本地';
      const note = ev.success ? '' : (ev.reason || '');
      tr.innerHTML =
        '<td style="text-align:center; font-size:14px;">' + mark + '</td>' +
        '<td>' + esc(ts) + '</td>' +
        '<td>' + esc(ev.user || '-') + '</td>' +
        '<td>' + esc(mode) + '</td>' +
        '<td>' + esc(ev.ip || '-') + '</td>' +
        '<td style="max-width:280px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">' + esc(note) + '</td>';
      tbody.appendChild(tr);
    });
    hmModal.classList.add('show');
  } catch (_) { toast('網路錯誤', true); }
}
function closeHmModal() { hmModal.classList.remove('show'); }
// (btn-history 已移至管理中心)
document.getElementById('hm-close').addEventListener('click', closeHmModal);
document.getElementById('hm-export').addEventListener('click', () => {
  window.location.href = '/api/auth/history/export?limit=2000';
});
hmModal.addEventListener('click', (e) => { if (e.target === hmModal) closeHmModal(); });

// ===== 個別檢查設定覆寫 modal =====
const cksModal = document.getElementById('cks-modal-bg');
let cksContext = { name: null, checkKey: null };

function openCheckSettingsModal(targetName, ckKey) {
  cksContext = { name: targetName, checkKey: ckKey };
  fetch('/api/state', { cache: 'no-store' }).then(r => r.json()).then(data => {
    const target = (data.targets || []).find(t => t.name === targetName);
    if (!target) { toast('找不到目標', true); return; }
    const c = target.checks.find(cc => checkKey(targetName, cc) === ckKey);
    if (!c) { toast('找不到檢查', true); return; }
    const globals = data.settings || {};
    const gi = globals.check_interval_seconds ?? 30;
    const gt = globals.tcp_timeout_seconds ?? 5;
    const gf = globals.failure_threshold ?? 3;
    const gr = globals.recovery_threshold ?? 1;
    const gm = globals.reminder_interval_minutes ?? 60;

    document.getElementById('cks-title').textContent = '檢查設定覆寫 — ' + targetName;
    document.getElementById('cks-interval').value = c.check_interval_seconds ?? '';
    document.getElementById('cks-timeout').value  = c.tcp_timeout_seconds ?? '';
    document.getElementById('cks-fail').value     = c.failure_threshold ?? '';
    document.getElementById('cks-recover').value  = c.recovery_threshold ?? '';
    document.getElementById('cks-reminder').value = c.reminder_interval_minutes ?? '';

    document.getElementById('cks-g-interval').textContent = '全域: ' + gi + ' 秒';
    document.getElementById('cks-g-timeout').textContent  = '全域: ' + gt + ' 秒';
    document.getElementById('cks-g-fail').textContent     = '全域: ' + gf + ' 次';
    document.getElementById('cks-g-recover').textContent  = '全域: ' + gr + ' 次';
    document.getElementById('cks-g-reminder').textContent = '全域: ' + (gm > 0 ? gm + ' 分鐘' : '關閉');
    document.getElementById('cks-g-interval-inline').textContent = gi + ' 秒';

    cksModal.classList.add('show');
  }).catch(() => toast('網路錯誤', true));
}

function closeCksModal() { cksModal.classList.remove('show'); }

async function saveCksSettings(clearAll) {
  if (!cksContext.name) return;
  const body = { name: cksContext.name, check_key: cksContext.checkKey };
  if (clearAll) {
    body.settings = {
      check_interval_seconds: null,
      tcp_timeout_seconds: null,
      failure_threshold: null,
      recovery_threshold: null,
      reminder_interval_minutes: null,
    };
  } else {
    const pick = id => {
      const v = document.getElementById(id).value.trim();
      return v === '' ? null : v;
    };
    body.settings = {
      check_interval_seconds:     pick('cks-interval'),
      tcp_timeout_seconds:        pick('cks-timeout'),
      failure_threshold:          pick('cks-fail'),
      recovery_threshold:         pick('cks-recover'),
      reminder_interval_minutes:  pick('cks-reminder'),
    };
  }
  try {
    const r = await fetch('/api/targets/settings', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    const data = await r.json();
    if (r.ok) {
      toast(clearAll ? '已全部清除,沿用全域' : '已儲存');
      closeCksModal();
      refresh();
    } else {
      toast(data.error || '儲存失敗', true);
    }
  } catch (_) { toast('網路錯誤', true); }
}

document.getElementById('cks-cancel').addEventListener('click', closeCksModal);
cksModal.addEventListener('click', (e) => { if (e.target === cksModal) closeCksModal(); });
document.getElementById('cks-save').addEventListener('click', () => saveCksSettings(false));
document.getElementById('cks-clear').addEventListener('click', () => {
  if (confirm('確定清除所有覆寫,改回沿用全域設定?')) saveCksSettings(true);
});

// ===== 測試工具:共用 result 畫法 =====
function setToolResult(elId, kind, html) {
  const el = document.getElementById(elId);
  el.style.display = 'block';
  el.innerHTML = html;
  const col = {
    ok:   ['var(--success-soft)', 'var(--success)'],
    fail: ['var(--danger-soft)',  'var(--danger)'],
    warn: ['var(--warn-soft)',    '#8a6300'],
    info: ['var(--brand-soft)',   'var(--brand)'],
  }[kind] || ['#f3f4f6', 'var(--muted)'];
  el.style.background = col[0];
  el.style.color = col[1];
}

// ===== 測試工具:RADIUS =====
const trdModal = document.getElementById('tool-radius-modal-bg');
function openToolRadius() {
  document.getElementById('trd-result').style.display = 'none';
  document.getElementById('trd-username').value = '';
  document.getElementById('trd-password').value = '';
  trdModal.classList.add('show');
  setTimeout(() => document.getElementById('trd-server').focus(), 50);
}
function closeToolRadius() { trdModal.classList.remove('show'); }
document.getElementById('trd-close').addEventListener('click', closeToolRadius);
trdModal.addEventListener('click', (e) => { if (e.target === trdModal) closeToolRadius(); });
document.getElementById('trd-secret-toggle').addEventListener('click', () => {
  const i = document.getElementById('trd-secret');
  i.type = i.type === 'password' ? 'text' : 'password';
});
document.getElementById('trd-load').addEventListener('click', async () => {
  try {
    const r = await fetch('/api/radius');
    const d = await r.json();
    if (r.ok) {
      document.getElementById('trd-server').value = d.server || '';
      document.getElementById('trd-port').value = d.port || 1812;
      document.getElementById('trd-secret').value = d.secret || '';
      document.getElementById('trd-timeout').value = d.timeout || 5;
      toast('已帶入現有 RADIUS 設定');
    } else toast(d.error || '讀取失敗', true);
  } catch (_) { toast('網路錯誤', true); }
});
document.getElementById('trd-run').addEventListener('click', async () => {
  const btn = document.getElementById('trd-run');
  btn.disabled = true; btn.textContent = '測試中...';
  try {
    const r = await fetch('/api/tools/radius-test', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        server: document.getElementById('trd-server').value.trim(),
        port: parseInt(document.getElementById('trd-port').value || '1812', 10),
        secret: document.getElementById('trd-secret').value,
        username: document.getElementById('trd-username').value.trim(),
        password: document.getElementById('trd-password').value,
        timeout: parseInt(document.getElementById('trd-timeout').value || '5', 10),
      }),
    });
    const d = await r.json();
    if (!r.ok) {
      setToolResult('trd-result', 'fail', '❌ ' + esc(d.error || '請求失敗'));
    } else if (d.authenticated) {
      setToolResult('trd-result', 'ok',
        '✅ <strong>認證成功</strong> · 耗時 ' + d.elapsed_ms + ' ms');
    } else {
      setToolResult('trd-result', 'fail',
        '❌ <strong>' + esc(d.message) + '</strong> · 耗時 ' + d.elapsed_ms + ' ms');
    }
  } catch (_) {
    setToolResult('trd-result', 'fail', '❌ 網路錯誤');
  } finally {
    btn.disabled = false; btn.textContent = '執行測試';
  }
});

// ===== 測試工具:AD =====
const tadModal = document.getElementById('tool-ad-modal-bg');
function openToolAD() {
  document.getElementById('tad-result').style.display = 'none';
  document.getElementById('tad-binddn').value = '';
  document.getElementById('tad-password').value = '';
  tadModal.classList.add('show');
  setTimeout(() => document.getElementById('tad-server').focus(), 50);
}
function closeToolAD() { tadModal.classList.remove('show'); }
document.getElementById('tad-close').addEventListener('click', closeToolAD);
tadModal.addEventListener('click', (e) => { if (e.target === tadModal) closeToolAD(); });
// SSL 勾選時自動切 port 636
document.getElementById('tad-ssl').addEventListener('change', (e) => {
  const p = document.getElementById('tad-port');
  p.value = e.target.checked ? 636 : 389;
});
document.getElementById('tad-run').addEventListener('click', async () => {
  const btn = document.getElementById('tad-run');
  btn.disabled = true; btn.textContent = '測試中...';
  try {
    const r = await fetch('/api/tools/ad-test', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        server: document.getElementById('tad-server').value.trim(),
        port: parseInt(document.getElementById('tad-port').value || '389', 10),
        use_ssl: document.getElementById('tad-ssl').checked,
        bind_dn: document.getElementById('tad-binddn').value.trim(),
        password: document.getElementById('tad-password').value,
      }),
    });
    const d = await r.json();
    if (!r.ok) {
      setToolResult('tad-result', 'fail', '❌ ' + esc(d.error || '請求失敗'));
    } else if (d.authenticated) {
      let msg = '✅ <strong>Bind 成功</strong> · 耗時 ' + d.elapsed_ms + ' ms';
      if (d.who_am_i) msg += '<br>whoami: <code>' + esc(d.who_am_i) + '</code>';
      setToolResult('tad-result', 'ok', msg);
    } else {
      setToolResult('tad-result', 'fail',
        '❌ <strong>' + esc(d.message) + '</strong> · 耗時 ' + d.elapsed_ms + ' ms');
    }
  } catch (_) {
    setToolResult('tad-result', 'fail', '❌ 網路錯誤');
  } finally {
    btn.disabled = false; btn.textContent = '執行測試';
  }
});

// ===== 測試工具:Traceroute =====
const ttrModal = document.getElementById('tool-tracert-modal-bg');
function openToolTracert() {
  document.getElementById('ttr-output').style.display = 'none';
  document.getElementById('ttr-output').textContent = '';
  document.getElementById('ttr-status').textContent = '';
  ttrModal.classList.add('show');
  setTimeout(() => document.getElementById('ttr-host').focus(), 50);
}
function closeToolTracert() { ttrModal.classList.remove('show'); }
document.getElementById('ttr-close').addEventListener('click', closeToolTracert);
ttrModal.addEventListener('click', (e) => { if (e.target === ttrModal) closeToolTracert(); });
document.getElementById('ttr-run').addEventListener('click', async () => {
  const btn = document.getElementById('ttr-run');
  const host = document.getElementById('ttr-host').value.trim();
  const hops = parseInt(document.getElementById('ttr-hops').value || '30', 10);
  if (!host) { toast('請填目標 host', true); return; }
  btn.disabled = true; btn.textContent = '執行中...';
  const out = document.getElementById('ttr-output');
  out.textContent = '';
  out.style.display = 'none';
  const status = document.getElementById('ttr-status');
  status.textContent = `執行中... 目標 ${host},最大 ${hops} 跳,可能需要 1 分鐘以上`;
  try {
    const t0 = performance.now();
    const r = await fetch('/api/tools/traceroute', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ host, max_hops: hops }),
    });
    const d = await r.json();
    const ms = Math.round(performance.now() - t0);
    if (!r.ok) {
      status.textContent = '';
      toast(d.error || '執行失敗', true);
    } else {
      status.textContent = `完成 · 耗時 ${(ms/1000).toFixed(1)} 秒 · return_code=${d.return_code}`;
      out.textContent = d.output || '(無輸出)';
      out.style.display = 'block';
    }
  } catch (_) {
    status.textContent = '';
    toast('網路錯誤', true);
  } finally {
    btn.disabled = false; btn.textContent = '執行';
  }
});

// Esc 關閉工具 modal
document.addEventListener('keydown', (e) => {
  if (e.key !== 'Escape') return;
  [trdModal, tadModal, ttrModal].forEach(m => {
    if (m.classList.contains('show')) m.classList.remove('show');
  });
});

// ===== RADIUS 設定 modal =====
const rdModal = document.getElementById('radius-modal-bg');
async function openRadiusModal() {
  try {
    const r = await fetch('/api/radius');
    const data = await r.json();
    if (!r.ok) { toast(data.error || '讀取失敗', true); return; }
    document.getElementById('rd-enabled').checked = !!data.enabled;
    document.getElementById('rd-server').value = data.server || '';
    document.getElementById('rd-port').value = data.port || 1812;
    document.getElementById('rd-secret').value = data.secret || '';
    document.getElementById('rd-timeout').value = data.timeout || 5;
    document.getElementById('rd-default-role').value = data.default_role || 'readonly';
    document.getElementById('rd-display-name').value = data.display_name || '';
    document.getElementById('rd-secret').type = 'password';
    rdModal.classList.add('show');
  } catch (_) { toast('網路錯誤', true); }
}
function closeRadiusModal() { rdModal.classList.remove('show'); }

function collectRadiusPayload() {
  return {
    enabled: document.getElementById('rd-enabled').checked,
    server: document.getElementById('rd-server').value.trim(),
    port: parseInt(document.getElementById('rd-port').value || '1812', 10),
    secret: document.getElementById('rd-secret').value,
    timeout: parseInt(document.getElementById('rd-timeout').value || '5', 10),
    default_role: document.getElementById('rd-default-role').value,
    display_name: document.getElementById('rd-display-name').value.trim(),
  };
}

// (btn-radius 已移至管理中心)
document.getElementById('rd-cancel').addEventListener('click', closeRadiusModal);
rdModal.addEventListener('click', (e) => { if (e.target === rdModal) closeRadiusModal(); });
document.getElementById('rd-secret-toggle').addEventListener('click', () => {
  const inp = document.getElementById('rd-secret');
  inp.type = inp.type === 'password' ? 'text' : 'password';
});
document.getElementById('rd-test').addEventListener('click', async () => {
  const p = collectRadiusPayload();
  if (!p.server || !p.secret) { toast('請填寫 server 與 secret', true); return; }
  try {
    const r = await fetch('/api/radius/test', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(p),
    });
    const data = await r.json();
    if (r.ok) {
      toast((data.reachable ? '✓ 連線成功' : '✗ 無法連線') + ' — ' + (data.message || ''),
            !data.reachable);
    } else {
      toast(data.error || '測試失敗', true);
    }
  } catch (_) { toast('網路錯誤', true); }
});
document.getElementById('rd-save').addEventListener('click', async () => {
  try {
    const r = await fetch('/api/radius', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(collectRadiusPayload()),
    });
    const data = await r.json();
    if (r.ok) { toast('RADIUS 設定已儲存'); closeRadiusModal(); }
    else { toast(data.error || '儲存失敗', true); }
  } catch (_) { toast('網路錯誤', true); }
});

// ===== 延遲門檻 modal =====
const latModal = document.getElementById('lat-modal-bg');
async function openLatencyModal() {
  try {
    const r = await fetch('/api/latency-thresholds');
    const data = await r.json();
    if (!r.ok) { toast(data.error || '讀取失敗', true); return; }
    const t = data.thresholds || {};
    const d = data.defaults || {};
    for (const type of ['tcp', 'icmp', 'http', 'dns']) {
      const vals = t[type] || d[type] || [];
      document.getElementById(`lat-${type}-1`).value = vals[0] ?? '';
      document.getElementById(`lat-${type}-2`).value = vals[1] ?? '';
      document.getElementById(`lat-${type}-3`).value = vals[2] ?? '';
      const dd = d[type] || [];
      document.getElementById(`lat-${type}-default`).textContent = `${dd[0]}/${dd[1]}/${dd[2]}`;
    }
    latModal.classList.add('show');
  } catch (_) { toast('網路錯誤', true); }
}
function closeLatModal() { latModal.classList.remove('show'); }

async function saveLatency(useDefaults) {
  const body = {};
  if (useDefaults) {
    // 送空 body,server 會清掉設定
  } else {
    for (const type of ['tcp', 'icmp', 'http', 'dns']) {
      const v1 = parseFloat(document.getElementById(`lat-${type}-1`).value);
      const v2 = parseFloat(document.getElementById(`lat-${type}-2`).value);
      const v3 = parseFloat(document.getElementById(`lat-${type}-3`).value);
      if ([v1, v2, v3].some(x => !(x > 0))) {
        toast(type.toUpperCase() + ' 三個值都必須 > 0', true); return;
      }
      if (!(v1 < v2 && v2 < v3)) {
        toast(type.toUpperCase() + ' 必須遞增 (fast < ok < slow)', true); return;
      }
      body[type] = [v1, v2, v3];
    }
  }
  try {
    const r = await fetch('/api/latency-thresholds', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    const data = await r.json();
    if (r.ok) {
      toast(useDefaults ? '已恢復預設門檻' : '門檻已儲存');
      closeLatModal();
      refresh();
    } else { toast(data.error || '儲存失敗', true); }
  } catch (_) { toast('網路錯誤', true); }
}

document.getElementById('lat-cancel').addEventListener('click', closeLatModal);
latModal.addEventListener('click', (e) => { if (e.target === latModal) closeLatModal(); });
document.getElementById('lat-save').addEventListener('click', () => saveLatency(false));
document.getElementById('lat-reset').addEventListener('click', () => {
  if (confirm('確定恢復所有門檻為預設值?')) saveLatency(true);
});

// ===== 事件紀錄設定 modal =====
const evcModal = document.getElementById('evc-modal-bg');
async function openEvConfigModal() {
  try {
    const r = await fetch('/api/events/config');
    const data = await r.json();
    if (!r.ok) { toast(data.error || '讀取失敗', true); return; }
    document.getElementById('evc-fail').checked = !!data.log_every_fail;
    document.getElementById('evc-success').checked = !!data.log_every_success;
    evcModal.classList.add('show');
  } catch (_) { toast('網路錯誤', true); }
}
function closeEvConfigModal() { evcModal.classList.remove('show'); }
document.getElementById('evc-cancel').addEventListener('click', closeEvConfigModal);
evcModal.addEventListener('click', (e) => { if (e.target === evcModal) closeEvConfigModal(); });
document.getElementById('evc-save').addEventListener('click', async () => {
  try {
    const r = await fetch('/api/events/config', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        log_every_fail: document.getElementById('evc-fail').checked,
        log_every_success: document.getElementById('evc-success').checked,
      }),
    });
    const data = await r.json();
    if (r.ok) { toast('事件紀錄設定已儲存'); closeEvConfigModal(); }
    else { toast(data.error || '儲存失敗', true); }
  } catch (_) { toast('網路錯誤', true); }
});

// ===== 清空監控狀態 modal =====
const rsModal = document.getElementById('reset-modal-bg');
function openResetModal() { rsModal.classList.add('show'); }
function closeResetModal() { rsModal.classList.remove('show'); }
// (btn-reset 已移至管理中心)
document.getElementById('rs-cancel').addEventListener('click', closeResetModal);
rsModal.addEventListener('click', (e) => { if (e.target === rsModal) closeResetModal(); });
document.getElementById('rs-submit').addEventListener('click', async () => {
  try {
    const r = await fetch('/api/reset', { method: 'POST' });
    const data = await r.json();
    if (r.ok) {
      toast('已清空監控狀態(原 ' + data.cleared + ' 筆)');
      closeResetModal();
      setTimeout(refresh, 500);
    } else {
      toast(data.error || '清空失敗', true);
    }
  } catch (_) { toast('網路錯誤', true); }
});

// ===== 監控事件 modal =====
const evModal = document.getElementById('events-modal-bg');
const evTbody = document.getElementById('events-tbody');
let evAll = [];   // 完整事件清單(未過濾)

function fmtEventDuration(secs) {
  if (secs == null) return '';
  if (secs < 60) return secs + ' 秒';
  const m = Math.floor(secs / 60), s = secs % 60;
  if (m < 60) return m + ' 分 ' + s + ' 秒';
  const h = Math.floor(m / 60), mm = m % 60;
  return h + ' 時 ' + mm + ' 分';
}

function renderEventsList() {
  const q = document.getElementById('ev-search').value.trim().toLowerCase();
  const fType = document.getElementById('ev-filter-type').value;
  const fEvt  = document.getElementById('ev-filter-event').value;

  const filtered = evAll.filter(ev => {
    if (fType && (ev.type || 'tcp') !== fType) return false;
    if (fEvt) {
      // up 再細分 recovery (有 down_duration_sec) vs ok (純連續成功)
      if (fEvt === 'up:recovery') {
        if (!(ev.event === 'up' && ev.down_duration_sec != null)) return false;
      } else if (fEvt === 'up:ok') {
        if (!(ev.event === 'up' && ev.down_duration_sec == null)) return false;
      } else if (ev.event !== fEvt) return false;
    }
    if (q) {
      const hay = [
        ev.target || '', ev.address || '', ev.error || '',
        ev.event || '', ev.type || '',
      ].join(' ').toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  });

  const countEl = document.getElementById('ev-count');
  countEl.textContent = filtered.length < evAll.length
    ? `(顯示 ${filtered.length} / ${evAll.length} 筆)`
    : `(最近 ${evAll.length} 筆,最新在前)`;

  evTbody.innerHTML = '';
  if (filtered.length === 0) {
    evTbody.innerHTML = '<tr><td colspan="6" style="text-align:center; padding:30px; color:var(--muted);">' +
      (evAll.length === 0 ? '尚無任何事件紀錄' : '沒有符合條件的紀錄') + '</td></tr>';
    return;
  }
  filtered.forEach(ev => {
    const tr = document.createElement('tr');
    tr.className = ev.event === 'down' ? 'fail' : 'ok';
    const ts = ev.ts ? new Date(ev.ts).toLocaleString() : '—';
    const badge = ev.event === 'down' ? '🔴 DOWN'
                : ev.event === 'up' && ev.down_duration_sec != null ? '✅ UP 恢復'
                : ev.event === 'up' ? '🟢 UP'
                : ev.event === 'first_up' ? '🟢 首次上線'
                : esc(ev.event);
    let detail = '';
    if (ev.event === 'down') {
      detail = esc(ev.error || '');
      if (ev.consecutive_failures) {
        detail += ' <span style="color:var(--muted); font-size:11px;">(連續失敗 ' + ev.consecutive_failures + ' 次)</span>';
      }
    }
    else if (ev.event === 'up') {
      const parts = [];
      if (ev.down_duration_sec != null) parts.push('中斷 ' + fmtEventDuration(ev.down_duration_sec));
      if (ev.latency_ms != null) parts.push('延遲 ' + ev.latency_ms + ' ms');
      detail = esc(parts.join(' · '));
    } else if (ev.event === 'first_up') {
      if (ev.latency_ms != null) detail = '延遲 ' + ev.latency_ms + ' ms';
    }
    tr.innerHTML =
      '<td style="white-space:nowrap;">' + badge + '</td>' +
      '<td>' + esc(ts) + '</td>' +
      '<td><strong>' + esc(ev.target || '') + '</strong></td>' +
      '<td><span class="type-tag ' + esc(ev.type || 'tcp') + '">' + esc((ev.type || 'tcp').toUpperCase()) + '</span></td>' +
      '<td style="max-width:280px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">' + esc(ev.address || '') + '</td>' +
      '<td>' + detail + '</td>';
    evTbody.appendChild(tr);
  });
}

let evAutoTimer = null;

async function reloadEvents(silent) {
  const btn = document.getElementById('ev-reload');
  if (!silent && btn) { btn.disabled = true; btn.textContent = '⟳ 載入中...'; }
  try {
    const r = await fetch('/api/events?limit=500', { cache: 'no-store' });
    const data = await r.json();
    if (!r.ok) {
      if (!silent) toast(data.error || '讀取失敗', true);
      return;
    }
    evAll = data.events || [];
    renderEventsList();
    const lastEl = document.getElementById('ev-last');
    if (lastEl) lastEl.textContent = '最後載入: ' + new Date().toLocaleTimeString();
  } catch (_) { if (!silent) toast('網路錯誤', true); }
  finally {
    if (!silent && btn) { btn.disabled = false; btn.textContent = '⟳ 重新載入'; }
  }
}

function startEvAutoRefresh() {
  stopEvAutoRefresh();
  // 每 5 秒重抓一次(silent 模式不顯示 loading / 錯誤 toast)
  evAutoTimer = setInterval(() => {
    if (evModal.classList.contains('show')
        && document.getElementById('ev-auto').checked) {
      reloadEvents(true);
    }
  }, 5000);
}
function stopEvAutoRefresh() {
  if (evAutoTimer) { clearInterval(evAutoTimer); evAutoTimer = null; }
}

async function openEventsModal() {
  document.getElementById('ev-search').value = '';
  document.getElementById('ev-filter-type').value = '';
  document.getElementById('ev-filter-event').value = '';
  document.getElementById('ev-auto').checked = true;
  evModal.classList.add('show');
  await reloadEvents();
  startEvAutoRefresh();
  setTimeout(() => document.getElementById('ev-search').focus(), 80);
}
function closeEventsModal() {
  evModal.classList.remove('show');
  stopEvAutoRefresh();
}

document.getElementById('btn-events').addEventListener('click', openEventsModal);
document.getElementById('ev-close').addEventListener('click', closeEventsModal);
document.getElementById('ev-reload').addEventListener('click', reloadEvents);
document.getElementById('ev-export').addEventListener('click', () => {
  // 組目前過濾條件成 URL(讓後端做一樣的過濾)
  const params = new URLSearchParams();
  const q = document.getElementById('ev-search').value.trim();
  const fType = document.getElementById('ev-filter-type').value;
  const fEvt  = document.getElementById('ev-filter-event').value;
  if (q) params.set('q', q);
  if (fType) params.set('type', fType);
  if (fEvt) params.set('event', fEvt);
  params.set('limit', '50000');
  // 觸發下載(瀏覽器會依 Content-Disposition 存檔)
  window.location.href = '/api/events/export?' + params.toString();
});
document.getElementById('ev-search').addEventListener('input', renderEventsList);
document.getElementById('ev-filter-type').addEventListener('change', renderEventsList);
document.getElementById('ev-filter-event').addEventListener('change', renderEventsList);
evModal.addEventListener('click', (e) => { if (e.target === evModal) closeEventsModal(); });
document.getElementById('ev-clear').addEventListener('click', async () => {
  if (currentUser && currentUser.role !== 'admin') { toast('需要 admin 權限', true); return; }
  if (!confirm('確定清空所有監控事件紀錄?\n此動作無法還原。')) return;
  try {
    const r = await fetch('/api/events', { method: 'DELETE' });
    const data = await r.json();
    if (r.ok) { toast('已清空 ' + data.cleared + ' 筆事件'); reloadEvents(); }
    else { toast(data.error || '清空失敗', true); }
  } catch (_) { toast('網路錯誤', true); }
});

// Esc 關閉任何開著的 modal
document.addEventListener('keydown', (e) => {
  if (e.key !== 'Escape') return;
  [pwModal, umModal, hmModal, rsModal, evModal, rdModal, evcModal, cksModal, latModal].forEach(m => { if (m.classList.contains('show')) m.classList.remove('show'); });
});

// 啟動
bootAuth();
setInterval(refreshAuthAware, 3000);

// ----- 卡片拖曳排序 (HTML5 native DnD) -----
(function setupDnD() {
  const grid = document.getElementById('grid');
  let draggingCard = null;

  function clearDropIndicators() {
    grid.querySelectorAll('.drop-before, .drop-after').forEach(el => {
      el.classList.remove('drop-before', 'drop-after');
    });
  }

  // 找到鼠標應該插在哪張卡前面(grid 排版要考慮 X 與 Y)
  function findDropTarget(clientX, clientY) {
    const cards = [...grid.querySelectorAll('.card:not(.dragging)')];
    // 挑出目前滑鼠「所在列」— Y 座標在某卡的上下邊界內的卡片
    let rowCards = cards.filter(c => {
      const r = c.getBoundingClientRect();
      return clientY >= r.top && clientY <= r.bottom;
    });
    // 若滑鼠在列間空白,退回依 Y 距離最近的列
    if (rowCards.length === 0) {
      let bestY = Infinity, best = null;
      for (const c of cards) {
        const r = c.getBoundingClientRect();
        const dy = Math.min(Math.abs(clientY - r.top), Math.abs(clientY - r.bottom));
        if (dy < bestY) { bestY = dy; best = c; }
      }
      if (best) {
        const br = best.getBoundingClientRect();
        rowCards = cards.filter(c => {
          const r = c.getBoundingClientRect();
          return Math.abs(r.top - br.top) < 4;
        });
      }
    }
    if (rowCards.length === 0) return { card: null, before: true };
    // 在該列找 X 位置最近的
    let best = null, bestDx = Infinity;
    for (const c of rowCards) {
      const r = c.getBoundingClientRect();
      const cx = r.left + r.width / 2;
      const dx = Math.abs(clientX - cx);
      if (dx < bestDx) { bestDx = dx; best = c; }
    }
    const r = best.getBoundingClientRect();
    const before = clientX < (r.left + r.width / 2);
    return { card: best, before };
  }

  grid.addEventListener('dragstart', (e) => {
    const card = e.target.closest('.card');
    if (!card) return;
    draggingCard = card;
    card.classList.add('dragging');
    refreshPaused = true;
    // 必要 — 否則 Firefox 不觸發 drag 系列事件
    try { e.dataTransfer.setData('text/plain', card.dataset.name); } catch (_) {}
    e.dataTransfer.effectAllowed = 'move';
  });

  grid.addEventListener('dragend', () => {
    if (draggingCard) draggingCard.classList.remove('dragging');
    draggingCard = null;
    clearDropIndicators();
    // 稍等一下再解除 pause,避免 dragend 後立刻觸發 refresh 把還沒送出的順序覆蓋
    setTimeout(() => { refreshPaused = false; }, 400);
  });

  grid.addEventListener('dragover', (e) => {
    if (!draggingCard) return;
    e.preventDefault();
    e.dataTransfer.dropEffect = 'move';
    clearDropIndicators();
    const { card, before } = findDropTarget(e.clientX, e.clientY);
    if (!card || card === draggingCard) return;
    card.classList.add(before ? 'drop-before' : 'drop-after');
  });

  grid.addEventListener('drop', async (e) => {
    if (!draggingCard) return;
    e.preventDefault();
    clearDropIndicators();
    const { card: target, before } = findDropTarget(e.clientX, e.clientY);
    if (target && target !== draggingCard) {
      if (before) grid.insertBefore(draggingCard, target);
      else grid.insertBefore(draggingCard, target.nextSibling);
    }
    // 把新順序丟到後端
    const names = [...grid.querySelectorAll('.card')].map(c => c.dataset.name).filter(Boolean);
    try {
      const r = await fetch('/api/targets/reorder', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ names }),
      });
      const data = await r.json();
      if (r.ok) { toast('順序已儲存'); }
      else {
        toast(data.error || '排序儲存失敗', true);
        refresh();  // 後端錯誤 → 拉回真實順序
      }
    } catch (err) {
      toast('網路錯誤', true);
      refresh();
    }
  });

  // 避免 drag 結束後瀏覽器把某些按鈕 focus 住
  grid.addEventListener('dragleave', (e) => {
    if (e.target === grid) clearDropIndicators();
  });
})();
</script>
</body>
</html>
"""
