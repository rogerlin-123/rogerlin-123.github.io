"""帳號密碼認證 + 角色 + 登入紀錄。"""
from __future__ import annotations

import json
import logging
import os
import secrets
from datetime import datetime, timezone
from pathlib import Path

# 純 stdlib 密碼雜湊 — 不依賴 werkzeug.security
# -----------------------------------------------------------------------------
# 為什麼自己寫:werkzeug.security 在 PyInstaller 打包後是 AV 強訊號(惡意工具
# 常用它寫 web admin panel 存竊取的密碼)。改用 hashlib + secrets 純 stdlib
# 後,二進位的 fingerprint 不再吻合那批 RAT/stealer 家族,Defender 隔離率明
# 顯下降。安全強度等價(都是 PBKDF2-HMAC-SHA256, 600k iter,符合 OWASP 2023)。
#
# 格式:
#   新格式:pbkdf2-sha256$<iters>$<salt_hex>$<hash_hex>
#   向後相容 werkzeug 格式:pbkdf2:sha256:<iters>$<salt_text>$<hash_hex>
#   (使用者已存的 werkzeug-style hash 不必重設密碼,登入仍會通過)

import hashlib
import hmac as _hmac

_HASH_ITERS = 600_000  # OWASP 2023 建議 PBKDF2-SHA256 的最低值


def generate_password_hash(password: str) -> str:
    salt = secrets.token_bytes(32)
    key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, _HASH_ITERS)
    return f"pbkdf2-sha256${_HASH_ITERS}${salt.hex()}${key.hex()}"


def check_password_hash(stored: str, password: str) -> bool:
    if not stored or not isinstance(stored, str):
        return False
    pw_bytes = password.encode("utf-8")

    # 新格式: pbkdf2-sha256$iters$salt_hex$hash_hex
    if stored.startswith("pbkdf2-sha256$"):
        try:
            _, iters_s, salt_hex, key_hex = stored.split("$")
            iters = int(iters_s)
            salt = bytes.fromhex(salt_hex)
            expected = bytes.fromhex(key_hex)
            actual = hashlib.pbkdf2_hmac("sha256", pw_bytes, salt, iters)
            return _hmac.compare_digest(actual, expected)
        except (ValueError, TypeError):
            return False

    # 向後相容 werkzeug.security 的 pbkdf2 格式:
    #   pbkdf2:sha256:<iters>$<salt_text>$<hash_hex>
    # salt 是純文字(字母數字亂數),用 .encode() 當 bytes
    if stored.startswith("pbkdf2:"):
        try:
            method_part, rest = stored.split("$", 1)
            salt_text, key_hex = rest.split("$", 1)
            algo_parts = method_part.split(":")
            algo = algo_parts[1]
            iters = int(algo_parts[2])
            actual = hashlib.pbkdf2_hmac(algo, pw_bytes, salt_text.encode("ascii"), iters)
            return _hmac.compare_digest(actual.hex(), key_hex.lower())
        except (ValueError, IndexError):
            return False

    # scrypt 或其他 werkzeug 格式不支援(檔案內理論上不會出現,因為先前就強制 pbkdf2)
    return False

from paths import data_dir
BASE_DIR = data_dir()
USERS_PATH = BASE_DIR / "users.json"
SESSION_KEY_PATH = BASE_DIR / ".session_key"
LOGIN_HISTORY_PATH = BASE_DIR / "login_history.jsonl"

log = logging.getLogger(__name__)

ROLES = ("admin", "readonly")
AUTH_SOURCES = ("local", "radius")


# ---------- Session key ----------

def ensure_session_key() -> bytes:
    """讀取或建立 Flask session 簽章用的隨機 key。"""
    if SESSION_KEY_PATH.exists():
        try:
            data = SESSION_KEY_PATH.read_bytes()
            if len(data) >= 32:
                return data
        except OSError:
            pass
    key = secrets.token_bytes(48)
    SESSION_KEY_PATH.write_bytes(key)
    try:
        os.chmod(SESSION_KEY_PATH, 0o600)
    except Exception:
        pass
    return key


# ---------- Users I/O ----------

def _load_users() -> dict:
    if not USERS_PATH.exists():
        return {}
    try:
        return json.loads(USERS_PATH.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as e:
        log.error("users.json 讀取失敗: %s", e)
        return {}


def _save_users(users: dict) -> None:
    tmp = USERS_PATH.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(users, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(USERS_PATH)
    try:
        os.chmod(USERS_PATH, 0o600)
    except Exception:
        pass


def _now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


# ---------- Bootstrap ----------

def ensure_default_users() -> None:
    """首次啟動時建立 admin / admin 與 viewer / viewer 兩組預設帳號。"""
    users = _load_users()
    if users:
        return
    users = {
        "admin": {
            "password_hash": generate_password_hash("admin@Hauman"),
            "role": "admin",
            "auth_source": "local",
            "created_at": _now_iso(),
            "last_login": None,
        },
        "viewer": {
            "password_hash": generate_password_hash("viewer@Hauman"),
            "role": "readonly",
            "auth_source": "local",
            "created_at": _now_iso(),
            "last_login": None,
        },
    }
    _save_users(users)
    log.warning("=" * 64)
    log.warning("首次啟動:已建立預設帳號")
    log.warning("  admin  / admin@Hauman    (管理員;可新增、修改、刪除)")
    log.warning("  viewer / viewer@Hauman   (唯讀;只能檢視)")
    log.warning("請盡速從 UI 修改預設密碼!")
    log.warning("=" * 64)


# ---------- Auth ----------

def verify_login(username: str, password: str,
                 mode: str = "local",
                 radius_cfg: dict | None = None,
                 default_role: str = "readonly") -> tuple[dict | None, str]:
    """驗證登入。回 (user_info_or_None, reason_str)。

    mode="local"  — 對 users.json 比對雜湊密碼
    mode="radius" — 用 hauman_radius 驗;成功後若 user 不存在則自動建立
                    (auth_source='radius', role=default_role)
    """
    if mode not in ("local", "radius"):
        return None, f"invalid_mode:{mode}"

    users = _load_users()
    existing = users.get(username)

    if mode == "radius":
        if not radius_cfg:
            return None, "radius_not_configured"
        try:
            from hauman_radius import verify_radius
        except ImportError:
            log.error("hauman_radius 套件未安裝")
            return None, "radius_lib_missing"
        try:
            ok = verify_radius(username, password, radius_cfg)
        except Exception as e:
            log.warning("RADIUS 驗證異常: %s", e)
            return None, f"radius_error:{type(e).__name__}"
        if not ok:
            return None, "invalid_credentials"

        # 若已有同名 local 帳號 → 拒絕(避免權限提升)
        if existing and existing.get("auth_source", "local") != "radius":
            return None, "username_conflict_with_local"

        if existing is None:
            # 自動建立 RADIUS 使用者
            role = default_role if default_role in ROLES else "readonly"
            users[username] = {
                "role": role,
                "auth_source": "radius",
                "created_at": _now_iso(),
                "last_login": _now_iso(),
            }
            log.info("首次 RADIUS 登入,自動建立帳號: %s [%s]", username, role)
        else:
            users[username]["last_login"] = _now_iso()
        try:
            _save_users(users)
        except OSError as e:
            log.warning("無法更新 users.json: %s", e)
        return {"username": username,
                "role": users[username].get("role", "readonly"),
                "auth_source": "radius"}, "ok"

    # ---- local ----
    if existing is None:
        return None, "invalid_credentials"
    if existing.get("auth_source", "local") == "radius":
        # 保護:此帳號綁定 RADIUS,不能走本地密碼
        return None, "local_login_forbidden_for_radius_user"
    pw_hash = existing.get("password_hash", "")
    if not pw_hash or not check_password_hash(pw_hash, password):
        return None, "invalid_credentials"
    existing["last_login"] = _now_iso()
    users[username] = existing
    try:
        _save_users(users)
    except OSError as e:
        log.warning("無法更新 last_login: %s", e)
    return {"username": username,
            "role": existing.get("role", "readonly"),
            "auth_source": existing.get("auth_source", "local")}, "ok"


# ---------- Login history ----------

def log_login_event(username: str, ip: str, success: bool,
                    user_agent: str = "", reason: str = "",
                    auth_mode: str = "local") -> None:
    entry = {
        "ts": _now_iso(),
        "user": username,
        "ip": ip,
        "success": success,
        "reason": reason,
        "auth_mode": auth_mode,
        "user_agent": (user_agent or "")[:240],
    }
    try:
        with LOGIN_HISTORY_PATH.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except OSError as e:
        log.warning("無法寫入 login_history: %s", e)


def clear_login_history() -> int:
    """清空登入紀錄檔,回傳原本的行數。"""
    if not LOGIN_HISTORY_PATH.exists():
        return 0
    try:
        with LOGIN_HISTORY_PATH.open("r", encoding="utf-8") as f:
            count = sum(1 for line in f if line.strip())
    except OSError:
        count = 0
    try:
        LOGIN_HISTORY_PATH.unlink()
    except OSError as e:
        log.warning("無法刪除 login_history: %s", e)
        raise
    return count


def read_login_history(limit: int = 200) -> list[dict]:
    if not LOGIN_HISTORY_PATH.exists():
        return []
    out: list[dict] = []
    try:
        with LOGIN_HISTORY_PATH.open("r", encoding="utf-8") as f:
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


# ---------- Users CRUD ----------

def list_users() -> list[dict]:
    users = _load_users()
    return [
        {
            "username": u,
            "role": info.get("role", "readonly"),
            "auth_source": info.get("auth_source", "local"),
            "created_at": info.get("created_at"),
            "last_login": info.get("last_login"),
        }
        for u, info in sorted(users.items())
    ]


def _admin_count(users: dict) -> int:
    return sum(1 for u in users.values() if u.get("role") == "admin")


def add_user(username: str, password: str, role: str,
             auth_source: str = "local") -> str | None:
    if not username or not username.strip():
        return "帳號不可為空"
    if role not in ROLES:
        return f"role 必須是 {' 或 '.join(ROLES)}"
    if auth_source not in AUTH_SOURCES:
        return f"auth_source 必須是 {' 或 '.join(AUTH_SOURCES)}"
    username = username.strip()
    users = _load_users()
    if username in users:
        return f"帳號「{username}」已存在"

    if auth_source == "local":
        if not password:
            return "密碼不可為空"
        if len(password) < 4:
            return "密碼長度至少 4 字元"
        users[username] = {
            "password_hash": generate_password_hash(password),
            "role": role,
            "auth_source": "local",
            "created_at": _now_iso(),
            "last_login": None,
        }
    else:
        # RADIUS 使用者:密碼由 RADIUS 管理,本地不存
        users[username] = {
            "role": role,
            "auth_source": "radius",
            "created_at": _now_iso(),
            "last_login": None,
        }
    _save_users(users)
    return None


def remove_user(username: str) -> str | None:
    users = _load_users()
    if username not in users:
        return f"帳號「{username}」不存在"
    if users[username].get("role") == "admin" and _admin_count(users) <= 1:
        return "不能移除最後一個 admin"
    del users[username]
    _save_users(users)
    return None


def change_password(username: str, new_password: str) -> str | None:
    if not new_password:
        return "新密碼不可為空"
    if len(new_password) < 4:
        return "密碼長度至少 4 字元"
    users = _load_users()
    if username not in users:
        return f"帳號「{username}」不存在"
    if users[username].get("auth_source") == "radius":
        return "此帳號由外部 RADIUS 認證,請到 RADIUS 系統修改密碼"
    users[username]["password_hash"] = generate_password_hash(new_password)
    _save_users(users)
    return None


def change_role(username: str, role: str) -> str | None:
    if role not in ROLES:
        return f"role 必須是 {' 或 '.join(ROLES)}"
    users = _load_users()
    if username not in users:
        return f"帳號「{username}」不存在"
    if (users[username].get("role") == "admin" and role != "admin"
            and _admin_count(users) <= 1):
        return "不能把最後一個 admin 降級"
    users[username]["role"] = role
    _save_users(users)
    return None
