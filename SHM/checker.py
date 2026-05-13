"""連線檢測模組 — 支援 TCP / ICMP / HTTP GET。"""
from __future__ import annotations

import logging
import platform
import re
import socket
import subprocess
import time
from dataclasses import dataclass

# SSL 驗證策略(2026-05 修整,降低 AV 隔離率):
# - 不再使用 truststore.inject_into_ssl()(該 API 替換 Python ssl 模組行為,
#   是 RAT/MITM 工具的高風險 fingerprint,Defender ML 模型直接打負分)
# - HTTP check 預設**不驗證 SSL**(verify_ssl=False),這是健康檢查場景下
#   合理的選擇:目的是確認服務可達 + 回應 200,不是檢查憑證鏈的真偽
# - 若使用者明確設定 verify_ssl: true(per-check),才走 certifi 預設驗證
# - urllib3 的 InsecureRequestWarning 一律靜音(避免 log 洗版)
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

_log = logging.getLogger(__name__)
_log.info("HTTP check 預設不驗證 SSL(verify_ssl=False),per-check 可改 true 啟用驗證")


@dataclass
class CheckResult:
    ok: bool
    latency_ms: float
    error: str


# --------------------------------------------------------------- TCP

def check_tcp(host: str, port: int, timeout: float) -> CheckResult:
    start = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            latency = (time.perf_counter() - start) * 1000.0
            return CheckResult(True, round(latency, 1), "")
    except socket.timeout:
        return CheckResult(False, 0.0, f"連線逾時 ({timeout}s)")
    except ConnectionRefusedError:
        return CheckResult(False, 0.0, "Connection refused")
    except socket.gaierror as e:
        return CheckResult(False, 0.0, f"DNS 解析失敗: {e}")
    except OSError as e:
        return CheckResult(False, 0.0, f"{type(e).__name__}: {e}")


# --------------------------------------------------------------- ICMP

_IS_WINDOWS = platform.system().lower() == "windows"
# Windows 中文 / 英文 ping 輸出的延遲擷取:time=1ms / 時間=1ms / time<1ms
_PING_LATENCY_PAT = re.compile(r"(?:time|時間)[<=]\s*(\d+(?:\.\d+)?)\s*ms", re.IGNORECASE)


def check_icmp(host: str, timeout: float) -> CheckResult:
    """以系統 ping 指令做 ICMP echo。Windows 用 ping -n;POSIX 用 ping -c -W。
    通常不需要 root —— 現代 Linux 用 cap_net_raw file capability(/bin/ping)。
    """
    timeout_ms = max(100, int(timeout * 1000))
    timeout_sec = max(1, int(timeout))

    # creationflags 是 Windows-only,POSIX 不傳避免 DeprecationWarning
    run_kwargs = dict(capture_output=True, timeout=timeout + 2)
    if _IS_WINDOWS:
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), host]
        run_kwargs["creationflags"] = 0x08000000  # CREATE_NO_WINDOW — 不跳出黑視窗
    else:
        cmd = ["ping", "-c", "1", "-W", str(timeout_sec), host]

    start = time.perf_counter()
    try:
        proc = subprocess.run(cmd, **run_kwargs)
    except subprocess.TimeoutExpired:
        return CheckResult(False, 0.0, f"ping 逾時 ({timeout}s)")
    except FileNotFoundError:
        return CheckResult(False, 0.0,
            "找不到 ping 指令(Alpine: apk add iputils;Debian: apt install iputils-ping)")
    except OSError as e:
        return CheckResult(False, 0.0, f"{type(e).__name__}: {e}")

    # Windows cp950 / Linux utf-8 都試一次,避免中文亂碼讓正規式抓不到
    raw = proc.stdout + proc.stderr
    text = raw.decode("utf-8", errors="replace")
    if _IS_WINDOWS and "\ufffd" in text:
        try:
            text = raw.decode("cp950", errors="replace")
        except Exception:
            pass

    # Windows ping 即使目標不可達 return code 仍可能是 0,需看輸出判斷
    if _IS_WINDOWS:
        # 成功跡象:有 TTL= 字樣(等於收到 echo reply)
        if "TTL=" not in text and "ttl=" not in text:
            # 常見失敗訊息
            if "無法連線" in text or "Destination host unreachable" in text:
                return CheckResult(False, 0.0, "Destination unreachable")
            if "要求已逾時" in text or "Request timed out" in text:
                return CheckResult(False, 0.0, "Request timed out")
            if "找不到主機" in text or "could not find host" in text.lower():
                return CheckResult(False, 0.0, "DNS 解析失敗")
            return CheckResult(False, 0.0, "ping 失敗")
    else:
        if proc.returncode != 0:
            # Linux ping 失敗時帶實際 stderr 訊息,方便診斷
            err_low = text.lower()
            if "operation not permitted" in err_low or "permission denied" in err_low:
                # 通常是 systemd 服務模式下 NoNewPrivileges + setuid ping 衝突,
                # 或 net.ipv4.ping_group_range 設定不對。修法:
                #   sudo setcap cap_net_raw+ep $(readlink -f $(which ping))
                # 或 unit file 加 AmbientCapabilities=CAP_NET_RAW
                return CheckResult(False, 0.0,
                    "ping 權限不足(systemd 服務可能需要 cap_net_raw 或 AmbientCapabilities)")
            if "name or service not known" in err_low \
               or "temporary failure in name resolution" in err_low \
               or "unknown host" in err_low:
                return CheckResult(False, 0.0, "DNS 解析失敗")
            if "network is unreachable" in err_low \
               or "destination host unreachable" in err_low \
               or "no route to host" in err_low:
                return CheckResult(False, 0.0, "Destination unreachable")
            # 一般失敗 — 把 ping 的實際輸出最後一行帶出來方便診斷
            last_line = ""
            for line in reversed(text.strip().splitlines()):
                line = line.strip()
                if line:
                    last_line = line[:120]
                    break
            return CheckResult(False, 0.0, f"ping 失敗: {last_line}" if last_line else "ping 失敗")

    match = _PING_LATENCY_PAT.search(text)
    if match:
        return CheckResult(True, round(float(match.group(1)), 1), "")
    # 抓不到延遲就用本地計時當後備
    latency = (time.perf_counter() - start) * 1000.0
    return CheckResult(True, round(latency, 1), "")


# --------------------------------------------------------------- DNS

_DNS_RECORD_TYPES = ("A", "AAAA", "CNAME", "MX", "TXT", "NS", "PTR")


def check_dns(
    hostname: str,
    timeout: float,
    dns_server: str = "",
    record_type: str = "A",
    expect_ip: str = "",
) -> CheckResult:
    """DNS 解析檢查。可指定查詢伺服器(否則用系統 resolver)與記錄型別。
    - 查到任一筆記錄 → OK,latency 為查詢耗時,error 留空
    - 指定 expect_ip 時回應必須含該 IP(僅 A/AAAA)
    """
    try:
        import dns.resolver
        import dns.exception
    except ImportError:
        return CheckResult(False, 0.0, "dnspython 未安裝")

    rtype = (record_type or "A").upper()
    if rtype not in _DNS_RECORD_TYPES:
        return CheckResult(False, 0.0, f"不支援的 record type: {rtype}")

    resolver = dns.resolver.Resolver(configure=True)
    if dns_server:
        resolver.nameservers = [dns_server]
    resolver.lifetime = timeout
    resolver.timeout = timeout

    start = time.perf_counter()
    try:
        answer = resolver.resolve(hostname, rtype)
    except dns.resolver.NXDOMAIN:
        return CheckResult(False, 0.0, "NXDOMAIN(找不到該網域)")
    except dns.resolver.NoAnswer:
        return CheckResult(False, 0.0, f"無 {rtype} 記錄")
    except dns.resolver.NoNameservers:
        return CheckResult(False, 0.0, "所有 DNS 伺服器都無法回應")
    except dns.exception.Timeout:
        return CheckResult(False, 0.0, f"查詢逾時 ({timeout}s)")
    except Exception as e:
        return CheckResult(False, 0.0, f"{type(e).__name__}: {str(e)[:120]}")

    latency = (time.perf_counter() - start) * 1000.0
    records = [r.to_text() for r in answer]

    if expect_ip and rtype in ("A", "AAAA"):
        if expect_ip not in records:
            return CheckResult(False, round(latency, 1),
                               f"回應未包含期望的 IP {expect_ip} (實際: {', '.join(records[:3])})")

    return CheckResult(True, round(latency, 1), "")


# --------------------------------------------------------------- HTTP GET

def check_http(
    url: str,
    timeout: float,
    expect_status: int | None = None,
    verify_ssl: bool = False,   # 預設不驗證(健康檢查場景合理選擇)
) -> CheckResult:
    """HTTP GET 檢測。
    - 預設接受 2xx / 3xx
    - 指定 expect_status 時必須完全相符
    - SSL 驗證預設**關閉**(verify_ssl=False);per-check 可改 True 啟用
    """
    start = time.perf_counter()
    try:
        r = requests.get(
            url,
            timeout=timeout,
            allow_redirects=True,
            verify=verify_ssl,
            headers={"User-Agent": "tcp_monitor/1.0 (health check)"},
        )
    except requests.exceptions.SSLError as e:
        msg = str(e)
        # 台灣常見情形:cert 由 TWCA 簽,瀏覽器信任但 Python certifi 不含
        if "unable to get local issuer certificate" in msg:
            short = "憑證鏈不被信任 (可能是 TWCA 等區域 CA;可勾選「跳過 SSL 驗證」)"
        elif "certificate has expired" in msg:
            short = "憑證已過期"
        elif "hostname" in msg.lower():
            short = "憑證 hostname 不符"
        else:
            short = str(e)[:200]
        return CheckResult(False, 0.0, f"SSL 錯誤: {short}")
    except requests.exceptions.ConnectTimeout:
        return CheckResult(False, 0.0, f"連線逾時 ({timeout}s)")
    except requests.exceptions.ReadTimeout:
        return CheckResult(False, 0.0, f"讀取逾時 ({timeout}s)")
    except requests.exceptions.ConnectionError as e:
        msg = str(e)[:200] or "連線失敗"
        return CheckResult(False, 0.0, f"連線失敗: {msg}")
    except requests.exceptions.InvalidURL:
        return CheckResult(False, 0.0, "URL 格式錯誤")
    except requests.RequestException as e:
        return CheckResult(False, 0.0, f"{type(e).__name__}: {str(e)[:200]}")

    latency = (time.perf_counter() - start) * 1000.0
    code = r.status_code

    if expect_status is not None:
        if code != int(expect_status):
            return CheckResult(False, round(latency, 1),
                               f"HTTP {code} (預期 {expect_status})")
    elif not (200 <= code < 400):
        return CheckResult(False, round(latency, 1), f"HTTP {code}")

    return CheckResult(True, round(latency, 1), "")


# --------------------------------------------------------------- 分派

def check(target: dict, timeout: float) -> CheckResult:
    """根據 target['type'] 路由到對應檢測函式。預設 tcp 以保持向後相容。"""
    ttype = (target.get("type") or "tcp").lower()
    try:
        if ttype == "icmp":
            return check_icmp(target["host"], timeout)
        if ttype == "http":
            return check_http(
                target["url"],
                timeout,
                expect_status=target.get("expect_status"),
                verify_ssl=bool(target.get("verify_ssl", False)),  # 預設不驗證
            )
        if ttype == "dns":
            return check_dns(
                target["hostname"],
                timeout,
                dns_server=str(target.get("dns_server", "")),
                record_type=str(target.get("record_type", "A")),
                expect_ip=str(target.get("expect_ip", "")),
            )
        # tcp (default)
        return check_tcp(target["host"], int(target["port"]), timeout)
    except KeyError as e:
        return CheckResult(False, 0.0, f"缺少必要欄位: {e}")
    except (TypeError, ValueError) as e:
        return CheckResult(False, 0.0, f"欄位錯誤: {e}")


def target_address(target: dict) -> str:
    """給 UI / log / 訊息顯示用的位址字串。"""
    ttype = (target.get("type") or "tcp").lower()
    if ttype == "icmp":
        return target.get("host", "?")
    if ttype == "http":
        return target.get("url", "?")
    return f"{target.get('host', '?')}:{target.get('port', '?')}"


def target_key(target: dict) -> str:
    """舊版單檢查 target 的 state 鍵(向後相容用)。"""
    ttype = (target.get("type") or "tcp").lower()
    name = target.get("name", "")
    if ttype == "icmp":
        return f"{name}#icmp:{target.get('host','')}"
    if ttype == "http":
        return f"{name}#http:{target.get('url','')}"
    return f"{name}@{target.get('host','')}:{target.get('port','')}"


# ----- 新版:一個 target 可以掛多個 check -----

def _normalize_check(c: dict) -> dict | None:
    """把單一 check dict 清理成標準形式。回 None 表示資料不合法。"""
    if not isinstance(c, dict):
        return None
    ttype = (c.get("type") or "tcp").lower()
    # enabled 預設為 True,只有明確寫 false 才算停用
    enabled = c.get("enabled", True) is not False

    base: dict = {}
    if ttype == "tcp":
        host = str(c.get("host", "")).strip()
        try:
            port = int(c.get("port"))
        except (TypeError, ValueError):
            return None
        if not host or not (1 <= port <= 65535):
            return None
        base = {"type": "tcp", "host": host, "port": port}
    elif ttype == "icmp":
        host = str(c.get("host", "")).strip()
        if not host:
            return None
        base = {"type": "icmp", "host": host}
    elif ttype == "http":
        url = str(c.get("url", "")).strip()
        if not url:
            return None
        base = {"type": "http", "url": url}
        es = c.get("expect_status")
        if es not in (None, "", 0):
            try:
                es_i = int(es)
                if 100 <= es_i <= 599:
                    base["expect_status"] = es_i
            except (TypeError, ValueError):
                pass
        # verify_ssl 預設 False(不驗);使用者明確設 True 才寫進 base
        if c.get("verify_ssl") is True:
            base["verify_ssl"] = True
    elif ttype == "dns":
        hostname = str(c.get("hostname", "")).strip()
        if not hostname:
            return None
        base = {"type": "dns", "hostname": hostname}
        rtype = str(c.get("record_type", "A")).strip().upper() or "A"
        if rtype in _DNS_RECORD_TYPES and rtype != "A":
            base["record_type"] = rtype  # 只有非 A 才顯式寫,YAML 乾淨些
        dns_server = str(c.get("dns_server", "")).strip()
        if dns_server:
            base["dns_server"] = dns_server
        expect_ip = str(c.get("expect_ip", "")).strip()
        if expect_ip:
            base["expect_ip"] = expect_ip
    else:
        return None

    # 只有停用時才顯式寫入 enabled 欄位,避免把乾淨的 YAML 塞滿 enabled: true
    if not enabled:
        base["enabled"] = False

    # 個別覆寫(留空即繼承全域;只有值為正整數/浮點才保留)
    for fld, caster, predicate in [
        ("check_interval_seconds", int, lambda v: v >= 1),
        ("tcp_timeout_seconds", float, lambda v: v > 0),
        ("failure_threshold", int, lambda v: v >= 1),
        ("recovery_threshold", int, lambda v: v >= 1),
        ("reminder_interval_minutes", int, lambda v: v >= 0),
    ]:
        if fld in c and c[fld] not in (None, "", 0) or (fld == "reminder_interval_minutes" and c.get(fld) == 0):
            try:
                v = caster(c[fld])
                if predicate(v):
                    base[fld] = v
            except (TypeError, ValueError):
                pass
    return base


def normalize_targets(raw: list) -> list[dict]:
    """把 config['targets'] 轉成統一格式 [{name, checks: [...]}]。

    支援兩種輸入:
    - 新版:{name, checks: [{type, ...}, ...]} — 允許 checks 為空陣列(目標佔位)
    - 舊版(單檢查):{name, type, host, port, ...} → 自動包一層
    """
    out: list[dict] = []
    for t in (raw or []):
        if not isinstance(t, dict):
            continue
        name = str(t.get("name", "")).strip()
        if not name:
            continue

        if isinstance(t.get("checks"), list):
            # 新版格式:允許空 checks 陣列(使用者先建立目標、稍後再加檢查)
            checks = [c for c in (_normalize_check(c) for c in t["checks"]) if c]
            out.append({"name": name, "checks": checks})
        else:
            # 舊版單檢查格式,整個 target 就是一個 check
            single = _normalize_check(t)
            if single:
                out.append({"name": name, "checks": [single]})
    return out


def check_key(target_name: str, check: dict) -> str:
    """state.json 的唯一鍵,格式:{target_name}::{type}:{address}。"""
    ttype = check.get("type", "tcp")
    if ttype == "icmp":
        return f"{target_name}::icmp:{check.get('host','')}"
    if ttype == "http":
        return f"{target_name}::http:{check.get('url','')}"
    if ttype == "dns":
        return (f"{target_name}::dns:{check.get('hostname','')}/"
                f"{check.get('record_type','A')}"
                + (f"@{check.get('dns_server','')}" if check.get('dns_server') else ""))
    return f"{target_name}::tcp:{check.get('host','')}:{check.get('port','')}"


def check_address(check: dict) -> str:
    """給 UI / 訊息顯示的位址字串。"""
    ttype = check.get("type", "tcp")
    if ttype == "icmp":
        return check.get("host", "?")
    if ttype == "http":
        return check.get("url", "?")
    if ttype == "dns":
        host = check.get("hostname", "?")
        server = check.get("dns_server", "")
        rtype = check.get("record_type", "A")
        return f"{host} [{rtype}]" + (f" @ {server}" if server else "")
    return f"{check.get('host','?')}:{check.get('port','?')}"


def migrate_state_keys(state: dict) -> dict:
    """把舊格式 state key 轉成新格式,確保累積的 consecutive 計數不歸零。
    舊:  Name@host:port              → Name::tcp:host:port
    舊:  Name#icmp:host               → Name::icmp:host
    舊:  Name#http:url                → Name::http:url
    """
    migrated = {}
    for k, v in state.items():
        if "::" in k:
            migrated[k] = v
            continue
        if "#icmp:" in k:
            migrated[k.replace("#icmp:", "::icmp:", 1)] = v
            continue
        if "#http:" in k:
            migrated[k.replace("#http:", "::http:", 1)] = v
            continue
        # name@host:port
        if "@" in k:
            try:
                name, rest = k.split("@", 1)
                host, port = rest.rsplit(":", 1)
                int(port)
                migrated[f"{name}::tcp:{host}:{port}"] = v
                continue
            except (ValueError, IndexError):
                pass
        migrated[k] = v
    return migrated
