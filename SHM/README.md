# run-linux/ — Linux source-run + systemd 服務

> 對應 Windows `run.bat` / macOS `run-macos/`,**不需要編譯執行檔**,直接用系統 Python 跑。
> 自包含資料夾,整個 copy 到 Linux 主機就能用。

---

## 兩種執行模式

| 模式 | 用法 | 適合 |
|------|------|------|
| 互動模式 | `./run.sh` | 開發、測試、人工偶爾跑 |
| **systemd 服務** | `sudo ./install-systemd.sh` | **生產環境**(開機自啟、當機重啟) |

---

## 第一次安裝(快速版)

```bash
# 1. 把整個 run-linux/ 資料夾複製到 Linux 主機
#    rsync -av run-linux/ user@server:/home/user/shm/

# 2. 確認 Python 版本(建議 3.10+)
python3 --version

# 沒裝就先裝:
sudo apt install python3 python3-venv python3-pip   # Ubuntu/Debian
sudo dnf install python3 python3-pip                # RHEL/Fedora

# 3. 給腳本執行權限
cd /home/user/shm
chmod +x run.sh stop.sh run-debug.sh install-systemd.sh uninstall-systemd.sh

# 4a. 互動模式試跑
./run.sh

# 4b. 或直接安裝成系統服務
sudo ./install-systemd.sh
```

`install-systemd.sh` 會自動:
1. 偵測 / 建立 venv 並裝依賴
2. 自動掃 hauman_radius wheel(`./hauman_radius/`、`~/Downloads/`、`$HAUMAN_RADIUS_WHL`)
3. 設定 `chown -R $SERVICE_USER` 給服務帳號
4. 用 template 產生 `/etc/systemd/system/system-health-monitor.service`(替換 `__SERVICE_USER__` / `__INSTALL_DIR__`)
5. `systemctl daemon-reload && enable --now system-health-monitor`
6. 印出 Web UI 網址、管理指令、防火牆指令

---

## 資料夾內容

```
run-linux/
├─ README.md                          本檔
├─ run.sh                              互動啟動(自動建 venv + 開瀏覽器)
├─ stop.sh                             互動停止
├─ run-debug.sh                        前景除錯(看即時輸出)
├─ install-systemd.sh                  註冊成 systemd 服務
├─ uninstall-systemd.sh                移除 systemd 服務
├─ systemd/
│   └─ system-health-monitor.service.template   systemd unit 範本
│
│ 以下由 pack-run-linux.bat (Windows 端) 從 project root 同步進來:
├─ monitor.py / web.py / checker.py / notifier.py
├─ auth.py / events.py / paths.py
├─ requirements.txt
├─ config.yaml
└─ static/
    ├─ logo.png
    └─ favicon.ico

執行後產生:
├─ .venv/                              Python virtualenv
├─ users.json / state.json / monitor.log
├─ monitor_events.jsonl / login_history.jsonl
├─ .session_key / monitor.pid / startup_error.log
```

---

## systemd 服務管理 cheat sheet

```bash
# 狀態
sudo systemctl status  system-health-monitor

# 起 / 停 / 重啟
sudo systemctl start   system-health-monitor
sudo systemctl stop    system-health-monitor
sudo systemctl restart system-health-monitor

# log(類似 tail -f)
sudo journalctl -u system-health-monitor -f

# 程式自己寫的 log
tail -f monitor.log

# 開機自啟切換
sudo systemctl enable  system-health-monitor   # 開
sudo systemctl disable system-health-monitor   # 關

# 移除
sudo ./uninstall-systemd.sh
```

---

## 防火牆放行(若要區網連)

```bash
# Ubuntu/Debian (ufw)
sudo ufw allow 5192/tcp

# RHEL/CentOS/Fedora (firewalld)
sudo firewall-cmd --permanent --add-port=5192/tcp
sudo firewall-cmd --reload

# 純 iptables(不持久,重開機消失)
sudo iptables -I INPUT -p tcp --dport 5192 -j ACCEPT
```

port 預設 5192,改 `config.yaml` 的 `web_port` 之後改防火牆規則 + `sudo systemctl restart system-health-monitor`。

---

## 預設帳號

第一次啟動會自動建:

| 帳號 | 密碼 | 角色 |
|------|------|------|
| `admin` | `admin@Hauman` | 管理員(全部操作) |
| `viewer` | `viewer@Hauman` | 唯讀(只能看) |

⚠️ **登入後立即到頭像 → 更改密碼**

---

## 疑難排解

**Q: `./run.sh` 跑不起來,Permission denied**
A: `chmod +x run.sh stop.sh run-debug.sh install-systemd.sh uninstall-systemd.sh`

**Q: `python3 -m venv` 失敗(Ubuntu/Debian)**
A: `sudo apt install python3-venv`

**Q: `pip install` 過程中某個 wheel 編譯失敗**
A: 通常是缺 build deps:
```bash
sudo apt install build-essential libffi-dev libssl-dev    # Ubuntu/Debian
sudo dnf install gcc python3-devel openssl-devel libffi-devel  # RHEL/Fedora
```

**Q: 服務一直 `activating (auto-restart)`**
A: 看完整錯誤:
```bash
sudo journalctl -u system-health-monitor --no-pager -n 100
sudo systemctl status system-health-monitor
cat monitor.log | tail -50
cat startup_error.log
```

**Q: 無 GUI 環境,瀏覽器沒自動開**
A: 正常 — `./run.sh` 偵測到沒 `$DISPLAY` 就跳過。從別台機器用瀏覽器連 `http://<server-ip>:5192`

**Q: 預設帳號密碼忘了**
A: `rm users.json && sudo systemctl restart system-health-monitor`,會回到預設

**Q: 想完全砍掉重來**
A:
```bash
sudo ./uninstall-systemd.sh
rm -rf .venv users.json state.json .session_key
rm -f  monitor.log monitor.pid monitor_events.jsonl login_history.jsonl
```

**Q: ICMP / ping check 全部失敗(monitor.log 噴「ping 權限不足」)**
A: systemd 服務模式下,`NoNewPrivileges=true` 會擋 setuid ping。三選一:

```bash
# 方案 1(推薦):把 ping 改用 file capability,不靠 setuid
sudo setcap cap_net_raw+ep $(readlink -f $(which ping))
getcap $(readlink -f $(which ping))   # 確認:cap_net_raw=ep
sudo systemctl restart system-health-monitor

# 方案 2:在 systemd unit 加 CAP_NET_RAW
sudo systemctl edit system-health-monitor
# 加入:
#   [Service]
#   AmbientCapabilities=CAP_NET_RAW
#   CapabilityBoundingSet=CAP_NET_RAW CAP_AUDIT_WRITE
sudo systemctl daemon-reload && sudo systemctl restart system-health-monitor

# 方案 3:確認 unprivileged ping 開著
cat /proc/sys/net/ipv4/ping_group_range
# 應該是 "0  2147483647";若是 "1  0",修:
echo "net.ipv4.ping_group_range = 0 2147483647" | sudo tee /etc/sysctl.d/99-shm.conf
sudo sysctl -p /etc/sysctl.d/99-shm.conf
```

驗證(以服務帳號身分跑 ping):
```bash
sudo -u $(grep '^User=' /etc/systemd/system/system-health-monitor.service | cut -d= -f2) \
    ping -c 1 -W 2 8.8.8.8
```

**Q: monitor.log 噴「找不到 ping 指令」**
A: 系統沒裝 ping。
```bash
sudo apt install iputils-ping   # Debian/Ubuntu
sudo dnf install iputils        # RHEL/Fedora
sudo apk add iputils            # Alpine
```

---

## 給 Windows 端維護者

這裡的 `*.py` / `static/` / `requirements.txt` / `config.yaml` 不要手動編輯。
它們是由 project root 的 `pack-run-linux.bat` 同步進來的(也在 `.gitignore`)。

修改源碼流程:
1. 在 project root 編輯 `monitor.py` / `web.py` / ...
2. 雙擊 `pack-run-linux.bat` 重新同步
3. 把整個 `run-linux/` 資料夾交給 Linux 端(rsync / Google Drive / scp)
4. Linux 端執行 `sudo ./install-systemd.sh`(或 `sudo systemctl restart system-health-monitor` 若已安裝)
