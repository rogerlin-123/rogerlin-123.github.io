🛡️ Secure-Encrypted-Safe (SES)

專業級安全加密帳密保險箱 (Linux/Ubuntu 專用)

這是一個專為 Linux 伺服器設計的自動化帳密管理系統，架構參考 SHM 模式。系統採用 SQLCipher 全資料庫加密、PBKDF2 密鑰衍生技術，並強制整合 Google Authenticator (2FA) 驗證，確保即使在資料庫檔案外洩或伺服器遭入侵時，數據依然具備極高的防護性。

🌟 核心特色

全資料庫加密：使用 SQLCipher (AES-256) 進行透明加密，檔案在硬碟上完全無法以一般 SQLite 工具讀取。

高強度金鑰衍生：主密碼不直接存儲，透過 PBKDF2-HMAC-SHA256 進行 200,000 次運算衍生出資料庫金鑰。

雙重驗證 (2FA)：整合 TOTP 協定，需輸入手機 Google Authenticator 驗證碼方可解鎖。

版本控制 (時光機)：自動記錄每個項目的前 20 次修改歷史，支援一鍵還原舊紀錄。

SHM 風格介面：具備現代化側邊導覽欄，支援「一鍵複製」密碼至剪貼簿功能。

自動化部署：內建 Systemd 腳本，支援開機啟動與崩潰自動重啟。

📂 專案結構

| 檔案名稱 | 職責說明 |
| web.py | Flask 主程式，處理 HTTPS 路由與介面操作。 |
| database.py | SQLCipher 接口，包含資料表結構與自動備份邏輯。 |
| auth.py | 安全核心：負責密鑰衍生 (PBKDF2) 與 2FA 驗證。 |
| setup.py | 初始化腳本：產生 2FA QR Code、Salt、以及初始加密庫。 |
| config.yaml | 系統設定檔 (包含 Port 8888、SSL 憑證路徑等)。 |
| install-systemd.sh | 一鍵安裝為系統服務 (Service) 的腳本。 |
| templates/ | 前端 HTML 模板 (Layout, Vault, Login, Dashboard)。 |
| backups/ | 自動產生的加密資料庫備份複本存放區。 |

🚀 部署步驟

1. 系統環境準備 (Ubuntu)

sudo apt update
sudo apt install python3-venv python3-full libsqlcipher-dev build-essential python3-dev



2. 建立虛擬環境與安裝套件

# 建立虛擬環境
python3 -m venv venv

# 啟動虛擬環境
source venv/bin/activate

# 安裝依賴套件
pip install pysqlcipher3 pyyaml pyotp qrcode[pil] Flask



3. 初始化系統 (產生 2FA)

執行初始化腳本，系統會產生 config.yaml 與掃描用的 QR Code 圖檔：

python setup.py



重要：請使用手機掃描產生的 2fa_setup_qr.png，完成後請務必從伺服器上刪除該圖片。

4. 設定 SSL 與 Port

編輯 config.yaml 確認以下資訊：

port: 8888

cert_path: (您的 .pem 憑證完整路徑)

key_path: (您的 .key 私鑰完整路徑)

防火牆開啟：sudo ufw allow 8888

5. 安裝為 Systemd 服務

chmod +x install-systemd.sh
./install-systemd.sh



🛠️ 管理與操作

服務指令

啟動：sudo systemctl start ses-safe

狀態：sudo systemctl status ses-safe

重啟：sudo systemctl restart ses-safe

查看日誌：sudo journalctl -u ses-safe -f

預設帳密

帳號：root

密碼：root@0305

注意：首次進入系統後，請務必立即前往設定修改預設密碼。

資料庫欄位定義

項目：目標網站或系統名稱。

使用者帳號：登入用的 Username 或 Email。

使用者代碼：如員工編號或輔助識別碼。

使用者密碼：加密存放的密碼。

更新日期：新增/修改時系統自動記錄。

備註：額外說明細節。

⚠️ 安全警告

手動解鎖機制：本系統設計為「每次服務重啟後，必須手動登入一次」以解鎖資料庫。這是為了避免加密金鑰以明文形式存在伺服器硬碟上。

備份安全：backups/ 內的檔案雖已由 SQLCipher 加密，但仍建議定期搬移至離線裝置異地儲存。

2FA 密鑰保管：請妥善保存 config.yaml 中的 otp_secret，萬一手機遺失，需依此密鑰才能在新的手機上恢復 2FA 驗證碼。

Developed for secure password management at https://secure.rogerlin.xyz:8888