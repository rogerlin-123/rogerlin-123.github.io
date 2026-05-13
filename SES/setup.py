import os
import yaml
import pyotp
import qrcode
from auth import AuthManager
from database import SESDatabase

def setup():
    print("=== Secure-Encrypted-Safe (SES) 初始化工具 ===")
    
    # 1. 定義路徑
    config_path = "config.yaml"
    db_path = "secure_vault.db"
    
    # 2. 產生 2FA 密鑰
    otp_secret = pyotp.random_base32()
    print(f"\n[1] 已產生隨機 2FA 密鑰: {otp_secret}")

    # 3. 產生 QR Code 圖片供手機掃描
    auth_mgr = AuthManager()
    uri = auth_mgr.get_totp_uri(otp_secret, username="root")
    img = qrcode.make(uri)
    qr_filename = "2fa_setup_qr.png"
    img.save(qr_filename)
    print(f"[2] 2FA 設置圖檔已儲存為: {qr_filename}")
    print("    請使用手機 Google Authenticator 掃描此圖片！")

    # 4. 準備預設設定
    default_config = {
        'server': {
            'host': '0.0.0.0',
            'port': 8888,
            'ssl_enabled': True,
            'cert_path': 'fullchain.pem',
            'key_path': 'privkey.pem'
        },
        'auth': {
            'default_user': 'root',
            'default_pass': 'root@0305',
            'otp_secret': otp_secret,
            'salt': 'SES_RANDOM_SALT_' + pyotp.random_base32()[:8]
        },
        'database': {
            'file_path': db_path,
            'backup_folder': './backups'
        }
    }

    # 5. 寫入 config.yaml
    with open(config_path, 'w', encoding='utf-8') as f:
        yaml.dump(default_config, f, default_flow_style=False)
    print(f"[3] 設定檔 {config_path} 已生成。")

    # 6. 初始化加密資料庫
    print("[4] 正在初始化加密資料庫...")
    # 使用預設密碼衍生出資料庫金鑰來建立檔案
    db_key = auth_mgr.derive_key(default_config['auth']['default_pass'])
    try:
        db = SESDatabase(db_path, db_key)
        print(f"    資料庫 {db_path} 已成功建立並鎖定。")
    except Exception as e:
        print(f"    資料庫建立失敗: {e}")

    print("\n=== 初始化完成 ===")
    print("提示：")
    print("1. 請確認手機已綁定 2FA。")
    print("2. 確保 SSL 憑證檔案路徑正確。")
    print("3. 執行 'python web.py' 啟動系統。")
    print(f"4. 為了安全，建議在掃描後刪除 {qr_filename}。")

if __name__ == "__main__":
    setup()