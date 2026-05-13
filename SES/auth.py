import hashlib
import pyotp
import qrcode
import io
import base64
from secrets import token_hex

class AuthManager:
    def __init__(self, salt="SES_DEFAULT_SALT_2026"):
        # Salt 建議存在 config.yaml，增加破解難度
        self.salt = salt.encode()

    def derive_key(self, password):
        """
        PBKDF2 演算法：將主密碼轉化為強大的資料庫密鑰
        """
        key = hashlib.pbkdf2_hmac(
            'sha256', 
            password.encode(), 
            self.salt, 
            200000 # 迭代次數，防止暴力破解
        )
        return key.hex()

    @staticmethod
    def generate_2fa_secret():
        """為新用戶產生隨機的 2FA 金鑰 (Base32)"""
        return pyotp.random_base32()

    @staticmethod
    def get_totp_uri(secret, username="root", issuer="Secure-Encrypted-Safe"):
        """產生用於手機 App 掃描的 URI"""
        return pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name=issuer)

    @staticmethod
    def generate_qr_code(uri):
        """將 URI 轉化為 Base64 圖片，方便在網頁顯示"""
        img = qrcode.make(uri)
        buf = io.BytesIO()
        img.save(buf, format='PNG')
        return base64.b64encode(buf.getvalue()).decode('utf-8')

    @staticmethod
    def verify_2fa(secret, code):
        """驗證手機輸入的 6 位數驗證碼"""
        totp = pyotp.totp.TOTP(secret)
        return totp.verify(code)

    @staticmethod
    def hash_password(password):
        """用於存儲在 config 的登入密碼雜湊(非資料庫密鑰)"""
        return hashlib.sha256(password.encode()).hexdigest()