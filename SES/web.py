from flask import Flask, render_template, request, redirect, url_for, session, flash
from auth import AuthManager
from database import SESDatabase
import yaml
import os

app = Flask(__name__)
app.secret_key = os.urandom(24) # 每次重啟都會更新，確保 Session 安全

# 讀取設定
with open("config.yaml", "r") as f:
    config = yaml.safe_load(f)

auth_mgr = AuthManager()
db = None # 初始資料庫連線為 None，直到解鎖

def is_logged_in():
    return 'authenticated' in session and session['authenticated']

@app.route('/')
def index():
    if not is_logged_in():
        return redirect(url_for('login'))
    return render_template('dashboard.html', user=config['auth']['default_user'])

@app.route('/login', methods=['GET', 'POST'])
def login():
    global db
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        otp_code = request.form.get('otp_code')

        # 1. 驗證基本帳密
        if username == config['auth']['default_user'] and password == config['auth']['default_pass']:
            # 2. 驗證 2FA (這裡假設 secret 已存在 config 或 db 中)
            # 實際開發時需處理首次綁定 2FA 的邏輯
            if auth_mgr.verify_2fa(config['auth']['otp_secret'], otp_code):
                # 3. 衍生金鑰並解鎖資料庫
                db_key = auth_mgr.derive_key(password)
                db = SESDatabase(config['database']['file_path'], db_key)
                
                session['authenticated'] = True
                return redirect(url_for('index'))
            else:
                flash("2FA 驗證碼錯誤")
        else:
            flash("帳號或密碼錯誤")
            
    return render_template('login.html')

@app.route('/vault')
def vault():
    if not is_logged_in(): return redirect(url_for('login'))
    # 從資料庫抓取資料 (需在 database.py 實作 get_all_entries)
    items = db.get_all_entries() if db else []
    return render_template('vault.html', items=items)

@app.route('/logout')
def logout():
    global db
    session.clear()
    db = None # 登出後切斷資料庫連線，記憶體清除金鑰
    return redirect(url_for('login'))

if __name__ == '__main__':
    # 讀取 Port 並執行 HTTPS
    app.run(
        host=config['server']['host'],
        port=config['server']['port'],
        ssl_context=(config['server']['cert_path'], config['server']['key_path'])
    )