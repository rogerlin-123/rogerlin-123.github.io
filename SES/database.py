import sqlite3
from pysqlcipher3 import dbapi2 as sqlcipher
import datetime
import os
import shutil

class SESDatabase:
    def __init__(self, db_path, password):
        self.db_path = db_path
        self.password = password
        self.conn = None
        self.setup_db()

    def get_connection(self):
        """建立並解鎖 SQLCipher 連線"""
        try:
            conn = sqlcipher.connect(self.db_path)
            # 這是 SQLCipher 的核心：輸入主密碼解鎖
            conn.execute(f"PRAGMA key = '{self.password}'")
            conn.execute("PRAGMA cipher_compatibility = 4")
            return conn
        except Exception as e:
            print(f"資料庫解鎖失敗: {e}")
            return None

    def setup_db(self):
        """初始化資料表結構與觸發器"""
        conn = self.get_connection()
        cursor = conn.cursor()

        # 1. 主密碼表 (符合您的 6 個欄位)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vault (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                item TEXT NOT NULL,
                username TEXT,
                user_code TEXT,
                password TEXT NOT NULL,
                updated_at DATETIME,
                remarks TEXT
            )
        ''')

        # 2. 歷史紀錄表 (儲存舊紀錄)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                vault_id INTEGER,
                item TEXT,
                username TEXT,
                user_code TEXT,
                password TEXT,
                updated_at DATETIME,
                remarks TEXT,
                archived_at DATETIME
            )
        ''')

        # 3. 建立觸發器：當 vault 修改時，自動把舊資料塞入 history
        cursor.execute('''
            CREATE TRIGGER IF NOT EXISTS archive_old_version
            BEFORE UPDATE ON vault
            BEGIN
                INSERT INTO history (vault_id, item, username, user_code, password, updated_at, remarks, archived_at)
                VALUES (OLD.id, OLD.item, OLD.username, OLD.user_code, OLD.password, OLD.updated_at, OLD.remarks, datetime('now'));
            END
        ''')
        
        # 4. 建立觸發器：保持 history 只有最近 20 筆 (針對每個項目)
        cursor.execute('''
            CREATE TRIGGER IF NOT EXISTS limit_history_size
            AFTER UPDATE ON vault
            BEGIN
                DELETE FROM history 
                WHERE id IN (
                    SELECT id FROM history 
                    WHERE vault_id = OLD.id 
                    ORDER BY archived_at DESC 
                    LIMIT -1 OFFSET 20
                );
            END
        ''')

        conn.commit()
        conn.close()

    def backup_db(self, backup_dir="backups"):
        """備份加密檔案"""
        if not os.path.exists(backup_dir):
            os.makedirs(backup_dir)
        
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = os.path.join(backup_dir, f"ses_vault_{timestamp}.db.bak")
        shutil.copy2(self.db_path, backup_path)
        return backup_path

    def add_entry(self, item, username, user_code, password, remarks):
        """新增帳密項目"""
        conn = self.get_connection()
        cursor = conn.cursor()
        now = datetime.datetime.now()
        cursor.execute('''
            INSERT INTO vault (item, username, user_code, password, updated_at, remarks)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (item, username, user_code, password, now, remarks))
        conn.commit()
        conn.close()
        # 每次變動後執行備份
        self.backup_db()
        