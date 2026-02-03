import sqlite3
import os
import base64
from datetime import datetime

class DBManager:
    def __init__(self, db_name="chat_history.db"):
        self.db_name = db_name
        self.init_db()

    def _get_connection(self):
        return sqlite3.connect(self.db_name, check_same_thread=False)

    def init_db(self):
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                content TEXT,
                type TEXT,
                file_path TEXT,
                is_sent INTEGER,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        conn.commit()
        conn.close()

    def _simple_encrypt(self, text):
        if text is None: return None
        key = 123 
        chars = bytearray(text.encode('utf-8'))
        encrypted = bytearray(b ^ key for b in chars)
        return base64.b64encode(encrypted).decode('utf-8')

    def _simple_decrypt(self, text):
        if text is None: return None
        try:
            decoded = base64.b64decode(text)
            key = 123
            decrypted = bytearray(b ^ key for b in decoded)
            return decrypted.decode('utf-8')
        except:
            return "[Error Decrypting]"

    def save_message(self, content, msg_type="text", file_path=None, is_sent=1):
        conn = self._get_connection()
        cursor = conn.cursor()
        
        enc_content = self._simple_encrypt(content)
        enc_file_path = self._simple_encrypt(file_path)
        
        cursor.execute('''
            INSERT INTO messages (content, type, file_path, is_sent)
            VALUES (?, ?, ?, ?)
        ''', (enc_content, msg_type, enc_file_path, is_sent))
        
        conn.commit()
        conn.close()

    def load_messages(self, limit=50):
        """بازیابی آخرین پیام‌ها"""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT content, type, file_path, is_sent, timestamp 
            FROM messages 
            ORDER BY id ASC
        ''') 
        
        rows = cursor.fetchall()
        conn.close()
        
        messages = []
        for row in rows:
            messages.append({
                "content": self._simple_decrypt(row[0]),
                "type": row[1],
                "file_path": self._simple_decrypt(row[2]),
                "is_sent": bool(row[3]),
                "timestamp": row[4]
            })
        return messages

    def clear_history(self):
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM messages")
        conn.commit()
        cursor.execute("VACUUM") 
        conn.close()
        return True