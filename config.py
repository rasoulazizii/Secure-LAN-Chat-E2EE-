import os

DEFAULT_PORT = 5050

def get_file_port(text_port):
    return text_port + 1

BUFFER_SIZE = 4096
FILES_DIR = "files"
SENT_DIR = os.path.join(FILES_DIR, "sent")
RECV_DIR = os.path.join(FILES_DIR, "received")
DB_NAME = "chat_history.db"

os.makedirs(SENT_DIR, exist_ok=True)
os.makedirs(RECV_DIR, exist_ok=True)