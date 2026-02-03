import sys
import os
import base64
import threading
import socket
import struct
from PyQt6.QtWidgets import *
from PyQt6.QtCore import *
from PyQt6.QtGui import *

import config
from crypto_manager import CryptoManager
from db_manager import DBManager
from network_manager import NetworkManager

class CommSignals(QObject):
    message_received = pyqtSignal(str, bool)
    status_updated = pyqtSignal(str, str)
    security_updated = pyqtSignal(str, str)
    clear_ui = pyqtSignal()

class LanChatApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.crypto = CryptoManager()
        self.db = DBManager(config.DB_NAME)
        self.signals = CommSignals()
        self.network = NetworkManager(self.on_network_packet, self.on_file_incoming)
        self.init_ui()
        self.connect_signals()
        self.network.start_server(config.DEFAULT_PORT)
        self.load_history()

    def get_local_ips(self):
        ips = []
        try:
            hostname = socket.gethostname()
            for info in socket.getaddrinfo(hostname, None):
                ip = info[4][0]
                if ":" not in ip and not ip.startswith("127."):
                    if ip not in ips: ips.append(ip)
        except: pass
        ips.append("127.0.0.1")
        return ips

    def init_ui(self):
        self.setWindowTitle("Secure E2EE Chat")
        self.resize(1000, 700)
        self.setStyleSheet("QMainWindow { background-color: #1a1a1a; } QWidget { color: white; font-family: 'Segoe UI'; }")
        central = QWidget()
        self.setCentralWidget(central)
        layout = QHBoxLayout(central)
        layout.setSpacing(0)
        layout.setContentsMargins(0,0,0,0)
        sidebar = QFrame()
        sidebar.setFixedWidth(300)
        sidebar.setStyleSheet("background-color: #252525; border-right: 1px solid #333;")
        side_layout = QVBoxLayout(sidebar)
        side_layout.addWidget(QLabel("MY LOCAL IPs:"))
        self.ip_list = QListWidget()
        self.ip_list.setMaximumHeight(100)
        self.ip_list.setStyleSheet("background: #111; border-radius: 5px; padding: 5px;")
        for ip in self.get_local_ips():
            self.ip_list.addItem(f" ● {ip}")
        side_layout.addWidget(self.ip_list)
        side_layout.addSpacing(20)
        side_layout.addWidget(QLabel("CONNECT TO PEER:"))
        self.peer_ip_input = QLineEdit()
        self.peer_ip_input.setPlaceholderText("Peer IP")
        self.peer_ip_input.setStyleSheet("padding: 8px; background: #333; border: 1px solid #555;")
        side_layout.addWidget(self.peer_ip_input)
        self.peer_port_input = QLineEdit()
        self.peer_port_input.setText(str(config.DEFAULT_PORT))
        self.peer_port_input.setStyleSheet("padding: 8px; background: #333; border: 1px solid #555;")
        side_layout.addWidget(self.peer_port_input)
        self.btn_connect = QPushButton("Connect")
        self.btn_connect.setStyleSheet("background-color: #0078d4; padding: 10px; font-weight: bold;")
        self.btn_connect.clicked.connect(self.connect_to_peer)
        side_layout.addWidget(self.btn_connect)
        side_layout.addSpacing(20)
        self.lbl_finger = QLabel("Not Secure")
        self.lbl_finger.setWordWrap(True)
        self.lbl_finger.setStyleSheet("color: #aaa; font-size: 11px;")
        side_layout.addWidget(self.lbl_finger)
        self.lbl_emoji = QLabel("")
        self.lbl_emoji.setAlignment(Qt.AlignmentFlag.AlignCenter)
        side_layout.addWidget(self.lbl_emoji)
        side_layout.addStretch()
        btn_clear = QPushButton("Clear History")
        btn_clear.setStyleSheet("background: #500; border: 1px solid #700;")
        btn_clear.clicked.connect(self.clear_history_action)
        side_layout.addWidget(btn_clear)
        chat_box = QWidget()
        chat_layout = QVBoxLayout(chat_box)
        self.lbl_status = QLabel("● SERVER LISTENING")
        self.lbl_status.setStyleSheet("color: #555; font-size: 12px;")
        chat_layout.addWidget(self.lbl_status)
        self.chat_display = QTextEdit()
        self.chat_display.setReadOnly(True)
        self.chat_display.setStyleSheet("background: #121212; border: none; font-size: 14px;")
        chat_layout.addWidget(self.chat_display)
        input_area = QHBoxLayout()
        self.btn_file = QPushButton("📎")
        self.btn_file.setFixedWidth(40)
        self.btn_file.clicked.connect(self.select_file)
        self.msg_input = QLineEdit()
        self.msg_input.setPlaceholderText("Message...")
        self.msg_input.setStyleSheet("padding: 10px; background: #222; border: 1px solid #444;")
        self.msg_input.returnPressed.connect(self.send_text)
        self.msg_input.textChanged.connect(self.send_typing)
        self.btn_send = QPushButton("Send")
        self.btn_send.clicked.connect(self.send_text)
        input_area.addWidget(self.btn_file)
        input_area.addWidget(self.msg_input)
        input_area.addWidget(self.btn_send)
        chat_layout.addLayout(input_area)
        layout.addWidget(sidebar)
        layout.addWidget(chat_box)

    def connect_signals(self):
        self.signals.message_received.connect(self.ui_add_message)
        self.signals.status_updated.connect(self.ui_update_status)
        self.signals.security_updated.connect(self.ui_update_security)
        self.signals.clear_ui.connect(self.chat_display.clear)

    def connect_to_peer(self):
        ip = self.peer_ip_input.text()
        try:
            port = int(self.peer_port_input.text())
        except: port = config.DEFAULT_PORT
        self.lbl_status.setText(f"● Connecting to {ip}...")
        def _thread():
            if self.network.connect_to_peer(ip, port):
                pub_bytes = base64.b64encode(self.crypto.get_public_key_bytes()).decode('ascii')
                self.network.send_packet({"type": "HANDSHAKE_INIT", "key": pub_bytes})
                self.signals.status_updated.emit(f"● Connected to {ip}", "#2ecc71")
            else:
                self.signals.status_updated.emit("● Connection Failed", "#ff4343")
        threading.Thread(target=_thread, daemon=True).start()

    def on_network_packet(self, data):
        t = data.get("type")
        if t == "HANDSHAKE_INIT":
            peer_pub = self.crypto.load_peer_public_key(base64.b64decode(data['key']))
            self.crypto.generate_session_key()
            enc_key = self.crypto.encrypt_session_key_for_peer(peer_pub)
            self.network.send_packet({"type": "HANDSHAKE_FINISH", "key": base64.b64encode(enc_key).decode('ascii')})
            self.signals.security_updated.emit(self.crypto.get_fingerprint(), self.crypto.get_visual_fingerprint())
            self.signals.status_updated.emit("● Securely Connected", "#2ecc71")
        elif t == "HANDSHAKE_FINISH":
            self.crypto.decrypt_session_key_from_peer(base64.b64decode(data['key']))
            self.signals.security_updated.emit(self.crypto.get_fingerprint(), self.crypto.get_visual_fingerprint())
            self.signals.status_updated.emit("● Securely Connected", "#2ecc71")
        elif t == "MESSAGE":
            msg = self.crypto.decrypt_data(base64.b64decode(data['content'])).decode('utf-8')
            self.db.save_message(msg, is_sent=0)
            self.signals.message_received.emit(msg, False)
        elif t == "TYPING":
            self.signals.status_updated.emit("● typing...", "#3498db")
            QTimer.singleShot(2000, lambda: self.signals.status_updated.emit("● Securely Connected", "#2ecc71"))
        elif t == "CMD_CLEAR":
            self.db.clear_history()
            self.signals.clear_ui.emit()

    def ui_add_message(self, text, is_sent):
        sender = "You" if is_sent else "Peer"
        color = "#00a2ed" if is_sent else "#2ecc71"
        self.chat_display.append(f'<p style="color:{color}"><b>[{sender}]:</b> {text}</p>')

    def ui_update_status(self, text, color):
        self.lbl_status.setText(text)
        self.lbl_status.setStyleSheet(f"color: {color}; font-weight: bold;")

    def ui_update_security(self, fp, vis):
        self.lbl_finger.setText(f"SECURE: {fp}")
        self.lbl_emoji.setText(vis)

    def send_text(self):
        txt = self.msg_input.text()
        if not txt or not self.crypto.session_key: return
        enc = base64.b64encode(self.crypto.encrypt_data(txt)).decode('ascii')
        if self.network.send_packet({"type": "MESSAGE", "content": enc}):
            self.db.save_message(txt, is_sent=1)
            self.ui_add_message(txt, True)
            self.msg_input.clear()

    def send_typing(self):
        if self.network.client_socket: self.network.send_packet({"type": "TYPING"})

    def select_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Send File")
        if path:
            self.ui_add_message(f"📤 Sending: {os.path.basename(path)}", True)
            def gen():
                with open(path, 'rb') as f:
                    while True:
                        chunk = f.read(4000)
                        if not chunk: break
                        yield self.crypto.encrypt_data(chunk)
            self.network.send_file(path, gen())

    def on_file_incoming(self, conn, header):
        name = header['name']
        save_path = os.path.join(config.RECV_DIR, name)
        try:
            with open(save_path, 'wb') as f:
                while True:
                    raw_len = self.network._recvall(conn, 4)
                    if not raw_len: break
                    l = struct.unpack('!I', raw_len)[0]
                    chunk = self.network._recvall(conn, l)
                    f.write(self.crypto.decrypt_data(chunk))
            conn.close()
            self.signals.message_received.emit(f"📁 Received: {name}", False)
        except: pass

    def load_history(self):
        for m in self.db.load_messages(): self.ui_add_message(m['content'], m['is_sent'])

    def clear_history_action(self):
        self.db.clear_history()
        self.chat_display.clear()
        self.network.send_packet({"type": "CMD_CLEAR"})

if __name__ == "__main__":
    app = QApplication(sys.argv)
    ex = LanChatApp()
    ex.show()
    sys.exit(app.exec())