import socket
import threading
import json
import struct
import os

class NetworkManager:
    def __init__(self, on_receive_callback, on_file_receive_callback):
        self.on_receive = on_receive_callback 
        self.on_file_receive = on_file_receive_callback
        self.running = False
        self.peer_ip = None
        self.port_text = None
        self.port_file = None
        self.server_socket = None
        self.client_socket = None

    def start_server(self, port):
        if self.running: self.stop_server()
        self.port_text = port
        self.port_file = port + 1
        self.running = True
        threading.Thread(target=self._listen_text, daemon=True).start()
        threading.Thread(target=self._listen_file, daemon=True).start()

    def stop_server(self):
        self.running = False
        if self.server_socket: self.server_socket.close()

    def connect_to_peer(self, ip, port):
        try:
            self.peer_ip = ip
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.settimeout(5)
            self.client_socket.connect((ip, port))
            self.client_socket.settimeout(None)
            threading.Thread(target=self._handle_client_text, args=(self.client_socket,), daemon=True).start()
            return True
        except:
            return False

    def send_packet(self, data_dict):
        if not self.client_socket: return False
        try:
            json_data = json.dumps(data_dict).encode('utf-8')
            msg_length = struct.pack('!I', len(json_data))
            self.client_socket.sendall(msg_length + json_data)
            return True
        except: return False

    def send_file(self, file_path, encrypted_gen):
        def _thread():
            try:
                f_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                f_sock.connect((self.peer_ip, self.port_file))
                header = json.dumps({"name": os.path.basename(file_path), "size": os.path.getsize(file_path)}).encode('utf-8')
                f_sock.sendall(struct.pack('!I', len(header)) + header)
                for chunk in encrypted_gen:
                    f_sock.sendall(struct.pack('!I', len(chunk)) + chunk)
                f_sock.close()
            except: pass
        threading.Thread(target=_thread, daemon=True).start()

    def _listen_text(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind(('0.0.0.0', self.port_text))
        self.server_socket.listen(1)
        while self.running:
            try:
                conn, addr = self.server_socket.accept()
                self.peer_ip = addr[0]
                self.client_socket = conn
                threading.Thread(target=self._handle_client_text, args=(conn,), daemon=True).start()
            except: break

    def _listen_file(self):
        f_serv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        f_serv.bind(('0.0.0.0', self.port_file))
        f_serv.listen(5)
        while self.running:
            try:
                conn, addr = f_serv.accept()
                threading.Thread(target=self._handle_file_conn, args=(conn,), daemon=True).start()
            except: break

    def _handle_file_conn(self, conn):
        try:
            raw_len = self._recvall(conn, 4)
            l = struct.unpack('!I', raw_len)[0]
            header = json.loads(self._recvall(conn, l).decode('utf-8'))
            self.on_file_receive(conn, header)
        except: conn.close()

    def _handle_client_text(self, conn):
        while self.running:
            try:
                raw_len = self._recvall(conn, 4)
                if not raw_len: break
                l = struct.unpack('!I', raw_len)[0]
                data = json.loads(self._recvall(conn, l).decode('utf-8'))
                self.on_receive(data)
            except: break
        conn.close()

    def _recvall(self, sock, n):
        data = bytearray()
        while len(data) < n:
            packet = sock.recv(n - len(data))
            if not packet: return None
            data.extend(packet)
        return data