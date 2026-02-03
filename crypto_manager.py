import os
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class CryptoManager:
    def __init__(self):
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.public_key = self.private_key.public_key()
        
        self.session_key = None
        self.aes_gcm = None  

    def get_public_key_bytes(self):
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def load_peer_public_key(self, bytes_data):
        return serialization.load_pem_public_key(bytes_data)

    def generate_session_key(self):
        self.session_key = AESGCM.generate_key(bit_length=256)
        self.aes_gcm = AESGCM(self.session_key)
        return self.session_key

    def encrypt_session_key_for_peer(self, peer_public_key):

        if not self.session_key:
            raise ValueError("Session key not generated yet!")

        encrypted_key = peer_public_key.encrypt(
            self.session_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return encrypted_key

    def decrypt_session_key_from_peer(self, encrypted_session_key):

        self.session_key = self.private_key.decrypt(
            encrypted_session_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        self.aes_gcm = AESGCM(self.session_key)

    def encrypt_data(self, plaintext):

        if not self.session_key:
            raise ValueError("No secure session established!")

        if isinstance(plaintext, str):
            data = plaintext.encode('utf-8')
        else:
            data = plaintext

        nonce = os.urandom(12)
        ciphertext = self.aes_gcm.encrypt(nonce, data, None)
        
        return nonce + ciphertext

    def decrypt_data(self, encrypted_data):

        if not self.session_key:
            raise ValueError("No secure session established!")

        nonce = encrypted_data[:12]
        ciphertext = encrypted_data[12:]

        try:
            plaintext_bytes = self.aes_gcm.decrypt(nonce, ciphertext, None)
            return plaintext_bytes
        except Exception as e:
            print(f"Decryption Error: {e}")
            return None

    def get_fingerprint(self):

        if not self.session_key:
            return "NO SECURE KEY"
        
        digest = hashlib.sha256(self.session_key).hexdigest()
        

        return f"{digest[:4]} - {digest[4:8]} - {digest[8:12]} - {digest[12:16]}".upper()

    def get_visual_fingerprint(self):

        emojis = ["🍎", "🍐", "🍊", "🍋", "🍌", "🍉", "🍇", "🍓", "🍒", "🍑", 
                  "🍍", "🥝", "🍅", "🍆", "🥑", "🥦"]
        
        if not self.session_key:
            return "🔒❌"

        digest = hashlib.sha256(self.session_key).digest()
        idx1 = digest[0] % 16
        idx2 = digest[1] % 16
        idx3 = digest[2] % 16
        idx4 = digest[3] % 16
        
        return f"{emojis[idx1]} {emojis[idx2]} {emojis[idx3]} {emojis[idx4]}"