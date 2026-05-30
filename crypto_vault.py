import os
import base64
import hashlib
from cryptography.fernet import Fernet

KEY_FILE = "secret.key"

def load_or_create_key():
    # 1. Tenta prima di caricare la Master Key dalla variabile d'ambiente
    env_key = os.getenv("NET_MANAGER_MASTER_KEY")
    if env_key:
        # Genera deterministica chiave Fernet valida a 32 byte base64-encoded tramite hashing SHA-256
        hashed = hashlib.sha256(env_key.encode('utf-8')).digest()
        return base64.urlsafe_b64encode(hashed)

    # 2. Fallback su file locale persistente
    if not os.path.exists(KEY_FILE):
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as k_file:
            k_file.write(key)
        return key
    with open(KEY_FILE, "rb") as k_file:
        return k_file.read()

CIPHER_SUITE = Fernet(load_or_create_key())

import logging as _log

def encrypt_password(password: str) -> str:
    if not password: return ""
    return CIPHER_SUITE.encrypt(password.encode()).decode()

def decrypt_password(token: str) -> str:
    if not token:
        return ""
    try:
        return CIPHER_SUITE.decrypt(token.encode()).decode()
    except Exception as e:
        _log.warning(f"[crypto_vault] Decifrazione fallita: {e}. "
                     f"La chiave Fernet potrebbe essere cambiata.")
        return ""
