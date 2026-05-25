import os
import hashlib
from datetime import datetime, timedelta, timezone
from cryptography.fernet import Fernet
import jwt

KEY_FILE = "secret.key"
GITIGNORE_FILE = ".gitignore"

from crypto_vault import encrypt_password, decrypt_password, load_or_create_key

# Chiave JWT derivata in modo deterministico dalla chiave Fernet caricata da crypto_vault
_key = load_or_create_key()
JWT_SECRET_KEY = hashlib.sha256(_key).hexdigest()
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

import logging

# Configurazione logger di Audit protetto
AUDIT_LOG_FILE = "audit.log"
audit_logger = logging.getLogger("audit")
audit_logger.setLevel(logging.INFO)

if not audit_logger.handlers:
    fh = logging.FileHandler(AUDIT_LOG_FILE, encoding="utf-8")
    fh.setFormatter(logging.Formatter('%(asctime)s - [AUDIT] - %(message)s'))
    audit_logger.addHandler(fh)

def log_audit(message: str):
    """Scrive un record di tracciabilità all'interno del registro sicuro audit.log."""
    audit_logger.info(message)

# --- JWT AUTHENTICATION ---

def create_access_token(data: dict, expires_delta: timedelta = None) -> str:
    """Genera un token JWT di accesso."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
    return encoded_jwt

def verify_access_token(token: str) -> dict:
    """Valida un token JWT. Ritorna il payload se valido, altrimenti None."""
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.PyJWTError:
        return None
