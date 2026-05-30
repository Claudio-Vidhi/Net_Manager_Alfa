import os
import hashlib
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime, timedelta, timezone
import jwt

JWT_KEY_FILE = "jwt_secret.key"

def load_or_create_jwt_secret() -> str:
    """Carica o genera una chiave segreta separata ed indipendente per i token JWT."""
    # 1. Priorità massima alla variabile d'ambiente per deployment cloud o containerizzati
    env_secret = os.getenv("NET_MANAGER_JWT_SECRET")
    if env_secret:
        return hashlib.sha256(env_secret.encode('utf-8')).hexdigest()
        
    # 2. Fallback su file persistito localmente (jwt_secret.key)
    if not os.path.exists(JWT_KEY_FILE):
        import secrets
        secret = secrets.token_hex(32)
        try:
            with open(JWT_KEY_FILE, "w", encoding="utf-8") as f:
                f.write(secret)
            
            # Assicura automaticamente che il file rimanga locale ed escluso da git
            if os.path.exists(".gitignore"):
                with open(".gitignore", "r", encoding="utf-8") as gf:
                    ignore_content = gf.read()
                if "jwt_secret.key" not in ignore_content:
                    with open(".gitignore", "a", encoding="utf-8") as gf:
                        gf.write("\njwt_secret.key\n")
        except Exception:
            pass
        return secret
        
    try:
        with open(JWT_KEY_FILE, "r", encoding="utf-8") as f:
            return f.read().strip()
    except Exception:
        return "fallback_default_jwt_secret_key_alfa_security"

JWT_SECRET_KEY = load_or_create_jwt_secret()
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# Configurazione logger di Audit protetto
AUDIT_LOG_FILE = "audit.log"
audit_logger = logging.getLogger("audit")
audit_logger.setLevel(logging.INFO)

if not audit_logger.handlers:
    fh = RotatingFileHandler(
        AUDIT_LOG_FILE,
        maxBytes=5 * 1024 * 1024,  # 5 MB
        backupCount=3,
        encoding="utf-8"
    )
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

from collections import defaultdict
import time

_failed_attempts = defaultdict(list)
MAX_ATTEMPTS = 5
LOCKOUT_SECONDS = 300

def is_locked_out(username: str) -> bool:
    """Verifica se l'utente è attualmente bloccato per troppi tentativi falliti."""
    now = time.time()
    attempts = [t for t in _failed_attempts[username] if now - t < LOCKOUT_SECONDS]
    _failed_attempts[username] = attempts
    return len(attempts) >= MAX_ATTEMPTS

def record_failed_attempt(username: str):
    """Registra un tentativo di login fallito."""
    _failed_attempts[username].append(time.time())

def reset_failed_attempts(username: str):
    """Resetta i tentativi falliti al login corretto."""
    _failed_attempts.pop(username, None)
