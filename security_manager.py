import os
import hashlib
from datetime import datetime, timedelta, timezone
from cryptography.fernet import Fernet
import jwt

KEY_FILE = "secret.key"
GITIGNORE_FILE = ".gitignore"

def ensure_key_and_gitignore():
    """Genera la chiave Fernet se non esiste e assicura che sia in .gitignore."""
    # 1. Verifica/Generazione chiave
    if not os.path.exists(KEY_FILE):
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as f:
            f.write(key)
    else:
        with open(KEY_FILE, "rb") as f:
            key = f.read()

    # 2. Verifica/Aggiornamento .gitignore
    if os.path.exists(GITIGNORE_FILE):
        with open(GITIGNORE_FILE, "r", encoding="utf-8") as f:
            content = f.read()
        if KEY_FILE not in content:
            # Assicura nuova linea prima di aggiungere
            sep = "" if content.endswith("\n") else "\n"
            with open(GITIGNORE_FILE, "a", encoding="utf-8") as f:
                f.write(f"{sep}# Key file\n{KEY_FILE}\n")
    else:
        with open(GITIGNORE_FILE, "w", encoding="utf-8") as f:
            f.write(f"# Key file\n{KEY_FILE}\n")

    return key

# Inizializza al caricamento del modulo
_key = ensure_key_and_gitignore()
_fernet = Fernet(_key)

# Chiave JWT derivata in modo deterministico dalla chiave Fernet
JWT_SECRET_KEY = hashlib.sha256(_key).hexdigest()
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# --- CRYPTOGRAPHY ---

def encrypt_credentials(plain_text: str) -> str:
    """Cifra una stringa di credenziali usando Fernet."""
    if not plain_text:
        return ""
    try:
        cipher_text_bytes = _fernet.encrypt(plain_text.encode('utf-8'))
        return cipher_text_bytes.decode('utf-8')
    except Exception:
        return plain_text

def decrypt_credentials(cipher_text: str) -> str:
    """Decifra una stringa usando Fernet. Ritorna il testo originale in caso di fallimento (retrocompatibilità)."""
    if not cipher_text:
        return ""
    try:
        decrypted_bytes = _fernet.decrypt(cipher_text.encode('utf-8'))
        return decrypted_bytes.decode('utf-8')
    except Exception:
        # Fallback al testo originale (es. dati non ancora cifrati sul disco)
        return cipher_text

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
