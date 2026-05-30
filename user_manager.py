import json
import os
import bcrypt

USERS_JSON = "users.json"

def get_users():
    if not os.path.exists(USERS_JSON):
        return {}
    with open(USERS_JSON, "r", encoding="utf-8") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return {}

def has_any_user() -> bool:
    return len(get_users()) > 0

def create_user(username: str, password: str) -> bool:
    users = get_users()
    if username in users:
        return False
    
    # Hashing sicuro con bcrypt (generazione automatica di salt sicuro con cost factor a 12)
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(rounds=12))
    
    users[username] = {
        "hashed_password": hashed_password.decode('utf-8')
    }
    
    with open(USERS_JSON, "w", encoding="utf-8") as f:
        json.dump(users, f, indent=4)
    return True

def verify_user(username: str, password: str) -> bool:
    users = get_users()
    if username not in users:
        return False
    
    user_data = users[username]
    # Confronto sicuro a tempo costante nativo di bcrypt
    return bcrypt.checkpw(password.encode('utf-8'), user_data["hashed_password"].encode('utf-8'))

def change_password(username: str, old_password: str, new_password: str) -> bool:
    """Permette di cambiare la password verificando quella attuale."""
    if not verify_user(username, old_password):
        return False
    users = get_users()
    hashed = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt(rounds=12))
    users[username]["hashed_password"] = hashed.decode('utf-8')
    with open(USERS_JSON, "w", encoding="utf-8") as f:
        json.dump(users, f, indent=4)
    return True
