import json
import os
import csv
import crypto_vault

HOSTS_CSV = "network_hosts.csv"
GROUPS_JSON = "groups.json"
VERSION_DATA_FILE = "detected_versions.json"

def get_all_groups():
    if not os.path.exists(GROUPS_JSON):
        default_groups = {"Generale": {"description": "Sede Principale predefinita"}}
        save_groups(default_groups)
        return default_groups
    with open(GROUPS_JSON, "r", encoding="utf-8") as f:
        try:
            data = json.load(f)
            if isinstance(data, list):
                # Convert legacy list to dictionary format
                new_dict = {}
                for g in data:
                    new_dict[g] = {"description": "Sede Principale predefinita" if g == "Generale" else f"Sede secondaria {g}"}
                save_groups(new_dict)
                return new_dict
            return data
        except Exception:
            default_groups = {"Generale": {"description": "Sede Principale predefinita"}}
            save_groups(default_groups)
            return default_groups

def save_groups(groups_dict):
    temp_filename = GROUPS_JSON + ".tmp"
    try:
        with open(temp_filename, "w", encoding="utf-8") as f:
            json.dump(groups_dict, f, indent=4)
        try:
            os.replace(temp_filename, GROUPS_JSON)
        except PermissionError:
            # Fallback per sistemi Windows in cui il file di destinazione è concorrentemente bloccato
            with open(GROUPS_JSON, "w", encoding="utf-8") as f:
                json.dump(groups_dict, f, indent=4)
            if os.path.exists(temp_filename):
                try:
                    os.remove(temp_filename)
                except:
                    pass
    except Exception as e:
        if os.path.exists(temp_filename):
            try:
                os.remove(temp_filename)
            except:
                pass
        raise e

def safe_write_hosts_csv(devices):
    temp_filename = HOSTS_CSV + ".tmp"
    try:
        with open(temp_filename, mode='w', newline='', encoding='utf-8') as f:
            fieldnames = ['IP', 'Vendor', 'Profile', 'Username', 'Password', 'Enable Secret', 'Group']
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for d in devices:
                writer.writerow(d)
        try:
            os.replace(temp_filename, HOSTS_CSV)
        except PermissionError:
            # Fallback per sistemi Windows
            with open(HOSTS_CSV, mode='w', newline='', encoding='utf-8') as f:
                fieldnames = ['IP', 'Vendor', 'Profile', 'Username', 'Password', 'Enable Secret', 'Group']
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                for d in devices:
                    writer.writerow(d)
            if os.path.exists(temp_filename):
                try:
                    os.remove(temp_filename)
                except:
                    pass
    except Exception as e:
        if os.path.exists(temp_filename):
            try:
                os.remove(temp_filename)
            except:
                pass
        raise e

def get_all_devices():
    devices = []
    if not os.path.exists(HOSTS_CSV):
        return devices
    with open(HOSTS_CSV, mode='r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            devices.append(row)
    return devices

def add_or_update_device(ip, vendor, profile, username, password, enable_secret, group):
    devices = get_all_devices()
    devices = [d for d in devices if d['IP'] != ip]
    
    enc_password = crypto_vault.encrypt_password(password)
    enc_secret = crypto_vault.encrypt_password(enable_secret)

    new_device = {
        'IP': ip, 'Vendor': vendor.lower(), 'Profile': profile,
        'Username': username, 'Password': enc_password, 'Enable Secret': enc_secret,
        'Group': group if group in get_all_groups() else 'Generale'
    }
    devices.append(new_device)
    safe_write_hosts_csv(devices)

def delete_device(ip):
    devices = get_all_devices()
    devices = [d for d in devices if d['IP'] != ip]
    safe_write_hosts_csv(devices)

# --- UTILITIES PER RILEVAMENTO VERSIONI (Richieste dal Core Engine e Server) ---

def get_detected_versions():
    if os.path.exists(VERSION_DATA_FILE):
        try:
            with open(VERSION_DATA_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        except:
            return {}
    return {}

def update_version_inventory(ip, vendor, version, status="online"):
    data = get_detected_versions()
    data[ip] = {"vendor": vendor, "version": version, "status": status}
    temp_filename = VERSION_DATA_FILE + ".tmp"
    try:
        with open(temp_filename, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=4)
        try:
            os.replace(temp_filename, VERSION_DATA_FILE)
        except PermissionError:
            # Fallback per sistemi Windows concorrentemente bloccati
            with open(VERSION_DATA_FILE, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=4)
            if os.path.exists(temp_filename):
                try:
                    os.remove(temp_filename)
                except:
                    pass
    except Exception as e:
        if os.path.exists(temp_filename):
            try:
                os.remove(temp_filename)
            except:
                pass
        raise e

# --- UTILITIES GESTIONE GRUPPI (CRUD) ---

def add_group(group_name: str, description: str = "") -> bool:
    """Aggiunge un nuovo gruppo se non esistente."""
    group_name = group_name.strip()
    if not group_name:
        return False
    groups = get_all_groups()
    if group_name not in groups:
        groups[group_name] = {"description": description or f"Sede {group_name}"}
        save_groups(groups)
        return True
    return False

def update_group(old_name: str, new_name: str, description: str = "") -> bool:
    """Rinomina un gruppo ed aggiorna tutti i dispositivi ad esso associati."""
    old_name = old_name.strip()
    new_name = new_name.strip()
    if not old_name or not new_name or old_name == "Generale":
        return False
    
    groups = get_all_groups()
    if old_name in groups:
        info = groups.pop(old_name)
        if description:
            info["description"] = description
        groups[new_name] = info
        save_groups(groups)
        
        # Aggiorna i dispositivi
        devices = get_all_devices()
        updated = False
        for d in devices:
            if d.get('Group') == old_name:
                d['Group'] = new_name
                updated = True
        if updated:
            safe_write_hosts_csv(devices)
        return True
    return False

def delete_group(group_name: str) -> bool:
    """Rimuove un gruppo e riassegna i dispositivi associati a 'Generale'."""
    group_name = group_name.strip()
    if not group_name or group_name == "Generale":
        return False
    
    groups = get_all_groups()
    if group_name in groups:
        groups.pop(group_name)
        save_groups(groups)
        
        # Riassegna i dispositivi
        devices = get_all_devices()
        updated = False
        for d in devices:
            if d.get('Group') == group_name:
                d['Group'] = "Generale"
                updated = True
        if updated:
            safe_write_hosts_csv(devices)
        return True
    return False
