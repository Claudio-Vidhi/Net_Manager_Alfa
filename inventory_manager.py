import json
import os
import csv
from security_manager import encrypt_credentials, decrypt_credentials

HOSTS_CSV = "network_hosts.csv"
VERSION_DATA_FILE = "detected_versions.json"
GROUPS_FILE = "groups.json"

def get_all_devices():
    devices = []
    if not os.path.exists(HOSTS_CSV):
        return devices
    with open(HOSTS_CSV, mode='r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            if 'Group' not in row or not row['Group']: 
                row['Group'] = 'Generale'
            # Decodifica trasparente
            row['Username'] = decrypt_credentials(row.get('Username', ''))
            row['Password'] = decrypt_credentials(row.get('Password', ''))
            row['Enable Secret'] = decrypt_credentials(row.get('Enable Secret', ''))
            devices.append(row)
    return devices

def save_all_devices(devices):
    with open(HOSTS_CSV, mode='w', newline='', encoding='utf-8') as f:
        fieldnames = ['IP', 'Vendor', 'Profile', 'Username', 'Password', 'Enable Secret', 'Group']
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for d in devices:
            writer.writerow({
                'IP': d.get('IP', ''),
                'Vendor': d.get('Vendor', 'cisco').lower(),
                'Profile': d.get('Profile', 'default'),
                'Username': encrypt_credentials(d.get('Username', 'Admin')),
                'Password': encrypt_credentials(d.get('Password', 'admin')),
                'Enable Secret': encrypt_credentials(d.get('Enable Secret', 'admin')),
                'Group': d.get('Group', 'Generale')
            })

def add_or_update_device(ip, vendor, profile, username, password, enable_secret, group):
    devices = get_all_devices()
    devices = [d for d in devices if d['IP'] != ip]
    
    new_device = {
        'IP': ip, 'Vendor': vendor.lower(), 'Profile': profile,
        'Username': username, 'Password': password, 'Enable Secret': enable_secret,
        'Group': group if group.strip() else 'Generale'
    }
    devices.append(new_device)
    save_all_devices(devices)
    
    # Assicura che il gruppo del dispositivo esista nella lista dei gruppi
    if group and group.strip():
        add_group(group.strip())

def delete_device(ip):
    devices = get_all_devices()
    devices = [d for d in devices if d['IP'] != ip]
    save_all_devices(devices)

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
    with open(VERSION_DATA_FILE, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=4)

# --- GESTIONE GRUPPI (CRUD) ---

def get_all_groups():
    """Recupera la lista dei gruppi salvati."""
    if not os.path.exists(GROUPS_FILE):
        default_groups = ["Generale"]
        save_groups(default_groups)
        return default_groups
    try:
        with open(GROUPS_FILE, 'r', encoding='utf-8') as f:
            groups = json.load(f)
            if "Generale" not in groups:
                groups.insert(0, "Generale")
            return groups
    except:
        return ["Generale"]

def save_groups(groups):
    """Salva la lista dei gruppi su file json."""
    if "Generale" not in groups:
        groups.insert(0, "Generale")
    with open(GROUPS_FILE, 'w', encoding='utf-8') as f:
        json.dump(groups, f, indent=4)

def add_group(group_name: str) -> bool:
    """Aggiunge un nuovo gruppo se non esistente."""
    group_name = group_name.strip()
    if not group_name:
        return False
    groups = get_all_groups()
    if group_name not in groups:
        groups.append(group_name)
        save_groups(groups)
        return True
    return False

def update_group(old_name: str, new_name: str) -> bool:
    """Rinomina un gruppo ed aggiorna tutti i dispositivi ad esso associati."""
    old_name = old_name.strip()
    new_name = new_name.strip()
    if not old_name or not new_name or old_name == "Generale":
        return False
    
    groups = get_all_groups()
    if old_name in groups:
        # Aggiorna la lista dei gruppi
        groups = [new_name if g == old_name else g for g in groups]
        # Rimuove eventuali duplicati
        groups = list(dict.fromkeys(groups))
        save_groups(groups)
        
        # Aggiorna i dispositivi
        devices = get_all_devices()
        updated = False
        for d in devices:
            if d.get('Group') == old_name:
                d['Group'] = new_name
                updated = True
        if updated:
            save_all_devices(devices)
        return True
    return False

def delete_group(group_name: str) -> bool:
    """Rimuove un gruppo e riassegna i dispositivi associati a 'Generale'."""
    group_name = group_name.strip()
    if not group_name or group_name == "Generale":
        return False
    
    groups = get_all_groups()
    if group_name in groups:
        groups.remove(group_name)
        save_groups(groups)
        
        # Riassegna i dispositivi
        devices = get_all_devices()
        updated = False
        for d in devices:
            if d.get('Group') == group_name:
                d['Group'] = "Generale"
                updated = True
        if updated:
            save_all_devices(devices)
        return True
    return False
