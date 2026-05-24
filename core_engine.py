import os
import re
import logging
from netmiko import ConnectHandler
from ping3 import ping
from inventory_manager import update_version_inventory, get_all_devices
from drivers.cisco_ios import CiscoIosDriver
from drivers.hp_procurve import HpProcurveDriver

BACKUP_FOLDER = 'backup-config'
logging.basicConfig(filename='error_log.txt', level=logging.ERROR, format='%(asctime)s - %(levelname)s - %(message)s')

if not os.path.exists(BACKUP_FOLDER):
    os.makedirs(BACKUP_FOLDER)

# Credenziali di default per il Profilo Rete Standard
DEFAULT_USERNAME = "Admin"
DEFAULT_PASSWORD = "admin"
DEFAULT_SECRET = "admin"

def sanitize_filename(filename):
    return ''.join('_' if char in r'\/:*?"<>|' else char for char in filename)

def get_device_credentials(device):
    """Estrae le credenziali in base al profilo selezionato (default o custom)."""
    profile = device.get('Profile', 'custom').lower()
    
    if profile == 'default':
        return DEFAULT_USERNAME, DEFAULT_PASSWORD, DEFAULT_SECRET
    
    # Altrimenti restituiamo quelle definite nel CSV, con fallback su quelle standard se vuote
    username = device.get('Username') or DEFAULT_USERNAME
    password = device.get('Password') or DEFAULT_PASSWORD
    secret = device.get('Enable Secret') or DEFAULT_SECRET
    return username, password, secret

def driver_factory(vendor, connection):
    """Factory Pattern per caricare dinamicamente il driver corretto."""
    vendor = vendor.lower()
    if vendor == 'cisco':
        return CiscoIosDriver(connection)
    elif vendor == 'hpe':
        return HpProcurveDriver(connection)
    else:
        raise ValueError(f"Vendor '{vendor}' non supportato dall'architettura driver.")

def run_backup_and_triage(device):
    """Esegue ping, backup e recupero della versione software di un apparato tramite Driver Factory."""
    ip = device['IP']
    vendor = device['Vendor'].lower()
    
    if ping(ip) is None:
        update_version_inventory(ip, vendor, "Non Rilevata", "offline")
        return {"status": "error", "message": f"Device {ip} non raggiungibile via ping"}

    username, password, secret = get_device_credentials(device)
    netmiko_type = 'cisco_ios' if vendor == 'cisco' else 'hp_procurve'
    
    device_params = {
        'device_type': netmiko_type,
        'host': ip,
        'username': username,
        'password': password,
        'secret': secret,
    }

    try:
        with ConnectHandler(**device_params) as net_connect:
            net_connect.enable()
            
            # Caricamento dinamico del driver tramite Factory Pattern
            driver = driver_factory(vendor, net_connect)
            
            version = driver.get_version()
            backup_cmd = driver.get_backup_command()
            
            # Registra la versione per l'EUVD Vulnerability Check con stato "online"
            update_version_inventory(ip, vendor, version, "online")
            
            # Esegue il backup della configurazione
            config_out = net_connect.send_command(backup_cmd)
            hostname_match = re.search(r'hostname\s+(\S+)', config_out, re.IGNORECASE | re.MULTILINE)
            sys_name = hostname_match.group(1).strip() if hostname_match else f"{vendor}_{ip}"
            
            file_path = os.path.join(BACKUP_FOLDER, f"{sanitize_filename(sys_name)}-{ip}.txt")
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(config_out)
                
            return {"status": "success", "version": version, "file": file_path}
            
    except Exception as e:
        logging.error(f"Errore su {ip}: {str(e)}")
        # Determina il tipo di stato del LED basandosi sull'errore
        status = "auth_failed" if "auth" in str(e).lower() or "credentials" in str(e).lower() else "offline"
        update_version_inventory(ip, vendor, "Non Rilevata", status)
        return {"status": "error", "message": str(e)}

def send_custom_command(device, command):
    """Invia un comando CLI arbitrario da Web UI al dispositivo."""
    vendor = device['Vendor'].lower()
    netmiko_type = 'cisco_ios' if vendor == 'cisco' else 'hp_procurve'
    
    username, password, secret = get_device_credentials(device)
    device_params = {
        'device_type': netmiko_type,
        'host': device['IP'],
        'username': username,
        'password': password,
        'secret': secret,
    }
    try:
        with ConnectHandler(**device_params) as net_connect:
            net_connect.enable()
            output = net_connect.send_command(command)
            return {"status": "success", "output": output}
    except Exception as e:
        return {"status": "error", "message": str(e)}
