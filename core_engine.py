import os
import re
import logging
from netmiko import ConnectHandler
from ping3 import ping
from inventory_manager import update_version_inventory, get_all_devices
from drivers.cisco_ios import CiscoIosDriver
from drivers.hp_procurve import HpProcurveDriver
from security_manager import decrypt_credentials

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
    """Estrae le credenziali in base al profilo selezionato, decifrandole in sicurezza."""
    profile = device.get('Profile', 'custom').lower()
    
    if profile == 'default':
        return DEFAULT_USERNAME, DEFAULT_PASSWORD, DEFAULT_SECRET
    
    # Altrimenti restituiamo quelle definite nel CSV decifrate, con fallback su quelle standard se vuote
    username = decrypt_credentials(device.get('Username')) or DEFAULT_USERNAME
    password = decrypt_credentials(device.get('Password')) or DEFAULT_PASSWORD
    secret = decrypt_credentials(device.get('Enable Secret')) or DEFAULT_SECRET
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
    """Esegue ping, backup (con neighbor tables CDP/LLDP) e triage del firmware."""
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
            
            # Caricamento dinamico del driver tramite Driver Factory
            driver = driver_factory(vendor, net_connect)
            
            version = driver.get_version()
            backup_cmd = driver.get_backup_command()
            
            # Registra la versione per l'EUVD Vulnerability Check con stato "online"
            update_version_inventory(ip, vendor, version, "online")
            
            # Esegue il backup della configurazione
            config_out = net_connect.send_command(backup_cmd)
            
            # --- ESTRAZIONE NEIGHBOR (CDP / LLDP) ---
            config_out += "\n\n=== NEIGHBOR DISCOVERY ===\n"
            if vendor == 'cisco':
                try:
                    cdp_out = net_connect.send_command("show cdp neighbors")
                    config_out += "\n--- SHOW CDP NEIGHBORS ---\n" + cdp_out
                except Exception:
                    pass
                try:
                    cdp_detail = net_connect.send_command("show cdp neighbors detail")
                    config_out += "\n--- SHOW CDP NEIGHBORS DETAIL ---\n" + cdp_detail
                except Exception:
                    pass
                try:
                    lldp_out = net_connect.send_command("show lldp neighbors")
                    config_out += "\n--- SHOW LLDP NEIGHBORS ---\n" + lldp_out
                except Exception:
                    pass
            elif vendor == 'hpe':
                try:
                    lldp_out = net_connect.send_command("show lldp info remote-device")
                    config_out += "\n--- SHOW LLDP NEIGHBORS ---\n" + lldp_out
                except Exception:
                    pass
                try:
                    lldp_detail = net_connect.send_command("show lldp info remote-device detail")
                    config_out += "\n--- SHOW LLDP NEIGHBORS DETAIL ---\n" + lldp_detail
                except Exception:
                    pass

            hostname_match = re.search(r'hostname\s+(\S+)', config_out, re.IGNORECASE | re.MULTILINE)
            sys_name = hostname_match.group(1).strip() if hostname_match else f"{vendor}_{ip}"
            
            file_path = os.path.join(BACKUP_FOLDER, f"{sanitize_filename(sys_name)}-{ip}.txt")
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(config_out)
                
            return {"status": "success", "version": version, "file": file_path}
            
    except Exception as e:
        logging.error(f"Errore su {ip}: {str(e)}")
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

# --- MOTORE EURISTICO DI NETWORK MAPPING ---

def extract_hostname_from_config(content: str) -> str:
    """Estrae l'hostname dalle righe di configurazione."""
    # Cisco: hostname Switch-A
    match = re.search(r'^\s*hostname\s+(\S+)', content, re.MULTILINE | re.IGNORECASE)
    if match:
        return match.group(1).strip().strip('"')
    # HPE: hostname "Switch-A" o similar
    match = re.search(r'^\s*hostname\s+"([^"]+)"', content, re.MULTILINE | re.IGNORECASE)
    if match:
        return match.group(1).strip()
    return None

def parse_cdp_lldp_neighbors(content: str) -> list:
    """Parsa le tabelle di vicini (CDP/LLDP) nel file di backup."""
    neighbors = []
    
    # 1. Parsing di "CDP Neighbors Detail" (Cisco)
    # Ciascun blocco inizia con "Device ID:" o "-------------------------"
    cdp_details = re.findall(
        r'Device ID:\s*([^\n\r]+).*?Entry address\(es\):\s*.*?IP address:\s*([^\n\r]+).*?Interface:\s*([^,\n]+),\s*Port ID \(outgoing port\):\s*([^\n\r]+)',
        content, re.DOTALL | re.IGNORECASE
    )
    for dev_id, ip, local_port, remote_port in cdp_details:
        neighbors.append({
            "neighbor_id": dev_id.strip(),
            "neighbor_ip": ip.strip(),
            "local_port": local_port.strip(),
            "remote_port": remote_port.strip()
        })

    # 2. Se non ci sono dettagli CDP, prova a parsare show cdp neighbors classico
    if not neighbors:
        cdp_section = re.search(r'--- SHOW CDP NEIGHBORS ---\s*\n(.*?)(\n---|\Z)', content, re.DOTALL | re.IGNORECASE)
        if cdp_section:
            lines = cdp_section.group(1).strip().split('\n')
            started = False
            for line in lines:
                if "Device ID" in line or "Local Intrfce" in line:
                    started = True
                    continue
                if not started or not line.strip() or line.startswith("Capability") or line.startswith("---"):
                    continue
                parts = re.split(r'\s{2,}', line.strip())
                if len(parts) >= 5:
                    dev_id = parts[0]
                    local_port = parts[1]
                    remote_port = parts[-1]
                    neighbors.append({
                        "neighbor_id": dev_id.strip(),
                        "neighbor_ip": None,
                        "local_port": local_port.strip(),
                        "remote_port": remote_port.strip()
                    })

    # 3. Parsing di LLDP remote device table (HPE e Cisco)
    # Struttura HPE:
    #   Local Port | Chassis ID                 Port ID      Port Description System Name
    #   ---------- + -------------------------- ------------ ---------------- -----------
    #   24         | 00 11 22 33 44 55          24           24               Switch-B
    lldp_section = re.search(r'Local Port\s+\|\s+Chassis ID.*?\n(.*?)(?=\n---|\Z)', content, re.DOTALL | re.IGNORECASE)
    if lldp_section:
        lines = lldp_section.group(1).strip().split('\n')
        for line in lines:
            if '-' in line and '+' in line:
                continue
            parts = [p.strip() for p in line.split('|')]
            if len(parts) >= 5:
                local_port = parts[0]
                port_id = parts[2]
                sys_name = parts[4]
                if sys_name and sys_name != 'System Name' and sys_name != '----------':
                    neighbors.append({
                        "neighbor_id": sys_name,
                        "neighbor_ip": None,
                        "local_port": local_port,
                        "remote_port": port_id
                    })

    # 4. Parsing dettagli LLDP (per raccogliere indirizzi IP se presenti)
    lldp_details = re.findall(
        r'System Name\s*:\s*([^\n\r]+).*?PortId\s*:\s*([^\n\r]+).*?IPv4 Address\s*:\s*([^\n\r]+)',
        content, re.DOTALL | re.IGNORECASE
    )
    for sys_name, port_id, ip in lldp_details:
        neighbors.append({
            "neighbor_id": sys_name.strip(),
            "neighbor_ip": ip.strip(),
            "local_port": "Unknown",
            "remote_port": port_id.strip()
        })

    return neighbors

def generate_network_map() -> dict:
    """Scansiona la cartella backup-config e genera la mappa di rete (nodi e collegamenti)."""
    devices = get_all_devices()
    
    # 1. Indicizzazione dei dispositivi noti dall'inventario
    # Mappa: Hostname -> IP, e IP -> Info Dispositivo
    ip_to_device = {d['IP']: d for d in devices}
    hostname_to_ip = {}
    
    nodes_map = {}
    links = []
    
    # 2. Legge tutti i file di backup in backup-config
    backup_files = []
    if os.path.exists(BACKUP_FOLDER):
        for f in os.listdir(BACKUP_FOLDER):
            if f.endswith('.txt'):
                backup_files.append(os.path.join(BACKUP_FOLDER, f))

    parsed_devices = {} # IP -> data
    
    # Primo passaggio: Rileva l'hostname reale dall'interno del file di backup
    for file_path in backup_files:
        filename = os.path.basename(file_path)
        # Il file si chiama {hostname}-{ip}.txt
        # Cerchiamo di estrarre l'IP dal nome del file (ultima parte prima di .txt)
        parts = filename[:-4].split('-')
        if len(parts) >= 2:
            ip = parts[-1]
        else:
            # Fallback regex IP
            ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', filename)
            ip = ip_match.group(1) if ip_match else None
            
        if not ip:
            continue

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception:
            continue

        hostname = extract_hostname_from_config(content)
        if not hostname:
            hostname = "-".join(parts[:-1]) if len(parts) >= 2 else filename[:-4]

        parsed_devices[ip] = {
            "hostname": hostname,
            "content": content,
            "file": file_path
        }
        hostname_to_ip[hostname.lower()] = ip

    # 3. Crea i Nodi per tutti i dispositivi in inventario
    for ip, d in ip_to_device.items():
        # Se abbiamo letto il backup, usiamo l'hostname reale, altrimenti l'IP
        label = parsed_devices.get(ip, {}).get("hostname", ip)
        nodes_map[ip] = {
            "id": ip,
            "label": label,
            "group": d.get('Group', 'Generale'),
            "status": "online" if ip in parsed_devices else "offline"
        }

    # 4. Secondo passaggio: Costruisce i Collegamenti (Links) e scopre nodi non censiti
    seen_links = set()
    
    for ip, info in parsed_devices.items():
        content = info["content"]
        source_id = ip
        
        # Estrae i vicini
        parsed_neighbors = parse_cdp_lldp_neighbors(content)
        
        for neigh in parsed_neighbors:
            neigh_id = neigh["neighbor_id"]
            neigh_ip = neigh["neighbor_ip"]
            local_port = neigh["local_port"]
            remote_port = neigh["remote_port"]
            
            # Risoluzione dell'IP del vicino
            target_ip = neigh_ip
            if not target_ip:
                # Cerca per hostname nella mappa
                target_ip = hostname_to_ip.get(neigh_id.lower())
            
            if not target_ip:
                # Se non riusciamo a trovare l'IP, usiamo l'hostname come ID per il nodo scoperto
                target_ip = f"discovered_{sanitize_filename(neigh_id)}"
                
            # Se il target non è presente nei nodi, creiamo un nodo "scoperto"
            if target_ip not in nodes_map:
                nodes_map[target_ip] = {
                    "id": target_ip,
                    "label": neigh_id,
                    "group": "Discovered",
                    "status": "discovered"
                }

            # Assicuriamo una chiave univoca per evitare duplicati bidirezionali (es. A->B e B->A)
            link_key = tuple(sorted([source_id, target_ip]))
            if link_key not in seen_links:
                seen_links.add(link_key)
                links.append({
                    "source": source_id,
                    "target": target_ip,
                    "local_port": local_port,
                    "remote_port": remote_port
                })

    return {
        "nodes": list(nodes_map.values()),
        "links": links
    }
