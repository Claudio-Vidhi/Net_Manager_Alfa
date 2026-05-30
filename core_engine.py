import os
import re
import logging
import socket
from netmiko import ConnectHandler
from inventory_manager import update_version_inventory, get_all_devices, get_detected_versions
from drivers.cisco_ios import CiscoIosDriver
from drivers.hp_procurve import HpProcurveDriver
from crypto_vault import decrypt_password
from security_manager import log_audit

BACKUP_FOLDER = 'backup-config'
logging.basicConfig(filename='error_log.txt', level=logging.ERROR, format='%(asctime)s - %(levelname)s - %(message)s')

if not os.path.exists(BACKUP_FOLDER):
    os.makedirs(BACKUP_FOLDER)

# Credenziali di default per il Profilo Rete Standard caricate da variabili d'ambiente
DEFAULT_USERNAME = os.getenv("NET_MANAGER_ADMIN_USER", "Admin")
DEFAULT_PASSWORD = os.getenv("NET_MANAGER_ADMIN_PASS", "admin")
DEFAULT_SECRET = os.getenv("NET_MANAGER_ADMIN_SECRET", "admin")


# Blacklist di comandi CLI pericolosi per prevenire down accidentali o dolosi della rete
DANGEROUS_COMMANDS = ["write erase", "reload", "delete", "format", "no boot", "erase"]

def sanitize_filename(filename: str) -> str:
    sanitized = ''.join(
        '_' if char in r'\/:*?"<>| ' else char
        for char in filename
        if ord(char) > 31  # rimuove caratteri di controllo
    )
    return sanitized or "device_unknown"

def get_device_credentials(device):
    """Estrae le credenziali in base al profilo selezionato, decifrandole in sicurezza."""
    profile = device.get('Profile', 'custom').lower()
    
    if profile == 'default':
        return DEFAULT_USERNAME, DEFAULT_PASSWORD, DEFAULT_SECRET
    
    # Altrimenti restituiamo quelle definite nel CSV decifrate, con fallback su quelle standard se vuote
    username = device.get('Username') or DEFAULT_USERNAME
    password = decrypt_password(device.get('Password')) or DEFAULT_PASSWORD
    secret = decrypt_password(device.get('Enable Secret')) or DEFAULT_SECRET
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

def is_reachable(ip: str, port: int = 22, timeout: int = 2) -> bool:
    """Verifica se l'apparato è raggiungibile tentando una connessione TCP sulla porta specificata."""
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except Exception:
        return False

def run_backup_and_triage(device):
    """Esegue la verifica di reachability TCP, backup (con neighbor tables CDP/LLDP) e triage del firmware."""
    ip = device['IP']
    vendor = device['Vendor'].lower()
    
    if not is_reachable(ip):
        update_version_inventory(ip, vendor, "Non Rilevata", "offline")
        log_audit(f"Triage fallito per dispositivo '{ip}': non raggiungibile sulla porta 22 (SSH).")
        return {"status": "error", "message": f"Device {ip} non raggiungibile sulla porta 22 (SSH)"}

    username, password, secret = get_device_credentials(device)
    netmiko_type = 'cisco_ios' if vendor == 'cisco' else 'hp_procurve'
    
    device_params = {
        'device_type': netmiko_type,
        'host': ip,
        'username': username,
        'password': password,
        'secret': secret,
        'timeout': 15,        # timeout connessione
        'auth_timeout': 10,   # timeout autenticazione
        'banner_timeout': 10, # timeout banner SSH
    }

    try:
        with ConnectHandler(**device_params) as net_connect:
            net_connect.enable()
            
            # Caricamento dinamico del driver tramite Driver Factory
            try:
                driver = driver_factory(vendor, net_connect)
            except ValueError as ve:
                log_audit(f"Vendor non supportato per '{ip}': {ve}")
                update_version_inventory(ip, vendor, "Non Rilevata", "error")
                return {"status": "error", "message": str(ve)}
            
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
                try:
                    lldp_detail = net_connect.send_command("show lldp neighbors detail")
                    config_out += "\n--- SHOW LLDP NEIGHBORS DETAIL ---\n" + lldp_detail
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
                
            log_audit(f"Triage e backup completati con successo per dispositivo '{ip}' (Firmware: '{version}').")
            return {"status": "success", "version": version, "file": file_path}
            
    except Exception as e:
        logging.error(f"Errore su {ip}: {str(e)}")
        status = "auth_failed" if "auth" in str(e).lower() or "credentials" in str(e).lower() else "offline"
        update_version_inventory(ip, vendor, "Non Rilevata", status)
        log_audit(f"Triage fallito per dispositivo '{ip}': errore di connessione/autenticazione ({str(e)}).")
        return {"status": "error", "message": str(e)}

def send_custom_command(device, command: str):
    """Invia un comando CLI all'apparato previa validazione di sicurezza."""
    if any(cmd in command.lower() for cmd in DANGEROUS_COMMANDS):
        return {
            "status": "error", 
            "message": "Comando non consentito dalla policy di sicurezza aziendale (Blacklisted)"
        }
        
    vendor = device['Vendor'].lower()
    netmiko_type = 'cisco_ios' if vendor == 'cisco' else 'hp_procurve'
    
    username, password, secret = get_device_credentials(device)
    device_params = {
        'device_type': netmiko_type,
        'host': device['IP'],
        'username': username,
        'password': password,
        'secret': secret,
        'timeout': 15,        # timeout connessione
        'auth_timeout': 10,   # timeout autenticazione
        'banner_timeout': 10, # timeout banner SSH
    }
    try:
        with ConnectHandler(**device_params) as net_connect:
            net_connect.enable()
            output = net_connect.send_command(command)
            log_audit(f"Comando CLI '{command}' eseguito con successo sul dispositivo '{device['IP']}'.")
            return {"status": "success", "output": output}
    except Exception as e:
        log_audit(f"Esecuzione comando CLI '{command}' fallita sul dispositivo '{device['IP']}': {str(e)}")
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

    # 5. Parsing di "show lldp neighbors" classico (Cisco)
    lldp_cisco_section = re.search(r'--- SHOW LLDP NEIGHBORS ---\s*\n(.*?)(\n---|\Z)', content, re.DOTALL | re.IGNORECASE)
    if lldp_cisco_section:
        lines = lldp_cisco_section.group(1).strip().split('\n')
        started = False
        for line in lines:
            if "Device ID" in line or "Local Intf" in line:
                started = True
                continue
            if not started or not line.strip() or line.startswith("Capability") or line.startswith("---") or "Total entries" in line:
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

    # 6. Parsing di "SHOW LLDP NEIGHBORS DETAIL" (Cisco)
    lldp_detail_section = re.search(r'--- SHOW LLDP NEIGHBORS DETAIL ---\s*\n(.*?)(?=\n--- [A-Z]|\n===|\Z)', content, re.DOTALL | re.IGNORECASE)
    if lldp_detail_section:
        blocks = re.split(r'-{20,}', lldp_detail_section.group(1))
        for block in blocks:
            if not block.strip():
                continue
            local_port_m = re.search(r'Local Intf:\s*([^\n\r]+)', block, re.IGNORECASE)
            port_id_m = re.search(r'Port id:\s*([^\n\r]+)', block, re.IGNORECASE)
            port_desc_m = re.search(r'Port Description:\s*([^\n\r]+)', block, re.IGNORECASE)
            sys_name_m = re.search(r'System Name:\s*([^\n\r]+)', block, re.IGNORECASE)
            ip_m = re.search(r'(?:Management Address - IPv4|Management Address|IP Address):\s*([0-9.]+)', block, re.IGNORECASE)
            sys_desc_m = re.search(r'System Description:\s*([^\n\r]+(?:(?:\n\r?|\r\n?)[ \t]+[^\n\r]+)*)', block, re.IGNORECASE)
            
            if sys_name_m:
                # remote port: prefer Port Description if available, otherwise Port id
                remote_port = "Unknown"
                if port_desc_m:
                    remote_port = port_desc_m.group(1).strip()
                elif port_id_m:
                    remote_port = port_id_m.group(1).strip()
                
                version_str = None
                if sys_desc_m:
                    sys_desc = re.sub(r'\s+', ' ', sys_desc_m.group(1)).strip()
                    version_str = sys_desc
                
                neighbors.append({
                    "neighbor_id": sys_name_m.group(1).strip(),
                    "neighbor_ip": ip_m.group(1).strip() if ip_m else None,
                    "local_port": local_port_m.group(1).strip() if local_port_m else "Unknown",
                    "remote_port": remote_port,
                    "version": version_str
                })

    # Deduplicazione intelligente per rimuovere duplicati FQDN/summary e fondere i dettagli ricchi
    merged_neighbors = {}
    for n in neighbors:
        neigh_id = n["neighbor_id"]
        base_id = neigh_id.split('.')[0] if '.' in neigh_id else neigh_id
        
        # Chiave di deduplicazione: porta locale e hostname base in minuscolo
        key = (n["local_port"].lower(), base_id.lower())
        
        if key not in merged_neighbors:
            merged_neighbors[key] = dict(n)
        else:
            existing = merged_neighbors[key]
            # Unisci i dettagli
            if n.get("neighbor_ip") and not existing.get("neighbor_ip"):
                existing["neighbor_ip"] = n["neighbor_ip"]
            if n.get("version") and not existing.get("version"):
                existing["version"] = n["version"]
            if n.get("remote_port") and n.get("remote_port") != "Unknown" and (existing.get("remote_port") == "Unknown" or len(n.get("remote_port")) < len(existing.get("remote_port")) or ":" not in n.get("remote_port")):
                existing["remote_port"] = n["remote_port"]
                
    return list(merged_neighbors.values())

def generate_network_map(group_filter=None) -> dict:
    """Scansiona la cartella backup-config e genera la mappa di rete (nodi e collegamenti)."""
    devices = get_all_devices()
    
    def get_device_type(hostname: str) -> str:
        name_lower = hostname.lower()
        if "ap" in name_lower or "wifi" in name_lower or "wlan" in name_lower:
            return "ap"
        elif "rtr" in name_lower or "router" in name_lower or "fw" in name_lower or "firewall" in name_lower:
            return "router"
        elif "phone" in name_lower or "ipphone" in name_lower or "tel" in name_lower:
            return "phone"
        elif "srv" in name_lower or "server" in name_lower or "esxi" in name_lower or "host" in name_lower or "nas" in name_lower or "ubuntu" in name_lower or "debian" in name_lower or "linux" in name_lower:
            return "server"
        elif "pc" in name_lower or "workstation" in name_lower or "client" in name_lower or "desktop" in name_lower or "laptop" in name_lower:
            return "pc"
        else:
            return "switch"
            
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
        ip_match = re.search(
            r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', filename
        )
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
    versions = get_detected_versions()
    for ip, d in ip_to_device.items():
        # Se abbiamo letto il backup, usiamo l'hostname reale, altrimenti l'IP
        label = parsed_devices.get(ip, {}).get("hostname", ip)
        scan = versions.get(ip, {"status": "offline"})
        status = scan.get("status", "offline")
        nodes_map[ip] = {
            "id": ip,
            "label": label,
            "group": d.get('Group', 'Generale'),
            "status": status,
            "device_type": get_device_type(label),
            "vendor": d.get('Vendor', 'cisco')
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
            
            # Pulisce l'hostname rimuovendo l'eventuale suffisso di dominio FQDN (.lab.local, ecc.)
            base_neigh_id = neigh_id.split('.')[0] if '.' in neigh_id else neigh_id

            # Risoluzione dell'IP del vicino
            target_ip = neigh_ip
            if not target_ip:
                # Cerca per hostname nella mappa (sia intero che base senza dominio)
                target_ip = hostname_to_ip.get(neigh_id.lower()) or hostname_to_ip.get(base_neigh_id.lower())
            
            if not target_ip:
                # Se non troviamo l'IP, usiamo il nome pulito come ID per evitare duplicati FQDN
                target_ip = f"discovered_{sanitize_filename(base_neigh_id)}"
                
            # Se il target non è presente nei nodi, creiamo un nodo "scoperto"
            if target_ip not in nodes_map:
                nodes_map[target_ip] = {
                    "id": target_ip,
                    "label": base_neigh_id,
                    "group": "Discovered",
                    "status": "discovered",
                    "device_type": get_device_type(base_neigh_id),
                    "vendor": "discovered",
                    "version": neigh.get("version")
                }
            elif neigh.get("version") and not nodes_map[target_ip].get("version"):
                nodes_map[target_ip]["version"] = neigh.get("version")

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

    nodes = list(nodes_map.values())
    if group_filter and group_filter != "all":
        # Nodi che appartengono al gruppo selezionato
        group_node_ids = {
            n["id"] for n in nodes_map.values()
            if n["group"] == group_filter
        }

        # Includi i vicini diretti (cross-group boundary nodes)
        # così i link verso l'upstream/downstream rimangono visibili
        boundary_ids = set()
        for link in links:
            if link["source"] in group_node_ids:
                boundary_ids.add(link["target"])
            if link["target"] in group_node_ids:
                boundary_ids.add(link["source"])

        valid_node_ids = group_node_ids | boundary_ids

        # I boundary node appaiono in grigio per distinguerli
        nodes = []
        for n in nodes_map.values():
            if n["id"] in group_node_ids:
                nodes.append(n)
            elif n["id"] in boundary_ids:
                # Copia con marcatura visiva come nodo esterno
                boundary_node = dict(n)
                boundary_node["is_boundary"] = True
                nodes.append(boundary_node)

        links = [l for l in links if
                 l["source"] in valid_node_ids and
                 l["target"] in valid_node_ids]

    return {
        "nodes": nodes,
        "links": links
    }
