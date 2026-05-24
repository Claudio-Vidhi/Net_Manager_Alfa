import os
import re

BACKUP_FOLDER = 'backup-config'

def parse_topology_from_backups():
    """Analizza i file di testo dei backup cercando i vicini CDP/LLDP per tracciare i link."""
    topology_map = {"nodes": [], "links": []}
    discovered_nodes = set()
    
    if not os.path.exists(BACKUP_FOLDER):
        return topology_map

    files = [f for f in os.listdir(BACKUP_FOLDER) if f.endswith('.txt')]
    
    # 1. Identificazione Nodi basata sui file di backup presenti
    for f in files:
        # Estrae l'IP o l'hostname dal nome del file (es: Switch1-10.0.0.1.txt)
        node_id = f.replace('.txt', '')
        discovered_nodes.add(node_id)
        
    for node in discovered_nodes:
        topology_map["nodes"].append({"id": node, "label": node})

    # 2. Parsing Euristico delle adiacenze (CDP / LLDP Neighbor tables memorizzate nel testo)
    for f in files:
        source_node = f.replace('.txt', '')
        filepath = os.path.join(BACKUP_FOLDER, f)
        
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as file_content:
            content = file_content.read()
            
            # Regex euristica per intercettare i vicini menzionati nei log di show cdp/lldp info
            # Cerca pattern comuni come Device ID, IP di management o stringhe di vicinato
            neighbors = re.findall(r'(?:Device ID|System Name|Capability):\s+(\S+)', content, re.IGNORECASE)
            
            for target in neighbors:
                # Pulisce i caratteri speciali della stringa trovata
                target_clean = target.split('(')[0].strip()
                
                # Trova se il vicino corrisponde a un nodo gestito nella nostra rete
                match_node = next((n for n in discovered_nodes if target_clean in n), None)
                if match_node and source_node != match_node:
                    link = {"source": source_node, "target": match_node}
                    if link not in topology_map["links"]:
                        topology_map["links"].append(link)
                        
    return topology_map
