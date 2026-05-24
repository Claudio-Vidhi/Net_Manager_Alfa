import json
import os
import csv

HOSTS_CSV = "network_hosts.csv"
VERSION_DATA_FILE = "detected_versions.json"

def get_all_devices():
    devices = []
    if not os.path.exists(HOSTS_CSV):
        return devices
    with open(HOSTS_CSV, mode='r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            devices.append(row)
    return devices

def add_device_to_csv(ip, vendor, credential_profile, username="", password="", enable_secret=""):
    """Salva il dispositivo associandolo a credenziali dirette o a un profilo di gruppo."""
    devices = get_all_devices()
    devices = [d for d in devices if d['IP'] != ip]
    
    new_device = {
        'IP': ip, 'Vendor': vendor.lower(), 'Profile': credential_profile,
        'Username': username, 'Password': password, 'Enable Secret': enable_secret
    }
    devices.append(new_device)
    
    with open(HOSTS_CSV, mode='w', newline='', encoding='utf-8') as f:
        fieldnames = ['IP', 'Vendor', 'Profile', 'Username', 'Password', 'Enable Secret']
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for d in devices:
            writer.writerow(d)

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
