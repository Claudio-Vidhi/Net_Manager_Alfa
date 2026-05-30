import re
from drivers.base_driver import BaseDriver

class CiscoIosDriver(BaseDriver):
    def get_version(self):
        output = self.connection.send_command("show version")
        match = re.search(r', Version\s+([^,]+)', output, re.IGNORECASE)
        return match.group(1).strip() if match else "Unknown"

    def get_backup_command(self):
        return "show running-config"
