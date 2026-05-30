import re
from drivers.base_driver import BaseDriver

class HpProcurveDriver(BaseDriver):
    def get_version(self):
        output = self.connection.send_command("show system")
        match = re.search(r'Firmware revision\s+:\s+(\S+)', output, re.IGNORECASE)
        return match.group(1).strip() if match else "Unknown"

    def get_backup_command(self):
        return "show run"
