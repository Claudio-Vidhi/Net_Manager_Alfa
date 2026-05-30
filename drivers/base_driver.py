class BaseDriver:
    def __init__(self, connection):
        self.connection = connection

    def get_version(self):
        raise NotImplementedError

    def get_backup_command(self):
        raise NotImplementedError
