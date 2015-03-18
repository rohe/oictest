import threading
import dataset
from prettytable import PrettyTable

PORT_COLUMN = 'port'
PORT_TYPE_COLUMN = 'port_type'
INSTANCE_ID_COLUMN = "instance_id"
ISSUER_COLUMN = "issuer"

class NoPortAvailable(Exception):
    pass

class PortDatabase():
    TABLE_NAME = 'ports'

    STATIC_PORT_TYPE = 'static'
    DYNAMIC_PORT_TYPE = 'dynamic'

    config_tread_lock = threading.Lock()

    def __init__(self, dict_path):
        self.database = dataset.connect('sqlite:///' + dict_path)
        self.table = self.database[self.TABLE_NAME]

    def upsert(self, port, issuer, instance_id, port_type):
        row = dict(port=port, port_type=port_type, instance_id=instance_id, issuer=issuer)
        self.table.upsert(row, [PORT_COLUMN])

    def _get_column_elements(self, column, entries=None):
        if not entries:
            entries = self.table.all()
        column_entries = []
        for entry in entries:
            column_entries.append(entry[column])
        return column_entries

    def get_all_ports(self):
        ports = self._get_column_elements(PORT_COLUMN)
        return map(int, ports)

    def get_all_issuers(self):
        return self._get_column_elements(ISSUER_COLUMN)

    def get_instance_ids(self, issuer):
        all_instance_ids = self.table.find(issuer=issuer)
        return self._get_column_elements(INSTANCE_ID_COLUMN, entries=all_instance_ids)


    def get_table_as_list(self):
        list = []
        for row in self.table:
            list.append([row[PORT_COLUMN], row['issuer'], row[INSTANCE_ID_COLUMN], row[PORT_TYPE_COLUMN]])
        return list

    def print_table(self):
        list =self.get_table_as_list()
        table = PrettyTable(["Port", "Issuer", "Instance ID", "Port Type"])
        table.padding_width = 1

        for row in list:
            table.add_row([str(x) for x in row])
        print table

    def _remove_row(self, port):
        self.table.delete(port=port)

    def _get_port_type(self, port):
        row = self.table.find_one(port=port)
        if not row:
            return None
        return row[PORT_TYPE_COLUMN]

    def _get_existing_port(self, issuer, instance_id, port_type=None):
        if not port_type:
            row = self.table.find_one(issuer=issuer, instance_id=instance_id)
        else:
            row = self.table.find_one(issuer=issuer, instance_id=instance_id, port_type=port_type)

        if not row:
            return None
        return row[PORT_COLUMN]

    def _get_next_free_port(self, min_port, max_port):
        existing_ports = self.get_all_ports()
        port = min_port
        while port in existing_ports:
            port += 1
        if port > max_port:
            raise NoPortAvailable(
                "No port is available at the moment, please try again later")
        return port

    def enter_row(self, issuer, instance_id, port_type, min_port, max_port):
        with self.config_tread_lock:
            port = self._get_existing_port(issuer=issuer, instance_id=instance_id)

            if self._get_port_type(port) == port_type:
                port = self._get_existing_port(issuer, instance_id, port_type)

                if port:
                    return port
            elif port is not None:
                self._remove_row(port)

            port = self._get_next_free_port(min_port, max_port)
            self.upsert(port, issuer, instance_id, port_type)
            return int(port)