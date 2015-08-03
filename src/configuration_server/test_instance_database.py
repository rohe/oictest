# -*- coding: utf-8 -*-
import json
import threading
import dataset
from prettytable import PrettyTable

PORT_COLUMN = 'port'
PORT_TYPE_COLUMN = 'port_type'
INSTANCE_ID_COLUMN = "instance_id"
ISSUER_COLUMN = "issuer"
CONFIG_FILE_COLUMN = 'config_file'


class NoPortAvailable(Exception):
    pass


class PortDatabase():
    TABLE_NAME = 'ports'

    STATIC_PORT_TYPE = 'static'
    DYNAMIC_PORT_TYPE = 'dynamic'

    config_tread_lock = threading.Lock()

    def __init__(self, database_path=None, is_port_used_func=None):
        self.database = dataset.connect('sqlite:///:memory:')
        if database_path is not None:
            self.database = dataset.connect('sqlite:///' + database_path)
        self.table = self.database[self.TABLE_NAME]
        self.is_port_used_func = is_port_used_func

    def clear(self):
        self.table.drop()
        self.table = self.database[self.TABLE_NAME]

    def upsert_row(self, row, config_file):
        self.upsert(port=row[PORT_COLUMN],
                    issuer=row[ISSUER_COLUMN],
                    instance_id=row[INSTANCE_ID_COLUMN],
                    port_type=row[PORT_TYPE_COLUMN],
                    config_file=config_file)

    def upsert(self, port, issuer, instance_id, port_type, config_file=None):
        if isinstance(issuer, str):
            issuer = unicode(issuer, encoding='utf-8')

        if isinstance(instance_id, str):
            instance_id = unicode(instance_id, encoding='utf-8')

        if isinstance(port_type, str):
            port_type = unicode(port_type, encoding='utf-8')

        if isinstance(config_file, dict):
            config_file = json.dumps(config_file)

        if isinstance(config_file, str):
            config_file = unicode(config_file, encoding='utf-8')

        row = dict(port=port,
                   port_type=port_type,
                   instance_id=instance_id,
                   issuer=issuer,
                   config_file=config_file)

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
        rows = self.table.find(order_by=[PORT_COLUMN])
        for row in rows:
            list.append([row[PORT_COLUMN], row[ISSUER_COLUMN], row[INSTANCE_ID_COLUMN], row[PORT_TYPE_COLUMN]])
        return list

    def get_row(self, port):
        row = self.table.find_one(port=port)

        if not row:
            return None

        if row[CONFIG_FILE_COLUMN]:
            row[CONFIG_FILE_COLUMN] = json.loads(row[CONFIG_FILE_COLUMN])

        if row[PORT_COLUMN]:
            row[PORT_COLUMN] = int(row[PORT_COLUMN])

        return row

    def print_table(self):
        list = self.get_table_as_list()
        table = PrettyTable(["Port", "Issuer", "Instance ID", "Port Type"])
        table.padding_width = 1

        for row in list:
            list = []
            for element in row:
                if isinstance(element, int):
                    list.append(element)
                else:
                    list.append(element.encode('utf8'))
            table.add_row(list)
        print table

    def remove_row(self, port):
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

        while self.is_port_used_func(port):
            port += 1

        return port

    def allocate_port(self, issuer, instance_id, port_type, min_port, max_port):
        with self.config_tread_lock:
            port = self._get_existing_port(issuer=issuer, instance_id=instance_id)

            if self._get_port_type(port) == port_type:
                port = self._get_existing_port(issuer, instance_id, port_type)

                if port:
                    return int(port)
            elif port is not None:
                self.remove_row(port)

            port = self._get_next_free_port(min_port, max_port)
            self.upsert(port, issuer, instance_id, port_type)
            return int(port)