# -*- coding: utf-8 -*-
import json
import threading

import dataset
from prettytable import PrettyTable

from configuration_server.configurations import UserFriendlyException, \
    set_contact_email_in_client_config

PORT_COLUMN = 'port'
PORT_TYPE_COLUMN = 'port_type'
INSTANCE_ID_COLUMN = "instance_id"
ISSUER_COLUMN = "issuer"
CONFIG_FILE_COLUMN = 'config_file'
EMAIL_COLUMN = 'email'

class NoPortAvailable(UserFriendlyException):
    pass


class PortMissingInDatabase(UserFriendlyException):
    pass


class MissingRequiredAttribute(Exception):
    pass


class PortDatabase():
    PORT_TABLE_NAME = 'ports'
    ISSUER_CONTACT_TABLE_NAME = 'issuer_contact'

    STATIC_PORT_TYPE = 'static'
    DYNAMIC_PORT_TYPE = 'dynamic'

    config_tread_lock = threading.Lock()

    def __init__(self, database_path=None, is_port_used_func=None):
        self.database = dataset.connect('sqlite:///:memory:')
        if database_path is not None:
            self.database = dataset.connect('sqlite:///' + database_path)
        self.port_table = self.database[self.PORT_TABLE_NAME]
        self.issuer_contact_table = self.database[self.ISSUER_CONTACT_TABLE_NAME]
        self.is_port_used_func = is_port_used_func

    def clear(self):
        self.issuer_contact_table.drop()
        self.issuer_contact_table = self.database[self.ISSUER_CONTACT_TABLE_NAME]

        self.port_table.drop()
        self.port_table = self.database[self.PORT_TABLE_NAME]

    def upsert_row(self, row, config_file=None, email=None):
        config_file = self.read_attibute_from_row_if_none(config_file, row, CONFIG_FILE_COLUMN)
        email = self.read_attibute_from_row_if_none(email, row, EMAIL_COLUMN)

        self.upsert(port=row[PORT_COLUMN],
                    issuer=row[ISSUER_COLUMN],
                    instance_id=row[INSTANCE_ID_COLUMN],
                    port_type=row[PORT_TYPE_COLUMN],
                    config_file=config_file,
                    email=email)

    def read_attibute_from_row_if_none(self, attribute, row, column):
        if not attribute:
            if column not in row:
                raise MissingRequiredAttribute("Missing Required Attribute: " + column)
            attribute = row[column]
        return attribute

    def remove_last_slash(self, string):
        if isinstance(string, basestring):
            if string.endswith("/"):
                string = string[:-1]
        return string

    def upsert(self, port, issuer, instance_id, port_type, config_file=None, email=None):
        issuer = self.remove_last_slash(issuer)
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

        if isinstance(email, str):
            email = unicode(email, encoding='utf-8')

        row = dict(port=port,
                   port_type=port_type,
                   instance_id=instance_id,
                   issuer=issuer,
                   config_file=config_file,
                   email=email)

        self.port_table.upsert(row, [PORT_COLUMN])

    def _get_column_elements(self, column, entries=None):
        if not entries:
            entries = self.port_table.all()
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
        issuer = self.remove_last_slash(issuer)
        all_instance_ids = self.port_table.find(issuer=issuer)
        return self._get_column_elements(INSTANCE_ID_COLUMN, entries=all_instance_ids)

    def get_port_table_as_list(self):
        list = []
        rows = self.port_table.find(order_by=[PORT_COLUMN])
        for row in rows:
            list.append([row[PORT_COLUMN], row[ISSUER_COLUMN], row[INSTANCE_ID_COLUMN],
                         row[PORT_TYPE_COLUMN]])
        return list

    def get_issuer_contact_table_as_list(self):
        list = []
        rows = self.issuer_contact_table.find(order_by=[ISSUER_COLUMN])
        for row in rows:
            list.append([row[ISSUER_COLUMN], row[EMAIL_COLUMN]])
        return list

    def port_column_to_int(self, row):
        if row[PORT_COLUMN]:
            row[PORT_COLUMN] = int(row[PORT_COLUMN])
        return row

    def get_port(self, issuer, instance_id):
        issuer = self.remove_last_slash(issuer)
        row = self.port_table.find_one(issuer=issuer, instance_id=instance_id)

        if not row:
            raise PortMissingInDatabase("Failed to identify test instance in database.",
                                        log_info="No port found in the database for the given "
                                                 "credentials issuer: %s instance_id: %s"
                                                 % (issuer, instance_id),
                                        show_trace=False)
        return self.port_column_to_int(row)[PORT_COLUMN]

    def get_row_by_port(self, port):
        row = self.port_table.find_one(port=port)

        if not row:
            return None

        if row[CONFIG_FILE_COLUMN]:
            row[CONFIG_FILE_COLUMN] = json.loads(row[CONFIG_FILE_COLUMN])

        row = self.port_column_to_int(row)

        return row

    def get_row_by_instance_id(self, issuer, instance_id):
        port = self.get_port(issuer, instance_id)
        return self.get_row_by_port(port)

    def get_configuration(self, issuer, instance_id):
        row = self.get_row_by_instance_id(issuer, instance_id)
        if row:
            return row[CONFIG_FILE_COLUMN]
        return None

    def print_port_table(self):
        list = self.get_port_table_as_list()
        table = PrettyTable(["Port", "Issuer", "Instance ID", "Port Type"])
        self.print_table(list, table)

    def print_issuer_contact_table(self):
        list = self.get_issuer_contact_table_as_list()
        table = PrettyTable(["Issuer", "Mail"])
        self.print_table(list, table)

    def print_table(self, list, table):
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
        self.port_table.delete(port=port)

    def _get_port_type(self, port):
        row = self.port_table.find_one(port=port)
        if not row:
            return None
        return row[PORT_TYPE_COLUMN]

    def get_existing_port(self, issuer, instance_id, port_type=None):
        issuer = self.remove_last_slash(issuer)
        if not port_type:
            row = self.port_table.find_one(issuer=issuer, instance_id=instance_id)
        else:
            row = self.port_table.find_one(issuer=issuer, instance_id=instance_id,
                                           port_type=port_type)

        if not row:
            return None
        return row[PORT_COLUMN]

    def _get_next_free_port(self, min_port, max_port):
        existing_ports = self.get_all_ports()
        port = min_port
        while port in existing_ports:
            port += 1
        if port > max_port:
            raise NoPortAvailable("")

        while self.is_port_used_func(port):
            port += 1

        return port

    def set_email_info(self, issuer, email):
        issuer = self.remove_last_slash(issuer)
        contact_info = dict(issuer=issuer, email=email)
        self.issuer_contact_table.upsert(contact_info, [ISSUER_COLUMN])

        rows = self.port_table.find(issuer=issuer)
        for row in rows:
            if row[CONFIG_FILE_COLUMN]:
                if row[CONFIG_FILE_COLUMN] != 'null':
                    updated_client_config = set_contact_email_in_client_config(
                        row[CONFIG_FILE_COLUMN],
                        email
                    )
                    row[CONFIG_FILE_COLUMN] = json.dumps(updated_client_config)
                    self.upsert_row(row)


    def allocate_port(self, issuer, instance_id, port_type, min_port, max_port):
        with self.config_tread_lock:
            port = self.get_existing_port(issuer=issuer, instance_id=instance_id)

            if self._get_port_type(port) == port_type:
                port = self.get_existing_port(issuer, instance_id, port_type)

                if port:
                    return int(port)
            elif port is not None:
                self.remove_row(port)

            port = self._get_next_free_port(min_port, max_port)
            self.upsert(port, issuer, instance_id, port_type)
            return int(port)

    def get_ports(self, issuer):
        ports = []
        rows = self.port_table.find(issuer=issuer)
        for row in rows:
            ports.append(int(row[PORT_COLUMN]))
        return ports

    def identify_existing_contact_info(self, issuer):
        row = self.issuer_contact_table.find_one(issuer=issuer)
        if row:
            if EMAIL_COLUMN in row:
                return row[EMAIL_COLUMN]
        return None
