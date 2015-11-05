#!/usr/bin/env python
import json
import os
import re
import sys
import argparse

from configuration_server.configurations import load_config_module, \
    CONFIG_DICT_INSTANCE_ID_KEY, create_module_string, \
    get_config_file_path, get_issuer_from_config_file
from configuration_server.test_instance_database import PortDatabase, CONFIG_FILE_COLUMN

DATABASE_SELECTED = "database"
CONFIG_FILE_SELECTED = "config_file"
OPRP_SSL_MODULE = "sslconf"


class PortDatabaseEditor(object):
    def __init__(self, config_file_path='.'):
        self.config_file_path = config_file_path
        sys.path.append(config_file_path)

    def get_config_file_dict(self, module):
        try:
            return load_config_module(module)
        except ImportError as ex:
            raise ImportError(ex.message + " in path: %s" % self.config_file_path)

    @staticmethod
    def get_issuer(config_file_dict):
        return get_issuer_from_config_file(config_file_dict)

    @staticmethod
    def get_port(filename):
        port = int(filename.split("_")[2].split(".")[0])
        return port

    @staticmethod
    def get_instance_id(config_file_dict, port):
        try:
            return config_file_dict[CONFIG_DICT_INSTANCE_ID_KEY]
        except KeyError:
            return str(port)

    @staticmethod
    def get_port_type(config_file_dict):
        if 'srv_discovery_url' in config_file_dict:
            return PortDatabase.DYNAMIC_PORT_TYPE
        return PortDatabase.STATIC_PORT_TYPE

    @staticmethod
    def _restore_config_file(database, full_config_file_path, port):
        config_dict = database.get_row_by_port(port)[CONFIG_FILE_COLUMN]
        module_content = create_module_string(config_dict,
                                              port,
                                              config_dict['base_url'],
                                              ssl_module=OPRP_SSL_MODULE)
        with open(full_config_file_path, "w") as _file:
            _file.write(module_content)

    def prompt_user_for_config_file_restoration(self, database, removed_config_file_ports):
        for port in removed_config_file_ports:
            full_config_file_path = get_config_file_path(port, self.config_file_path)

            msg = 'The configuration file: %s has been remove but could be restored from ' \
                  'the database. If not restored it will be removed permanently ' \
                  'from the database. Do you want to restore it?' % full_config_file_path

            user_input = raw_input("%s (y/N) " % msg).lower()

            if user_input == 'y':
                self._restore_config_file(database, full_config_file_path, port)
            elif user_input == 'n':
                database.remove_row(port)
            else:
                sys.stdout.write("\nPlease respond with 'Y' or 'N' \n\n")
                return self.prompt_user_for_config_file_restoration(database,
                                                                    removed_config_file_ports)

    def prompt_user_for_selecting_db_or_file_config(self,
                                                    database_config,
                                                    file_config,
                                                    config_module):
        sorted_database_config = json.dumps(database_config, sort_keys=True)
        sorted_file_config = json.dumps(file_config, sort_keys=True)

        msg = "The configuration (%s) in the Database and the configuration " \
              "File differs. The two configurations:\n" \
              "D: %s \nF: %s \nWhich one would you like to use?" \
              % (config_module, sorted_database_config, sorted_file_config)

        user_input = raw_input("%s (d/F) " % msg).lower()

        if user_input == 'd':
            return DATABASE_SELECTED
        elif user_input == 'f':
            return CONFIG_FILE_SELECTED
        else:
            sys.stdout.write("\nPlease respond with 'D' or 'F' \n\n")
            return self.prompt_user_for_selecting_db_or_file_config(database_config,
                                                                    file_config,
                                                                    config_module)

    @staticmethod
    def identify_ports_for_removed_config_files(database, config_files):
        database_ports = database.get_all_ports()
        config_file_ports = []
        for file in config_files:
            port = int(re.search(r'\d+', file).group())
            config_file_ports.append(port)
        ports = set(database_ports).difference(set(config_file_ports))
        return list(ports)

    def synchronize_removed_config_files(self, database, config_files):
        ports = self.identify_ports_for_removed_config_files(database, config_files)
        self.prompt_user_for_config_file_restoration(database, ports)

    def list_config_files(self):
        config_file_pattern = re.compile("rp_conf_[0-9]+.py$")
        files = [file for file in os.listdir(self.config_file_path) if
                 config_file_pattern.match(file)]
        return files

    @staticmethod
    def convert_dict_to_unicode(dictionary):
        if isinstance(dictionary, dict):
            dictionary = json.dumps(dictionary)

        if isinstance(dictionary, str):
            dictionary = unicode(dictionary, encoding='utf-8')

        return json.loads(dictionary)

    def sync_database_information(self, database, module):
        try:
            file_config_info = self.get_config_file_dict(module)
        except Exception as ex:
            print(ex.message)
        else:
            port = self.get_port(module)
            issuer = self.get_issuer(file_config_info)
            instance_id = self.get_instance_id(file_config_info, port)
            port_type = self.get_port_type(file_config_info)

            try:
                database_config_info = database.get_row_by_port(port)[CONFIG_FILE_COLUMN]
            except TypeError:
                database.upsert(port=port,
                                issuer=issuer,
                                instance_id=instance_id,
                                port_type=port_type,
                                config_file=file_config_info)
            else:
                if not database_config_info:
                    database.upsert(port=port,
                                    issuer=issuer,
                                    instance_id=instance_id,
                                    port_type=port_type,
                                    config_file=file_config_info)
                    database_config_info = file_config_info

                database_config_info_as_unicode = self.convert_dict_to_unicode(database_config_info)
                file_config_info_as_unicode = self.convert_dict_to_unicode(file_config_info)
                if database_config_info_as_unicode != file_config_info_as_unicode:
                    selected_config_version = self.prompt_user_for_selecting_db_or_file_config(
                        database_config_info_as_unicode, file_config_info_as_unicode, module)
                    if selected_config_version == DATABASE_SELECTED:
                        module_content = create_module_string(database_config_info,
                                                              port,
                                                              base_url=database_config_info['base_url'],
                                                              ssl_module=OPRP_SSL_MODULE)
                        with open(get_config_file_path(port, self.config_file_path), "w") as _file:
                            _file.write(module_content)
                    elif selected_config_version == CONFIG_FILE_SELECTED:
                        database.upsert(port=port,
                                        issuer=issuer,
                                        instance_id=instance_id,
                                        port_type=port_type,
                                        config_file=file_config_info)

    def extract_database_info_from_config_file(self, database):
        self.synchronize_removed_config_files(database, self.list_config_files())
        config_files = self.list_config_files()

        for module in config_files:
            module = module[:-3]

            self.sync_database_information(database, module)


if __name__ == "__main__":
    PARSER = argparse.ArgumentParser()
    PARSER.add_argument('-s', dest='show_database_content', action='store_true',
                        help="Print database")

    PARSER.add_argument('-r', dest='port_to_remove',
                        help="Remove port")

    PARSER.add_argument('-g', dest='generate_database', action='store_true',
                        help="Generate database from configuration files in current folder")

    PARSER.add_argument('-p', dest='oprp_config_file_path',
                        help="Path to where the oprp config files are located")

    PARSER.add_argument(dest="database")
    ARGS = PARSER.parse_args()

    DATABASE = PortDatabase(ARGS.database)

    if ARGS.port_to_remove:
        DATABASE.remove_row(ARGS.port_to_remove)

    if ARGS.oprp_config_file_path:
        CONFIG_EDITOR = PortDatabaseEditor(ARGS.oprp_config_file_path)
    else:
        CONFIG_EDITOR = PortDatabaseEditor()

    if ARGS.generate_database:
        CONFIG_EDITOR.extract_database_info_from_config_file(DATABASE)

    if ARGS.show_database_content:
        DATABASE.print_port_table()
        DATABASE.print_issuer_contact_table()
