import importlib
import os
import imp
import argparse
import re
import sys

from port_database import PortDatabase
from config_server import get_issuer_from_config_file
from config_server import CONFIG_DICT_INSTANCE_ID_KEY
from config_server import load_config_module


class ConfigFileEditor(object):

    def __init__(self, config_file_path='../rp'):
        self.config_file_path = config_file_path
        sys.path.append(config_file_path)

    def get_config_file_dict(self, module):
        try:
            return load_config_module(module)
        except ImportError as ex:
            raise ImportError(ex.message + " in path %s" % self.config_file_path)

    def get_issuer(self, config_file_dict):
        return get_issuer_from_config_file(config_file_dict)

    def get_port(self, filename):
        port = int(filename.split("_")[2].split(".")[0])
        return port

    def get_instance_id(self, config_file_dict, port):
        try:
            return config_file_dict[CONFIG_DICT_INSTANCE_ID_KEY]
        except KeyError:
            return str(port)

    def get_port_type(self, config_file_dict):
        try:
            config_file_dict['srv_discovery_url']
            return PortDatabase.DYNAMIC_PORT_TYPE
        except KeyError:
            return PortDatabase.STATIC_PORT_TYPE

    def extract_database_info_from_config_file(self, database):
        files = [f for f in os.listdir('.')]

        config_file_pattern = re.compile("rp_conf_[0-9]+.py$")
        for module in files:
            if config_file_pattern.match(module):
                module = module[:-3]

                try:
                    config_file_dict = self.get_config_file_dict(module)
                except Exception as ex:
                    print(ex.message)
                else:
                    port = self.get_port(module)
                    issuer = self.get_issuer(config_file_dict)
                    instance_id = self.get_instance_id(config_file_dict, port)
                    port_type = self.get_port_type(config_file_dict)

                    database.upsert(port=port,issuer=issuer, instance_id=instance_id, port_type=port_type)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-s', dest='show_database_content', action='store_true',
                        help="Print database")

    parser.add_argument('-r', dest='port_to_remove',
                        help="Remove port")

    parser.add_argument('-g', dest='generate_database', action='store_true',
                        help="Generate database from configuration files in current folder")

    parser.add_argument('-p', dest='oprp_config_file_path',
                        help="Generate database from configuration files in current folder")

    parser.add_argument(dest="database")
    args = parser.parse_args()

    database = PortDatabase(args.database)

    if args.show_database_content:
        database.print_table()

    if args.port_to_remove:
        database._remove_row(args.port_to_remove)

    if args.oprp_config_file_path:
        config_editor = ConfigFileEditor(args.oprp_config_file_path)
    else:
        config_editor = ConfigFileEditor()

    if args.generate_database:
        config_editor.extract_database_info_from_config_file(database)
        database.print_table()
