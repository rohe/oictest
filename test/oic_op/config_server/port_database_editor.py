import os
import argparse
from port_database import PortDatabase
from config_server import get_issuer_from_config_file
from config_server import parse_config_string
from config_server import CONFIG_DICT_INSTANCE_ID_KEY


class ConfigFileEditor(object):

    def get_config_file_dict(self, config_file_path):
        with open(config_file_path, "r") as config_file:
            config_module = config_file.read()
            config_file_dict = parse_config_string(config_module)
        return config_file_dict

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

    def extract_database_info_from_config_file(self, folder, database):
        for filename in os.listdir(folder):
            if filename.startswith("rp_conf") and filename.endswith(".py"):
                config_file_dict = self.get_config_file_dict(folder + filename)

                port = self.get_port(filename)
                issuer = self.get_issuer(config_file_dict)
                instance_id = self.get_instance_id(config_file_dict, port)
                port_type = self.get_port_type(config_file_dict)

                database.upsert(port=port,issuer=issuer, instance_id=instance_id, port_type=port_type)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-p', dest='print_database', action='store_true',
                        help="Print database")

    parser.add_argument('-r', dest='port_to_remove',
                        help="Remove port")

    parser.add_argument('-g', dest='folder_path',
                        help="Generate database from configuration files in folder")

    parser.add_argument(dest="database")
    args = parser.parse_args()

    database = PortDatabase(args.database)

    if args.print_database:
        database.print_table()

    if args.port_to_remove:
        database._remove_row(args.port_to_remove)

    if args.folder_path:
        config_editor = ConfigFileEditor()
        config_editor.extract_database_info_from_config_file(args.folder_path, database)
