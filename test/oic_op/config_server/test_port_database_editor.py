import os
from mock import MagicMock, patch
import mock
from port_database_editor import ConfigFileEditor
from config_server import CONFIG_DICT_INSTANCE_ID_KEY
from config_server import get_config_file_path
from port_database import PortDatabase, CONFIG_FILE_COLUMN

__author__ = 'danielevertsson'

import unittest

class TestPortDatabaseEditor(unittest.TestCase):

    def setUp(self):
        self.config_editor = ConfigFileEditor("../rp")
        self.test_db = "./test.db"
        self.database = PortDatabase(self.test_db)

    def tearDown(self):
        os.remove(self.test_db)

    def test_get_instance_id_from_config_with_instance_id(self):
        _instance_id = "ID_1"
        config_file_dict = {CONFIG_DICT_INSTANCE_ID_KEY: _instance_id}
        returned_instance_id = self.config_editor.get_instance_id(config_file_dict, 8000)
        self.assertEqual(_instance_id, returned_instance_id)

    def _remove_config_files(self, folder, ports):
        for port in ports:
            config_file_name = get_config_file_path(port, folder)
            os.remove(config_file_name)

    def _create_config_files(self, folder, ports, file_content=""):
        for port in ports:
            config_file_name = get_config_file_path(port, folder)
            with open(config_file_name, "w") as _file:
                _file.write(file_content)

    def test_port_is_returned_when_no_instance_id_exists(self):
        port = 8000
        config_file_dict = {}
        returned_instance_id = self.config_editor.get_instance_id(config_file_dict, port)
        self.assertEqual(port, int(returned_instance_id))

    def test_get_port_from_module(self):
        port = self.config_editor.get_port("rp_conf_8001")
        self.assertEqual(port, 8001)

    def test_get_config_file_dict_from_module(self):
        folder = "."
        ports = [0]
        file_content = "CLIENT = {'first_key': 'public',\n 'second_key': 'public'}"
        self._create_config_files(folder, ports, file_content=file_content)
        client = self.config_editor.get_config_file_dict("rp_conf_%s" % ports[0])
        self.assertTrue(client)
        self._remove_config_files(folder, ports)

    def test_get_config_file_dict_from_module_without_client_attibute(self):
        folder = "."
        ports = [2]
        file_content = "NON_CLIENT = {'first_key': 'public'}"
        self._create_config_files(folder, ports, file_content=file_content)
        with self.assertRaises(AttributeError):
            self.config_editor.get_config_file_dict("rp_conf_%s" % ports[0])
        self._remove_config_files(folder, ports)

    def _setup_database_entries(self, database_ports=[8001, 8002, 8003]):
        for port in database_ports:
            self.database.upsert(issuer="google", port=port, instance_id="test" + str(port), port_type=PortDatabase.DYNAMIC_PORT_TYPE)

    def test_identify_removed_config_files(self):
        database_ports = [8001, 8002, 8003]
        self._setup_database_entries(database_ports)
        ports = self.config_editor.identify_ports_for_removed_config_files(self.database, ['rp_conf_8001.py', 'rp_conf_8003.py'])
        self.assertEqual(ports, [8002])

    def test_restore_removed_config_file(self):
        database_ports = [8001, 8002]
        self._setup_database_entries(database_ports)
        self.config_editor._restore_config_file = MagicMock(return_value=None)

        with mock.patch('__builtin__.raw_input', return_value='y'):
            self.config_editor.prompt_user_for_config_file_restoration(self.database, [8002])
        self.assertTrue(self.config_editor._restore_config_file.called)

    def test_remove_unwanted_config_file_info_from_database(self):
        database_ports = [8001, 8002]
        self._setup_database_entries(database_ports)

        with mock.patch('__builtin__.raw_input', return_value='n'):
            self.config_editor.prompt_user_for_config_file_restoration(self.database, [8002])
        self.assertEqual(self.database.get_all_ports(), [8001])

    def test_add_config_info_to_existing_entry_if_not_existing(self):
        database_ports = [8001]
        self._setup_database_entries(database_ports)
        instance_id = self.database.get_row(8001)[CONFIG_DICT_INSTANCE_ID_KEY]
        config_file_dict = {'srv_discovery_url': "https://test.com", CONFIG_DICT_INSTANCE_ID_KEY: instance_id}
        self.config_editor.get_config_file_dict = MagicMock(return_value=config_file_dict)
        self.assertTrue(self.database.get_row(8001)[CONFIG_FILE_COLUMN] == None)

        self.config_editor.sync_database_information(self.database, "rp_conf_8001.py")
        config_file_in_db = self.database.get_row(8001)[CONFIG_FILE_COLUMN]
        self.assertEqual(config_file_dict, config_file_in_db)

    def test_non_existing_entry_in_database(self):
        config_file_dict = {'srv_discovery_url': "https://test.com", CONFIG_DICT_INSTANCE_ID_KEY: "test_id"}
        self.config_editor.get_config_file_dict = MagicMock(return_value=config_file_dict)

        with self.assertRaises(TypeError) as ex:
            self.database.get_row(8001)[CONFIG_FILE_COLUMN]

        self.config_editor.sync_database_information(self.database, "rp_conf_8001.py")
        config_file_in_db = self.database.get_row(8001)[CONFIG_FILE_COLUMN]
        self.assertEqual(config_file_dict, config_file_in_db)

if __name__ == '__main__':
    unittest.main()