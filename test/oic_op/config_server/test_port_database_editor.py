import os
from mock import MagicMock, patch
import mock
from port_database_editor import ConfigFileEditor
from config_server import CONFIG_DICT_INSTANCE_ID_KEY
from config_server import get_config_file_path
from port_database import PortDatabase


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

    def _setup_three_database_entries(self, database_ports=[8001, 8002, 8003]):
        issuer="google"
        self.database.upsert(issuer=issuer, port=database_ports[0], instance_id="test", port_type=PortDatabase.DYNAMIC_PORT_TYPE)
        self.database.upsert(issuer=issuer, port=database_ports[1], instance_id="test1", port_type=PortDatabase.DYNAMIC_PORT_TYPE)
        try:
            self.database.upsert(issuer=issuer, port=database_ports[2], instance_id="test2", port_type=PortDatabase.DYNAMIC_PORT_TYPE)
        except IndexError:
            pass

    def test_identify_removed_config_files(self):
        database_ports = [8001, 8002, 8003]
        self._setup_three_database_entries(database_ports)
        ports = self.config_editor.identify_ports_for_removed_config_files(self.database, ['rp_conf_8001.py', 'rp_conf_8003.py'])
        self.assertEqual(ports, [8002])

    def test_restore_removed_config_file(self):
        database_ports = [8001, 8002]
        self._setup_three_database_entries(database_ports)
        self.config_editor._restore_config_file = MagicMock(return_value=None)

        with mock.patch('__builtin__.raw_input', return_value='y'):
            self.config_editor.prompt_user_for_config_file_restoration(self.database, [8002])
        self.assertTrue(self.config_editor._restore_config_file.called)

    def test_remove_unwanted_config_file_info_from_database(self):
        database_ports = [8001, 8002]
        self._setup_three_database_entries(database_ports)

        with mock.patch('__builtin__.raw_input', return_value='n'):
            self.config_editor.prompt_user_for_config_file_restoration(self.database, [8002])
        self.assertEqual(self.database.get_all_ports(), [8001])

if __name__ == '__main__':
    unittest.main()