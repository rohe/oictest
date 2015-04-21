import os
from mock import patch
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

    def remove_config_files(self, folder, ports):
        for port in ports:
            config_file_name = get_config_file_path(port, folder)
            os.remove(config_file_name)

    def create_config_files(self, folder, ports, file_content=""):
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
        folder = ""
        ports = [0]
        file_content = "CLIENT = {'first_key': 'public',\n 'second_key': 'public'}"
        self.create_config_files(folder, ports, file_content=file_content)
        client = self.config_editor.get_config_file_dict("rp_conf_%s" % ports[0])
        self.assertTrue(client)
        self.remove_config_files(folder, ports)

    def test_get_config_file_dict_from_module_without_client_attibute(self):
        folder = ""
        ports = [2]
        file_content = "NON_CLIENT = {'first_key': 'public'}"
        self.create_config_files(folder, ports, file_content=file_content)
        with self.assertRaises(AttributeError):
            self.config_editor.get_config_file_dict("rp_conf_%s" % ports[0])
        self.remove_config_files(folder, ports)


if __name__ == '__main__':
    unittest.main()