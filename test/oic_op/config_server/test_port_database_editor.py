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
        self.config_editor = ConfigFileEditor()
        self.test_db = "./test.db"
        self.database = PortDatabase(self.test_db)

    def test_get_instance_id_from_config_with_instance_id(self):
        _instance_id = "ID_1"
        config_file_dict = {CONFIG_DICT_INSTANCE_ID_KEY: _instance_id}
        returned_instance_id = self.config_editor.get_instance_id(config_file_dict, 8000)
        self.assertEqual(_instance_id, returned_instance_id)

    def remove_config_files(self, folder, ports):
        for port in ports:
            config_file_name = get_config_file_path(port, folder)
            os.remove(config_file_name)

    def create_config_files(self, folder, ports):
        for port in ports:
            config_file_name = get_config_file_path(port, folder)
            with open(config_file_name, "w") as _file:
                _file.write("")

    @patch('port_database_editor.ConfigFileEditor.get_config_file_dict')
    @patch('port_database_editor.ConfigFileEditor.get_port_type')
    @patch('port_database_editor.ConfigFileEditor.get_instance_id')
    @patch('port_database_editor.ConfigFileEditor.get_issuer')
    def test_extract_database_info_from_config_file(self,
                                                    mock_get_issuer,
                                                    mock_get_instance_id,
                                                    mock_get_port_type,
                                                    mock_get_config_file_dict):
        folder = ""
        ports = [1,3,10]
        self.create_config_files(folder, ports)
        mock_get_issuer.side_effect = ["issuer_1",
                                       "issuer_2",
                                       "issuer_3"]
        mock_get_instance_id.side_effect = ["instance_id_1",
                                            "instance_id_2",
                                            "instance_id_3"]
        mock_get_port_type.side_effect = [PortDatabase.DYNAMIC_PORT_TYPE,
                                          PortDatabase.DYNAMIC_PORT_TYPE,
                                          PortDatabase.STATIC_PORT_TYPE]
        mock_get_config_file_dict.return_value = None
        self.config_editor.extract_database_info_from_config_file(".", self.database)
        self.assertItemsEqual(self.database.get_all_ports(), ports)
        self.remove_config_files(folder, ports)

    def test_port_is_returned_when_no_instance_id_exists(self):
        port = 8000
        config_file_dict = {}
        returned_instance_id = self.config_editor.get_instance_id(config_file_dict, port)
        self.assertEqual(port, int(returned_instance_id))

if __name__ == '__main__':
    unittest.main()