from mock import patch
from port_database_editor import ConfigFileEditor
from config_server import CONFIG_DICT_INSTANCE_ID_KEY

__author__ = 'danielevertsson'

import unittest

class TestPortDatabaseEditor(unittest.TestCase):

    def setUp(self):
        self.config_editor = ConfigFileEditor()

    def test_get_instance_id_from_config_with_instance_id(self):
        _instance_id = "ID_1"
        config_file_dict = {CONFIG_DICT_INSTANCE_ID_KEY: _instance_id}
        returned_instance_id = self.config_editor.get_instance_id(config_file_dict, 8000)
        self.assertEqual(_instance_id, returned_instance_id)

    def test_port_is_returned_when_no_instance_id_exists(self):
        port = 8000
        config_file_dict = {}
        returned_instance_id = self.config_editor.get_instance_id(config_file_dict, port)
        self.assertEqual(port, returned_instance_id)

if __name__ == '__main__':
    unittest.main()