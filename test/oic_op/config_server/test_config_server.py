import subprocess
from config_server import NoResponseException
from config_server import check_if_oprp_started
from config_server import kill_existing_process_on_port
from config_server import get_oprp_pid
from config_server import convert_to_simple_list
from config_server import convert_to_gui_list
from config_server import create_new_configuration_dict
from config_server import get_issuer_from_gui_config

__author__ = 'danielevertsson'

import unittest

class TestConfigServer(unittest.TestCase):

    def test_check_if_oprp_started_raises_NoResponseException(self):
        with self.assertRaises(NoResponseException):
            check_if_oprp_started(None, oprp_url="http://1234.1234.1234.1234:8000", timeout=1)

    def test_returns_correct_pid(self):
        p = subprocess.Popen(['grep', 'rp_conf_0.py'], stdout=subprocess.PIPE)
        pid = get_oprp_pid(0)
        self.assertEqual(p.pid, pid)

    def test_killing_existing_process(self):
        _port = 0
        _filename = "rp_conf_%s.py" % _port

        #Process which simulate a running OPRP instance
        subprocess.Popen(['grep', _filename], stdout=subprocess.PIPE)
        kill_existing_process_on_port(_port)
        _pid = get_oprp_pid(_port)
        self.assertEqual(_pid, None)

    def test_convert_to_simple_list(self):
        gui_list = [{"name": "test1"}, {"name": "test2"}]
        simple_list = convert_to_simple_list(gui_list)
        self.assertEqual(["test1", "test2"], simple_list)

    def test_convert_to_gui_list(self):
        gui_list = convert_to_gui_list(["test1", "test2"])
        expected_list = [{"type": "test1", "name": "test1"},
                         {"type": "test2", "name": "test2"}]
        self.assertEqual(gui_list, expected_list)

    def test_get_static_disco_issuer_from_gui_config(self):
        issuer = 'issuer_test'
        gui_config = create_new_configuration_dict(issuer)
        returned_issuer = get_issuer_from_gui_config(gui_config)
        self.assertEqual(issuer, returned_issuer)

    def test_get_dynamic_disco_issuer_from_gui_config(self):
        issuer = 'issuer_test'
        gui_config = create_new_configuration_dict()
        gui_config['fetchDynamicInfoFromServer']['input_field']['value'] = issuer
        returned_issuer = get_issuer_from_gui_config(gui_config)
        self.assertEqual(issuer, returned_issuer)

if __name__ == '__main__':
    unittest.main()