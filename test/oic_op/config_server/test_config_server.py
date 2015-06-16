import os
import copy
import subprocess
from threading import Thread
from beaker.middleware import SessionMiddleware
from cherrypy import wsgiserver
from mock import patch
from port_database import PortDatabase
from config_server import NoResponseException
from config_server import check_if_oprp_started
from config_server import kill_existing_process_on_port
from config_server import get_oprp_pid
from config_server import identify_existing_config_file
from config_server import get_config_file_path
from config_server import create_module_string
from config_server import NoMatchException
from config_server import convert_to_simple_list
from config_server import convert_to_gui_drop_down
from config_server import create_new_configuration_dict
from config_server import get_issuer_from_gui_config
from config_server import write_config_file
from config_server import convert_config_gui_structure
from config_server import create_key_dict_pair_if_non_exist
from config_server import _generate_static_input_fields
from config_server import convert_instance
from config_server import convert_to_value_list
from config_server import set_dynamic_discovery_issuer_config_gui_structure
from config_server import load_config_module
from config_server import get_port_from_database
from config_server import is_port_unused_by_other_process

__author__ = 'danielevertsson'

import unittest


def application(environ, start_response):
    pass

class TestConfigServer(unittest.TestCase):

    def test_if_possible_to_separate_between_test_instance_and_other_process(self):
        self.assertFalse(is_port_unused_by_other_process(9000))

        p = subprocess.Popen(['grep', 'rp_conf_9001'], stdout=subprocess.PIPE)
        self.assertFalse(is_port_unused_by_other_process(9001))
        p.kill()

        self.start_http_server_thread(9000)
        self.assertTrue(is_port_unused_by_other_process(9000))

        self.start_http_server_thread(9001)
        p = subprocess.Popen(['grep', 'rp_conf_9001'], stdout=subprocess.PIPE)
        self.assertFalse(is_port_unused_by_other_process(9001))


    def start_server(self, port):
        SRV = wsgiserver.CherryPyWSGIServer(('0.0.0.0', port),
                                        SessionMiddleware(application))
        print "serving at port: " + str(port)
        SRV.start()
        print "here"

    def start_http_server_thread(self, port):
        thread = Thread(target=self.start_server, args=(port, ))
        thread.daemon = True
        thread.start()

    @patch('config_server.CONF')
    def test_alloc_port_used_by_other_process(self, mock_server_config):
        test_db = "test.db"
        mock_server_config.STATIC_CLIENT_REGISTRATION_PORTS_DATABASE_FILE = test_db
        self.start_http_server_thread(8000)
        allocated_port = get_port_from_database("issuer", "id", 8000, 8100, PortDatabase.STATIC_PORT_TYPE)
        self.assertEqual(8001, allocated_port)
        os.remove(test_db)

    @patch('config_server.CONF')
    def test_alloc_multiple_ports_used_by_other_processes(self, mock_server_config):
        test_db = "test.db"
        mock_server_config.STATIC_CLIENT_REGISTRATION_PORTS_DATABASE_FILE = test_db
        self.start_http_server_thread(8000)
        self.start_http_server_thread(8001)
        self.start_http_server_thread(8002)
        allocated_port = get_port_from_database("issuer", "id", 8000, 8100, PortDatabase.STATIC_PORT_TYPE)
        self.assertEqual(8003, allocated_port)
        os.remove(test_db)

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
        gui_list = convert_to_gui_drop_down(["test1", "test2"])
        expected_list = [{"type": "test1", "name": "test1"},
                         {"type": "test2", "name": "test2"}]
        self.assertEqual(gui_list, expected_list)

    @patch('config_server._generate_static_input_fields')
    def test_get_static_disco_issuer_from_gui_config(self, mock_generate_static_input_fields):
        issuer = 'issuer_test'
        mock_generate_static_input_fields.return_value = _generate_static_input_fields(issuer)
        gui_config = create_new_configuration_dict()
        returned_issuer = get_issuer_from_gui_config(gui_config)
        self.assertEqual(issuer, returned_issuer)

    def test_get_dynamic_disco_issuer_from_gui_config(self):
        issuer = 'issuer_test'
        gui_config = create_new_configuration_dict()
        gui_config = set_dynamic_discovery_issuer_config_gui_structure(issuer, gui_config)
        returned_issuer = get_issuer_from_gui_config(gui_config)
        self.assertEqual(issuer, returned_issuer)

    @patch('config_server._generate_static_input_fields')
    def test_get_static_disco_issuer_from_gui_config_containing_both_dynamic_and_static_issuer(self, mock_generate_static_input_fields):
        static_issuer = 'static_issuer'
        mock_generate_static_input_fields.return_value = _generate_static_input_fields(static_issuer)
        gui_config = create_new_configuration_dict()
        gui_config = set_dynamic_discovery_issuer_config_gui_structure("dynamic_issuer", gui_config, show_field=False)
        returned_issuer = get_issuer_from_gui_config(gui_config)
        self.assertEqual(static_issuer, returned_issuer)

    def _setup_config_server_mock(self, mock_server_config):
        mock_server_config.OPRP_DIR_PATH = '../rp/'
        mock_server_config.OPRP_SSL_MODULE = "sslconf"
        mock_server_config.HOST = "localhost"

    @patch('config_server.CONF')
    def test_identify_existing_config_file(self, mock_server_config):
        self._setup_config_server_mock(mock_server_config)

        _port = 0
        config_file = get_config_file_path(_port, mock_server_config.OPRP_DIR_PATH)
        configuration = create_module_string({}, _port)
        write_config_file(config_file, configuration, _port)

        config_client_dict = identify_existing_config_file(_port)
        self.assertTrue(isinstance(config_client_dict, dict))
        os.remove(config_file)

    @patch('config_server.CONF')
    def test_identify_existing_missing_client_attribute(self, mock_server_config):
        self._setup_config_server_mock(mock_server_config)
        _port = 1
        config_file = get_config_file_path(_port, mock_server_config.OPRP_DIR_PATH)
        write_config_file(config_file, "", _port)
        with self.assertRaises(AttributeError):
            identify_existing_config_file(_port)
        os.remove(config_file)

    @patch('config_server.CONF')
    def test_identify_config_file_which_does_not_exist(self, mock_server_config):
        self._setup_config_server_mock(mock_server_config)
        with self.assertRaises(NoMatchException):
            identify_existing_config_file(-1)

    def test_create_key_if_non_exist(self):
        dict = {}
        dict = create_key_dict_pair_if_non_exist("key", dict)
        dict['key']['sub_key'] = "value"
        self.assertEqual(dict['key']['sub_key'], "value")

    @patch('config_server.identify_existing_config_file')
    def test_overwrite_static_with_dynamic_discovery(self, mock_identify_existing_config_file):
        static_client_discovery_info = {"provider_info": {"jwks_uri": "example.com/jwks",
                                                          "authorization_endpoint": "example.com/auth",
                                                          "response_types_supported": "response_types_supported",
                                                          "id_token_signing_alg_values_supported": ['alg'],
                                                          "subject_types_supported": ['subject_type'],
                                                          "issuer": "example.com"}}
        mock_identify_existing_config_file.return_value = copy.deepcopy(static_client_discovery_info)

        dynamic_discovery_issuer = "example2.com"
        new_gui_config = create_new_configuration_dict()
        new_gui_config = set_dynamic_discovery_issuer_config_gui_structure(dynamic_discovery_issuer, new_gui_config)
        config_file_dict = convert_config_gui_structure(new_gui_config, 0, "id")

        self.assertDictContainsSubset({"srv_discovery_url": dynamic_discovery_issuer}, config_file_dict)
        with self.assertRaises(KeyError):
            config_file_dict['provider_info']

    @patch('config_server._generate_static_input_fields')
    @patch('config_server.identify_existing_config_file')
    def test_overwrite_dynamic_with_static_discovery(self, mock_identify_existing_config_file, mock_generate_static_input_fields):
        dynamic_discovery_issuer = "example2.com"
        static_client_discovery_info = {"srv_discovery_url": dynamic_discovery_issuer}
        mock_identify_existing_config_file.return_value = copy.deepcopy(static_client_discovery_info)

        default_static_discovery_value = "example"
        mock_generate_static_input_fields.return_value = _generate_static_input_fields(default_static_discovery_value)
        new_gui_config = create_new_configuration_dict()
        new_gui_config['fetchStaticProviderInfo']['showInputFields'] = True
        config_file_dict = convert_config_gui_structure(new_gui_config, 0, "id")

        self.assertTrue(config_file_dict['provider_info'])
        with self.assertRaises(KeyError):
            config_file_dict['srv_discovery_url']

    @patch('config_server.identify_existing_config_file')
    def test_do_not_overwrite_custom_value_config_file(self, mock_identify_existing_config_file):
        custom_info = {"custom_key": "custom_value"}
        mock_identify_existing_config_file.return_value = copy.deepcopy(custom_info)
        new_gui_config = create_new_configuration_dict()
        config_dict = convert_config_gui_structure(new_gui_config, 0, "id")
        self.assertDictContainsSubset(custom_info, config_dict)

    def test_convert_list_instance_to_list_should_be_untouched(self):
        to_list = True
        value = ["test"]
        field_value = convert_instance(to_list, value)
        self.assertEqual(field_value, convert_to_value_list(value))

    def test_convert_string_to_non_list_instance_should_untouched(self):
        to_list = False
        value = "test"
        field_value = convert_instance(to_list, value)
        self.assertEqual(field_value, value)

    def test_convert_string_to_list_instance(self):
        to_list = True
        value = "test"
        field_value = convert_instance(to_list, value)
        self.assertEqual(field_value, convert_to_value_list([value]))

    @patch('config_server.identify_existing_config_file')
    def test_if_instance_id_is_save_to_config_file(self, mock_identify_existing_config_file):
        new_gui_config = create_new_configuration_dict()
        instance_id = "my_instance_id"
        mock_identify_existing_config_file.side_effect = NoMatchException()
        config_dict = convert_config_gui_structure(new_gui_config, 0, instance_id)
        self.assertDictContainsSubset({"instance_id": instance_id}, config_dict)

    def test_import_non_existing_module(self):
        with self.assertRaises(ImportError):
            load_config_module("non_existing_module")

if __name__ == '__main__':
    unittest.main()