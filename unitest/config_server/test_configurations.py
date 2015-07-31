import copy
import sys

import pytest
from mock import patch, Mock, MagicMock

from configuration_server.configurations import convert_to_gui_drop_down, _generate_static_input_fields, \
    create_new_configuration_dict, get_issuer_from_gui_config, set_dynamic_discovery_issuer_config_gui_structure, \
    identify_existing_config_file, \
    create_key_dict_pair_if_non_exist, convert_config_gui_structure, convert_instance, convert_to_value_list, \
    load_config_module, generate_config_module_name, get_config_file_path, convert_to_uft8, \
    convert_abbreviation_to_response_type, convert_response_type_to_abbreviation, UnKnownResponseTypeAbbreviation


__author__ = 'danielevertsson'

class TestConfigurationModule:

    def test_convert_to_gui_list(self):
        gui_list = convert_to_gui_drop_down(["test1", "test2"])
        expected_list = [{"type": "test1", "name": "test1"},
                         {"type": "test2", "name": "test2"}]
        assert gui_list == expected_list

    @patch('configuration_server.configurations._generate_static_input_fields')
    def test_get_static_disco_issuer_from_gui_config(self, mock_generate_static_input_fields):
        issuer = 'issuer_test'
        mock_generate_static_input_fields.return_value = _generate_static_input_fields(issuer)
        gui_config = create_new_configuration_dict()
        returned_issuer = get_issuer_from_gui_config(gui_config)
        assert issuer == returned_issuer

    def test_get_dynamic_disco_issuer_from_gui_config(self):
        issuer = 'issuer_test'
        gui_config = create_new_configuration_dict()
        gui_config = set_dynamic_discovery_issuer_config_gui_structure(issuer, gui_config)
        returned_issuer = get_issuer_from_gui_config(gui_config)
        assert issuer == returned_issuer

    @patch('configuration_server.configurations._generate_static_input_fields')
    def test_get_static_disco_issuer_from_gui_config_containing_both_dynamic_and_static_issuer(self, mock_generate_static_input_fields):
        static_issuer = 'static_issuer'
        mock_generate_static_input_fields.return_value = _generate_static_input_fields(static_issuer)
        gui_config = create_new_configuration_dict()
        gui_config = set_dynamic_discovery_issuer_config_gui_structure("dynamic_issuer", gui_config, show_field=False)
        returned_issuer = get_issuer_from_gui_config(gui_config)
        assert static_issuer == returned_issuer

    def _setup_server_config(self):
        server_config = Mock()
        server_config.OPRP_DIR_PATH = '.'
        server_config.OPRP_SSL_MODULE = "sslconf"
        server_config.HOST = "localhost"
        server_config.STATIC_CLIENT_REGISTRATION_PORTS_DATABASE_FILE = None
        sys.path.append(server_config.OPRP_DIR_PATH)
        return server_config

    def _create_temp_config_module_files(self, ports, tmpdir, file_extension=".py"):
        for port in ports:
            file = tmpdir.join(generate_config_module_name(port, file_extension))
            file.write("PORT = 8001")

    @patch('configuration_server.configurations.load_config_module')
    def test_identify_existing_config_file(self, load_config_module_mock, tmpdir):
        load_config_module_mock.return_value = {"client_conf": ""}
        _port = 1
        ports = [_port, -_port]
        self._create_temp_config_module_files(ports, tmpdir)
        self._create_temp_config_module_files([_port], tmpdir, ".pyc")
        config_client_dict = identify_existing_config_file(_port, str(tmpdir))
        assert config_client_dict

    @patch('importlib.import_module')
    def test_load_client_attribute_in_config_module(self, import_module_mock):
        client_info = {'srv_discovery_url': 'asd'}
        config_module = Mock()
        config_module.CLIENT = client_info
        import_module_mock.return_value = config_module
        loaded_client_info = load_config_module(config_module)
        assert loaded_client_info == client_info

    @patch('importlib.import_module')
    def test_load_client_non_existing_client_attribute(self, import_module_mock):
        empty_module = MagicMock(spec=[])
        import_module_mock.return_value = empty_module
        with pytest.raises(AttributeError):
            load_config_module(empty_module)

    def test_identify_config_file_which_does_not_exist(self):
        assert None == identify_existing_config_file(-1, ".")

    def test_create_key_if_non_exist(self):
        dict = {}
        dict = create_key_dict_pair_if_non_exist("key", dict)
        dict['key']['sub_key'] = "value"
        assert dict['key']['sub_key'] == "value"

    @patch('configuration_server.configurations.identify_existing_config_file')
    def test_overwrite_static_with_dynamic_discovery(self, mock_identify_existing_config_file):
        server_config = self._setup_server_config()
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
        config_file_dict = convert_config_gui_structure(new_gui_config, 0, "id", True, CONF=server_config)

        assert "srv_discovery_url" in config_file_dict
        assert dynamic_discovery_issuer == config_file_dict['srv_discovery_url']

        with pytest.raises(KeyError):
            config_file_dict['provider_info']

    @patch('configuration_server.configurations._generate_static_input_fields')
    @patch('configuration_server.configurations.identify_existing_config_file')
    def test_overwrite_dynamic_with_static_discovery(self, mock_identify_existing_config_file, mock_generate_static_input_fields):
        server_config = self._setup_server_config()
        dynamic_discovery_issuer = "example2.com"
        static_client_discovery_info = {"srv_discovery_url": dynamic_discovery_issuer}
        mock_identify_existing_config_file.return_value = copy.deepcopy(static_client_discovery_info)

        default_static_discovery_value = "example"
        mock_generate_static_input_fields.return_value = _generate_static_input_fields(default_static_discovery_value)
        new_gui_config = create_new_configuration_dict()
        new_gui_config['fetchStaticProviderInfo']['showInputFields'] = True
        config_file_dict = convert_config_gui_structure(new_gui_config, 0, "id", True, server_config)

        assert config_file_dict['provider_info']
        with pytest.raises(KeyError):
            config_file_dict['srv_discovery_url']

    @patch('configuration_server.configurations.LOGGER')
    @patch('configuration_server.configurations.identify_existing_config_file')
    def test_do_not_overwrite_custom_value_config_file(self, mock_identify_existing_config_file, logger):
        server_config = self._setup_server_config()
        custom_info = {"custom_key": "custom_value"}
        mock_identify_existing_config_file.return_value = copy.deepcopy(custom_info)
        new_gui_config = create_new_configuration_dict()
        config_dict = convert_config_gui_structure(new_gui_config, 0, "id", True, server_config)
        assert all(item in config_dict.items() for item in custom_info.items())

    def test_convert_list_instance_to_list_should_be_untouched(self):
        to_list = True
        value = ["test"]
        field_value = convert_instance(to_list, value)
        assert field_value == convert_to_value_list(value)

    def test_convert_string_to_non_list_instance_should_untouched(self):
        to_list = False
        value = "test"
        field_value = convert_instance(to_list, value)
        assert field_value == value

    def test_convert_string_to_list_instance(self):
        to_list = True
        value = "test"
        field_value = convert_instance(to_list, value)
        assert field_value == convert_to_value_list([value])

    @patch('configuration_server.configurations.LOGGER')
    @patch('configuration_server.configurations.identify_existing_config_file')
    def test_if_instance_id_is_save_to_config_file(self, mock_identify_existing_config_file, logger):
        server_config = self._setup_server_config()
        new_gui_config = create_new_configuration_dict()
        instance_id = "my_instance_id"
        mock_identify_existing_config_file.return_value = None
        config_dict = convert_config_gui_structure(new_gui_config, 0, instance_id, True, server_config)
        assert all(item in config_dict.items() for item in {"instance_id": instance_id}.items())

    def test_import_non_existing_module(self):
        with pytest.raises(ImportError):
            load_config_module("non_existing_module")

    @pytest.mark.parametrize("abbreviation", [
        "C",
        "I",
        "IT",
        "CI",
        "CT",
        "CIT"
    ])
    def test_enter_correct_response_type_abbreviation(self, abbreviation):
        response_type = convert_abbreviation_to_response_type(abbreviation)
        abbreviation_result = convert_response_type_to_abbreviation(response_type)
        assert abbreviation == abbreviation_result

    def test_enter_non_existing_abbreviation(self):
        with pytest.raises(UnKnownResponseTypeAbbreviation):
            convert_abbreviation_to_response_type("QQQ")
