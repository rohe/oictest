import copy
import json
import os
import sys

import pytest

from mock import patch, Mock, MagicMock

from configuration_server.config_values import CONTACT_EMAIL
from configuration_server.configurations import convert_to_gui_drop_down, _generate_static_input_fields, \
    create_new_configuration_dict, get_issuer_from_gui_config, set_dynamic_discovery_issuer_config_gui_structure, \
    identify_existing_config_file, \
    create_key_dict_pair_if_non_exist, convert_config_gui_structure, convert_instance, convert_to_value_list, \
    load_config_module, generate_config_module_name, convert_abbreviation_to_response_type, \
    convert_response_type_to_abbreviation, UnKnownResponseTypeAbbreviation, \
    set_test_specific_request_parameters, set_issuer, GuiConfig, UserFriendlyException, \
    handle_exception, set_email_to_file, set_contact_email_in_client_config

ISSUER = "issuer"

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
        gui_config = set_dynamic_discovery_issuer_config_gui_structure("dynamic_issuer/", gui_config, show_field=False)
        returned_issuer = get_issuer_from_gui_config(gui_config)
        assert static_issuer == returned_issuer

    def _setup_server_config(self, oprp_dir_path="."):
        server_config = Mock()
        server_config.OPRP_DIR_PATH = oprp_dir_path
        server_config.OPRP_SSL_MODULE = "sslconf"
        server_config.HOST = "localhost"
        server_config.PORT_DATABASE_FILE = None
        sys.path.append(server_config.OPRP_DIR_PATH)
        return server_config

    def _create_temp_config_module_files(self, ports, tmpdir, file_extension=".py",
                                         client_attribute="{}"):
        if not isinstance(tmpdir, basestring):
            tmpdir = str(tmpdir)

        for port in ports:
            path = os.path.join(tmpdir, generate_config_module_name(port, file_extension))
            with open(path, "w", 0) as file:
                file.write("PORT = 8001\n"
                           "BASE ='http://localhost'\n"
                           "CLIENT = " + client_attribute)
        sslconf_path = os.path.join(tmpdir, "sslconf.py")
        with open(sslconf_path, "w", 0) as sslconf_file:
            sslconf_file.write("")
        sys.path.append(tmpdir)

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
        config_file_dict = convert_config_gui_structure(new_gui_config, 0, "id", True, conf=server_config)

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

    @pytest.mark.parametrize("config_file_key,gui_struct_key, value", [
        ("webfinger_subject", "webfingerSubject", 1),
        ("login_hint", "loginHint", 2),
        ("ui_locales", "uiLocales", 3),
        ("claims_locales", "claimsLocales", 4),
        ("acr_values", "acrValues", 5),
        ("webfinger_url", "webfinger_url", 6),
        ("webfinger_email", "webfinger_email", 7),
    ])
    def test_convert_test_specific_request_parameters(self,
                                                      config_file_key,
                                                      gui_struct_key,
                                                      value):
        gui_conf_structure = {}
        config_file = {config_file_key: value}
        with pytest.raises(KeyError):
            gui_conf_structure[gui_struct_key]
        set_test_specific_request_parameters(config_file, gui_conf_structure)
        assert gui_conf_structure[gui_struct_key] == value

    def test_set_static_and_dynamic_disco_issuer(self):
        config = set_issuer(ISSUER, create_new_configuration_dict())
        gui_config = GuiConfig(config)
        assert ISSUER == gui_config.get_static_discovery_issuer()
        assert ISSUER == gui_config.get_dynamic_discovery_issuer()

    def test_user_friendly_exception_extra_parameter(self):
        message = "message"
        log_info = "log_info"
        ex = UserFriendlyException(message, log_info)
        assert ex.message == message
        assert ex.log_info == log_info

    def side_effect(value):
        return value

    @patch('uuid.uuid4')
    @patch('configuration_server.configurations.LOGGER')
    def test_separate_between_user_friendly_exception_message_and_log_info(self, logger, uuid4_mock):
        event_id = "a1s2d3"
        message = "message"
        log_info = "log_info"
        ex = UserFriendlyException(message, log_info)
        uuid4_mock.return_value = event_id
        response_encoder = MagicMock()
        handle_exception(ex, response_encoder)
        response_encoder.service_error.assert_called_once_with(message, event_id=event_id)
        assert logger.error.called

    @patch('uuid.uuid4')
    def test_if_exception_is_not_user_friendly_standard_message_should_be_used(self, uuid4_mock):
        event_id = "a1s2d3"
        uuid4_mock.return_value = event_id
        message = "message"
        ex = Exception("Exception message")
        response_encoder = MagicMock()
        handle_exception(ex, response_encoder, message=message)
        response_encoder.service_error.assert_called_once_with(message, event_id=event_id)

    def test_set_email_to_config_file(self, tmpdir):
        server_config = self._setup_server_config(oprp_dir_path=str(tmpdir))
        ports = [8001, 8002, 8003, 8004]
        existing_key = "srv_discovery_url"
        client_attribute = json.dumps({existing_key: 'https://example.com'})
        self._create_temp_config_module_files(ports, tmpdir, client_attribute=client_attribute)
        set_email_to_file(ports[:3], "asd@asd.se", server_config)
        for port in ports[:3]:
            config_module = identify_existing_config_file(port, server_config.OPRP_DIR_PATH)
            assert CONTACT_EMAIL in config_module
            assert existing_key in config_module

        config_module = identify_existing_config_file(8004, server_config.OPRP_DIR_PATH)
        assert CONTACT_EMAIL not in config_module

    @pytest.mark.parametrize("client_attribute", [
        json.dumps({'srv_discovery_url': 'https://example.com'}),
        {'srv_discovery_url': 'https://example.com'}
    ])
    def test_set_contact_email_in_client_config(self, client_attribute):
        result = set_contact_email_in_client_config(client_attribute, "asd@asd.se")
        assert result[CONTACT_EMAIL].decode('utf-8')
