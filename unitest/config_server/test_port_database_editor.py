import os

from mock import MagicMock
import mock
import pytest

from configuration_server.configurations import CONFIG_DICT_INSTANCE_ID_KEY, get_config_file_path
from configuration_server.test_instance_database import PortDatabase, CONFIG_FILE_COLUMN
from configuration_server.port_database_editor import PortDatabaseEditor

__author__ = 'danielevertsson'

class TestPortDatabaseEditor:
    port_db_editor = None
    database = None

    @pytest.fixture(autouse=True)
    def port_db_editor(self):
        self.port_db_editor = PortDatabaseEditor()
        self.database = PortDatabase()

    def test_get_instance_id_from_config_with_instance_id(self):
        _instance_id = "ID_1"
        config_file_dict = {CONFIG_DICT_INSTANCE_ID_KEY: _instance_id}
        returned_instance_id = self.port_db_editor.get_instance_id(config_file_dict, 8000)
        assert _instance_id == returned_instance_id

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
        returned_instance_id = self.port_db_editor.get_instance_id(config_file_dict, port)
        assert port == int(returned_instance_id)

    def test_get_port_from_module(self, port_db_editor):
        port = self.port_db_editor.get_port("rp_conf_8001")
        assert port == 8001

    def test_get_config_file_dict_from_module(self):
        folder = "."
        ports = [0]
        file_content = "CLIENT = {'first_key': 'public',\n 'second_key': 'public'}"
        self._create_config_files(folder, ports, file_content=file_content)
        client = self.port_db_editor.get_config_file_dict("rp_conf_%s" % ports[0])
        assert client
        self._remove_config_files(folder, ports)

    def test_get_config_file_dict_from_module_without_client_attibute(self):
        folder = "."
        ports = [2]
        file_content = "NON_CLIENT = {'first_key': 'public'}"
        self._create_config_files(folder, ports, file_content=file_content)
        with pytest.raises(AttributeError):
            self.port_db_editor.get_config_file_dict("rp_conf_%s" % ports[0])
        self._remove_config_files(folder, ports)

    def _setup_database_entries(self, database_ports=[8001, 8002, 8003]):
        for port in database_ports:
            self.database.upsert(issuer="google", port=port, instance_id="test" + str(port), port_type=PortDatabase.DYNAMIC_PORT_TYPE)

    def test_identify_removed_config_files(self):
        database_ports = [8001, 8002, 8003]
        self._setup_database_entries(database_ports)
        ports = self.port_db_editor.identify_ports_for_removed_config_files(self.database, ['rp_conf_8001.py', 'rp_conf_8003.py'])
        assert ports == [8002]

    def test_restore_removed_config_file(self):
        database_ports = [8001, 8002]
        self._setup_database_entries(database_ports)
        self.port_db_editor._restore_config_file = MagicMock(return_value=None)

        with mock.patch('__builtin__.raw_input', return_value='y'):
            self.port_db_editor.prompt_user_for_config_file_restoration(self.database, [8002])
        assert self.port_db_editor._restore_config_file.called

    def test_remove_unwanted_config_file_info_from_database(self):
        database_ports = [8001, 8002]
        self._setup_database_entries(database_ports)

        with mock.patch('__builtin__.raw_input', return_value='n'):
            self.port_db_editor.prompt_user_for_config_file_restoration(self.database, [8002])
        assert self.database.get_all_ports() == [8001]

    def test_add_config_info_to_existing_entry_if_not_existing(self):
        database_ports = [8001]
        self._setup_database_entries(database_ports)
        instance_id = self.database.get_row(8001)[CONFIG_DICT_INSTANCE_ID_KEY]
        config_file_dict = {'srv_discovery_url': "https://test.com", CONFIG_DICT_INSTANCE_ID_KEY: instance_id}
        self.port_db_editor.get_config_file_dict = MagicMock(return_value=config_file_dict)
        assert self.database.get_row(8001)[CONFIG_FILE_COLUMN] == None

        self.port_db_editor.sync_database_information(self.database, "rp_conf_8001.py")
        config_file_in_db = self.database.get_row(8001)[CONFIG_FILE_COLUMN]
        assert config_file_dict == config_file_in_db

    def test_non_existing_entry_in_database(self):
        config_file_dict = {'srv_discovery_url': "https://test.com", CONFIG_DICT_INSTANCE_ID_KEY: "test_id"}
        self.port_db_editor.get_config_file_dict = MagicMock(return_value=config_file_dict)
        with pytest.raises(TypeError):
            self.database.get_row(8001)[CONFIG_FILE_COLUMN]

        self.port_db_editor.sync_database_information(self.database, "rp_conf_8001.py")
        config_file_in_db = self.database.get_row(8001)[CONFIG_FILE_COLUMN]
        assert config_file_dict == config_file_in_db