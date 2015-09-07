# pylint: disable=no-self-use
# -*- coding: utf-8 -*-
import os
import random
import string
import pytest
from configuration_server.test_instance_database import PortDatabase, \
    NoPortAvailable, PORT_COLUMN, \
    CONFIG_FILE_COLUMN, \
    PortMissingInDatabase
from mock import Mock

__author__ = 'danielevertsson'


def is_port_used_func(port):
    return False


@pytest.fixture()
def setup_empty_database():
    return PortDatabase(is_port_used_func=is_port_used_func)


def set_base_attribute(base_attribute, fixed_attribute_value, index):
    if not fixed_attribute_value:
        return base_attribute + index
    return fixed_attribute_value


def set_port_type(index, static_port_type_value):
    if static_port_type_value:
        return static_port_type_value
    if index % 2 == 0:
        return PortDatabase.DYNAMIC_PORT_TYPE
    return PortDatabase.STATIC_PORT_TYPE


def allocate_ports(database, number_of_entries, port_type, issuer=None):
    if not issuer:
        issuer = ISSUER_GOOGLE

    index = 0
    while index < number_of_entries:
        index += 1
        port = database.allocate_port(issuer,
                                      "ID_%s" % index,
                                      port_type,
                                      DYNAMIC_CLIENT_REGISTRATION_PORT_RANGE_MIN,
                                      DYNAMIC_CLIENT_REGISTRATION_PORT_RANGE_MAX)
    return port


def generate_database_entries(entries_to_generate=1, base_port=8000, base_issuer="issuer",
                              base_instance_id="id", base_config_file_dict_value="value",
                              static_port_value=None, static_issuer_value=None,
                              static_instance_id_value=None, static_port_type_value=None):
    index = 0
    database = PortDatabase(is_port_used_func=is_port_used_func)
    while index < entries_to_generate:
        port = set_base_attribute(base_port, static_port_value, index)
        issuer = set_base_attribute(base_issuer, static_issuer_value, str(index))
        instance_id = set_base_attribute(base_instance_id, static_instance_id_value, str(index))
        port_type = set_port_type(index, static_port_type_value)
        config_file = {"key": base_config_file_dict_value + str(index)}

        database.upsert(port=port,
                        issuer=issuer,
                        instance_id=instance_id,
                        port_type=port_type,
                        config_file=config_file)
        index = index + 1
    return database


ISSUER_GOOGLE = "google"
DYNAMIC_CLIENT_REGISTRATION_PORT_RANGE_MIN = 1
DYNAMIC_CLIENT_REGISTRATION_PORT_RANGE_MAX = 3


class TestPortDatabase(object):
    def test_create_database_file(self):
        database_file = "./test.db"
        PortDatabase(database_file, is_port_used_func=is_port_used_func)
        assert os.path.isfile(database_file)
        os.remove(database_file)

    def test_create_multiple_in_memory_database(self):
        db1 = PortDatabase(is_port_used_func=is_port_used_func)
        db1.upsert(8001, "issuer1", "id1", PortDatabase.STATIC_PORT_TYPE)

        db2 = PortDatabase(is_port_used_func=is_port_used_func)
        db2.upsert(8002, "issuer2", "id2", PortDatabase.STATIC_PORT_TYPE)

        assert not os.path.isfile(":memory:")
        assert db1.get_all_ports() == [8001]
        assert db2.get_all_ports() == [8002]

    def test_list_all_ports(self):
        database = generate_database_entries(entries_to_generate=3, base_port=8001)
        ports = database.get_all_ports()
        assert ports == [8001, 8002, 8003]

    def test_list_all_issuers(self):
        database = generate_database_entries(entries_to_generate=3, base_issuer="issuer")
        issuers = database.get_all_issuers()
        assert issuers == ["issuer0", "issuer1", "issuer2"]

    def test_get_database_as_list_and_check_number_of_elements(self):
        database = generate_database_entries(entries_to_generate=3)
        list = database.get_table_as_list()
        assert len(list) == 3

    def test_get_database_as_list_and_check_if_ports_are_correct(self):
        database = generate_database_entries(entries_to_generate=3, base_port=8001)
        list = database.get_table_as_list()
        ports = []
        for element in list:
            ports.append(element[0])
        assert ports == [8001, 8002, 8003]

    def test_print_table(self):
        database = generate_database_entries(entries_to_generate=3)
        database.print_table()

    def test_if_entries_with_same_port_is_only_updated(self):
        database = generate_database_entries(entries_to_generate=3, static_port_value=8001)
        ports = database.get_all_ports()
        assert ports == [8001]
        assert len(database.get_table_as_list()) == 1

    def test_remove_entry_based_on_port(self):
        database = generate_database_entries(entries_to_generate=3, base_port=8001)
        database.remove_row(8001)
        assert database.get_all_ports() == [8002, 8003]

    def test_get_port_based_on_issuer_and_id(self):
        database = generate_database_entries(entries_to_generate=3, base_port=8001,
                                             static_issuer_value="issuer")
        port = database.get_existing_port("issuer", 'id1')
        assert port == 8002

    def test_get_next_free_port(self):
        database = generate_database_entries(entries_to_generate=3, base_port=8001,
                                             static_issuer_value="issuer")
        port = database._get_next_free_port(8001, 8010)
        assert port == 8004

    def test_enter_row_with_existing_port(self):
        database = generate_database_entries(entries_to_generate=3, base_port=8001,
                                             static_issuer_value="issuer")
        port = database.allocate_port("issuer", 'id1', PortDatabase.STATIC_PORT_TYPE, 8001, 8010)
        assert port == 8002

    def test_enter_row_with_non_existing_port(self):
        database = generate_database_entries(entries_to_generate=3, base_port=8001,
                                             static_issuer_value="issuer")
        port = database.allocate_port("issuer", 'id3', PortDatabase.STATIC_PORT_TYPE, 8001, 8010)
        assert port == 8004

    def test_fill_port_database(self, setup_empty_database):
        database = setup_empty_database
        port = allocate_ports(database,
                              DYNAMIC_CLIENT_REGISTRATION_PORT_RANGE_MAX,
                              PortDatabase.DYNAMIC_PORT_TYPE)
        assert port == DYNAMIC_CLIENT_REGISTRATION_PORT_RANGE_MAX

    def test_add_to_many_entries_to_port_database(self, setup_empty_database):
        database = setup_empty_database
        with pytest.raises(NoPortAvailable):
            allocate_ports(database,
                           DYNAMIC_CLIENT_REGISTRATION_PORT_RANGE_MAX + 1,
                           PortDatabase.DYNAMIC_PORT_TYPE)

    def test_get_existing_port_with_non_existing_credientials(self, setup_empty_database):
        database = setup_empty_database
        assert database.get_existing_port("", "", "") == None

    def test_get_port_type(self):
        database = generate_database_entries(base_port=8001,
                                             static_port_type_value=PortDatabase.DYNAMIC_PORT_TYPE)
        port_type = database._get_port_type(8001)
        assert port_type == PortDatabase.DYNAMIC_PORT_TYPE

    def test_allocate_dynamic_port_do_not_use_existing_static_port(self):
        instance_id = "id1"
        database = generate_database_entries(base_port=8001,
                                             static_issuer_value=ISSUER_GOOGLE,
                                             static_instance_id_value=instance_id,
                                             static_port_type_value=PortDatabase.STATIC_PORT_TYPE)
        port = database.allocate_port(ISSUER_GOOGLE, instance_id, PortDatabase.DYNAMIC_PORT_TYPE,
                                      8001, 8003)
        assert port == 8001

    def test_use_existing_static_port(self):
        instance_id = "id1"
        database = generate_database_entries(base_port=8001,
                                             static_issuer_value=ISSUER_GOOGLE,
                                             static_instance_id_value=instance_id,
                                             static_port_type_value=PortDatabase.STATIC_PORT_TYPE)
        port = database.allocate_port(ISSUER_GOOGLE, instance_id, PortDatabase.STATIC_PORT_TYPE,
                                      8001, 8003)
        assert port == 8001

    def test_if_static_port_is_remove_when_switching_to_dynamic_port(self):
        instance_id = "id1"
        static_port = 8501
        database = generate_database_entries(static_port_value=static_port,
                                             static_issuer_value=ISSUER_GOOGLE,
                                             static_instance_id_value=instance_id,
                                             static_port_type_value=PortDatabase.STATIC_PORT_TYPE)
        database.allocate_port(ISSUER_GOOGLE, instance_id, PortDatabase.DYNAMIC_PORT_TYPE, 8001,
                               8003)
        ports = database.get_all_ports()
        assert static_port not in ports

    def test_list_instance_ids_for_one_issuer(self, setup_empty_database):
        database = setup_empty_database
        allocate_ports(database, 3, PortDatabase.DYNAMIC_PORT_TYPE, issuer=ISSUER_GOOGLE)
        database.upsert(port=8004, issuer="apberget", instance_id='test1', port_type="static")
        database.upsert(port=8005, issuer="apberget", instance_id='test2', port_type="static")
        instance_ids = database.get_instance_ids(ISSUER_GOOGLE)
        assert instance_ids == ["ID_1", "ID_2", "ID_3"]

    def test_add_large_config_file(self):
        random_string = ''.join(random.choice(string.ascii_uppercase) for _ in range(100000))
        port = 8000
        database = generate_database_entries(static_port_value=port)
        database.upsert_row(database.get_row(port), random_string)
        row = database.table.find_one(port=port)
        assert row['config_file'] == random_string

    def test_add_config_file_to_existing_database_entry(self):
        port = 8000
        database = generate_database_entries(static_port_value=port)
        row = database.get_row(port)
        config_file = {"test": 1}
        database.upsert_row(row, config_file)
        row = database.get_row(port)
        assert row[PORT_COLUMN] == port
        assert row[CONFIG_FILE_COLUMN] == config_file

    def test_enter_issuer_non_ascii_charaters(self):
        issuer = unicode('https://example/öäå', encoding='utf-8')
        database = generate_database_entries(static_issuer_value=issuer)
        assert database.get_all_ports() == [8000]

    def test_get_non_existing_row(self, setup_empty_database):
        database = setup_empty_database
        row = database.get_row(8000)
        assert row is None

    def test_get_next_unused_port(self):
        is_port_used_func = Mock()
        is_port_used_func.side_effect = [True, True,
                                         False]  # Inicates that the two first ports are used
        database = PortDatabase(is_port_used_func=is_port_used_func)
        port = database._get_next_free_port(min_port=8000, max_port=8005)
        assert port == 8002

    def test_clearing_database(self):
        database = generate_database_entries(entries_to_generate=3)
        assert len(database.get_all_ports()) == 3
        database.clear()
        assert len(database.get_all_ports()) == 0

    def test_get_none_existing_port(self, setup_empty_database):
        database = setup_empty_database
        with pytest.raises(PortMissingInDatabase):
            database.get_port(issuer="issuer", instance_id="id")

    def test_get_port_by_issuer_and_instance_id(self, setup_empty_database):
        database = generate_database_entries(entries_to_generate=3,
                                             base_instance_id="ID",
                                             base_port=8000,
                                             static_issuer_value=ISSUER_GOOGLE)
        assert database.get_port(issuer=ISSUER_GOOGLE, instance_id="ID1") == 8001

    @pytest.mark.parametrize("instance_id, config_file", [
        ("ID0", {"key": "value0"}),
        ("ID1", {"key": "value1"}),
        ("ID2", {"key": "value2"}),
    ])
    def test_loading_config_file(self, instance_id, config_file):
        database = generate_database_entries(entries_to_generate=3,
                                             base_instance_id="ID",
                                             base_config_file_dict_value="value",
                                             static_issuer_value=ISSUER_GOOGLE)

        assert database.get_configuration(ISSUER_GOOGLE, instance_id) == config_file
