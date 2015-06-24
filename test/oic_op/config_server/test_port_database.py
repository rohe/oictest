# -*- coding: utf-8 -*-
import json
import os
import unittest
from port_database import PortDatabase
from port_database import NoPortAvailable
from config_server import get_default_client
from port_database import PORT_COLUMN, CONFIG_FILE_COLUMN

__author__ = 'danielevertsson'

class TestPortDatabase(unittest.TestCase):

    TABLE_NAME = 'ports'

    def setUp(self):
        self.test_db = "./test.db"
        self.database = PortDatabase(self.test_db)

    def tearDown(self):
        os.remove(self.test_db)

    def create_three_unique_entries(self):
        self.database.upsert(port=8001, issuer="google", instance_id='test1', port_type="dynamic")
        self.database.upsert(port=8002, issuer="facebook", instance_id='test2', port_type="static")
        self.database.upsert(port=8003, issuer="apberget", instance_id='test3', port_type="static")

    def test_list_all_ports(self):
        self.create_three_unique_entries()
        ports = self.database.get_all_ports()
        self.assertEqual(ports, [8001, 8002, 8003])

    def test_list_all_issuers(self):
        self.create_three_unique_entries()
        issuers = self.database.get_all_issuers()
        self.assertEqual(issuers, ["google", "facebook", "apberget"])

    def test_get_port_by_issuer(self):
        port = 8001
        self.create_three_unique_entries()
        row = self.database.table.find_one(port=port)
        self.assertEqual(row['port'], port)

    def test_get_database_as_list_and_check_number_of_elements(self):
        self.create_three_unique_entries()
        list = self.database.get_table_as_list()
        self.assertEqual(len(list), 3)

    def test_get_database_as_list_and_check_if_ports_are_correct(self):
        self.create_three_unique_entries()
        list = self.database.get_table_as_list()
        ports = []
        for element in list:
            ports.append(element[0])
        self.assertEqual(ports, [8001, 8002, 8003])

    def test_print_table(self):
        self.create_three_unique_entries()
        self.database.print_table()

    def create_three_entries_with_same_port(self):
        self.database.upsert(port=8001, issuer="google", instance_id='test1', port_type="dynamic")
        self.database.upsert(port=8001, issuer="facebook", instance_id='test2', port_type="static")
        self.database.upsert(port=8001, issuer="apberget", instance_id='test3', port_type="static")

    def test_if_entries_with_same_port_is_only_updated(self):
        self.create_three_entries_with_same_port()
        ports = self.database.get_all_ports()
        self.assertEqual(ports, [8001])

    def test_remove_entry_based_on_port(self):
        self.create_three_unique_entries()
        self.database._remove_row(8001)
        self.assertEqual(self.database.get_all_ports(), [8002, 8003])

    def create_three_entries_with_same_issuer_google_but_different_instance_ids(self):
        self.database.upsert(port=8001, issuer="google", instance_id='test1', port_type="dynamic")
        self.database.upsert(port=8002, issuer="google", instance_id='test2', port_type="static")
        self.database.upsert(port=8003, issuer="google", instance_id='test3', port_type="static")

    def test_get_port_based_on_issuer_and_id(self):
        self.create_three_entries_with_same_issuer_google_but_different_instance_ids()
        port = self.database._get_existing_port("google", 'test2', "static")
        self.assertEqual(port, 8002)

    def test_get_next_free_port(self):
        self.create_three_entries_with_same_issuer_google_but_different_instance_ids()
        port = self.database._get_next_free_port(8001, 8010)
        self.assertEqual(port, 8004)

    def test_enter_row_with_existing_port(self):
        self.create_three_entries_with_same_issuer_google_but_different_instance_ids()
        port = self.database.allocate_port("google", 'test2', "static", 8001, 8010)
        self.assertEqual(port, 8002)

    def test_enter_row_with_non_existing_port(self):
        self.create_three_entries_with_same_issuer_google_but_different_instance_ids()
        port = self.database.allocate_port("google", 'test4', "static", 8001, 8010)
        self.assertEqual(port, 8004)

    ISSUER_GOOGLE = "google"
    DYNAMIC_CLIENT_REGISTRATION_PORT_RANGE_MIN = 1
    DYNAMIC_CLIENT_REGISTRATION_PORT_RANGE_MAX = 3

    def allocate_ports(self, number_of_entries, port_type, issuer=None):
        if not issuer:
            issuer = self.ISSUER_GOOGLE

        index = 0
        while index < number_of_entries:
            index += 1
            port = self.database.allocate_port(issuer,
                                           "ID_%s" % index,
                                           port_type,
                                           self.DYNAMIC_CLIENT_REGISTRATION_PORT_RANGE_MIN,
                                           self.DYNAMIC_CLIENT_REGISTRATION_PORT_RANGE_MAX)
        return port

    def test_fill_port_database(self):
        port = self.allocate_ports(self.DYNAMIC_CLIENT_REGISTRATION_PORT_RANGE_MAX,
                                   self.database.DYNAMIC_PORT_TYPE)
        self.assertEqual(port, self.DYNAMIC_CLIENT_REGISTRATION_PORT_RANGE_MAX)

    def test_add_to_many_entries_to_port_database(self):
        with self.assertRaises(NoPortAvailable):
            self.allocate_ports(self.DYNAMIC_CLIENT_REGISTRATION_PORT_RANGE_MAX+1,
                                       self.database.DYNAMIC_PORT_TYPE)

    def test_get_existing_port_with_non_existing_credientials(self):
        port = self.database._get_existing_port("","","")
        self.assertEqual(port, None)

    def test_get_port_type(self):
        self.database.upsert(port=8001, issuer="google", instance_id='test1', port_type=PortDatabase.DYNAMIC_PORT_TYPE)
        port_type = self.database._get_port_type(8001)
        self.assertEqual(port_type, PortDatabase.DYNAMIC_PORT_TYPE)

    def test_allocate_dynamic_port_do_not_use_existing_static_port(self):
        issuer = "google"
        instance_id='test1'
        self.database.upsert(port=8501, issuer=issuer, instance_id=instance_id, port_type=PortDatabase.STATIC_PORT_TYPE)
        port = self.database.allocate_port(issuer, instance_id, PortDatabase.DYNAMIC_PORT_TYPE, 8001, 8003)
        self.assertEqual(port, 8001)

    def test_use_existing_dynamic_port(self):
        issuer = "google"
        instance_id='test1'
        self.database.upsert(port=8001, issuer=issuer, instance_id=instance_id, port_type=PortDatabase.STATIC_PORT_TYPE)
        port = self.database.allocate_port(issuer, instance_id, PortDatabase.STATIC_PORT_TYPE, 8001, 8003)
        self.assertEqual(port, 8001)

    def test_if_static_port_is_remove_when_switching_to_dynamic_port(self):
        issuer = "google"
        instance_id='test1'
        static_port = 8501
        self.database.upsert(port=static_port, issuer=issuer, instance_id=instance_id, port_type=PortDatabase.STATIC_PORT_TYPE)
        self.database.allocate_port(issuer, instance_id, PortDatabase.DYNAMIC_PORT_TYPE, 8001, 8003)
        ports = self.database.get_all_ports()
        self.assertNotIn(static_port, ports)

    def test_list_instance_ids_for_one_issuer(self):
        self.allocate_ports(3, PortDatabase.DYNAMIC_PORT_TYPE, issuer=self.ISSUER_GOOGLE)
        self.database.upsert(port=8004, issuer="apberget", instance_id='test1', port_type="static")
        self.database.upsert(port=8005, issuer="apberget", instance_id='test2', port_type="static")
        instance_ids = self.database.get_instance_ids(self.ISSUER_GOOGLE)
        self.assertEqual(instance_ids, ["ID_1", "ID_2", "ID_3"])

    def test_enter_issuer_non_ascii_charaters(self):
        issuer = unicode('https://example/öäå', encoding='utf-8')
        self.database.upsert(issuer=issuer, port=8000, instance_id="test", port_type=PortDatabase.DYNAMIC_PORT_TYPE)
        self.assertEqual(self.database.get_all_ports(), [8000])

    def test_add_large_config_file(self):
        defalut_config = get_default_client()
        self.database.upsert(issuer="issuer",
                             port=8000,
                             instance_id="test",
                             port_type=PortDatabase.DYNAMIC_PORT_TYPE,
                             config_file=json.dumps(defalut_config))
        row = self.database.table.find_one(issuer="issuer", instance_id="test")
        config = json.loads(row['config_file'])
        self.assertTrue(isinstance(config, dict))

    def test_add_config_file_to_existing_database_entry(self):
        port = 8004
        config_file = {"etst":1}
        self.database.upsert(port=port, issuer="apberget", instance_id='test1', port_type="static")
        row = self.database.get_row(port)
        self.database.upsert_row(row, config_file)
        row = self.database.get_row(port)
        self.assertEqual(row[PORT_COLUMN], port)
        self.assertEqual(row[CONFIG_FILE_COLUMN], config_file)

if __name__ == '__main__':
    unittest.main()