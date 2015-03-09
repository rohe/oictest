import subprocess
from config_server import NoResponseException
from config_server import check_if_oprp_started
from config_server import write_config_file
from config_server import kill_existing_process_on_port
from config_server import get_oprp_pid

__author__ = 'danielevertsson'

import unittest

class TestConfigServer(unittest.TestCase):

    def test_check_if_oprp_started_raises_NoResponseException(self):
        with self.assertRaises(NoResponseException):
            check_if_oprp_started(None, oprp_url="http://1234.1234.1234.1234:8000", timeout=1)

    def test_write_config_without_write_access(self):
        with self.assertRaises(IOError):
            write_config_file("no_write_access_file.txt", "content")

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

if __name__ == '__main__':
    unittest.main()