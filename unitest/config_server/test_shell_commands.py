import responses

from threading import Thread
from mock import patch
import pytest
from beaker.middleware import SessionMiddleware
from cherrypy import wsgiserver

from configuration_server.configurations import generate_config_module_name
from configuration_server.test_instance_database import PortDatabase
from configuration_server.shell_commands import get_oprp_pid, \
    is_port_used_by_another_process, \
    NoResponseException, \
    check_if_oprp_started

__author__ = 'danielevertsson'


def application():
    pass


class TestShellCommands:
    def ps_output(self, port, pid=100552):
        out = "87552 ttys001    0:00.12 login -pf danielevertsson \n" + \
              str(pid) + " ttys000    0:00.17 server " + generate_config_module_name(port) +\
              "\n87553 ttys001    0:00.07 -bash \n"
        return out

    @patch('subprocess.Popen.communicate')
    def test_returns_correct_pid(self, popen_communicate_mock):
        port = 0
        pid = 10253
        popen_communicate_mock.return_value = (self.ps_output(port, pid), "")
        identifed_pid = get_oprp_pid(port)
        assert pid == identifed_pid

    def _start_server(self, SRV):
        try:
            SRV.start()
        except KeyboardInterrupt:
            SRV.stop()

    def _start_http_server_thread(self, port):
        self.srv = wsgiserver.CherryPyWSGIServer(('0.0.0.0', port),
                                                 SessionMiddleware(application))
        self.thread = Thread(target=self._start_server, args=(self.srv,))
        self.thread.daemon = True
        self.thread.start()

    @patch('subprocess.Popen.communicate')
    def test_if_possible_to_separate_between_test_instance_and_other_process(
            self,
            popen_communicate_mock):

        port = 9001
        popen_communicate_mock.return_value = (self.ps_output(port), "")
        assert not is_port_used_by_another_process(9001)

        free_port = port + 1
        while is_port_used_by_another_process(free_port):
            free_port += 1
        self._start_http_server_thread(free_port)
        assert is_port_used_by_another_process(free_port)

    def _allocate_next_free_port(self):
        port_db = PortDatabase(is_port_used_func=is_port_used_by_another_process)
        return port_db.allocate_port("issuer",
                                     "instance_id",
                                     PortDatabase.STATIC_PORT_TYPE,
                                     8000,
                                     8100)

    def test_alloc_port_used_by_other_process(self):
        self._start_http_server_thread(8000)
        allocated_port = self._allocate_next_free_port()
        assert 8001 == allocated_port

    def test_alloc_multiple_ports_used_by_other_processes(self):
        self._start_http_server_thread(8000)
        self._start_http_server_thread(8001)
        self._start_http_server_thread(8002)
        allocated_port = self._allocate_next_free_port()
        assert 8003 == allocated_port

    def test_check_if_oprp_started_raises_NoResponseException(self):
        with pytest.raises(NoResponseException):
            check_if_oprp_started(None, oprp_url="http://1234.1234.1234.1234:8000", timeout=1)

    def get_external_host_url(self, port):
        return "http://localhost:%s" % port

    @responses.activate
    def test_if_able_to_get_200_ok_from_running_server(self):
        responses.add(responses.GET,
                      self.get_external_host_url(9001),
                      body={},
                      status=200,
                      content_type='application/json')
        return_code = check_if_oprp_started(None,
                                            oprp_url=self.get_external_host_url(9001),
                                            timeout=1)
        assert return_code

    @patch("configuration_server.shell_commands.run_command")
    def test_trows_exception_while_running_command(self, run_command_mock):
        run_command_mock.side_effect = Exception()
        port_is_used = is_port_used_by_another_process(8000)
        assert port_is_used
