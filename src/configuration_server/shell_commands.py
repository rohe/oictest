import datetime
import logging
import os
import signal
import subprocess
import requests
import time
from requests.exceptions import ConnectionError
from configuration_server.configurations import UserFriendlyException

__author__ = 'danielevertsson'

LOGGER = logging.getLogger("configuration_server.shell_commands")


class NoResponseException(UserFriendlyException):
    pass


def check_if_oprp_started(port, oprp_url, timeout=5):
    stop_time = datetime.datetime.now() + datetime.timedelta(seconds=timeout)

    response = None

    while datetime.datetime.now() < stop_time:
        try:
            response = requests.get(oprp_url, verify=False)

            if response.status_code == 200:
                LOGGER.debug("The RP is running on port %s and returned status code 200 OK" % port)
                return True

            time.sleep(1)
        except ConnectionError:
            pass

    error_message = "Test instance (%s) failed to return '200 OK' within %s sec. " % \
                    (oprp_url, timeout)

    if response:
        error_message += "The last response returned from the test instance: %s" % response
    else:
        error_message += "No response where returned from the test instance"

    raise NoResponseException("Failed to start test instance %s." % oprp_url,
                              log_info=error_message)


def kill_existing_process_on_port(port, base_url):

    pid = get_oprp_pid(port)

    if pid:
        try:
            os.kill(pid, signal.SIGKILL)
            LOGGER.debug("Killed RP running on port %s" % port)
        except OSError as ex:
            LOGGER.error("Failed to kill process (%s) connected to the server %s" % (pid, base_url))
            raise ex
    else:
        LOGGER.debug("No process has been killed. Found no test instance running on port %s" % port)


def log_process_information(output, port):
    try:
        pids = output.splitlines()
        for pid in pids:
            process_info = run_command([["ps", "-ax"], ["grep", str(int(pid))]])
            LOGGER.debug("Apparently port %s is already in use by process: %s" %
                         (port, process_info))
    except Exception:
        pass


def is_port_used_by_another_process(port):
    result = None
    try:
        oprp_pid = get_oprp_pid(port)
        result = run_command([
            ["lsof", "-i", ":%s" % port],
            ["grep", "LISTEN"],
            ["awk", '{print $2}']
        ])
        if not (result and not oprp_pid):
            return False

    except Exception as ex:
        LOGGER.exception(str(ex))
        LOGGER.error("Failed to verify if any other process is running on port: %s" % port)

    if result:
        log_process_information(result, port)
    return True


def get_oprp_pid(port):
    pid = None
    p = subprocess.Popen(['ps', '-ax'], stdout=subprocess.PIPE)
    out, err = p.communicate()
    for line in out.splitlines():
        if "rp_conf_" + str(port) in line:
            pid = int(line.split(None, 1)[0])
            break

    return pid


def run_command(commands_to_pipe):

    past_sub_process = None
    p = None

    for command in commands_to_pipe:

        if past_sub_process:
            p = subprocess.Popen(command, stdin=past_sub_process.stdout, stdout=subprocess.PIPE)
        else:
            p = subprocess.Popen(command, stdout=subprocess.PIPE)

        past_sub_process = p

    return p.stdout.read()
