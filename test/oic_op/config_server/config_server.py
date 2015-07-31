#!/usr/bin/env python
# -*- coding: utf-8 -*-
import importlib
import json
from logging import FileHandler
import os
import logging
import sys
import subprocess

import argparse
from requestlogger import WSGILogger, ApacheFormatter
from dirg_util.http_util import HttpHandler
from mako.lookup import TemplateLookup
from oic.utils.http_util import NotFound
from oic.utils.http_util import Response

from configuration_server.configurations import convert_config_file, get_issuer_from_gui_config, convert_to_gui_drop_down, \
    convert_config_gui_structure, generate_profile, is_using_dynamic_client_registration, handle_exception, \
    create_module_string, get_config_file_path, write_config_file, get_default_client

from configuration_server.shell_commands import is_port_used_by_another_process, kill_existing_process_on_port, \
    check_if_oprp_started, NoResponseException
from configuration_server.test_instance_database import PortDatabase, NoPortAvailable

from configuration_server.response_encoder import ResponseEncoder


LOGGER = logging.getLogger("configuration_server")

LOOKUP = TemplateLookup(directories=['templates', 'htdocs'],
                        module_directory='modules',
                        input_encoding='utf-8',
                        output_encoding='utf-8')

SERVER_ENV = {}
OP_CONFIG = "op_config"
NO_PORT_ERROR_MESSAGE = "It appears that no ports are available at the " \
                        "moment. Please try again later."
CONF = None

def setup_logging(logfile):
    hdlr = logging.FileHandler(logfile)
    base_formatter = logging.Formatter(
        "%(asctime)s %(name)s:%(levelname)s %(message)s")

    hdlr.setFormatter(base_formatter)
    LOGGER.addHandler(hdlr)
    LOGGER.setLevel(logging.DEBUG)


def static(environ, start_response, logger, path):
    try:
        text = open(path).read()
        if path.endswith(".ico"):
            start_response('200 OK', [('Content-Type', "image/x-icon")])
        elif path.endswith(".html"):
            start_response('200 OK', [('Content-Type', 'text/html')])
        elif path.endswith(".json"):
            start_response('200 OK', [('Content-Type', 'application/json')])
        elif path.endswith(".jwt"):
            start_response('200 OK', [('Content-Type', 'application/jwt')])
        elif path.endswith(".txt"):
            start_response('200 OK', [('Content-Type', 'text/plain')])
        elif path.endswith(".css"):
            start_response('200 OK', [('Content-Type', 'text/css')])
        else:
            start_response('200 OK', [('Content-Type', "text/plain")])
        return [text]
    except IOError:
        resp = NotFound()
        return resp(environ, start_response)


def op_config(environ, start_response):
    resp = Response(mako_template="op_config.mako",
                    template_lookup=LOOKUP,
                    headers=[])
    return resp(environ, start_response)

def handle_get_op_config(session, response_encoder):
    """
    Handles the get config Gui structure request
    :return A configuration Gui structure which is based on the configuration
    file saved in the session
    """
    if OP_CONFIG in session:

        try:
            _op_config = session[OP_CONFIG]
        except KeyError:
            _op_config = None

        if not isinstance(_op_config, dict):
            return response_encoder.service_error(
                "No JSON object could be decoded. Please check if the file is "
                "a valid json file")

        config_gui_structure = convert_config_file(_op_config)
        return response_encoder.return_json(json.dumps(config_gui_structure))

    return response_encoder.service_error(
        "No file saved in this current session")

def handle_request_instance_ids(response_encoder, parameters):
    if 'opConfigurations' not in parameters:
        return response_encoder.bad_request()

    config_gui_structure = parameters['opConfigurations']
    issuer = get_issuer_from_gui_config(config_gui_structure)
    port_db = PortDatabase(CONF.STATIC_CLIENT_REGISTRATION_PORTS_DATABASE_FILE)
    instance_ids = port_db.get_instance_ids(issuer)

    existing_instance_ids = {}
    if len(instance_ids) > 0:
        existing_instance_ids['value'] = instance_ids[0]

    existing_instance_ids['values'] = convert_to_gui_drop_down(instance_ids)

    return_info = {"existing_instance_ids": existing_instance_ids, "issuer": issuer}
    return response_encoder.return_json(json.dumps(return_info))


def handle_does_op_config_exist(session, response_encoder):
    """
    Handles the request checking if the configuration file exists
    :return Returns a dictionary {"does_config_file_exist" : true} if the
    session contains a config file else {"does_config_file_exist" : false}
    """
    result = json.dumps({"does_config_file_exist": (OP_CONFIG in session)})
    return response_encoder.return_json(result)


def handle_download_config_file(session, response_encoder, parameters):
    """
    :return Return the configuration file stored in the session
    """
    if 'op_configurations' not in parameters:
        return response_encoder.bad_request()

    config_gui_structure = parameters['op_configurations']
    instance_id = ""
    port = -1
    config_file_dict = convert_config_gui_structure(config_gui_structure,
                                                    port,
                                                    instance_id,
                                                    is_port_in_database(port),
                                                    CONF)
    filedict = json.dumps({"configDict": config_file_dict})
    return response_encoder.return_json(filedict)

class ConfigSizeToLarge(Exception):
    pass

def validate_configuration_size(config):
    if isinstance(config, dict):
        config_string = json.dumps(config)
    if len(config_string) > CONF.CONFIG_MAX_NUMBER_OF_CHARS_ALLOWED:
        raise ConfigSizeToLarge("The given configuration contained %s chars when the "
                                "maximum number of chars are %s" % (len(config_string),
                                                                    CONF.CONFIG_MAX_NUMBER_OF_CHARS_ALLOWED))
    return config


def handle_upload_config_file(parameters, session, response_encoder):
    """
    Adds a uploaded config file to the session
    :return Default response, should be ignored
    """
    if 'configFileContent' not in parameters:
        return response_encoder.bad_request()

    try:
        session[OP_CONFIG] = validate_configuration_size(json.loads(parameters['configFileContent']))
    except ValueError:
        return response_encoder.service_error(
            "Failed to load the configuration file. Make sure the config file "
            "follows the appopriate format")
    except ConfigSizeToLarge:
        LOGGER.debug("Some one tried to upload a configuration which exceeded the allowed file limit.")
        return response_encoder.service_error("The uploaded configuration file exceeds the allowed file limit.")

    return response_encoder.return_json("{}")


def start_rp_process(port, command, working_directory=None):
    failed_to_start_message = "RP (%s) failed to start" % get_base_url(port)
    LOGGER.debug("Try to start RP on {} with command {}".format(port, command))

    if is_port_used_by_another_process(port):
        raise Exception(failed_to_start_message)

    try:
        p = subprocess.Popen(command,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE,
                             cwd=working_directory)
        retcode = p.poll()  # returns None while subprocess is running

    except Exception as ex:
        LOGGER.fatal(
            "Failed to run oprp script: {} Error message: ".format(
                command[0], ex))
        raise Exception(failed_to_start_message)

    if retcode is None:
        check_if_oprp_started(port, get_base_url(port))
    else:
        LOGGER.error("Return code {} != None. Command executed: {}".format(
            retcode, command))
        raise NoResponseException(failed_to_start_message)


def save_config_info_in_database(_port, session):
    port_db = PortDatabase(CONF.STATIC_CLIENT_REGISTRATION_PORTS_DATABASE_FILE)
    row = port_db.get_row(_port)
    port_db.upsert_row(row, session[OP_CONFIG])

def is_port_in_database(_port):
    port_db = PortDatabase(CONF.STATIC_CLIENT_REGISTRATION_PORTS_DATABASE_FILE)
    return port_db.get_row(_port) == None

def get_base_url(port):
    return 'https://%s:%d/' % (CONF.HOST, int(port))

def handle_start_op_tester(session, response_encoder, parameters):
    if 'op_configurations' not in parameters:
        return response_encoder.bad_request()

    config_gui_structure = parameters['op_configurations']
    _profile = generate_profile(config_gui_structure)
    _instance_id = parameters['oprp_instance_id']
    _port = None

    if is_using_dynamic_client_registration(config_gui_structure):
        try:
            issuer = get_issuer_from_gui_config(config_gui_structure)
            _port = allocate_dynamic_port(issuer, _instance_id)
        except NoPortAvailable:
            pass
    else:
        if "port" in session:
            _port = session['port']

    if not _port:
        LOGGER.error(NO_PORT_ERROR_MESSAGE)
        return response_encoder.service_error(NO_PORT_ERROR_MESSAGE)

    config_string = convert_config_gui_structure(config_gui_structure,
                                                                _port,
                                                                _instance_id,
                                                                is_port_in_database(_port),
                                                                CONF)
    try:
        session[OP_CONFIG] = validate_configuration_size(config_string)
    except ConfigSizeToLarge as ex:
        return handle_exception(ex, response_encoder, "The configuration you are trying to store exceeds the allowed file limit.")

    config_module = create_module_string(session[OP_CONFIG],
                                         _port,
                                         CONF,
                                         get_base_url(_port))
    config_file_path = get_config_file_path(_port, CONF.OPRP_DIR_PATH)

    try:
        write_config_file(config_file_path, config_module, _port, oprp_dir_path=CONF.OPRP_DIR_PATH)
        LOGGER.debug("Written configuration to file: %s" % config_file_path)
    except IOError as ioe:
        error_message = "Failed to write configurations file (%s) to disk. " \
                        "Please contact technical support" % config_file_path
        return handle_exception(ioe, response_encoder, error_message)


    try:
        save_config_info_in_database(_port, session)
        LOGGER.debug('Configurations for the test instance using instance ID equal to "%s" which should be using port %s to has been saved in the database' % (_instance_id, _port))
    except Exception as ex:
        return handle_exception(ex, response_encoder, "Failed to store configurations in database. Please contact technical support")

    try:
        kill_existing_process_on_port(_port, get_base_url(_port))
    except Exception as ex:
        return handle_exception(ex, response_encoder, "Failed to restart test instance. Please contact technical support")

    config_file_name = os.path.basename(config_file_path)
    config_module = config_file_name.split(".")[0]

    try:
        start_rp_process(_port, [CONF.OPRP_PATH, "-p", _profile, "-t",
                                CONF.OPRP_TEST_FLOW, config_module], "../rp/")
        return response_encoder.return_json(
            json.dumps({"oprp_url": str(get_base_url(_port))}))
    except Exception as ex:
        LOGGER.error(ex.message)
        return response_encoder.service_error(ex.message)


def get_port_from_database(issuer, instance_id, min_port, max_port, port_type):
    is_port_unused_func = is_port_used_by_another_process
    port_db = PortDatabase(CONF.STATIC_CLIENT_REGISTRATION_PORTS_DATABASE_FILE, is_port_unused_func)
    return port_db.allocate_port(issuer, instance_id, port_type, min_port, max_port)



def allocate_dynamic_port(issuer, oprp_instance_id):
    return get_port_from_database(issuer,
                                  oprp_instance_id,
                                  CONF.DYNAMIC_CLIENT_REGISTRATION_PORT_RANGE_MIN,
                                  CONF.DYNAMIC_CLIENT_REGISTRATION_PORT_RANGE_MAX,
                                  PortDatabase.DYNAMIC_PORT_TYPE)

def allocate_static_port(issuer, oprp_instance_id):
    return get_port_from_database(issuer,
                                  oprp_instance_id,
                                  CONF.STATIC_CLIENT_REGISTRATION_PORT_RANGE_MIN,
                                  CONF.STATIC_CLIENT_REGISTRATION_PORT_RANGE_MAX,
                                  PortDatabase.STATIC_PORT_TYPE)


def handle_create_new_config_file(response_encoder, session):
    session[OP_CONFIG] = get_default_client()
    return response_encoder.return_json("{}")


def get_existing_port(issuer, static_ports_db):
    for port in static_ports_db.keys():
        if static_ports_db[port] == issuer:
            return port
    return None


def handle_get_redirect_url(session, response_encoder, parameters):
    if "oprp_instance_id" not in parameters:
        return response_encoder.bad_request()
    if 'issuer' not in parameters:
        return response_encoder.bad_request()

    try:
        port = allocate_static_port(parameters['issuer'], parameters["oprp_instance_id"])
    except NoPortAvailable as ex:
        LOGGER.fatal(ex.message)
        return response_encoder.service_error(ex.message)

    session['port'] = port

    redirect_url = get_base_url(port) + "authz_cb"

    return response_encoder.return_json(
        json.dumps({"redirect_url": redirect_url}))


def handle_path(environ, start_response):
    path = environ.get('PATH_INFO', '').lstrip('/')
    session = environ['beaker.session']
    http_helper = HttpHandler(environ, start_response, session, LOGGER)
    response_encoder = ResponseEncoder(environ=environ,
                                       start_response=start_response)
    parameters = http_helper.query_dict()
    if path == "favicon.ico":
        return static(environ, start_response, LOGGER, "static/favicon.ico")
    if path.startswith("static/"):
        return static(environ, start_response, LOGGER, path)

    # TODO This is all web frameworks which should be imported via dirg-util
    if path.startswith("_static/"):
        return static(environ, start_response, LOGGER, path)
    if path.startswith("export/"):
        return static(environ, start_response, LOGGER, path)
    if path == "":
        return op_config(environ, start_response)
    if path == "create_new_config_file":
        return handle_create_new_config_file(response_encoder, session)
    if path == "get_op_config":
        return handle_get_op_config(session, response_encoder)
    if path == "does_op_config_exist":
        return handle_does_op_config_exist(session, response_encoder)
    if path == "download_config_file":
        return handle_download_config_file(session, response_encoder, parameters)
    if path == "upload_config_file":
        return handle_upload_config_file(parameters, session, response_encoder)
    if path == "start_op_tester":
        return handle_start_op_tester(session, response_encoder, parameters)
    if path == "get_redirect_url":
        return handle_get_redirect_url(session, response_encoder, parameters)
    if path == "request_instance_ids":
        return handle_request_instance_ids(response_encoder, parameters)
    return http_helper.http404()

def application(environ, start_response):
    try:
        return handle_path(environ, start_response);
    except Exception as ex:
        LOGGER.exception(ex)
        raise ex

loggingapp = WSGILogger(application, [FileHandler("access.log")], ApacheFormatter())
loggingapp.logger.propagate = False

if __name__ == '__main__':
    from beaker.middleware import SessionMiddleware
    from cherrypy import wsgiserver

    parser = argparse.ArgumentParser()
    parser.add_argument(dest="config")
    args = parser.parse_args()

    # global ACR_VALUES
    # ACR_VALUES = CONF.ACR_VALUES

    session_opts = {
        'session.type': 'memory',
        'session.cookie_expires': True,
        'session.auto': True,
        'session.timeout': 900
    }

    CONF = importlib.import_module(sys.argv[1])

    current_dir = os.path.dirname(os.path.abspath(__file__))

    if not hasattr(CONF, 'OPRP_PATH'):
        CONF.OPRP_PATH =  current_dir + "/../rp/oprp2.py"

    if not hasattr(CONF, 'OPRP_DIR_PATH'):
        CONF.OPRP_DIR_PATH = current_dir + "/../rp/"

    SERVER_ENV.update({"template_lookup": LOOKUP, "base_url": CONF.BASE})

    setup_logging("config_server.log")

    SRV = wsgiserver.CherryPyWSGIServer(('0.0.0.0', CONF.PORT),
                                        SessionMiddleware(loggingapp,
                                                          session_opts))
    try:
        _dir_path = CONF.OPRP_DIR_PATH
    except AttributeError:
        _dir_path = ""
    if CONF.OPRP_DIR_PATH not in sys.path:
        sys.path.append(CONF.OPRP_DIR_PATH)

    if CONF.BASE.startswith("https"):
        import cherrypy
        from cherrypy.wsgiserver import ssl_pyopenssl
        # from OpenSSL import SSL

        SRV.ssl_adapter = ssl_pyopenssl.pyOpenSSLAdapter(
            CONF.SERVER_CERT, CONF.SERVER_KEY, CONF.CA_BUNDLE)
        # SRV.ssl_adapter.context = SSL.Context(SSL.SSLv23_METHOD)
        # SRV.ssl_adapter.context.set_options(SSL.OP_NO_SSLv3)
        try:
            cherrypy.server.ssl_certificate_chain = CONF.CERT_CHAIN
        except AttributeError:
            pass
        extra = " using SSL/TLS"
    else:
        extra = ""

    txt = "Config server started, listening on port:%s%s" % (CONF.PORT, extra)
    LOGGER.info(txt)
    print txt

    try:
        SRV.start()
    except KeyboardInterrupt:
        SRV.stop()