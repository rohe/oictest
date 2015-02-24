#!/usr/bin/env python
import collections
import copy
import importlib
import json
import os
import threading
import time
import argparse
import datetime
import logging
import sys
import requests
import subprocess
import signal

from dirg_util.http_util import HttpHandler
from mako.lookup import TemplateLookup

from issuer_port_database import MySqllite3Dict
from requests.exceptions import ConnectionError
from response_encoder import ResponseEncoder

from oic.oauth2.message import REQUIRED_LIST_OF_SP_SEP_STRINGS
from oic.oauth2.message import OPTIONAL_LIST_OF_STRINGS
from oic.oauth2.message import OPTIONAL_LIST_OF_SP_SEP_STRINGS
from oic.oauth2.message import REQUIRED_LIST_OF_STRINGS
from oic.oic.message import ProviderConfigurationResponse
from oic.utils.http_util import NotFound
from oic.utils.http_util import Response

LOGGER = logging.getLogger("")

LOOKUP = TemplateLookup(directories=['templates', 'htdocs'],
                        module_directory='modules',
                        input_encoding='utf-8',
                        output_encoding='utf-8')

SERVER_ENV = {}
OP_CONFIG = "op_config"
NO_PORT_ERROR_MESSAGE = "It appears that no ports are available at the " \
                        "moment. Please try again later."


def setup_logging(logfile):
    hdlr = logging.FileHandler(logfile)
    base_formatter = logging.Formatter(
        "%(asctime)s %(name)s:%(levelname)s %(message)s")

    hdlr.setFormatter(base_formatter)
    LOGGER.addHandler(hdlr)
    LOGGER.setLevel(logging.DEBUG)


def static(environ, start_response, logger, path):
    logger.info("[static]sending: %s" % (path,))

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


def create_new_configuration_dict():
    """
    :return Returns a new configuration which follows the internal data
    structure
    """
    static_input_fields_list = generate_static_input_fields()
    op_configurations = {
        "fetchInfoFromServerDropDown": {
            "name": "How should the application fetch provider configurations "
                    "from the server?",
            "value": "",
            "values": [{"type": "dynamic", "name": "Dynamically"},
                       {"type": "static", "name": "Statically"}]
        },
        "fetchStaticProviderInfo": {"showInputFields": False,
                                    "input_fields": static_input_fields_list},
        "fetchDynamicInfoFromServer": {"showInputField": False,
                                       "input_field": {"label": "Issuer url *",
                                                       "value": "",
                                                       "show": False,
                                                       "isList": False}},
        "dynamicClientRegistrationDropDown": {
            "label": "Do the provider support dynamic client registration?",
            "value": "yes",
            "values": [{"type": "yes", "name": "yes"},
                       {"type": "no", "name": "no"}]
        },
        "responseTypeDropDown": {
            "label": "Which response type should be used?",
            "value": "code",
            "values": [
                {"type": "code", "name": "code"},
                {"type": "id_token", "name": "id_token"},
                {"type": "id_token token", "name": "id_token token"},
                {"type": "code id_token", "name": "code id_token"},
                {"type": "code token", "name": "code token"},
                {"type": "code id_token token", "name": "code id_token token"}
            ]
        },
        "signingEncryptionFeaturesCheckboxes": {
            "label": "Select supported features:",
            "features": [
                {"name": 'JWT signed with "None" algorithm (Unsigned)',
                 "selected": False, "abbreviation": "n"},
                {"name": 'JWT signed with algorithm other then "None"',
                 "selected": False, "abbreviation": "s"},
                {"name": 'Encrypted JWT', "selected": False,
                 "abbreviation": "e"}
            ]
        },
        "supportsStaticClientRegistrationTextFields": [
            {"id": "redirect_uris", "label": "Redirect uris",
             "textFieldContent": "", "disabled": True},
            {"id": "client_id", "label": "Client id *", "textFieldContent": ""},
            {"id": "client_secret", "label": "Client secret *",
             "textFieldContent": ""}],

        "clientSubjectType": {
            "label": "Select which subject identifier type the client should "
                     "use: ",
            "value": "public",
            "values": [{"type": "public", "name": "public"},
                       {"type": "pairwise", "name": "pairwise"}]
        },
        "webfingerSubject": "",
        "loginHint": "",
        "uiLocales": "",
        "claimsLocales": "",
        "acrValues": "",
    }
    return op_configurations


def is_pyoidc_message_list(field_type):
    if field_type == REQUIRED_LIST_OF_SP_SEP_STRINGS:
        return True
    elif field_type == OPTIONAL_LIST_OF_STRINGS:
        return True
    elif field_type == OPTIONAL_LIST_OF_SP_SEP_STRINGS:
        return True
    elif field_type == REQUIRED_LIST_OF_STRINGS:
        return True
    return False


def generate_static_input_fields():
    """
    Generates all static input fields based on ProviderConfigurationResponse
    class localed in [your path]/pyoidc/scr/oic/oic/message.py
    
    :return:The static input fields presented as the internal data structure
    """
    _config_key_list = ProviderConfigurationResponse.c_param.keys()
    _config_key_list.sort()
    _config_fields_dict = ProviderConfigurationResponse.c_param

    _config_fields_list = []

    required_fields = ["issuer",
                       'authorization_endpoint',
                       'jwks_uri',
                       'response_types_supported',
                       'subject_types_supported',
                       'id_token_signing_alg_values_supported']

    for _field_label in _config_key_list:
        _field_type = _config_fields_dict[_field_label]
        config_field = {'id': _field_label, 'label': _field_label,
                        'values': [], 'show': False, 'required': False,
                        'isList': is_pyoidc_message_list(_field_type)}
        if _field_label in required_fields:
            config_field['required'] = True
            config_field['show'] = True
            config_field['label'] += " *"
        _config_fields_list.append(config_field)

    return _config_fields_list


def dynamic_discovery_to_gui_structure(config_file_dict, config_gui_structure):
    """
    Converts the configuration file structure to the Internal data structure
    :param config_gui_structure: Data structure used to hold and show
    configuration information in the Gui
    :param config_file_dict: Internal data structure containing all info
    gathered in the web interface
    :return The updated presentation of the internal data structure
    """
    config_gui_structure["fetchInfoFromServerDropDown"]["value"] = "dynamic"
    config_gui_structure["fetchDynamicInfoFromServer"]["showInputField"] = True
    config_gui_structure["fetchDynamicInfoFromServer"]["input_field"]["value"]\
        = \
        config_file_dict["srv_discovery_url"]

    return config_gui_structure


def is_list_instance(element):
    return not isinstance(element, basestring)


def convert_static_provider_info_to_gui(config_file_dict, config_gui_structure):
    """
    Converts a static provider from config file to a gui structure
    :param config_gui_structure: Data structure used to hold and show
    configuration information in the Gui
    :param config_file_dict: The configuration file from which the
    configuration static provider data should be gathered
    :return The updated configuration GUI data structure
    """
    provider_info_key = "provider_info"

    config_gui_structure["fetchInfoFromServerDropDown"]["value"] = "static"
    config_gui_structure["fetchStaticProviderInfo"]["showInputFields"] = True

    for input_fieldId in config_file_dict[provider_info_key]:
        for input_field in config_gui_structure["fetchStaticProviderInfo"][
                "input_fields"]:
            if input_field['id'] == input_fieldId:
                input_field['show'] = True
                attribute_value = config_file_dict[provider_info_key][
                    input_fieldId]

                if is_list_instance(attribute_value):
                    input_field['values'] = convert_to_value_list(
                        attribute_value)
                else:
                    input_field['values'] = attribute_value

    return config_gui_structure


def client_registration_supported_to_gui(config_file_dict,
                                         config_gui_structure):
    """
    Converts a required information from config file to a config GUI structure
    :param config_gui_structure: Data structure used to hold and show
    configuration information in the Gui
    :param config_file_dict: The configuration file from which the
    configuration required information data should be gathered
    :return The updated configuration GUI data structure
    """
    supports_dynamic_client_registration = False

    if "client_registration" not in config_file_dict:
        return config_gui_structure

    if "client_id" in config_file_dict["client_registration"]:
        supports_dynamic_client_registration = True
        config_gui_structure["dynamicClientRegistrationDropDown"][
            "value"] = "no"

        for text_field in config_gui_structure[
                "supportsStaticClientRegistrationTextFields"]:
            if text_field["id"] == "client_id":
                text_field["textFieldContent"] = \
                    config_file_dict["client_registration"]["client_id"]

    if "client_secret" in config_file_dict["client_registration"]:
        supports_dynamic_client_registration = True
        config_gui_structure["dynamicClientRegistrationDropDown"][
            "value"] = "no"

        for text_field in config_gui_structure[
                "supportsStaticClientRegistrationTextFields"]:
            if text_field["id"] == "client_secret":
                text_field["textFieldContent"] = \
                    config_file_dict["client_registration"]["client_secret"]

    if not supports_dynamic_client_registration:
        config_gui_structure["dynamicClientRegistrationDropDown"][
            "value"] = "yes"

    return config_gui_structure


def convert_sub_claims_to_lists(sub_claims):
    lists = []

    if 'value' in sub_claims:
        lists.append({"value": sub_claims['value']})

    elif "values" in sub_claims:
        for element in sub_claims['values']:
            lists.append({"value": element})

    return lists


def convert_to_value_list(elements):
    value_list = []
    for element in elements:
        value_list.append({"value": element})

    return value_list


def set_feature_list(config_structure_dict, oprp_arg):
    feature_list = config_structure_dict['signingEncryptionFeaturesCheckboxes'][
        'features']

    for feature in feature_list:
        feature['selected'] = feature['abbreviation'] in oprp_arg


def convert_abbreviation_to_response_type(response_type_abbreviation):
    response_types = {
        "C": "code",
        "I": "id_token",
        "IT": "id_token token",
        "CI": "code id_token",
        "CT": "code token",
        "CIT": "code id_token token"
    }

    return response_types[response_type_abbreviation]


def parse_profile(profile):
    if not isinstance(profile, basestring):
        raise ValueError("profile value of wrong type")

    _args = profile.split(".")

    response_type = convert_abbreviation_to_response_type(_args[0])
    crypto_feature_support = _args[3]

    return response_type, crypto_feature_support


def convert_config_file(config_file_dict):
    """
    Converts a config file structure to a config GUI structure
    :param config_file_dict: The configuration file from which should be 
    converted
    :return The updated configuration GUI data structure
    """
    config_structure_dict = create_new_configuration_dict()

    if "srv_discovery_url" in config_file_dict:
        config_structure_dict = dynamic_discovery_to_gui_structure(
            config_file_dict,
            config_structure_dict)

    elif "provider_info" in config_file_dict:
        # Now we know it's an static provider
        config_structure_dict = convert_static_provider_info_to_gui(
            config_file_dict,
            config_structure_dict)

    config_structure_dict = client_registration_supported_to_gui(
        config_file_dict,
        config_structure_dict)

    config_structure_dict['clientSubjectType']['value'] = \
        config_file_dict['preferences']['subject_type']

    response_type, crypto_feature_support = parse_profile(
        config_file_dict['behaviour']['profile'])

    config_structure_dict['responseTypeDropDown']['value'] = response_type

    if crypto_feature_support:
        set_feature_list(config_structure_dict, crypto_feature_support)

    if 'webfinger_subject' in config_file_dict:
        config_structure_dict['webfingerSubject'] = config_file_dict[
            'webfinger_subject']

    if 'login_hint' in config_file_dict:
        config_structure_dict['loginHint'] = config_file_dict['login_hint']

    if "ui_locales" in config_file_dict:
        config_structure_dict['uiLocales'] = config_file_dict['ui_locales']

    if "claims_locales" in config_file_dict:
        config_structure_dict['claimsLocales'] = config_file_dict['claims_locales']

    if "acr_values" in config_file_dict:
        config_structure_dict['acrValues'] = config_file_dict['acr_values']

    return config_structure_dict


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


def convert_static_provider_info_to_file(config_gui_structure,
                                         config_file_dict):
    """
    Converts static information in the internal data structure and updates
    the configDict
    which follows the "Configuration file structure", see setup.rst
    :param config_gui_structure: Data structure used to hold and show
    configuration information in the Gui
    :param config_file_dict: configuration dictionary which follows the
    "Configuration file structure"
    :return Configuration dictionary updated with the new static information
    """
    visible_input_field_list = []
    provider_attribute_dict = {}

    for input_field in config_gui_structure['fetchStaticProviderInfo'][
            'input_fields']:
        if input_field['show']:
            visible_input_field_list.append(input_field)

    for input_field in visible_input_field_list:
        attribut_id = input_field['id']

        if input_field['isList']:
            provider_attribute_dict[attribut_id] = convert_to_list(
                input_field['values'])
        else:
            provider_attribute_dict[attribut_id] = input_field['values']

    config_file_dict['provider_info'] = provider_attribute_dict

    return config_file_dict


def client_registration_to_gui_structure(config_gui_structure,
                                         config_file_dict):
    """
    Converts required information in the web interface to the
    a configuration dictionary which follows the "Configuration file
    structure", see setup.rst
    :param config_gui_structure: Data structure used to hold and show
    configuration information in the Gui
    :param config_file_dict: configuration dictionary which follows the
    "Configuration file structure"
    :return Configuration dictionary updated with the new required information
    """
    support_dynamic_client_registration = \
        config_gui_structure['dynamicClientRegistrationDropDown'][
            'value'] == 'yes'

    if not support_dynamic_client_registration:
        for attribute in config_gui_structure[
                'supportsStaticClientRegistrationTextFields']:
            if 'client_registration' not in config_file_dict:
                config_file_dict['client_registration'] = {}

            if attribute['id'] == 'client_id':
                config_file_dict['client_registration']['client_id'] = \
                    attribute['textFieldContent']
            elif attribute['id'] == 'client_secret':
                config_file_dict['client_registration']['client_secret'] = \
                    attribute['textFieldContent']
            elif attribute['id'] == 'redirect_uris':
                config_file_dict['client_registration']['redirect_uris'] = [
                    attribute['textFieldContent']]

    else:
        try:
            del config_file_dict['client_registration']['client_id']
        except KeyError:
            pass

        try:
            del config_file_dict['client_registration']['client_secret']
        except KeyError:
            pass

    return config_file_dict


def convert_sub_claims_to_dict(sub_claims_gui):
    sub_claims = {"values": []}

    if len(sub_claims_gui) == 1:
        return sub_claims_gui[0]

    elif len(sub_claims_gui) > 1:
        for element in sub_claims_gui:
            sub_claims["values"].append(element['value'])

    return sub_claims


def convert_to_list(value_dict):
    _list = []
    for element in value_dict:
        _list.append(element['value'])

    return _list


def clear_optional_keys(config_dict):
    optional_fields = ['webfinger_subject', 'login_hint', 'sub_claim',
                       'ui_locales', 'claims_locales', 'acr_values']

    for field in optional_fields:
        if field in config_dict:
            del config_dict[field]

    return config_dict


def parse_crypto_feature_abbreviation(config_gui_structure):
    arg = ""
    for feature in config_gui_structure['signingEncryptionFeaturesCheckboxes'][
            'features']:
        if feature['selected']:
            arg += feature['abbreviation']
    return arg


def convert_response_type_to_abbreviation(response_type):
    abbreviations_dict = {"code": "C",
                          "id_token": "I",
                          "id_token token": "IT",
                          "code id_token": "CI",
                          "code token": "CT",
                          "code id_token token": "CIT"}

    return abbreviations_dict[response_type]


def convert_dynamic_client_registration_to_abbreviation(config_gui_structure):
    if config_gui_structure['dynamicClientRegistrationDropDown'][
            'value'] == "yes":
        return "T"
    return "F"


def convert_dynamic_discovery_to_abbreviation(config_gui_structure):
    if contains_dynamic_discovery_info(config_gui_structure):
        return "T"
    return "F"


def contains_dynamic_discovery_info(config_gui_structure):
    return config_gui_structure['fetchDynamicInfoFromServer'][
        'showInputField'] is True


def generate_profile(config_gui_structure):
    response_type_abbr = convert_response_type_to_abbreviation(
        config_gui_structure["responseTypeDropDown"]["value"])
    dynamic_discovery_abbr = convert_dynamic_discovery_to_abbreviation(
        config_gui_structure)
    dynamic_client_registration_abbr = \
        convert_dynamic_client_registration_to_abbreviation(
            config_gui_structure)
    crypto_features_abbr = parse_crypto_feature_abbreviation(
        config_gui_structure)

    profile = response_type_abbr + "." + \
        dynamic_discovery_abbr + "." + \
        dynamic_client_registration_abbr + "." + \
        crypto_features_abbr + "."

    return profile


def convert_config_gui_structure(config_gui_structure):
    """
    Converts the internal data structure to a dictionary which follows the
    "Configuration file structure", see setup.rst
    :param config_gui_structure: Data structure used to hold and show
    configuration information in the Gui
    :return A dictionary which follows the "Configuration file structure",
    see setup.rst
    """
    config_dict = get_default_client()

    if contains_dynamic_discovery_info(config_gui_structure):
        dynamic_input_field_value = \
            config_gui_structure['fetchDynamicInfoFromServer']['input_field'][
                'value']
        config_dict['srv_discovery_url'] = dynamic_input_field_value

    elif config_gui_structure['fetchStaticProviderInfo']['showInputFields']:
        config_dict = convert_static_provider_info_to_file(config_gui_structure,
                                                           config_dict)

    config_dict = client_registration_to_gui_structure(config_gui_structure,
                                                       config_dict)

    config_dict['preferences']['subject_type'] = \
        config_gui_structure["clientSubjectType"]["value"]

    config_dict['behaviour']['profile'] = generate_profile(config_gui_structure)

    config_dict = clear_optional_keys(config_dict)

    if config_gui_structure['webfingerSubject'] != "":
        config_dict['webfinger_subject'] = config_gui_structure[
            'webfingerSubject']

    if config_gui_structure['loginHint'] != "":
        config_dict['login_hint'] = config_gui_structure['loginHint']

    if config_gui_structure['uiLocales'] != "":
        config_dict['ui_locales'] = config_gui_structure['uiLocales']

    if config_gui_structure['claimsLocales'] != "":
        config_dict['claims_locales'] = config_gui_structure['claimsLocales']

    if config_gui_structure['acrValues'] != "":
        config_dict['acr_values'] = config_gui_structure['acrValues']

    return config_dict


def handle_post_op_config(response_encoder, parameters, session):
    """
    Saves the data added in the web interface to the session
    :return A default Json structure, which should be ignored
    """
    config_gui_structure = parameters['opConfigurations']
    session["profile"] = generate_profile(config_gui_structure)
    session[OP_CONFIG] = convert_config_gui_structure(config_gui_structure)
    return response_encoder.return_json({})


def handle_does_op_config_exist(session, response_encoder):
    """
    Handles the request checking if the configuration file exists
    :return Returns a dictionary {"doesConfigFileExist" : true} if the
    session contains a config file else {"doesConfigFileExist" : false}
    """
    result = json.dumps({"doesConfigFileExist": (OP_CONFIG in session)})
    return response_encoder.return_json(result)


def handle_download_config_file(session, response_encoder):
    """
    :return Return the configuration file stored in the session
    """
    filedict = json.dumps({"configDict": session[OP_CONFIG]})
    return response_encoder.return_json(filedict)


def handle_upload_config_file(parameters, session, response_encoder):
    """
    Adds a uploaded config file to the session
    :return Default response, should be ignored
    """
    try:
        session[OP_CONFIG] = json.loads(parameters['configFileContent'])
    except ValueError:
        return response_encoder.service_error(
            "Failed to load the configuration file. Make sure the config file "
            "follows the appopriate format")

    return response_encoder.return_json({})


def get_default_client():
    default = importlib.import_module("default_oprp_config")
    return copy.deepcopy(default.CLIENT)


def get_base_url(port):
    return 'https://%s:%d/' % (CONF.HOST, port)

#TODO throws an unhandled exception if swedish chars is used.
def convert_from_unicode(data):
    if isinstance(data, basestring):
        return str(data)
    elif isinstance(data, collections.Mapping):
        return dict(map(convert_from_unicode, data.iteritems()))
    elif isinstance(data, collections.Iterable):
        return type(data)(map(convert_from_unicode, data))
    else:
        return data


def create_module_string(client_config, port):
    _client = copy.deepcopy(client_config)

    base = get_base_url(port)

    _client['client_info'] = {
        "application_type": "web",
        "application_name": "OIC test tool",
        "contacts": ["roland.hedberg@umu.se"],
        "redirect_uris": ["%sauthz_cb" % base],
        "post_logout_redirect_uris": ["%slogout" % base]
    }

    if 'client_registration' in _client:
        del _client['client_info']

    _client['key_export_url'] = "%sexport/jwk_%%s.json" % base
    _client['base_url'] = base

    _client = convert_from_unicode(_client)

    return "from " + CONF.RP_SSL_MODULE + " import *\nPORT = " + str(
        port) + "\nBASE =\'" + str(base) + "\'\nCLIENT = " + str(_client)


class NoPortAvailable(Exception):
    pass


def get_next_free_port(existing_ports, max_port, min_port):
    port = min_port
    while port in existing_ports:
        port += 1
    if port > max_port:
        raise NoPortAvailable(
            "No port is available at the moment, please try again later")
    return port


def create_config_file(port, rp_config_folder):
    with open(rp_config_folder + "rp_conf_" + str(port) + ".py",
              "w") as config_file:
        config_file.write("")
        config_file.close()
        return config_file, port


def save_empty_config_file(min_port, max_port):
    rp_config_folder = CONF.OPRP_DIR_PATH

    if not os.path.exists(rp_config_folder):
        os.makedirs(rp_config_folder)

    existing_ports = []

    for filename in os.listdir(rp_config_folder):
        if filename.startswith("rp_conf"):
            port_as_string = filename.split("_")[2].split(".")[0]
            existing_ports.append(int(port_as_string))

    port = get_next_free_port(existing_ports, max_port, min_port)

    return create_config_file(port, rp_config_folder)


class NoResponseException(Exception):
    pass


def check_if_oprp_started(port, oprp_url=None, timeout=5):
    if not oprp_url:
        oprp_url = get_base_url(port)

    stop_time = datetime.datetime.now() + datetime.timedelta(seconds=timeout)

    while datetime.datetime.now() < stop_time:
        try:
            response = requests.get(oprp_url, verify=False)

            if response.status_code == 200:
                return

            time.sleep(1)
        except ConnectionError:
            pass

    raise NoResponseException("RP (%s) failed to start" % oprp_url)


def start_rp_process(port, command, working_directory=None):
    LOGGER.info("Starting RP on {} with command {}".format(port, command))
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
        raise Exception("Failed to run oprp script: {}".format(ex))

    if retcode is None:
        check_if_oprp_started(port)
    else:
        LOGGER.error("Return code {} != None. Command executed: {}".format(
            retcode, command))
        raise NoResponseException(
            "RP (%s) failed to start" % get_base_url(port))


config_tread_lock = threading.Lock()


def kill_existing_process_on_port(port, session):
    # Check if process is running on specified port
    try:
        response = requests.get(get_base_url(port), verify=False)

        try:
            _ = session[OP_CONFIG]
        except KeyError:
            pass
        else:
            if response.status_code == 200:
                p = subprocess.Popen(['ps', '-A'], stdout=subprocess.PIPE)
                out, err = p.communicate()

                for line in out.splitlines():
                    if "rp_conf_" + str(port) in line:
                        pid = int(line.split(None, 1)[0])
                        os.kill(pid, signal.SIGKILL)
                        break

    except ConnectionError:
        pass


def handle_start_op_tester(session, response_encoder):
    try:
        _config = session[OP_CONFIG]
    except KeyError:
        _config = {}

    if "client_registration" not in _config:
        try:
            config_file, port = allocate_dynamic_port(session)
        except NoPortAvailable:
            return response_encoder.service_error(NO_PORT_ERROR_MESSAGE)
    else:
        config_file, port = create_config_file(session['port'],
                                               CONF.OPRP_DIR_PATH)

    if not port:
        return response_encoder.service_error(NO_PORT_ERROR_MESSAGE)

    config_module = create_module_string(session[OP_CONFIG], port)

    with open(config_file.name, "w") as _file:
        _file.write(config_module)

    kill_existing_process_on_port(port, session)

    config_file_name = os.path.basename(config_file.name)
    config_module = config_file_name.split(".")[0]

    if "oprp_arg" in session:
        oprp_arg = session["profile"]
    else:
        oprp_arg = "C.T.T.ns"

    try:
        start_rp_process(port, [CONF.OPRP_PATH, "-p", oprp_arg, "-t",
                                CONF.OPRP_TEST_FLOW, config_module], "../rp/")
        return response_encoder.return_json(
            json.dumps({"oprp_url": str(get_base_url(port))}))
    except Exception as ex:
        return response_encoder.service_error(ex.message)


def allocate_dynamic_port(session):
    try:
        return session["config_file"], session["dynamic_port"]
    except KeyError:
        pass

    with config_tread_lock:
        config_file, port = save_empty_config_file(CONF.PORT_DYNAMIC_NUM_MIN,
                                                   CONF.PORT_DYNAMIC_NUM_MAX)
        session["dynamic_port"] = port
        session["config_file"] = config_file
        return config_file, port


def allocate_static_port(issuer):
    with config_tread_lock:
        static_ports_db = MySqllite3Dict(CONF.DATABASE_FILE)

        stored_ports = static_ports_db.keys()
        port = get_next_free_port(stored_ports, CONF.PORT_STATIC_NUM_MAX,
                                  CONF.PORT_STATIC_NUM_MIN)

        static_ports_db[port] = issuer
        return port


def handle_create_new_config_file(response_encoder, session):
    session[OP_CONFIG] = get_default_client()
    return response_encoder.return_json("{}")


def handle_get_redirect_url(session, response_encoder, parameters):
    issuer = parameters['issuer']
    static_ports_db = MySqllite3Dict(CONF.DATABASE_FILE)

    port = None

    if issuer not in static_ports_db.values():
        try:
            port = allocate_static_port(issuer)
        except NoPortAvailable as ex:
            LOGGER.fatal(ex.message)
            return response_encoder.service_error(ex.message)

    if not port:
        for port in static_ports_db.keys():
            if static_ports_db[port] == issuer:
                break

    session['port'] = port

    redirect_url = get_base_url(port) + "authz_cb"

    return response_encoder.return_json(
        json.dumps({"redirect_url": redirect_url}))


def application(environ, start_response):
    path = environ.get('PATH_INFO', '').lstrip('/')
    LOGGER.info("Connection from: %s" % environ["REMOTE_ADDR"])
    LOGGER.info("path: %s" % path)

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

    if path == "post_op_config":
        return handle_post_op_config(response_encoder, parameters, session)

    if path == "does_op_config_exist":
        return handle_does_op_config_exist(session, response_encoder)

    if path == "download_config_file":
        return handle_download_config_file(session, response_encoder)

    if path == "upload_config_file":
        return handle_upload_config_file(parameters, session, response_encoder)

    if path == "start_op_tester":
        return handle_start_op_tester(session, response_encoder)

    if path == "get_redirect_url":
        return handle_get_redirect_url(session, response_encoder, parameters)

    return http_helper.http404()


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

    SERVER_ENV.update({"template_lookup": LOOKUP, "base_url": CONF.BASE})

    setup_logging("config_server.log")

    SRV = wsgiserver.CherryPyWSGIServer(('0.0.0.0', CONF.PORT),
                                        SessionMiddleware(application,
                                                          session_opts))

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