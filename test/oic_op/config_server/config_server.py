#!/usr/bin/env python
# -*- coding: utf-8 -*-

import collections
import copy
import importlib
import json
import os
import ast
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
from requests.exceptions import ConnectionError
from response_encoder import ResponseEncoder
from oic.oauth2.message import REQUIRED_LIST_OF_SP_SEP_STRINGS
from oic.oauth2.message import OPTIONAL_LIST_OF_STRINGS
from oic.oauth2.message import OPTIONAL_LIST_OF_SP_SEP_STRINGS
from oic.oauth2.message import REQUIRED_LIST_OF_STRINGS
from oic.oic.message import ProviderConfigurationResponse
from oic.utils.http_util import NotFound
from oic.utils.http_util import Response
from port_database import PortDatabase, NoPortAvailable


LOGGER = logging.getLogger("")
urllib3_logger = logging.getLogger('requests.packages.urllib3')
urllib3_logger.setLevel(logging.WARNING)

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
    static_input_fields_list = _generate_static_input_fields()
    op_configurations = {
        "fetchInfoFromServerDropDown": {
            "name": "Does the OP have a .well-known/openid-configuration endpoint?",
            "value": "",
            "values": [{"type": "dynamic", "name": "yes"},
                       {"type": "static", "name": "no"}]
        },
        "fetchStaticProviderInfo": {"showInputFields": False,
                                    "input_fields": static_input_fields_list},
        "fetchDynamicInfoFromServer": {"showInputField": False,
                                       "input_field": {"label": "What is the issuer path for this configuration information? *",
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
            "label": "Which response type do you want to use by default?: ",
            "value": "public",
            "values": [{"type": "public", "name": "public"},
                       {"type": "pairwise", "name": "pairwise"}]
        },
        "webfingerSubject": "",
        "loginHint": "",
        "uiLocales": "",
        "claimsLocales": "",
        "acrValues": "",
        "webfinger_url": "",
        "webfinger_email": ""
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


def convert_instance(_is_list, default_input_value):
    if _is_list:
        if isinstance(default_input_value, list):
            field_value = convert_to_value_list(default_input_value)
        else:
            field_value = convert_to_value_list([default_input_value])
    else:
        field_value = default_input_value
    return field_value


def _generate_static_input_fields(default_input_value=[]):
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
        _is_list = is_pyoidc_message_list(_field_type)

        field_value = convert_instance(_is_list, default_input_value)

        config_field = {'id': _field_label,
                        'label': _field_label,
                        'values': field_value,
                        'show': False,
                        'required': False,
                        'isList': _is_list}
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


def convert_to_gui_drop_down(config_file_dict):
    gui_list = []
    for element in config_file_dict:
        gui_list.append({"type": element, "name": element})
    return gui_list

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

    if "webfinger_url" in config_file_dict:
        config_structure_dict['webfinger_url'] = config_file_dict['webfinger_url']

    if "webfinger_email" in config_file_dict:
        config_structure_dict['webfinger_email'] = config_file_dict['webfinger_email']

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


def static_provider_info_to_config_file_dict(config_gui_structure,
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


def client_registration_to_config_file_dict(config_gui_structure,
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


def clear_config_keys(config_dict):
    optional_fields = ['webfinger_subject',
                       'login_hint',
                       'sub_claim',
                       'ui_locales',
                       'claims_locales',
                       'acr_values',
                       'provider_info',
                       'srv_discovery_url',
                       'webfinger_url',
                       'webfinger_email']

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

def set_dynamic_discovery_issuer_config_gui_structure(issuer, config_gui_structure, show_field=True):
    config_gui_structure['fetchDynamicInfoFromServer']['showInputField'] = show_field
    config_gui_structure['fetchDynamicInfoFromServer']['input_field']['value'] = issuer
    return config_gui_structure

def contains_dynamic_discovery_info(config_gui_structure):
    return config_gui_structure['fetchDynamicInfoFromServer']['showInputField'] is True

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

class NoMatchException(Exception):
    pass

def convert_to_simple_list(config_gui_structure):
    simple_list = []

    for element in config_gui_structure:
        simple_list.append(element['name'])

    return simple_list

def parse_config_string(config_string):
    client = config_string.split('\n')[3]
    dict = client.split("CLIENT = ")[1]
    return ast.literal_eval(dict)

def identify_existing_config_file(port):
    for filename in os.listdir(CONF.OPRP_DIR_PATH):
        if filename.startswith("rp_conf"):
            file_port = int(filename.split("_")[2].split(".")[0])
            if file_port == port:
                with open(CONF.OPRP_DIR_PATH + filename,"r") as config_file:
                    config_string = config_file.read()
                    if config_string == "":
                        break
                    return parse_config_string(config_string)

    raise NoMatchException("No match found for port: %s" % port)

def create_key_dict_pair_if_non_exist(key, dict):
    if key not in dict:
        dict[key] = {}
    return dict

def subject_type_to_config_file_dict(config_dict, config_gui_structure):
    config_dict = create_key_dict_pair_if_non_exist('preferences', config_dict)
    config_dict['preferences']['subject_type'] = \
        config_gui_structure["clientSubjectType"]["value"]
    return config_dict


def profile_to_config_file_dict(config_dict, config_gui_structure):
    config_dict = create_key_dict_pair_if_non_exist('behaviour', config_dict)
    config_dict['behaviour']['profile'] = generate_profile(config_gui_structure)
    return config_dict

CONFIG_DICT_INSTANCE_ID_KEY = 'instance_id'

def convert_config_gui_structure(config_gui_structure, port, instance_id):
    """
    Converts the internal data structure to a dictionary which follows the
    "Configuration file structure", see setup.rst
    :param config_gui_structure: Data structure used to hold and show
    configuration information in the Gui
    :return A dictionary which follows the "Configuration file structure",
    see setup.rst
    """
    try:
        config_dict = identify_existing_config_file(port)
    except NoMatchException:
        config_dict = get_default_client()

    config_dict = clear_config_keys(config_dict)
    config_dict[CONFIG_DICT_INSTANCE_ID_KEY] = instance_id

    if contains_dynamic_discovery_info(config_gui_structure):
        dynamic_input_field_value = config_gui_structure['fetchDynamicInfoFromServer']\
                                                        ['input_field']\
                                                        ['value']
        config_dict['srv_discovery_url'] = dynamic_input_field_value

    elif config_gui_structure['fetchStaticProviderInfo']['showInputFields']:
        config_dict = static_provider_info_to_config_file_dict(config_gui_structure,
                                                           config_dict)

    config_dict = client_registration_to_config_file_dict(config_gui_structure,config_dict)
    config_dict = subject_type_to_config_file_dict(config_dict, config_gui_structure)
    config_dict = profile_to_config_file_dict(config_dict, config_gui_structure)

    if config_gui_structure['webfingerSubject'] != "":
        config_dict['webfinger_subject'] = config_gui_structure['webfingerSubject']

    if config_gui_structure['loginHint'] != "":
        config_dict['login_hint'] = config_gui_structure['loginHint']

    if config_gui_structure['uiLocales'] != "":
        config_dict['ui_locales'] = config_gui_structure['uiLocales']

    if config_gui_structure['claimsLocales'] != "":
        config_dict['claims_locales'] = config_gui_structure['claimsLocales']

    if config_gui_structure['acrValues'] != "":
        config_dict['acr_values'] = config_gui_structure['acrValues']

    if config_gui_structure['webfinger_url'] != "":
        config_dict['webfinger_url'] = config_gui_structure['webfinger_url']

    if config_gui_structure['webfinger_email'] != "":
        config_dict['webfinger_email'] = config_gui_structure['webfinger_email']

    return config_dict

def handle_request_instance_ids(response_encoder, parameters):
    config_gui_structure = parameters['opConfigurations']
    issuer = get_issuer_from_gui_config(config_gui_structure)
    port_db = PortDatabase(CONF.STATIC_CLIENT_REGISTRATION_PORTS_DATABASE_FILE)
    instance_ids = port_db.get_instance_ids(issuer)

    existing_instance_ids = {}
    if len(instance_ids) > 0:
        existing_instance_ids['value'] = instance_ids[0]

    existing_instance_ids['values'] = convert_to_gui_drop_down(instance_ids)

    return response_encoder.return_json(json.dumps(existing_instance_ids))


def handle_does_op_config_exist(session, response_encoder):
    """
    Handles the request checking if the configuration file exists
    :return Returns a dictionary {"does_config_file_exist" : true} if the
    session contains a config file else {"does_config_file_exist" : false}
    """
    result = json.dumps({"does_config_file_exist": (OP_CONFIG in session)})
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
    return 'https://%s:%d/' % (CONF.HOST, int(port))

#TODO throws an unhandled exception if swedish chars is used.
def convert_from_unicode(data):
    if isinstance(data, basestring):
        try:
            return str(data)
        except UnicodeEncodeError as ex:
            return data.encode('utf8')
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

    return "from " + CONF.OPRP_SSL_MODULE + " import *\nPORT = " + str(
        port) + "\nBASE =\'" + str(base) + "\'\nCLIENT = " + str(_client)


def get_config_file_path(port, rp_config_folder):
    return rp_config_folder + "rp_conf_" + str(port) + ".py"


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
                LOGGER.debug("The RP is running on port: %s and returning status code 200 OK" % port)
                return

            time.sleep(1)
        except ConnectionError:
            pass

    raise NoResponseException("RP (%s) failed to start" % oprp_url)


def start_rp_process(port, command, working_directory=None):
    LOGGER.debug("Try to start RP on {} with command {}".format(port, command))
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

def get_oprp_pid(port):
    pid = None
    p = subprocess.Popen(['ps', '-A'], stdout=subprocess.PIPE)
    out, err = p.communicate()
    for line in out.splitlines():
        if "rp_conf_" + str(port) in line:
            pid = int(line.split(None, 1)[0])
            break

    return pid


def kill_existing_process_on_port(port):

    pid = get_oprp_pid(port)

    if pid:
        try:
            os.kill(pid, signal.SIGKILL)
            LOGGER.debug("Killed RP running on port %s" % port)
        except OSError as ex:
            LOGGER.error("Failed to kill process (%s) connected to the server %s" % (pid, get_base_url(port)))
            raise


def write_config_file(config_file_name, config_module):
    with open(config_file_name, "w") as _file:
        _file.write(config_module)

def is_using_dynamic_client_registration(config_gui_structure):
    return config_gui_structure['dynamicClientRegistrationDropDown']['value'] == "yes"

def get_issuer_from_config_file(config_file):
    try:
        return config_file['srv_discovery_url']
    except KeyError:
        return config_file['provider_info']['issuer']

def find_static_provider_info_field(input_fields, fields_id):
    for input_field in input_fields:
        if input_field['id'] == fields_id:
            return input_field


def get_issuer_from_gui_config(gui_config):
    if contains_dynamic_discovery_info(gui_config):
        dynamic_disco_issuer = gui_config['fetchDynamicInfoFromServer']['input_field']['value']
        return dynamic_disco_issuer
    else:
        input_fields = gui_config['fetchStaticProviderInfo']['input_fields']
        issuer_field = find_static_provider_info_field(input_fields, "issuer")
        return issuer_field['values']

def handle_start_op_tester(session, response_encoder, parameters):
    config_gui_structure = parameters['op_configurations']
    _profile = generate_profile(config_gui_structure)
    _instance_id = parameters['oprp_instance_id']

    if is_using_dynamic_client_registration(config_gui_structure):
        try:
            issuer = get_issuer_from_gui_config(config_gui_structure)
            port = allocate_dynamic_port(issuer, _instance_id)
        except NoPortAvailable:
            pass
    else:
        port = session['port']

    if not port:
        LOGGER.error(NO_PORT_ERROR_MESSAGE)
        return response_encoder.service_error(NO_PORT_ERROR_MESSAGE)

    LOGGER.debug("The RP will try to start on port: %s" % port)
    config_file_path = get_config_file_path(port,
                                            CONF.OPRP_DIR_PATH)

    session[OP_CONFIG] = convert_config_gui_structure(config_gui_structure, port, _instance_id)
    config_module = create_module_string(session[OP_CONFIG], port)

    try:
        write_config_file(config_file_path, config_module)
        LOGGER.debug("Written configuration to file: %s" % config_file_path)
    except IOError as ioe:
        LOGGER.exception(str(ioe))
        response_encoder.service_error("Failed to write configurations file (%s) to disk. Please contact technical support" % config_file_path)

    kill_existing_process_on_port(port)

    config_file_name = os.path.basename(config_file_path)
    config_module = config_file_name.split(".")[0]

    try:
        start_rp_process(port, [CONF.OPRP_PATH, "-p", _profile, "-t",
                                CONF.OPRP_TEST_FLOW, config_module], "../rp/")
        return response_encoder.return_json(
            json.dumps({"oprp_url": str(get_base_url(port))}))
    except Exception as ex:
        LOGGER.error(ex.message)
        return response_encoder.service_error(ex.message)


def get_port_from_database(issuer, instance_id, min_port, max_port, port_type):
    port_db = PortDatabase(CONF.STATIC_CLIENT_REGISTRATION_PORTS_DATABASE_FILE)
    return port_db.enter_row(issuer, instance_id, port_type, min_port, max_port)


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
    try:
        port = allocate_static_port(parameters['issuer'], parameters["oprp_instance_id"])
    except NoPortAvailable as ex:
        LOGGER.fatal(ex.message)
        return response_encoder.service_error(ex.message)

    session['port'] = port

    redirect_url = get_base_url(port) + "authz_cb"

    return response_encoder.return_json(
        json.dumps({"redirect_url": redirect_url}))


def application(environ, start_response):
    path = environ.get('PATH_INFO', '').lstrip('/')
    LOGGER.info("Connection from: %s" % environ["REMOTE_ADDR"])
    LOGGER.info("Path: %s" % path)

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
        return handle_download_config_file(session, response_encoder)

    if path == "upload_config_file":
        return handle_upload_config_file(parameters, session, response_encoder)

    if path == "start_op_tester":
        return handle_start_op_tester(session, response_encoder, parameters)

    if path == "get_redirect_url":
        return handle_get_redirect_url(session, response_encoder, parameters)

    if path == "request_instance_ids":
        return handle_request_instance_ids(response_encoder, parameters)

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