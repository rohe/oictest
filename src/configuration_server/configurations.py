#!/usr/bin/env python
# -*- coding: utf-8 -*-
import importlib
import logging
import os
import re
import collections
import copy
import shutil
import datetime
import time
import traceback
import uuid

from oic.oauth2.message import REQUIRED_LIST_OF_SP_SEP_STRINGS
from oic.oauth2.message import OPTIONAL_LIST_OF_STRINGS
from oic.oauth2.message import OPTIONAL_LIST_OF_SP_SEP_STRINGS
from oic.oauth2.message import REQUIRED_LIST_OF_STRINGS
from oic.oic.message import ProviderConfigurationResponse
from configuration_server.config_values import CONFIG_FILE_KEYS, GUI_CONFIG_STRUCTURE_KEYS

from configuration_server.response_encoder import ResponseEncoder


__author__ = 'danielevertsson'

CONFIG_DICT_INSTANCE_ID_KEY = 'instance_id'
LOGGER = logging.getLogger("configuration_server.configuration")


class UnKnownResponseTypeAbbreviation(Exception):
    pass


class GuiConfig:

    def __init__(self, gui_config_structure=None):

        if not gui_config_structure:
            gui_config_structure = create_new_configuration_dict()

        self.config_structure = gui_config_structure

    def get_dynamic_discovery_issuer(self):
        return self.config_structure['fetchDynamicInfoFromServer']['input_field']['value']

    def set_dynamic_discovery_issuer(self, issuer):
        self.config_structure['fetchDynamicInfoFromServer']['input_field']['value'] = issuer

    def set_dynamic_discovery_visibility(self, visible):
        self.config_structure['fetchDynamicInfoFromServer']['showInputField'] = visible

    def get_static_discovery_issuer(self):
        input_fields = self.config_structure['fetchStaticProviderInfo']['input_fields']
        issuer_field = find_static_provider_info_field(input_fields, "issuer")
        return issuer_field['values']

    def set_static_discovery_issuer(self, issuer):
        input_fields = self.config_structure['fetchStaticProviderInfo']['input_fields']
        issuer_field = find_static_provider_info_field(input_fields, "issuer")
        issuer_field['values'] = issuer


def get_config_file_path(port, rp_config_folder):
    if not rp_config_folder.endswith("/"):
        rp_config_folder += "/"
    return rp_config_folder + generate_config_module_name(port)


def parse_crypto_feature_abbreviation(config_gui_structure):
    arg = ""
    for feature in config_gui_structure['signingEncryptionFeaturesCheckboxes']['features']:
        if feature['selected']:
            arg += feature['abbreviation']
    return arg


def convert_dynamic_client_registration_to_abbreviation(config_gui_structure):
    if config_gui_structure['dynamicClientRegistrationDropDown']['value'] == "yes":
        return "T"
    return "F"


def convert_dynamic_discovery_to_abbreviation(config_gui_structure):
    if contains_dynamic_discovery_info(config_gui_structure):
        return "T"
    return "F"


def convert_response_type_to_abbreviation(response_type):
    abbreviations_dict = {
        "code": "C",
        "id_token": "I",
        "id_token token": "IT",
        "code id_token": "CI",
        "code token": "CT",
        "code id_token token": "CIT"
    }

    return abbreviations_dict[response_type]


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

    profile = "%s.%s.%s.%s." % (response_type_abbr,
                                dynamic_discovery_abbr,
                                dynamic_client_registration_abbr,
                                crypto_features_abbr)

    return profile


def load_config_module(module):
    test_conf = importlib.import_module(module)
    try:
        return test_conf.CLIENT
    except AttributeError as ex:
        raise AttributeError("Module (%s) has no attribute 'CLIENT'" % module)


def identify_existing_config_file(port, oprp_dir_path):
    files = [f for f in os.listdir(oprp_dir_path)]
    config_file_pattern = re.compile("rp_conf_[0-9]+.py$")

    for filename in files:
        if config_file_pattern.match(filename):
            module = filename[:-3]
            file_port = int(module.split("_")[2])
            if file_port == port:
                return load_config_module(module)
    return None


def generate_config_module_name(port, file_extension=".py"):
    return "rp_conf_" + str(port) + file_extension


def backup_existing_config_file(config_file_path, oprp_dir_path, port):
    if not oprp_dir_path.endswith("/"):
        oprp_dir_path += "/"
    backup_dir = oprp_dir_path + "config_backup"
    try:
        os.makedirs(backup_dir)
    except OSError:
        pass
    time_stamp = datetime.datetime.fromtimestamp(time.time()).strftime('%Y%m%d_%H.%M.%S')
    config_file_name = generate_config_module_name(port)
    backup_file = os.path.join(backup_dir, config_file_name + "_" + time_stamp)

    try:
        shutil.copy(config_file_path, backup_file)
    except:
        LOGGER.debug("Failed to make a backup of config file: %s" % config_file_path)
        pass


def write_config_file(config_file_path, config_module, port, oprp_dir_path="."):
    backup_existing_config_file(config_file_path, oprp_dir_path, port)

    with open(config_file_path, "w") as _file:
        _file.write(config_module)


def convert_to_uft8(data):
    if isinstance(data, basestring):
        try:
            return str(data)
        except UnicodeEncodeError as ex:
            return data.encode('utf8')
    elif isinstance(data, collections.Mapping):
        return dict(map(convert_to_uft8, data.iteritems()))
    elif isinstance(data, collections.Iterable):
        return type(data)(map(convert_to_uft8, data))
    else:
        return data


def create_module_string(client_config, port, base_url, conf=None, ssl_module=None):
    _client = copy.deepcopy(client_config)

    if not ssl_module:
        ssl_module = conf.OPRP_SSL_MODULE

    _client['client_info'] = {
        "application_type": "web",
        "application_name": "OIC test tool",
        "contacts": ["roland.hedberg@umu.se"],
        "redirect_uris": ["%sauthz_cb" % base_url],
        "post_logout_redirect_uris": ["%slogout" % base_url]
    }

    if 'client_registration' in _client:
        del _client['client_info']

    _client['key_export_url'] = "%sexport/jwk_%%s.json" % base_url
    _client['base_url'] = base_url

    _client = convert_to_uft8(_client)

    return "from " + ssl_module + " import *\nPORT = " + str(
        port) + "\nBASE =\'" + str(base_url) + "\'\nCLIENT = " + str(_client)


def get_default_client():
    default = importlib.import_module("configuration_server.default_oprp_config")
    return copy.deepcopy(default.CLIENT)


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


def convert_to_list(value_dict):
    _list = []
    for element in value_dict:
        _list.append(element['value'])

    return _list


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

    for input_field in config_gui_structure['fetchStaticProviderInfo']['input_fields']:
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
        for attribute in config_gui_structure['supportsStaticClientRegistrationTextFields']:
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


class UserFriendlyException(Exception):
    def __init__(self, message, log_info=None, show_trace=True):
        super(UserFriendlyException, self).__init__(message)
        self.log_info = log_info
        self.show_trace = show_trace


def log_exception(event_id, exception):
    logged_exception = type(exception)("[" + event_id + "] " + exception.message)
    LOGGER.exception(str(logged_exception))


def handle_exception(exception, response_encoder, message="", failed_to_message=""):
    if failed_to_message:
        message = "Failed to %s. Please contact technical support." % failed_to_message

    event_id = str(uuid.uuid4())

    if isinstance(exception, UserFriendlyException):
        if exception.show_trace:
            log_exception(event_id, exception)
    else:
        log_exception(event_id, exception)

    print(traceback.format_exc())
    if response_encoder:
        if isinstance(exception, UserFriendlyException):
            if exception.log_info:
                LOGGER.error("[" + event_id + "] " + exception.log_info)
            return response_encoder.service_error(exception.message, event_id=event_id)
        LOGGER.error("[" + event_id + "] " + message)
        return response_encoder.service_error(message, event_id=event_id)
    return None


def does_configuration_exists(port_database, issuer, instance_id, conf):
    port = port_database.get_port(issuer=issuer, instance_id=instance_id)
    config = port_database.get_configuration(issuer=issuer, instance_id=instance_id)

    try:
        config = identify_existing_config_file(port, conf.OPRP_DIR_PATH)
    except Exception as ex:
        handle_exception(ex, None)

    return config is not None


def convert_config_gui_structure(config_gui_structure, port, instance_id,
                                 is_port_in_database, conf):
    """
    Converts the internal data structure to a dictionary which follows the
    "Configuration file structure", see setup.rst
    :param config_gui_structure: Data structure used to hold and show
    configuration information in the Gui
    :return A dictionary which follows the "Configuration file structure",
    see setup.rst
    """
    try:
        config_dict = identify_existing_config_file(port, conf.OPRP_DIR_PATH)
    except Exception as ex:
        handle_exception(ex, None)

    if not is_port_in_database and config_dict:
        file_path = get_config_file_path(port, conf.OPRP_DIR_PATH)
        LOGGER.error("The identified configuration file does not exist in the database. "
                     "File path: %s" % file_path)

    if not (is_port_in_database and config_dict):
        config_dict = get_default_client()

    config_dict = clear_config_keys(config_dict)

    if instance_id:
        config_dict[CONFIG_DICT_INSTANCE_ID_KEY] = instance_id

    if contains_dynamic_discovery_info(config_gui_structure):
        gui_config = GuiConfig(config_gui_structure)
        config_dict['srv_discovery_url'] = gui_config.get_dynamic_discovery_issuer()

    elif config_gui_structure['fetchStaticProviderInfo']['showInputFields']:
        config_dict = static_provider_info_to_config_file_dict(config_gui_structure,
                                                               config_dict)

    config_dict = client_registration_to_config_file_dict(config_gui_structure, config_dict)
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


def find_static_provider_info_field(input_fields, fields_id):
    for input_field in input_fields:
        if input_field['id'] == fields_id:
            return input_field


def contains_dynamic_discovery_info(config_gui_structure):
    return config_gui_structure['fetchDynamicInfoFromServer']['showInputField'] is True


def get_issuer_from_gui_config(gui_config_structure):
    issuer = None

    gui_config = GuiConfig(gui_config_structure)

    if contains_dynamic_discovery_info(gui_config_structure):
        issuer = gui_config.get_dynamic_discovery_issuer()
    else:
        issuer = gui_config.get_static_discovery_issuer()

    if issuer.endswith("/"):
        issuer = issuer[:-1]

    return issuer


def is_using_dynamic_client_registration(config_gui_structure):
    return config_gui_structure['dynamicClientRegistrationDropDown']['value'] == "yes"


def set_dynamic_discovery_issuer_config_gui_structure(issuer,
                                                      config_gui_structure,
                                                      show_field=True):
    gui_config = GuiConfig(config_gui_structure)
    gui_config.set_dynamic_discovery_visibility(show_field)
    gui_config.set_dynamic_discovery_issuer(issuer)
    return gui_config.config_structure


def convert_to_gui_drop_down(config_file_dict):
    gui_list = []
    for element in config_file_dict:
        gui_list.append({"type": element, "name": element})
    return gui_list


def convert_abbreviation_to_response_type(response_type_abbreviation):
    response_types = {
        "C": "code",
        "I": "id_token",
        "IT": "id_token token",
        "CI": "code id_token",
        "CT": "code token",
        "CIT": "code id_token token"
    }
    try:
        return response_types[response_type_abbreviation]
    except KeyError:
        raise UnKnownResponseTypeAbbreviation(
            "The supplied response type abbreviation (%s) is not recognized"
            % response_type_abbreviation)


def parse_profile(profile):
    if not isinstance(profile, basestring):
        raise ValueError("profile value of wrong type")

    _args = profile.split(".")

    response_type = convert_abbreviation_to_response_type(_args[0])
    crypto_feature_support = _args[3]

    return response_type, crypto_feature_support


def set_feature_list(config_structure_dict, oprp_arg):
    feature_list = config_structure_dict['signingEncryptionFeaturesCheckboxes'][
        'features']

    for feature in feature_list:
        feature['selected'] = feature['abbreviation'] in oprp_arg


def set_test_specific_request_parameters(config_file_dict, config_structure_dict):
    for (key, value) in CONFIG_FILE_KEYS.iteritems():
        if value in config_file_dict:
            gui_config_key = GUI_CONFIG_STRUCTURE_KEYS[key]
            config_structure_dict[gui_config_key] = config_file_dict[value]
    return config_structure_dict


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

    config_structure_dict = set_test_specific_request_parameters(config_file_dict,
                                                                 config_structure_dict)

    return config_structure_dict


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
    gui_config = GuiConfig(config_gui_structure)
    gui_config.set_dynamic_discovery_visibility(True)
    gui_config.set_dynamic_discovery_issuer(config_file_dict["srv_discovery_url"])
    return gui_config.config_structure


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

        for text_field in config_gui_structure["supportsStaticClientRegistrationTextFields"]:
            if text_field["id"] == "client_id":
                text_field["textFieldContent"] = \
                    config_file_dict["client_registration"]["client_id"]

    if "client_secret" in config_file_dict["client_registration"]:
        supports_dynamic_client_registration = True
        config_gui_structure["dynamicClientRegistrationDropDown"][
            "value"] = "no"

        for text_field in config_gui_structure["supportsStaticClientRegistrationTextFields"]:
            if text_field["id"] == "client_secret":
                text_field["textFieldContent"] = \
                    config_file_dict["client_registration"]["client_secret"]

    if not supports_dynamic_client_registration:
        config_gui_structure["dynamicClientRegistrationDropDown"][
            "value"] = "yes"

    return config_gui_structure


def is_list_instance(element):
    return not isinstance(element, basestring)


def convert_to_value_list(elements):
    value_list = []
    for element in elements:
        value_list.append({"value": element})

    return value_list


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
        for input_field in config_gui_structure["fetchStaticProviderInfo"]["input_fields"]:
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


def get_issuer_from_config_file(config_file):
    try:
        return config_file['srv_discovery_url']
    except KeyError:
        return config_file['provider_info']['issuer']


def _generate_static_input_fields(default_input_value=None):
    """
    Generates all static input fields based on ProviderConfigurationResponse
    class localed in [your path]/pyoidc/scr/oic/oic/message.py

    :return:The static input fields presented as the internal data structure
    """
    if default_input_value is None:
        default_input_value = []

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


def set_issuer(issuer, gui_config_structure):
    gui_config = GuiConfig(gui_config_structure)
    gui_config.set_static_discovery_issuer(issuer)
    gui_config.set_dynamic_discovery_issuer(issuer)
    return gui_config.config_structure


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
                                       "input_field": {
                                           "label": "What is the issuer path for this "
                                                    "configuration information? *",
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
            "label": "Which response type should be used by default?",
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
                {"name": 'JWT signed with algorithm other than "none"',
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
            "label": "Which subject type do you want to use by default?: ",
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
