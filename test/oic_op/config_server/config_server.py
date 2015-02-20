#!/usr/bin/env python
import collections
import copy
import importlib
import json
import os
import threading
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
                                    "inputFields": static_input_fields_list},
        "fetchDynamicInfoFromServer": {"showInputField": False,
                                       "inputField": {"label": "Issuer url *",
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
                 "selected": False, "argument": "n"},
                {"name": 'JWT signed with algorithm other then "None"',
                 "selected": False, "argument": "s"},
                {"name": 'Encrypted JWT', "selected": False, "argument": "e"}
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
        # Since angular js needs objects to use in ng-model the subClaim
        # elements looks like this ['claim', 'value']
        "subClaim": [],
        # Since angular js needs objects to use in ng-model the list elements
        # uses elements like this {"value": ""}
        "uiLocales": [],
        "claimsLocales": [],
        "acrValues": [],
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


def convertDynamicProviderData(configFileDict, configGuiStructure):
    """
    Converts the configuration file structure to the Internal data structure
    :param configGuiStructure: Data structure used to hold and show
    configuration information in the Gui
    :param configFileDict: Internal data structure containing all info
    gathered in the web interface
    :return The updated presentation of the internal data structure
    """
    configGuiStructure["fetchInfoFromServerDropDown"]["value"] = "dynamic"
    configGuiStructure["fetchDynamicInfoFromServer"]["showInputField"] = True
    configGuiStructure["fetchDynamicInfoFromServer"]["inputField"]["value"] = \
    configFileDict["srv_discovery_url"]

    return configGuiStructure


def isListInstance(element):
    return not isinstance(element, basestring)


def convertStaticProviderInfoToGui(configFileDict, configGuiStructure):
    """
    Converts a static provider from config file to a gui structure
    :param configGuiStructure: Data structure used to hold and show
    configuration information in the Gui
    :param configFileDict: The configuration file from which the
    configuration static provider data should be gathered
    :return The updated configuration GUI data structure
    """
    PROVIDER_INFO_KEY = "provider_info"

    configGuiStructure["fetchInfoFromServerDropDown"]["value"] = "static"
    configGuiStructure["fetchStaticProviderInfo"]["showInputFields"] = True

    for inputFieldId in configFileDict[PROVIDER_INFO_KEY]:
        for inputField in configGuiStructure["fetchStaticProviderInfo"][
            "inputFields"]:
            if inputField['id'] == inputFieldId:
                inputField['show'] = True
                attributeValue = configFileDict[PROVIDER_INFO_KEY][inputFieldId]

                if isListInstance(attributeValue):
                    inputField['values'] = convertToValueList(attributeValue)
                else:
                    inputField['values'] = attributeValue

    return configGuiStructure


def containElements(any_structure):
    return any_structure


def convertClientRegistrationSupported(configFileDict, configGuiStructure):
    """
    Converts a required information from config file to a config GUI structure
    :param configGuiStructure: Data structure used to hold and show
    configuration information in the Gui
    :param configFileDict: The configuration file from which the
    configuration required information data should be gathered
    :return The updated configuration GUI data structure
    """
    supportsDynamicClientRegistration = False

    if "client_registration" not in configFileDict:
        return configGuiStructure

    if "client_id" in configFileDict["client_registration"]:
        supportsDynamicClientRegistration = True
        configGuiStructure["dynamicClientRegistrationDropDown"]["value"] = "no"

        for textFiled in configGuiStructure[
            "supportsStaticClientRegistrationTextFields"]:
            if textFiled["id"] == "client_id":
                textFiled["textFieldContent"] = \
                configFileDict["client_registration"]["client_id"]

    if "client_secret" in configFileDict["client_registration"]:
        supportsDynamicClientRegistration = True
        configGuiStructure["dynamicClientRegistrationDropDown"]["value"] = "no"

        for textFiled in configGuiStructure[
            "supportsStaticClientRegistrationTextFields"]:
            if textFiled["id"] == "client_secret":
                textFiled["textFieldContent"] = \
                configFileDict["client_registration"]["client_secret"]

    if not supportsDynamicClientRegistration:
        configGuiStructure["dynamicClientRegistrationDropDown"]["value"] = "yes"

    return configGuiStructure


def convertSubClaimsToLists(subClaims):
    lists = []

    if 'value' in subClaims:
        lists.append({"value": subClaims['value']})

    elif "values" in subClaims:
        for element in subClaims['values']:
            lists.append({"value": element})

    return lists


def convertToValueList(list):
    valueList = []
    for element in list:
        valueList.append({"value": element})

    return valueList


def setFeatureList(configStructureDict, oprp_arg):
    feature_list = configStructureDict['signingEncryptionFeaturesCheckboxes'][
        'features']

    for feature in feature_list:
        if feature['argument'] in oprp_arg:
            feature['selected'] = True
        else:
            feature['selected'] = False


def convertToConfigGuiStructure(configFileDict):
    """
    Converts a config file structure to a config GUI structure
    :param configFileDict: The configuration file from which should be converted
    :return The updated configuration GUI data structure
    """
    configStructureDict = create_new_configuration_dict()

    if "srv_discovery_url" in configFileDict:
        configStructureDict = convertDynamicProviderData(configFileDict,
                                                         configStructureDict)

    elif "provider_info" in configFileDict:
        # Now we know it's an static provider
        configStructureDict = convertStaticProviderInfoToGui(configFileDict,
                                                             configStructureDict)

    configStructureDict = convertClientRegistrationSupported(configFileDict,
                                                             configStructureDict)

    configStructureDict['clientSubjectType']['value'] = \
    configFileDict['preferences']['subject_type']

    configStructureDict['responseTypeDropDown']['value'] = \
    configFileDict['behaviour']['response_type']

    if 'oprp_arg' in configFileDict:
        setFeatureList(configStructureDict, configFileDict['oprp_arg'])

    if 'webfinger_subject' in configFileDict:
        configStructureDict['webfingerSubject'] = configFileDict[
            'webfinger_subject']

    if 'login_hint' in configFileDict:
        configStructureDict['loginHint'] = configFileDict['login_hint']

    if "sub_claim" in configFileDict:
        configStructureDict['subClaim'] = convertSubClaimsToLists(
            configFileDict['sub_claim'])

    if "ui_locales" in configFileDict:
        configStructureDict['uiLocales'] = convertToValueList(
            configFileDict['ui_locales'])

    if "claims_locales" in configFileDict:
        configStructureDict['claimsLocales'] = convertToValueList(
            configFileDict['claims_locales'])

    if "acr_values" in configFileDict:
        configStructureDict['acrValues'] = convertToValueList(
            configFileDict['acr_values'])

    return configStructureDict


def handle_get_op_config(session, response_encoder):
    """
    Handles the get config Gui structure request
    :return A configuration Gui structure which is based on the configuration
    file saved in the session
    """
    if OP_CONFIG in session:

        try:
            op_config = session[OP_CONFIG]
        except KeyError:
            op_config = None

        if not isinstance(op_config, dict):
            return response_encoder.serviceError(
                "No JSON object could be decoded. Please check if the file is "
                "a valid json file")

        configGuiStructure = convertToConfigGuiStructure(op_config)
        return response_encoder.returnJSON(json.dumps(configGuiStructure))

    return response_encoder.serviceError(
        "No file saved in this current session")


def convertStaticProviderInfoToFile(configGuiStructure, configFileDict):
    """
    Converts static information in the internal data structure and updates
    the configDict
    which follows the "Configuration file structure", see setup.rst
    :param configGuiStructure: Data structure used to hold and show
    configuration information in the Gui
    :param configFileDict: configuration dictionary which follows the
    "Configuration file structure"
    :return Configuration dictionary updated with the new static information
    """
    visibleInputFieldList = []
    providerAttributeDict = {}

    for inputField in configGuiStructure['fetchStaticProviderInfo'][
        'inputFields']:
        if inputField['show'] == True:
            visibleInputFieldList.append(inputField)

    for inputField in visibleInputFieldList:
        attributId = inputField['id']

        if inputField['isList']:
            providerAttributeDict[attributId] = convertToList(
                inputField['values'])
        else:
            providerAttributeDict[attributId] = inputField['values']

    configFileDict['provider_info'] = providerAttributeDict

    return configFileDict


def convertClientRegistration(configGuiStructure, configFileDict):
    """
    Converts required information in the web interface to the
    a configuration dictionary which follows the "Configuration file
    structure", see setup.rst
    :param configGuiStructure: Data structure used to hold and show
    configuration information in the Gui
    :param configFileDict: configuration dictionary which follows the
    "Configuration file structure"
    :return Configuration dictionary updated with the new required information
    """
    support_dynamic_client_registration = \
    configGuiStructure['dynamicClientRegistrationDropDown']['value'] == 'yes'

    if not support_dynamic_client_registration:
        for attribute in configGuiStructure[
            'supportsStaticClientRegistrationTextFields']:
            if 'client_registration' not in configFileDict:
                configFileDict['client_registration'] = {}

            if attribute['id'] == 'client_id':
                configFileDict['client_registration']['client_id'] = attribute[
                    'textFieldContent']
            elif attribute['id'] == 'client_secret':
                configFileDict['client_registration']['client_secret'] = \
                attribute['textFieldContent']
            elif attribute['id'] == 'redirect_uris':
                configFileDict['client_registration']['redirect_uris'] = [
                    attribute['textFieldContent']]

    else:
        try:
            del configFileDict['client_registration']['client_id']
        except KeyError:
            pass

        try:
            del configFileDict['client_registration']['client_secret']
        except KeyError:
            pass

    return configFileDict


def convertSubClaimsToDict(subClaimsGui):
    subClaims = {"values": []}

    if len(subClaimsGui) == 1:
        singleClaim = subClaimsGui[0]
        return singleClaim

    elif len(subClaimsGui) > 1:
        for element in subClaimsGui:
            subClaims["values"].append(element['value'])

    return subClaims


def convertToList(valueDict):
    list = []
    for element in valueDict:
        list.append(element['value'])

    return list


def clear_optional_keys(configDict):
    optional_fields = ['webfinger_subject', 'login_hint', 'sub_claim',
                       'ui_locales', 'claims_locales', 'acr_values']

    for field in optional_fields:
        if field in configDict:
            del configDict[field]

    return configDict


def convertFeaturesToOprpArgument(configGuiStructure):
    arg = ""
    for feature in configGuiStructure['signingEncryptionFeaturesCheckboxes'][
        'features']:
        if feature['selected']:
            arg += feature['argument']
    return arg


def convertToResponseTypeArgToArgument(response_type):
    arguments = {"code": "C",
                 "id_token": "I",
                 "id_token token": "IT",
                 "code id_token": "CI",
                 "code token": "CT",
                 "code id_token token": "CIT"}

    return arguments[response_type]


def convertDynamicClientRegistrationToArgument(configGuiStructure):
    if configGuiStructure['dynamicClientRegistrationDropDown'][
        'value'] == "yes":
        return "T"
    return "F"


def convertDynamicDiscoveryToArgument(configGuiStructure):
    if containsDynamicDiscoveryInfo(configGuiStructure):
        return "T"
    return "F"


def collectOprpArgs(configGuiStructure):
    response_type = convertToResponseTypeArgToArgument(
        configGuiStructure["responseTypeDropDown"]["value"])
    supports_dynamic_discovery = convertDynamicDiscoveryToArgument(
        configGuiStructure)
    supports_dynamic_client_registration = \
        convertDynamicClientRegistrationToArgument(
        configGuiStructure)
    supported_signing_encryption_features = convertFeaturesToOprpArgument(
        configGuiStructure)

    return response_type + "." + supports_dynamic_discovery + "." + \
           supports_dynamic_client_registration + "." + \
           supported_signing_encryption_features


def containsDynamicDiscoveryInfo(configGuiStructure):
    return configGuiStructure['fetchDynamicInfoFromServer'][
               'showInputField'] == True


def convertOpConfigToConfigFile(configGuiStructure, session):
    """
    Converts the internal data structure to a dictionary which follows the
    "Configuration file structure", see setup.rst
    :param configGuiStructure: Data structure used to hold and show
    configuration information in the Gui
    :return A dictionary which follows the "Configuration file structure",
    see setup.rst
    """
    configDict = get_default_client()

    if containsDynamicDiscoveryInfo(configGuiStructure):
        dynamicInputFieldValue = \
        configGuiStructure['fetchDynamicInfoFromServer']['inputField']['value']
        configDict['srv_discovery_url'] = dynamicInputFieldValue

    elif configGuiStructure['fetchStaticProviderInfo'][
        'showInputFields'] == True:
        configDict = convertStaticProviderInfoToFile(configGuiStructure,
                                                     configDict)

    configDict = convertClientRegistration(configGuiStructure, configDict)

    configDict['preferences']['subject_type'] = \
    configGuiStructure["clientSubjectType"]["value"]

    configDict['behaviour']['response_type'] = \
    configGuiStructure["responseTypeDropDown"]["value"]

    configDict['oprp_arg'] = convertFeaturesToOprpArgument(configGuiStructure)

    configDict = clear_optional_keys(configDict)

    if configGuiStructure['webfingerSubject'] != "":
        configDict['webfinger_subject'] = configGuiStructure['webfingerSubject']

    if configGuiStructure['loginHint'] != "":
        configDict['login_hint'] = configGuiStructure['loginHint']

    if configGuiStructure['subClaim']:
        configDict['sub_claim'] = convertSubClaimsToDict(
            configGuiStructure['subClaim'])

    if configGuiStructure['uiLocales']:
        configDict['ui_locales'] = convertToList(
            configGuiStructure['uiLocales'])

    if configGuiStructure['claimsLocales']:
        configDict['claims_locales'] = convertToList(
            configGuiStructure['claimsLocales'])

    if configGuiStructure['acrValues']:
        configDict['acr_values'] = convertToList(
            configGuiStructure['acrValues'])

    return configDict


def handle_post_op_config(response_encoder, parameters, session):
    """
    Saves the data added in the web interface to the session
    :param opConfigurations: Internal data structure containing all info
    gathered in the web interface
    :return A default Json structure, which should be ignored
    """
    opConfigurations = parameters['opConfigurations']
    session["oprp_arg"] = collectOprpArgs(opConfigurations)
    session[OP_CONFIG] = convertOpConfigToConfigFile(opConfigurations, session)
    return response_encoder.returnJSON({})


def handle_does_op_config_exist(session, response_encoder):
    """
    Handles the request checking if the configuration file exists
    :return Returns a dictionary {"doesConfigFileExist" : true} if the
    session contains a config file else {"doesConfigFileExist" : false}
    """
    result = json.dumps({"doesConfigFileExist": (OP_CONFIG in session)})
    return response_encoder.returnJSON(result)


def handle_download_config_file(session, response_encoder):
    """
    :return Return the configuration file stored in the session
    """
    filedict = json.dumps({"configDict": session[OP_CONFIG]})
    return response_encoder.returnJSON(filedict)


def handle_upload_config_file(parameters, session, response_encoder):
    """
    Adds a uploaded config file to the session
    :return Default response, should be ignored
    """
    try:
        session[OP_CONFIG] = json.loads(parameters['configFileContent'])
    except ValueError:
        return response_encoder.serviceError(
            "Failed to load the configuration file. Make sure the config file "
            "follows the appopriate format")

    return response_encoder.returnJSON({})


def get_default_client():
    default = importlib.import_module("default_oprp_config")
    return copy.deepcopy(default.CLIENT)


def get_base_url(port):
    return 'https://%s:%d/' % (CONF.HOST, port)


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
        except ConnectionError:
            pass

    raise NoResponseException("RP (%s) failed to start" % oprp_url)


def start_rp_process(port, command, working_directory=None):
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
            return response_encoder.serviceError(NO_PORT_ERROR_MESSAGE)
    else:
        config_file, port = create_config_file(session['port'],
                                               CONF.OPRP_DIR_PATH)

    if not port:
        return response_encoder.serviceError(NO_PORT_ERROR_MESSAGE)

    config_module = create_module_string(session[OP_CONFIG], port)

    with open(config_file.name, "w") as _file:
        _file.write(config_module)

    kill_existing_process_on_port(port, session)

    config_file_name = os.path.basename(config_file.name)
    config_module = config_file_name.split(".")[0]

    if "oprp_arg" in session:
        oprp_arg = session["oprp_arg"]
    else:
        oprp_arg = "C.T.T.ns"

    try:
        start_rp_process(port, [CONF.OPRP_PATH, "-p", oprp_arg, "-t",
                                CONF.OPRP_TEST_FLOW, config_module], "../rp/")
        return response_encoder.returnJSON(
            json.dumps({"oprp_url": str(get_base_url(port))}))
    except Exception as ex:
        return response_encoder.serviceError(ex.message)


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
    return response_encoder.returnJSON("{}")


def handle_get_redirect_url(session, response_encoder, parameters):
    issuer = parameters['issuer']
    static_ports_db = MySqllite3Dict(CONF.DATABASE_FILE)

    port = None

    if issuer not in static_ports_db.values():
        try:
            port = allocate_static_port(issuer)
        except NoPortAvailable as ex:
            LOGGER.fatal(ex.message)
            return response_encoder.serviceError(ex.message)

    if not port:
        for port in static_ports_db.keys():
            if static_ports_db[port] == issuer:
                break

    session['port'] = port

    redirect_url = get_base_url(port) + "authn_cb"

    return response_encoder.returnJSON(
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