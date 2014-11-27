import copy
import json
from urlparse import urlparse

from oic import oic
from oic.oic import ProviderConfigurationResponse
from oic.utils.authn.client import CLIENT_AUTHN_METHOD
from oic.utils.keyio import keyjar_init
from oictest.testflows import RmCookie

__author__ = 'roland'

import logging

logger = logging.getLogger(__name__)


class OIDCError(Exception):
    pass


def flow2sequence(operations, item):
    flow = operations.FLOWS[item]
    return [operations.PHASES[phase] for phase in flow["sequence"]]


class Client(oic.Client):
    def __init__(self, client_id=None, ca_certs=None,
                 client_prefs=None, client_authn_method=None, keyjar=None,
                 verify_ssl=True, behaviour=None):
        oic.Client.__init__(self, client_id, ca_certs, client_prefs,
                            client_authn_method, keyjar, verify_ssl)
        if behaviour:
            self.behaviour = behaviour


class OIDCTestSetup(object):
    def __init__(self, config, test_defs, port):
        """

        :param config: Imported configuration module
        :return:
        """
        self.client_cls = Client
        self.config = config
        self.test_features = []
        self.test_defs = test_defs
        self._port = port
        self.client = self.create_client(**config.CLIENT)

    def create_client(self, **kwargs):
        """
        Instantiate a client instance

        :param: Keyword arguments
            Keys are ["srv_discovery_url", "client_info", "client_registration",
            "provider_info". "keys]
        :return: client instance
        """

        _key_set = set(kwargs.keys())
        args = {}

        client = self.client_cls(client_authn_method=CLIENT_AUTHN_METHOD,
                                 behaviour=kwargs["behaviour"],
                                 verify_ssl=self.config.VERIFY_SSL, **args)

        # The behaviour parameter is not significant for the election process
        _key_set.discard("behaviour")
        try:
            setattr(client, "allow", kwargs["allow"])
        except KeyError:
            pass
        else:
            _key_set.discard("allow")

        try:
            jwks = keyjar_init(client, kwargs["keys"])
        except KeyError:
            pass
        else:
            # export JWKS
            p = urlparse(self.config.CLIENT["key_export_url"] % self._port)
            f = open("."+p.path, "w")
            f.write(json.dumps(jwks))
            f.close()
            client.jwks_uri = p.geturl()

        self.test_features = _key_set

        try:
            client.client_prefs = copy.copy(kwargs["preferences"])
        except KeyError:
            pass
        else:
            _key_set.discard("preferences")

        if "client_info" in _key_set:
            client.redirect_uris = self.config.CLIENT[
                "client_info"]["redirect_uris"]
        elif "client_registration" in _key_set:
            reg_info = self.config.CLIENT["client_registration"]
            client.redirect_uris = reg_info["redirect_uris"]
            client.client_id = reg_info["client_id"]
            client.client_secret = reg_info["client_secret"]

        if "provider_info" in _key_set:
            client.provider_info = ProviderConfigurationResponse(
                **self.config.CLIENT["provider_info"])

            for key, val in self.config.CLIENT["provider_info"].items():
                if key.endswith("_endpoint"):
                    setattr(client, key, val)

        return client

    def make_sequence(self, flow):
        """
        Translate a flow name into a sequence of request/responses.

        :param flow: Which test flow to use
        :return: test sequence and test definitions
        """

        sequence = flow2sequence(self.test_defs, flow)

        res = {"sequence": sequence,
               #"tests": [],
               "flow": [flow],
               "block": [],
               "mode": "",
               "expect_exception": False}

        _flow = self.test_defs.FLOWS[flow]

        for param in ["tests", "block", "mode", "expect_exception",
                      "note", "cache"]:
            try:
                res[param] = _flow[param]
            except KeyError:
                pass

        return res

    @staticmethod
    def _insert(seq, ext):
        """
        Add a step to the flow sequence

        :param seq: The flow sequence
        :param ext: The extra step, should be added to the top and then after
        every RmCookie
        :return: The new extended flow sequence
        """
        rseq = [ext]
        for n in range(0, len(seq)):
            if seq[n] == RmCookie:
                rseq.append(seq[n])
                rseq.append(ext)
            else:
                rseq.append(seq[n])
        return rseq

    def add_init(self, test_spec):
        """
        Add client registration and provider info gathering if necessary

        :param test_spec:
        :return:
        """
        _seq = test_spec["sequence"]
        _flow = test_spec["flow"]

        if "client_info" in self.test_features and \
                "registration" not in test_spec["block"]:
            _register = True
            # May not be the first item in the sequence
            for sq in _seq:
                try:
                    if sq[0].request == "RegistrationRequest":
                        _register = False
                except TypeError:
                    pass
            if _register:
                _ext = self.test_defs.PHASES["oic-registration"]
                test_spec["sequence"] = self._insert(_seq, _ext)
                _seq = test_spec["sequence"]
        if "srv_discovery_url" in self.test_features:
            op_spec = self.test_defs.PHASES["provider-discovery"]
            if op_spec not in _seq:
                test_spec["sequence"] = self._insert(_seq, op_spec)

        return test_spec


def request_and_return(conv, url, response=None, method="GET", body=None,
                       body_type="json", state="", http_args=None,
                       **kwargs):
    """
    :param url: The URL to which the request should be sent
    :param response: Response type
    :param method: Which HTTP method to use
    :param body: A message body if any
    :param body_type: The format of the body of the return message
    :param http_args: Arguments for the HTTP client
    :return: A cls or ErrorResponse instance or the HTTP response
        instance if no response body was expected.
    """

    if http_args is None:
        http_args = {}

    logger.debug("request.headers: %s" % http_args)
    logger.debug("request.body: %s" % body)
    logger.debug("request.url: %s" % url)
    logger.debug("request.method: %s" % method)
    _cli = conv.client
    try:
        _resp = _cli.http_request(url, method, data=body, **http_args)
    except Exception:
        raise

    conv.position = url
    conv.last_response = _resp
    conv.last_content = _resp.content

    if not "keyjar" in kwargs:
        kwargs["keyjar"] = conv.keyjar

    _response = _cli.parse_request_response(_resp, response, body_type, state,
                                            **kwargs)

    # Need special handling of id_token
    if "id_token" in _response:
        _dict = json.loads(_resp.text)
        conv.id_token = _dict["id_token"]

    conv.protocol_response.append((_response, _resp.content))

    return _response


def test_summation(conv, sid):
    status = 0
    for item in conv.test_output:
        if isinstance(item, tuple):
            continue
        if item["status"] > status:
            status = item["status"]

    if status == 0:
        status = 1

    info = {
        "id": sid,
        "status": status,
        "tests": conv.test_output
    }

    return info
