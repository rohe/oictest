import copy
import json

from oic.utils.authn.client import CLIENT_AUTHN_METHOD
from oic.utils.keyio import KeyJar
from oic.utils.keyio import KeyBundle

__author__ = 'roland'

import logging

logger = logging.getLogger(__name__)


class OIDCError(Exception):
    pass


def flow2sequence(operations, item):
    flow = operations.FLOWS[item]
    return [operations.PHASES[phase] for phase in flow["sequence"]]


class OIDCTestSetup(object):
    def __init__(self, client_cls, config, test_defs):
        """

        :param config: Imported configuration module
        :return:
        """
        self.client_cls = client_cls
        self.config = config
        self.test_features = []
        self.client = self.create_client(**config.CLIENT)
        self.test_defs = test_defs

    def create_client(self, **kwargs):
        """
        Instantiate a _client instance

        :param: Keyword arguments
            Keys are ["srv_discovery_url", "client_info", "client_registration",
            "provider_info". "keys]
        :return: _client instance
        """

        _key_set = set(kwargs.keys())
        args = {}

        _client = self.client_cls(client_authn_method=CLIENT_AUTHN_METHOD,
                                 behaviour=kwargs["behaviour"],
                                 verify_ssl=self.config.VERIFY_SSL, **args)

        # The behaviour parameter is not significant for the election process
        _key_set.discard("behaviour")
        try:
            setattr(_client, "allow", kwargs["allow"])
        except KeyError:
            pass
        else:
            _key_set.discard("allow")

        try:
            jwks = self.construct_jwks(_client, kwargs["keys"])
        except KeyError:
            pass
        else:
            # export JWKS
            f = open("export/jwk.json", "w")
            f.write(json.dumps(jwks))
            f.close()
            _client.jwks_uri = self.config.CLIENT["key_export_url"]

        self.test_features = _key_set

        try:
            _client.client_prefs = copy.copy(kwargs["preferences"])
        except KeyError:
            pass
        else:
            _key_set.discard("preferences")

        if "client_info" in _key_set:
            _client.redirect_uris = self.config.CLIENT[
                "client_info"]["redirect_uris"]
        elif "client_registration" in _key_set:
            reg_info = self.config.CLIENT["client_registration"]
            _client.redirect_uris = reg_info["redirect_uris"]
            _client.client_id = reg_info["client_id"]
            _client.client_secret = reg_info["client_secret"]

        return _client

    @staticmethod
    def construct_jwks(_client, key_conf):
        """
        Construct the jwks
        """
        if _client.keyjar is None:
            _client.keyjar = KeyJar()

        kbl = []
        kid_template = "a%d"
        kid = 0
        for typ, info in key_conf.items():
            kb = KeyBundle(source="file://%s" % info["key"], fileformat="der",
                           keytype=typ)

            for k in kb.keys():
                k.serialize()
                k.kid = kid_template % kid
                kid += 1
                _client.kid[k.use][k.kty] = k.kid
            _client.keyjar.add_kb("", kb)

            kbl.append(kb)

        jwks = {"keys": []}
        for kb in kbl:
            # ignore simple keys
            jwks["keys"].extend([k.to_dict()
                                 for k in kb.keys() if k.kty != 'oct'])

        return jwks

    def make_sequence(self, flow):
        """
        Translate a flow name into a sequence of request/responses.

        :param flow: Which test flow to use
        :return: test sequence and test definitions
        """

        sequence = flow2sequence(self.test_defs, flow)

        res = {"sequence": sequence,
               "tests": {"pre": [], "post": []},
               "flow": [flow],
               "block": [],
               "mode": "",
               "expect_exception": False}

        _flow = self.test_defs.FLOWS[flow]

        for param in ["tests", "block", "mode", "expect_exception"]:
            try:
                res[param] = _flow[param]
            except KeyError:
                pass

        return res

    def add_init(self, test_spec):
        """
        Add _client registration and provider info gathering if necessary

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
                _seq.insert(0, _ext)
                _flow.insert(0, "oic-registration")

        if "srv_discovery_url" in self.test_features:
            op_spec = self.test_defs.PHASES["provider-discovery"]
            if op_spec not in _seq:
                _seq.insert(0, op_spec)
                _flow.insert(0, "provider-discovery")

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
    :param http_args: Arguments for the HTTP _client
    :return: A cls or ErrorResponse instance or the HTTP response
        instance if no response body was expected.
    """

    if http_args is None:
        http_args = {}

    _cli = conv._client
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

    conv.protocol_response.append((_response, _resp.content))

    return _response


def test_summation(conv, sid):
    status = 0
    for item in conv.test_output:
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
