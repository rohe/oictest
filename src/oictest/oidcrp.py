import copy
import json
from urlparse import urlparse
from jwkest import unpack
from jwkest import BadSyntax
from jwkest.jwe import DecryptionFailed

from oic import oic
from oic.exception import MessageException
from oic.oauth2.message import ErrorResponse
from oic.oauth2.message import Message
from oic.oic import ProviderConfigurationResponse
from oic.utils.authn.client import CLIENT_AUTHN_METHOD
from oic.utils.keyio import keyjar_init
from oic.utils.time_util import utc_time_sans_frac
from oictest.testflows import RmCookie

__author__ = 'roland'

import logging

logger = logging.getLogger(__name__)


class OIDCError(Exception):
    pass


class MissingErrorResponse(Exception):
    pass


def flow2sequence(operations, item):
    flow = operations.FLOWS[item]
    return [operations.PHASES[phase] for phase in flow["sequence"]]


class Client(oic.Client):
    def __init__(self, client_id=None, ca_certs=None,
                 client_prefs=None, client_authn_methods=None, keyjar=None,
                 verify_ssl=True, behaviour=None):
        oic.Client.__init__(self, client_id, ca_certs, client_prefs,
                            client_authn_methods, keyjar, verify_ssl)
        if behaviour:
            self.behaviour = behaviour


class OIDCTestSetup(object):
    def __init__(self, config, test_defs, port, client_cls=Client):
        """

        :param config: Imported configuration module
        :return:
        """
        self.client_cls = client_cls
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

        client = self.client_cls(client_authn_methods=CLIENT_AUTHN_METHOD,
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
            try:
                client.client_secret = reg_info["client_secret"]
            except KeyError:
                pass

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
               "flow": [flow],
               "block": [],
               "mode": "",
               "expect_exception": False}

        _flow = self.test_defs.FLOWS[flow]

        for param in ["tests", "block", "mode", "expect_exception",
                      "note", "cache", "profile"]:
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
        # _flow = test_spec["flow"]

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


def request_and_return(conv, url, trace, response_type=None, method="GET",
                       body=None, body_type="json", state="", http_args=None,
                       **kwargs):
    """
    :param url: The URL to which the request should be sent
    :param response_type: Response type
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

    conv.timestamp.append(url, utc_time_sans_frac())

    return do_response(_resp, conv, url, trace, _cli, body_type, response_type,
                       state, **kwargs)


def do_response(response, conv, url, trace, client, body_type, response_type,
                state, **kwargs):
    """

    :param response:
    :param conv:
    :param url:
    :param trace:
    :param client:
    :param body_type:
    :param response_type:
    :param state:
    :param kwargs:
    :return:
    """
    conv.position = url
    conv.last_response = response
    conv.last_content = response.content

    trace.reply("STATUS: %d" % response.status_code)

    _response = None
    if response.status_code >= 400:  # an error
        if response.text:
            try:
                _response = ErrorResponse().from_json(response.text)
            except (MessageException, ValueError):
                trace.reply("Non OIDC error message: %s" % response.content)
        else:
            raise MissingErrorResponse()
    elif response.status_code == 204:  # No response
        _response = Message()
    else:
        try:
            uiendp = client.provider_info["userinfo_endpoint"]
        except KeyError:
            uiendp = ""

        if uiendp == url:
            _iss = client.provider_info["issuer"]
            _ver_keys = client.keyjar.get("ver", issuer=_iss)
            _info = [(k.kid, k.kty) for k in _ver_keys]
            trace.info("Available verification keys: {}".format(_info))
            kwargs["key"] = _ver_keys
            _dec_keys = client.keyjar.get("enc", issuer="")
            _info = [(k.kid, k.kty) for k in _dec_keys]
            trace.info("Available decryption keys: {}".format(_info))
            kwargs["key"].extend(_dec_keys)
        elif "keyjar" not in kwargs:
            kwargs["keyjar"] = conv.keyjar

        trace.reply("BODY: %s" % response.text)
        try:
            _response = client.parse_request_response(response, response_type,
                                                      body_type, state,
                                                      **kwargs)
        except DecryptionFailed:
            p = unpack(response)
            trace.log(
                "Failed decryption on response with JWT header {}".format(p[0]))
            raise

        # Need special handling of id_token
        if "id_token" in _response:
            _dict = json.loads(response.text)
            conv.id_token = _dict["id_token"]
            # header = json.loads(b64d(str(conv.id_token.split(".")[0])))
            # trace.info("IdToken JWT header: %s" % header)
        else:
            try:
                res = unpack(response.content)
            except (BadSyntax, TypeError):
                pass
            else:
                trace.info("JWT header: %s" % res[0])

    if _response is None:
        conv.protocol_response.append((_response, ""))
    else:
        conv.protocol_response.append((_response, response.content))

    return _response


def test_summation(test_output, sid):
    status = 1
    for item in test_output:
        if isinstance(item, tuple):
            continue
        if item["status"] > status:
            status = item["status"]

    info = {
        "id": sid,
        "status": status,
        "tests": test_output
    }

    return info
