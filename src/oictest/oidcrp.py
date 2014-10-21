import copy
import json

from oic import oic
# from oic.utils.http_util import Redirect
# from oic.oauth2 import rndstr
# from oic.oauth2 import ErrorResponse
# from oic.oic import AuthorizationResponse
# from oic.oic import AuthorizationRequest
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


class Client(oic.Client):
    def __init__(self, client_id=None, ca_certs=None,
                 client_prefs=None, client_authn_method=None, keyjar=None,
                 verify_ssl=True, behaviour=None):
        oic.Client.__init__(self, client_id, ca_certs, client_prefs,
                            client_authn_method, keyjar, verify_ssl)
        if behaviour:
            self.behaviour = behaviour

    # def create_authn_request(self, session, acr_value=None):
    #     session["state"] = rndstr()
    #     session["nonce"] = rndstr()
    #     request_args = {
    #         "response_type": self.behaviour["response_type"],
    #         "scope": self.behaviour["scope"],
    #         "state": session["state"],
    #         "nonce": session["nonce"],
    #         "redirect_uri": self.registration_response["redirect_uris"][0]
    #     }
    #
    #     if acr_value is not None:
    #         request_args["acr_values"] = acr_value
    #
    #     cis = self.construct_AuthorizationRequest(request_args=request_args)
    #     logger.debug("request: %s" % cis)
    #
    #     url, body, ht_args, cis = self.uri_and_body(AuthorizationRequest, cis,
    #                                                 method="GET",
    #                                                 request_args=request_args)
    #
    #     logger.debug("body: %s" % body)
    #     logger.info("URL: %s" % url)
    #     logger.debug("ht_args: %s" % ht_args)
    #
    #     resp = Redirect(str(url))
    #     if ht_args:
    #         resp.headers.extend([(a, b) for a, b in ht_args.items()])
    #     logger.debug("resp_headers: %s" % resp.headers)
    #     return resp
    #
    # def callback(self, response):
    #     """
    #     This is the method that should be called when an AuthN response has been
    #     received from the OP.
    #
    #     :param response: The URL returned by the OP
    #     :return:
    #     """
    #     authresp = self.parse_response(AuthorizationResponse, response,
    #                                    sformat="dict", keyjar=self.keyjar)
    #
    #     if isinstance(authresp, ErrorResponse):
    #         return OIDCError("Access denied")
    #
    #     try:
    #         self.id_token[authresp["state"]] = authresp["id_token"]
    #     except KeyError:
    #         pass
    #
    #     if self.behaviour["response_type"] == "code":
    #         # get the access token
    #         try:
    #             args = {
    #                 "code": authresp["code"],
    #                 "redirect_uri": self.registration_response[
    #                     "redirect_uris"][0],
    #                 "client_id": self.client_id,
    #                 "client_secret": self.client_secret
    #             }
    #
    #             atresp = self.do_access_token_request(
    #                 scope="openid", state=authresp["state"], request_args=args,
    #                 authn_method=self.registration_response[
    #                     "token_endpoint_auth_method"])
    #         except Exception as err:
    #             logger.error("%s" % err)
    #             raise
    #
    #         if isinstance(atresp, ErrorResponse):
    #             raise OIDCError("Invalid response %s." % atresp["error"])
    #
    #     inforesp = self.do_user_info_request(state=authresp["state"])
    #
    #     if isinstance(inforesp, ErrorResponse):
    #         raise OIDCError("Invalid response %s." % inforesp["error"])
    #
    #     userinfo = inforesp.to_dict()
    #
    #     logger.debug("UserInfo: %s" % inforesp)
    #
    #     return userinfo


class OIDCTestSetup(object):
    def __init__(self, config, test_defs):
        """

        :param config: Imported configuration module
        :return:
        """
        self.client_cls = Client
        self.config = config
        self.test_features = []
        self.client = self.create_client(**config.CLIENT)
        self.test_defs = test_defs

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
            jwks = self.construct_jwks(client, kwargs["keys"])
        except KeyError:
            pass
        else:
            # export JWKS
            f = open("export/jwk.json", "w")
            f.write(json.dumps(jwks))
            f.close()
            client.jwks_uri = self.config.CLIENT["key_export_url"]

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

        return client

    @staticmethod
    def construct_jwks(client, key_conf):
        """
        Construct the jwks
        """
        if client.keyjar is None:
            client.keyjar = KeyJar()

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
                client.kid[k.use][k.kty] = k.kid
            client.keyjar.add_kb("", kb)

            kbl.append(kb)

        jwks = {"keys": []}
        for kb in kbl:
            # ignore simple keys
            jwks["keys"].extend([k.to_dict()
                                 for k in kb.keys() if k.kty != 'oct'])

        return jwks

    # @staticmethod
    # def register_args(client_reg_conf):
    #     """
    #     Filter client registration arguments so no extras are slipped in.
    #
    #     :param client_reg_conf:
    #     :return:
    #     """
    #     info = {}
    #     for prop in RegistrationRequest.c_param.keys():
    #         try:
    #             info[prop] = client_reg_conf[prop]
    #         except KeyError:
    #             pass
    #     return info

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
    :param http_args: Arguments for the HTTP client
    :return: A cls or ErrorResponse instance or the HTTP response
        instance if no response body was expected.
    """

    if http_args is None:
        http_args = {}

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
