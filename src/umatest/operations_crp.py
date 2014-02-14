from oic.oauth2 import dynreg, rndstr
from oic.oauth2 import JSON_ENCODED

from uma import PAT
from uma import AAT
from uma.client import UMACONF_PATTERN
from uma.json_resource_server import OPER2SCOPE
from uma.message import ProviderConfiguration
from uma.message import ResourceSetDescription
from uma.message import StatusResponse

from oauth2test.check import CheckAuthorizationResponse
from oauth2test.check import VerifyAccessTokenResponse

from oictest.check import CheckEndpoint
from oictest.oic_operations import ConnectionVerify
from oictest.oic_operations import AuthzResponse
from oictest.oic_operations import DResponse

from rrtest.check import CheckHTTPResponse
from rrtest.opfunc import Operation
from rrtest.request import BodyResponse
from rrtest.request import Request
from rrtest.request import GetRequest
from rrtest.request import PostRequest
from rrtest.request import UrlResponse

from umatest.check import RegistrationInfo
from umatest.check import VerifyRPTResponse
from umatest.check import ProviderConfigurationInfo


class AuthorizationRequest(GetRequest):
    request = "AuthorizationRequest"
    _request_args = {}
    tests = {"pre": [], "post": [CheckHTTPResponse]}


class AuthorizationRequestCode(AuthorizationRequest):
    _request_args = {"response_type": ["code"]}


class AuthorizationRequestCodePAT(AuthorizationRequest):
    _request_args = {"response_type": ["code"]}
    role = "RS"

    def __init__(self, conv):
        super(AuthorizationRequest, self).__init__(conv)
        self.request_args["scope"] = PAT


class AuthorizationRequestCodeAAT(AuthorizationRequest):
    _request_args = {"response_type": ["code"]}
    role = "C"

    def __init__(self, conv):
        super(AuthorizationRequest, self).__init__(conv)
        self.request_args["scope"] = AAT


class AccessTokenRequest(PostRequest):
    request = "AccessTokenRequest"
    _kw_args = {"authn_method": "client_secret_basic"}


class AccessTokenRequestC(PostRequest):
    request = "AccessTokenRequest"
    _kw_args = {"authn_method": "client_secret_basic"}
    role = "C"


class AccessTokenRequestRS(PostRequest):
    request = "AccessTokenRequest"
    _kw_args = {"authn_method": "client_secret_basic"}
    role = "RS"


class RPTRequest(PostRequest):
    request = "RPTRequest"
    _kw_args = {"authn_method": "bearer_header"}
    role = "C"

    def __init__(self, conv):
        super(PostRequest, self).__init__(conv)
        self.kw_args["access_token"] = conv.client.token[
            conv.requester]["AAT"]["access_token"]
        self.kw_args["request_args"] = {}


class RPTResponse(BodyResponse):
    response = "RPTResponse"
    tests = {"post": [VerifyRPTResponse]}

    def __call__(self, conv, response):
        uid = conv.requester
        try:
            conv.client.token[uid]["RPT"] = response
        except KeyError:
            conv.client.token[uid] = {"RPT": response}


class AuthorizationResponse(UrlResponse):
    response = "AuthorizationResponse"
    tests = {"post": [CheckAuthorizationResponse]}


class AccessTokenResponse(BodyResponse):
    response = "AccessTokenResponse"
    tests = {"post": [VerifyAccessTokenResponse]}


class AccessTokenResponsePAT(AccessTokenResponse):
    role = "RS"

    def __call__(self, conv, response):
        uid = conv.resource_owner
        # Client key, could be ignored since I'm only dealing with one
        conv.client.authz_registration(uid, response,
                                       conv.client.provider_info.keys()[0],
                                       conv.client.client_id)


class AccessTokenResponseAAT(AccessTokenResponse):
    role = "C"

    def __call__(self, conv, response):
        uid = conv.requester
        # should be the same as
        # uid = atresp["id_token"]["sub"]
        try:
            conv.client.token[uid]["AAT"] = response
        except KeyError:
            conv.client.token[uid] = {"AAT": response}


class AccessTokenResponsePRT(AccessTokenResponse):
    role = "C"

    def __call__(self, conv, response):
        uid = conv.resource_owner
        # should be the same as
        # uid = atresp["id_token"]["sub"]
        try:
            conv.client.token[uid]["PRT"] = response
        except KeyError:
            conv.client.token[uid] = {"PRT": response}


class RegistrationRequest(PostRequest):
    request = "RegistrationRequest"
    content_type = JSON_ENCODED
    _request_args = {}

    def __init__(self, conv):
        PostRequest.__init__(self, conv)

        _reg_info = conv.client_config["registration_info"]
        for arg in dynreg.RegistrationRequest().parameters():
            if arg in _reg_info:
                self.request_args[arg] = _reg_info[arg]

        # verify the registration info
        self.tests["post"].append(RegistrationInfo)


class RegistrationRequestC(RegistrationRequest):
    role = "C"


class RegistrationRequestRS(RegistrationRequest):
    role = "RS"


class ProviderConfigurationResponse(BodyResponse):
    response = "ProviderConfigurationResponse"


class ClientInfoResponse(BodyResponse):
    response = "ClientInfoResponse"

    def __call__(self, conv, response):
        conv.client.store_registration_info(response)


class Discover(Operation):
    tests = {"post": [ProviderConfigurationInfo]}
    conv_param = "provider_info"
    request = None

    def __init__(self, conv, **kwargs):
        Operation.__init__(self, conv, **kwargs)
        self.request = "DiscoveryRequest"
        self.function = self.discover
        self.do_postop = True

    def discover(self, client, issuer, **kwargs):
        pcr = client.provider_config(issuer, serv_pattern=UMACONF_PATTERN,
                                     response_cls=ProviderConfiguration)
        if len(client.provider_info) == 2 and "" in client.provider_info.keys():
            _di = client.provider_info[""]
            del client.provider_info[""]
            client.provider_info.values()[0].update(_di)
            client.handle_provider_config(pcr, issuer)
            self.do_postop = False

        self.trace.info("%s" % client.keyjar)
        client.match_preferences(pcr)
        return "", DResponse(status=200, ctype="application/json"), pcr

    def post_op(self, result, conv, args):
        # Update the conv with the provider information
        # This overwrites what's there before. In some cases this might not
        # be preferable.

        if self.do_postop:
            attr = getattr(conv, self.conv_param, None)
            if attr is None:
                setattr(conv, self.conv_param, result[2].to_dict())
            else:
                attr.update(result[2].to_dict())


class DiscoverRS(Discover):
    role = "RS"


class DiscoverC(Discover):
    role = "C"


class PutRequest(Request):
    method = "PUT"
    tests = {"pre": [CheckEndpoint], "post": [CheckHTTPResponse]}


class ResourceSetRegistration(PutRequest):

    def __call__(self, location="", response="", content="", features=None,
                 **cargs):
        owner = self.conv.resource_owner
        _client = self.conv.client
        url, ht_args = _client.register_init(
            owner, "resource_set_registration_endpoint", rsid=cargs["rsid"])
        self.trace.request("URL: %s" % url)
        self.trace.request("BODY: %s" % content)
        for param in ["headers", "auth"]:
            try:
                self.trace.request("%s: %s" % (param.upper(), ht_args[param]))
            except KeyError:
                pass

        return self.do_request(_client, url, content, ht_args)


class ResourceSetsRegistration(Operation):
    tests = {}
    request = ResourceSetDescription

    def __init__(self, conv, **kwargs):
        Operation.__init__(self, conv, **kwargs)
        self.function = self.register

    def register(self, client, *args, **kwargs):
        owner = self.conv.resource_owner
        descs = client.dataset.build_resource_set_description(owner)
        for path, desc in descs:
            try:
                op = ResourceSetRegistration(self.conv)
                rsid = rndstr()
                url, response, text = op(content=desc.to_json(), rsid=rsid)
                # response should be a StatusResponse

                status_resp = StatusResponse().from_json(text)
                #client.register_resource_set_description(uid,
                #                                         path)
                assert status_resp["status"] == "created"

                client.path2rsid[path] = rsid
                csi = dict(resource_set_descr=desc.to_json())
                csi["_id"] = status_resp["_id"]
                csi["_rev"] = status_resp["_rev"]
                csi["rsid"] = rsid
                client.permreg.add_resource_set_description(owner, csi)

            except Exception, err:
                raise

        return "", DResponse(status=200, ctype="application/json"), None


class PermissionRegistrationRequest(PostRequest):
    request = "PermissionRegistrationRequest"
    _kw_args = {"authn_method": "bearer_header"}
    role = "RS"

    def __init__(self, conv):
        super(PostRequest, self).__init__(conv)
        rsets = conv.client.permreg.get(conv.resource_owner, "resource_set")
        rset = rsets[0]
        self.kw_args["access_token"] = conv.client.token[
            conv.requester]["RPT"]["access_token"]
        
        self.kw_args["request_args"] = {"resource_set_id": rset["rsid"],
                                        "scopes": [OPER2SCOPE["GET"]]}


class PermissionRegistrationResponse(BodyResponse):
    response = "PermissionRegistrationResponse"


class AuthorizationDataRequest(PostRequest):
    request = "PermissionRegistrationRequest"
    _kw_args = {"authn_method": "bearer_header"}
    role = "C"

    def __init__(self, conv):
        super(PostRequest, self).__init__(conv)
        self.kw_args["access_token"] = conv.client.token[
            conv.requester]["RPT"]["access_token"]
        self.kw_args["request_args"] = {"rpt": conv.client.token[
            conv.requester]["RPT"]["access_token"], "ticket": "ticket"}


class IntrospectionRequest(PostRequest):
    request = "IntrospectionRequest"
    _kw_args = {"authn_method": "bearer_header"}
    role = "RS"

    def __init__(self, conv):
        super(PostRequest, self).__init__(conv)
        self.kw_args["access_token"] = conv.client.token[
            conv.requester]["PAT"]["access_token"]
        rpt = conv._client["C"].token[conv.requester]["RPT"]["access_token"]
        self.kw_args["request_args"] = {"rpt": rpt}


class IntrospectionResponseInsuf(BodyResponse):
    response = "IntrospectionResponse"


class IntrospectionResponseSuf(BodyResponse):
    response = "IntrospectionResponse"


class UserSetPermission(PostRequest):
    request = "Message"
    _kw_args = {"user_auth": "bearer_header"}
    role = ""

    def __init__(self, conv):
        super(PostRequest, self).__init__(conv)
        rsets = conv.client.permreg.get(conv.resource_owner, "resource_set")
        rset = rsets[0]
        rsd = ResourceSetDescription().from_json(rset["resource_set_descr"])
        
        self.kw_args["request_args"] = {
            "user": "alice", "requestor": "roger",
            "name": rsd["name"], "scopes": rsd["scopes"]}
        _as = conv.provider_info.keys()[0]
        self.kw_args["endpoint"] = "%s/perm_reg" % _as


# =============================================================================

PHASES = {
    "verify": (ConnectionVerify, AuthzResponse),
    "pat-login": (AuthorizationRequestCodePAT, AuthorizationResponse),
    "aat-login": (AuthorizationRequestCodeAAT, AuthorizationResponse),
    "access-token-request": (AccessTokenRequest, AccessTokenResponse),
    "access-token-request-pat": (AccessTokenRequestRS, AccessTokenResponsePAT),
    "access-token-request-aat": (AccessTokenRequestC, AccessTokenResponseAAT),
    "provider-discovery": (Discover, ProviderConfigurationResponse),
    "c-provider-discovery": (DiscoverC, ProviderConfigurationResponse),
    "rs-provider-discovery": (DiscoverRS, ProviderConfigurationResponse),
    "c-registration": (RegistrationRequestC, ClientInfoResponse),
    "rs-registration": (RegistrationRequestRS, ClientInfoResponse),
    "resource_registration": (ResourceSetsRegistration, BodyResponse),
    "token-request-rpt": (RPTRequest, RPTResponse),
    "introspection-1": (IntrospectionRequest, IntrospectionResponseInsuf),
    "introspection-2": (IntrospectionRequest, IntrospectionResponseSuf),
    "rs-permission-reg": (PermissionRegistrationRequest,
                          PermissionRegistrationResponse),
    "authorization-data": (AuthorizationDataRequest, AuthorizationResponse),
    "alice-register": (UserSetPermission, BodyResponse)
}

# =============================================================================

FLOWS = {
    # 'verify': {
    #     "name": 'Special flow used to find necessary user interactions',
    #     "descr": 'Request with response_type=code',
    #     "sequence": ["verify"],
    #     "endpoints": ["authorization_endpoint"],
    #     "block": ["key_export"],
    # },
    'FT-rs-get-config-data': {
        "name": 'Provider configuration discovery',
        "descr": 'Exchange in which Client Discovers and Uses OP Information',
        "sequence": ["rs-provider-discovery"],
        "endpoints": [],
        "block": ["registration", "key_export"],
        "depends": ['verify'],
    },
    'FT-rs-get-dyn-client-creds': {
        "name": 'Dynamic client registration',
        "descr": ('RS interacts with AS to request and receive client'
                  'credentials dynamically'),
        "sequence": ["rs-provider-discovery", "rs-registration"],
        "endpoints": [],
        "block": ["key_export"],
        "depends": ['FT-rs-get-config-data'],
    },
    'rs-code': {
        "name": 'Basic Code flow with authentication',
        "descr": ('Very basic test of a Provider using the authorization code ',
                  'flow. The test tool acting as a consumer is very relaxed',
                  'and tries to obtain an ID Token.'),
        "sequence": ["rs-provider-discovery", "rs-registration", "pat-login"],
        "depends": ["FT-rs-get-dyn-client-creds"],
        "endpoints": ["authorization_endpoint"]
    },
    'FT-rs-get-pat': {
        "name": 'AS successfully issues PAT to RS',
        "descr": ('AS issues PAT to RS given correct OAuth authorization_code '
                  'grant flow (required by the spec) and request for '
                  'protection API'),
        "depends": ["rs-code"],
        "sequence": ["rs-provider-discovery", "rs-registration", "pat-login",
                     "access-token-request-pat"],
        "endpoints": ["authorization_endpoint", "token_endpoint"]
    },
    'FT-rs-rsr': {
        "name": 'RS registers a resource set at AS',
        "descr": 'RS registers a resource set at the AS',
        "depends": ["FT-rs-get-pat"],
        "sequence": ["rs-provider-discovery", "rs-registration", "pat-login",
                     "access-token-request-pat", "resource_registration"],
        "endpoints": ["authorization_endpoint", "token_endpoint",
                      "resource_set_registration_endpoint"]
    },
    'FT-c-get-dyn-client-creds': {
        "name": 'Dynamic client registration',
        "descr": ('C interacts with AS to request and receive client'
                  'credentials dynamically'),
        "sequence": ["c-provider-discovery", "c-registration"],
        "endpoints": [],
        "block": ["key_export"],
        "depends": ['oic-verify'],
    },
    'FT-c-get-aat': {
        "name": 'AS successfully issues AAT to C',
        "descr": ('AS issues AAT to C given correct OAuth authorization_code '
                  'grant flow (required by the spec) and request for '
                  'protection API'),
        "depends": ["FT-c-get-dyn-client-creds"],
        "sequence": ["c-provider-discovery", "c-registration", "aat-login",
                     "access-token-request-aat"],
        "endpoints": ["authorization_endpoint", "token_endpoint"]
    },
    'RH-c-get-aat-and-rs-get-pat': {
        "name": 'AS successfully issues AAT to C and PAT to RS',
        "descr": 'AS successfully issues AAT to C and PAT to RS',
        "depends": ["FT-c-get-aat", "FT-rs-get-pat"],
        "sequence": ["c-provider-discovery", "c-registration", "aat-login",
                     "access-token-request-aat", "rs-provider-discovery",
                     "rs-registration", "pat-login",
                     "access-token-request-pat"],
        "endpoints": ["authorization_endpoint", "token_endpoint"]
    },
    'RH-c-get-prt': {
        "name": 'C gets RPT from AS',
        "descr": 'AS successfully issues PRT to C',
        "depends": ["FT-c-get-aat"],
        "sequence": ["c-provider-discovery", "c-registration", "aat-login",
                     "access-token-request-aat", "token-request-rpt"],
        "endpoints": ["authorization_endpoint", "token_endpoint"]
    },
    'RH-rs-introspection-1': {
        "name": 'C gets RPT from AS',
        "descr": 'AS successfully issues PRT to C',
        "depends": ["FT-c-get-aat"],
        "sequence": ["c-provider-discovery", "c-registration", "aat-login",
                     "access-token-request-aat", "token-request-rpt",
                     "rs-provider-discovery", "rs-registration", "pat-login",
                     "access-token-request-pat",
                     "introspection-1"],
        "endpoints": ["authorization_endpoint", "token_endpoint"]
    },
    # 'RH-rs-introspection-2': {
    #     "name": 'C gets RPT from AS',
    #     "descr": 'AS successfully issues PRT to C',
    #     "depends": ["FT-c-get-aat"],
    #     "sequence": ["c-provider-discovery", "c-registration", "aat-login",
    #                  "access-token-request-aat", "token-request-rpt",
    #                  "rs-provider-discovery", "rs-registration", "pat-login",
    #                  "access-token-request-pat",
    #                  "alice-register",
    #                  "introspection-1", "rs-permission-reg",
    #                  "c-authorization-data", "introspection-2"],
    #     "endpoints": ["authorization_endpoint", "token_endpoint"]
    # }
}
