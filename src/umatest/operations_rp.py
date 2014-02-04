from oic.oauth2 import dynreg, rndstr
from oic.oauth2 import JSON_ENCODED

from uma import PAT
from uma.client import UMACONF_PATTERN
from uma.message import ProviderConfiguration, ResourceSetDescription

from oauth2test.check import CheckAuthorizationResponse
from oauth2test.check import CheckErrorResponseForInvalidType
from oauth2test.check import CheckSecondCodeUsageErrorResponse
from oauth2test.check import CheckPresenceOfStateParameter
from oauth2test.check import VerifyAccessTokenResponse

from oictest.oic_operations import ConnectionVerify
from oictest.oic_operations import AuthzResponse
from oictest.oic_operations import DResponse

from rrtest.check import CheckHTTPResponse, VerifyError
from rrtest.opfunc import Operation
from rrtest.request import BodyResponse
from rrtest.request import ErrorResponse
from rrtest.request import GetRequest
from rrtest.request import PostRequest
from rrtest.request import UrlResponse

from uma.check import RegistrationInfo
from uma.check import ProviderConfigurationInfo


class AuthorizationRequest(GetRequest):
    request = "AuthorizationRequest"
    _request_args = {}
    tests = {"pre": [], "post": [CheckHTTPResponse]}


class AuthorizationRequestCode(AuthorizationRequest):
    _request_args = {"response_type": ["code"]}


class AuthorizationRequestCodePAT(AuthorizationRequest):
    _request_args = {"response_type": ["code"]}

    def __init__(self, conv):
        super(AuthorizationRequest, self).__init__(conv)
        self.request_args["scope"] = PAT


class AccessTokenRequest(PostRequest):
    request = "AccessTokenRequest"
    _kw_args = {"authn_method": "client_secret_basic"}


class AuthorizationResponse(UrlResponse):
    response = "AuthorizationResponse"
    tests = {"post": [CheckAuthorizationResponse]}


class AccessTokenResponse(BodyResponse):
    response = "AccessTokenResponse"
    tests = {"post": [VerifyAccessTokenResponse]}


class AccessTokenSecondRequest(AccessTokenRequest):
    tests = {"post": [VerifyError]}


class AccessTokenSecondResponse(AccessTokenResponse):
    tests = {"post": [CheckSecondCodeUsageErrorResponse]}


class AccessTokenResponsePAT(AccessTokenResponse):
    def __call__(self, conv, response):
        uid = conv.kwargs["resource_owner"]
        _key = rndstr()  # Not really sure why I have this but ..
        conv.client.authz_registration(uid, response,
                                       conv.client.provider_info.keys()[0],
                                       _key)


class AuthorizationRequestCodeWithState(AuthorizationRequestCode):
    def __init__(self, conv=None):
        super(AuthorizationRequestCodeWithState, self).__init__(conv)

        self.request_args["state"] = "afdsliLKJ253oiuffaslkj"


class AuthorizationResponseWhichForcesState(AuthorizationResponse):
    tests = {"post": [CheckPresenceOfStateParameter]}


class AccessTokenInvalidTypeRequest(AccessTokenRequest):
    tests = {"post": [VerifyError]}

    def __init__(self, conv):
        super(AccessTokenInvalidTypeRequest, self).__init__(conv)

        self.request_args["grant_type"] = 'nissesapa'


class AccessTokenInvalidTypeResponse(ErrorResponse):
    tests = {"post": [CheckErrorResponseForInvalidType]}


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

    def discover(self, client, orig_response, content, issuer, **kwargs):
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


class ResourceSetRegistration(Operation):
    tests = {}
    request = ResourceSetDescription

    def __init__(self, conv, **kwargs):
        Operation.__init__(self, conv, **kwargs)
        self.function = self.register

    def register(self, client, *args, **kwargs):
        uid = self.conv.kwargs["resource_owner"]
        descs = client.dataset.build_resource_set_description(uid)
        for path, desc in descs:
            try:
                client.register_resource_set_description(uid, desc.to_json(),
                                                         path)
            except Exception, err:
                raise

        return "", DResponse(status=200, ctype="application/json"), None


# =============================================================================

PHASES = {
    "verify": (ConnectionVerify, AuthzResponse),
    "login": (AuthorizationRequestCodePAT, AuthorizationResponse),
    "access-token-request": (AccessTokenRequest, AccessTokenResponse),
    "access-token-request-pat": (AccessTokenRequest, AccessTokenResponsePAT),
    "access-token-second-request": (AccessTokenSecondRequest,
                                    AccessTokenSecondResponse),
    # "login-with-state": (AuthorizationRequestCodeWithState,
    #                      AuthorizationResponseWhichForcesState),
    "access-token-request-invalid-type": (AccessTokenInvalidTypeRequest,
                                          AccessTokenInvalidTypeResponse),
    "provider-discovery": (Discover, ProviderConfigurationResponse),
    "registration": (RegistrationRequest, ClientInfoResponse),
    "resource_registration": (ResourceSetRegistration, BodyResponse)
}

# =============================================================================

FLOWS = {
    'verify': {
        "name": 'Special flow used to find necessary user interactions',
        "descr": 'Request with response_type=code',
        "sequence": ["verify"],
        "endpoints": ["authorization_endpoint"],
        "block": ["key_export"]
    },
    'FT-rs-get-config-data': {
        "name": 'Provider configuration discovery',
        "descr": 'Exchange in which Client Discovers and Uses OP Information',
        "sequence": ["provider-discovery"],
        "endpoints": [],
        "block": ["registration", "key_export"],
        "depends": ['oic-verify'],
    },
    'FT-rs-get-dyn-client-creds': {
        "name": 'Dynamic client registration',
        "descr": ('RS interacts with AS to request and receive client'
                  'credentials dynamically'),
        "sequence": ["registration"],
        "endpoints": [],
        "block": ["key_export"],
        "depends": ['oic-verify'],
    },
    'code': {
        "name": 'Basic Code flow with authentication',
        "descr": ('Very basic test of a Provider using the authorization code ',
                  'flow. The test tool acting as a consumer is very relaxed',
                  'and tries to obtain an ID Token.'),
        "sequence": ["login"],
        "endpoints": ["authorization_endpoint"]
    },
    'FT-rs-get-pat': {
        "name": 'AS successfully issues PAT to RS',
        "descr": ('AS issues PAT to RS given correct OAuth authorization_code '
                  'grant flow (required by the spec) and request for '
                  'protection API'),
        "depends": ["basic-code-authn"],
        "sequence": ["login", "access-token-request-pat"],
        "endpoints": ["authorization_endpoint", "token_endpoint"]
    },
    'code-idtoken-double_post': {
        "name": 'Basic Code flow with two requests for ID Token',
        "descr": ('Tries to use the same access grant twice. ',
                  'This is according to the standard *not* allowed.'),
        "depends": ["basic-code-authn"],
        "sequence": ["login", "access-token-request",
                     "access-token-second-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint"]
    },
    'code-presence-of-state': {
        'name':
            'Basic Code flow with authentication which checks for state parameter',
        'descr': ('Basic test of a Provider using the authorization code ',
                  'flow. The test tool acting as a consumer is relaxed but ',
                  'ensures that the state parameter in the authorization ',
                  'response is equal to the state given in the authorization ,'
                  'request.'),
        'sequence': ['login-with-state']
    },
    'code-faulty-grant-type': {
        'name': 'Basic Code flow with faulty grant_type',
        'descr': ('Basic test of a Provider which checks that the provider',
                  'correctly indicates faulty values for the grant_type',
                  'parameter.'),
        'sequence': ['login', 'access-token-request-invalid-type'],
    },
    'FT-rs-rsr': {
        "name": 'RS registers resource sets at AS',
        "descr": ('Very basic test of a Provider using the authorization code ',
                  'flow. The test tool acting as a consumer is very relaxed',
                  'and tries to obtain an ID Token.'),
        "depends": ["code-idtoken_post"],
        "sequence": ["login", "access-token-request-pat",
                     "resource_registration"],
        "endpoints": ["authorization_endpoint", "token_endpoint",
                      "resource_set_registration_endpoint"]
    },
}
