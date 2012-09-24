import urlparse
from oictest.opfunc import DResponse
from oictest.check import Error

__author__ = 'rohe0002'

from oictest.oic_operations import OpenIDRequestCode
from oictest.oic_operations import Request
from oictest.oic_operations import Discover
from oictest.oic_operations import ProviderConfigurationResponse
from oictest.oic_operations import AccessTokenRequestCSPost
from oictest.oic_operations import AccessTokenRequestCSJWT
from oictest.oic_operations import AccessTokenRequestPKJWT
from oictest.oic_operations import OpenIDRequestToken
from oictest.oic_operations import OpenIDRequestIDToken
from oictest.oic_operations import OpenIDRequestCodeToken
from oictest.oic_operations import OpenIDRequestCodeIDToken
from oictest.oic_operations import OpenIDRequestCodeIDTokenToken
from oictest.oic_operations import OpenIDRequestCodeIDTClaim1
from oictest.oic_operations import RegistrationRequest_KeyExp
from oictest.oic_operations import OpenIDRequestCodeScopeEMail
from oictest.oic_operations import OpenIDRequestCodeUIClaim1
from oictest.oic_operations import UserinfoResponse
from oictest.oic_operations import OpenIDRequestIDTokenToken
from oictest.oic_operations import RegistrationResponseCARS
from oictest.oic_operations import UserInfoRequestGetBearerHeader
from oictest.oic_operations import Response
from oictest.oic_operations import RegistrationRequest
from oictest.oic_operations import BodyResponse
#from oictest.oic_operations import ProviderConfigurationResponse
from oictest.oic_operations import AuthzResponse
from oictest.oic_operations import AccessTokenRequest
from oictest.oic_operations import AccessTokenResponse
from oictest.oic_operations import GetRequest

class HTTPResponse(object):
    def __init__(self):
        self.status_code = 200

class TraceLogRequest(GetRequest):
    request = "ResourceRequest"

    def __init__(self):
        GetRequest.__init__(self)

    def __call__(self, environ, trace, location, response, content, features):
        _pinfo = environ["provider_info"]
        part = urlparse.urlparse(_pinfo["authorization_endpoint"])
        _client = environ["client"]
        _client.resource_endpoint = "%s://%s/tracelog" % (part.scheme,
                                                          part.netloc)
        self.kw_args = {"authn_method": "bearer_header"}
        return GetRequest.__call__(self, environ, trace, location, response,
                                   content, features)


class DataResponse(Response):
    where = "body"
    type = "text"

class OpenIDRequestCodeGeo(OpenIDRequestCode):

    def __init__(self):
        OpenIDRequestCode.__init__(self)
        self.request_args["userinfo_claims"] = {"claims": {"geolocation": None}}

class UserInfoClaims(UserInfoRequestGetBearerHeader):
    def __call__(self, environ, trace, location, response, content, features):
        info = environ["response_message"]
        # {'_claims_sources': {
        #   'https://localhost:8089/': {
        #       'access_token': 'wdVcjbXVV6A9jraG',
        #       'endpoint': 'https://localhost:8089//userclaimsinfo'}},
        # '_claims_names': {'geolocation': 'https://localhost:8089/'},
        # 'user_id': 'uppe0001'}
        _client = environ["client"]
        try:
            trace = environ["trace"]
        except KeyError:
            trace = None
        userinfo = {}
        for id, spec in info["_claims_sources"].items():
            if trace:
                trace.info("--> URL: %s" % spec["endpoint"])
            res = _client.get_userinfo_claims(**spec)
            if trace:
                trace.info("<-- CONTENT: %s" % res.to_dict())
                trace.info(70*"=")
            userinfo.update(res)

        return "", DResponse(200), userinfo

class DiscoveryByEmail(Request):
    request = None
    tests = {"pre":[], "post": []}

    def __init__(self, cconf=None):
        Request.__init__(self, cconf)
        self.principal = "diana@kodtest.se"
        self.idtype = "mail"

    #noinspection PyUnusedLocal
    def __call__(self, environ, trace, location, response, content, features):
        client = environ["client"]
        issuer = client.discover(self.principal, self.idtype)
        return "", HTTPResponse(), issuer

class DiscoveryByURL(Request):
    request = None
    tests = {"pre":[], "post": []}

    def __init__(self, cconf):
        Request.__init__(self, cconf)
        self.principal = "http://kodtest.se/diana"
        self.idtype = "url"

    def __call__(self, environ, trace, location, response, content, features):
        client = environ["client"]
        issuer = client.discover(self.principal, self.idtype)
        return "", HTTPResponse(), issuer

class VerifyIssuer(Error):
    id = "verify-issuer"

    def _func(self, environ):
        msg = environ["content"]
        try:
            assert msg == self._kwargs["issuer"]
        except AssertionError:
            self._message = "Wrong issuer"
            self._status = self.status

        return {}

PHASES = {
    "email_discovery": (DiscoveryByEmail, BodyResponse),
    "url_discovery": (DiscoveryByURL, BodyResponse),
    "provider-discovery": (Discover, ProviderConfigurationResponse),

    "oic-registration": (RegistrationRequest, RegistrationResponseCARS),
    "oic-registration-ke": (RegistrationRequest_KeyExp, RegistrationResponseCARS),

    "oic-login": (OpenIDRequestCode, AuthzResponse),
    "oic-login-token": (OpenIDRequestToken, AuthzResponse),
    "oic-login-idtoken": (OpenIDRequestIDToken, AuthzResponse),
    "oic-login-code+token": (OpenIDRequestCodeToken, AuthzResponse),
    "oic-login-code+idtoken": (OpenIDRequestCodeIDToken, AuthzResponse),
    "oic-login-idtoken+token": (OpenIDRequestIDTokenToken, AuthzResponse),
    "oic-login-code+idtoken+token": (OpenIDRequestCodeIDTokenToken,
                                     AuthzResponse),
    "access-token-request":(AccessTokenRequest, AccessTokenResponse),
    "access-token-request_csj":(AccessTokenRequestCSJWT,
                                AccessTokenResponse),
    "access-token-request_csp":(AccessTokenRequestCSPost,
                                AccessTokenResponse),
    "access-token-request_pkj":(AccessTokenRequestPKJWT,
                                AccessTokenResponse),
    "oic-login+idtc1": (OpenIDRequestCodeIDTClaim1, AuthzResponse),
    "user-info-request":(UserInfoRequestGetBearerHeader, UserinfoResponse),

    "oic-login+email": (OpenIDRequestCodeScopeEMail, AuthzResponse),
    "oic-login+spec1": (OpenIDRequestCodeUIClaim1, AuthzResponse),
    }

FLOWS = {
    "ping": {
        "name": "Uses ping to find out if the host is there",
        "sequence": ["ping"],
        "endpoints": [],
        "block": ["registration", "key_export", "discovery"],
    },
    "rp-02": {
        "name":"Can Discover Identifiers using E-Mail Syntax",
        "sequence": ["email_discovery"],
        "endpoints": [],
        "block": ["registration", "key_export", "discovery"],
        "tests": [(VerifyIssuer, {"issuer":"https://www.kodtest.se:8088/"})],
        },
    "rp-03": {
        "name":"Can Discover Identifiers using URL Syntax",
        "sequence": ["url_discovery"],
        "endpoints": [],
        "block": ["registration", "key_export", "discovery"],
        "tests": [(VerifyIssuer, {"issuer":"https://www.kodtest.se:8088/"})],
    },
    "rp-04": {
        "name":"Uses Discovery",
        "sequence": [],
        "endpoints": [],
        "block": ["registration", "key_export"],
        "depends": ['ping'],
        },
    "rp-05": {
        "descr":"Uses Dynamic Registration",
        "sequence": ["oic-registration"],
        "endpoints": ["authorization_endpoint", "token_endpoint"],
        "depends": ['rp-02'],
        "block": ["key_export"],
        },
    # =================
    'rp-07': {
        "name": 'Access token request with client_secret_basic authentication',
        "sequence": ["oic-login", "access-token-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint"],
        "depends": ['rp-04'],
        },
    'rp-08': {
        "name": 'Access token request with client_secret_post authentication',
        "sequence": ["oic-login", "access-token-request_csp"],
        "endpoints": ["authorization_endpoint", "token_endpoint"],
        "depends": ['rp-04'],
        },
    'rp-09': {
        "name": 'Access token request with client_secret_jwt authentication',
        "sequence": ["oic-registration-ke", "oic-login",
                     "access-token-request_csj"],
        "endpoints": ["authorization_endpoint", "token_endpoint"],
        "depends": ['rp-04'],
        },
    'rp-10': {
        "name": 'Access token request with public_key_jwt authentication',
        "sequence": ["oic-registration-ke", "oic-login",
                     "access-token-request_pkj"],
        "endpoints": ["authorization_endpoint", "token_endpoint"],
        "depends": ['rp-04'],
        },
    # =================
    'rp-12': {
        "name": "Verifies Correct c_hash when Code Flow Used",
        "depends": ['rp-05'],
        "sequence": ["oic-login-code+idtoken"],
        "endpoints": ["authorization_endpoint", "token_endpoint"],
        },
    'rp-13': {
        "name": "Verifies Correct at_hash when Implicit Flow Used",
        "depends": ['rp-05'],
        "sequence": ['oic-login-idtoken+token'],
        "endpoints": ["authorization_endpoint"],
        },
    'rp-14': {
        "name": "Rejects Incorrect c_hash when Code Flow Used",
        "depends": ['rp-12'],
        "sequence": ["oic-login-code+idtoken"],
        "endpoints": ["authorization_endpoint", "token_endpoint"],
        },
    'rp-15': {
        "name": "Rejects Incorrect at_hash when Implicit Flow Used",
        "depends": ['rp-13'],
        "sequence": ['oic-login-idtoken+token'],
        "endpoints": ["authorization_endpoint"],
        },
    # =================
    #
    'rp-21': {
        "name": 'Requesting UserInfo Claims with scope Values',
        "sequence": ["oic-login+email", "access-token-request",
                     "user-info-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint",
                      "userinfo_endpoint"],
        "depends": ['mj-01'],
        },
    'rp-22': {
        "name": 'Requesting UserInfo Claims with OpenID Request Object',
        "sequence": ["oic-login+spec1", "access-token-request",
                     "user-info-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint",
                      "userinfo_endpoint"],
        "depends": ['mj-01'],
        },

    # =================
    'rp-25': {
        "name": 'Can Request and Use Signed UserInfo Response',
        "sequence": ["oic-login", "access-token-request",
                     "user-info-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint",
                      "userinfo_endpoint"],
        "depends": ['mj-01'],
        },
    'rp-27': {
        "name": 'Uses Distributed Claims',
        "sequence": ["oic-login", "access-token-request",
                     "user-info-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint",
                      "userinfo_endpoint"],
        "depends": ['mj-01'],
        },

    }