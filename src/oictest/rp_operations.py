import urlparse
from oictest.opfunc import DResponse

__author__ = 'rohe0002'

from oictest.oic_operations import OpenIDRequestCode, OpenIDRequestIDTokenToken
from oictest.oic_operations import UserinfoResponse
from oictest.oic_operations import UserInfoRequestGetBearerHeader
from oictest.oic_operations import Response
from oictest.oic_operations import RegistrationRequest
from oictest.oic_operations import RegistrationResponse
from oictest.oic_operations import Discover
from oictest.oic_operations import ProviderConfigurationResponse
from oictest.oic_operations import AuthzResponse
from oictest.oic_operations import AccessTokenRequest
from oictest.oic_operations import AccessTokenResponse
from oictest.oic_operations import GetRequest

class TraceLogRequest(GetRequest):
    request = "ResourceRequest"

    def __init__(self):
        GetRequest.__init__(self)

    def __call__(self, environ, trace, location, response, content):
        _pinfo = environ["provider_info"]
        part = urlparse.urlparse(_pinfo["authorization_endpoint"])
        _client = environ["client"]
        _client.resource_endpoint = "%s://%s/tracelog" % (part.scheme,
                                                          part.netloc)
        self.kw_args = {"authn_method": "bearer_header"}
        return GetRequest.__call__(self, environ, trace, location, response,
                                   content)


class DataResponse(Response):
    where = "body"
    type = "text"

class OpenIDRequestCodeGeo(OpenIDRequestCode):

    def __init__(self):
        OpenIDRequestCode.__init__(self)
        self.request_args["userinfo_claims"] = {"claims": {"geolocation": None}}

class UserInfoClaims(UserInfoRequestGetBearerHeader):
    def __call__(self, environ, trace, location, response, content):
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

PHASES = {
    "oic-registration": (RegistrationRequest, RegistrationResponse),
    "provider-discovery": (Discover, ProviderConfigurationResponse),
    "login": (OpenIDRequestCode, AuthzResponse),
    "login-geo": (OpenIDRequestCodeGeo, AuthzResponse),
    "token" : (AccessTokenRequest, AccessTokenResponse),
    "info" : (TraceLogRequest, DataResponse),
    "user-info-request":(UserInfoRequestGetBearerHeader, UserinfoResponse),
    "claims_request": (UserInfoClaims, UserinfoResponse),
    "oic-login-idtoken+token": (OpenIDRequestIDTokenToken, AuthzResponse),
}

FLOWS = {
    "simple": {
        "sequence": ["login", "token", "info"],
        "endpoints": ["authorization_endpoint", "token_endpoint"],
    },
    "userinfo": {
        "sequence": ["login-geo", "token", "user-info-request", "info"],
        "endpoints": ["authorization_endpoint", "token_endpoint",
                      "userinfo_endpoint"],
        },
    "userinfo2": {
        "sequence": ["login-geo", "token", "user-info-request",
                     "claims_request", "info"],
        "endpoints": ["authorization_endpoint", "token_endpoint",
                      "userinfo_endpoint"],
        },
    'mj-06': {
        "name": 'Request with response_type=id_token token',
        "sequence": ['oic-login-idtoken+token', "info"],
        "endpoints": ["authorization_endpoint"],
        },

    }