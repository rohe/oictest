from oauth2test.check import CheckAuthorizationResponse
from oauth2test.check import VerifyAccessTokenResponse
from rrtest.check import CheckHTTPResponse
from rrtest.request import BodyResponse
from rrtest.request import GetRequest
from rrtest.request import Request
from rrtest.request import Response
from rrtest.request import UrlResponse
from rrtest.request import PostRequest


class AuthorizationRequest(GetRequest):
    request = "AuthorizationRequest"
    _request_args = {}
    tests = {"pre": [], "post": [CheckHTTPResponse]}


class AuthorizationRequestCode(AuthorizationRequest):
    _request_args = {"response_type": ["code"]}


class AccessTokenRequest(PostRequest):
    request = "AccessTokenRequest"
    _kw_args = {"authn_method": "client_secret_basic"}


class AuthorizationResponse(UrlResponse):
    response = "AuthorizationResponse"
    tests = {"post": [CheckAuthorizationResponse]}


class AccessTokenResponse(BodyResponse):
    response = "AccessTokenResponse"

    def __init__(self):
        BodyResponse.__init__(self)
        self.tests = {"post": [VerifyAccessTokenResponse]}


PHASES = {
    "login": (AuthorizationRequestCode, AuthorizationResponse),
    "access-token-request": (AccessTokenRequest, AccessTokenResponse),
}


FLOWS = {
    'code': {
        "name": 'Basic Code flow with authentication',
        "descr": ('Very basic test of a Provider using the authorization code ',
                  'flow. The test tool acting as a consumer is very relaxed',
                  'and tries to obtain an ID Token.'),
        "sequence": ["login"],
        "endpoints": ["authorization_endpoint"]
    },
    'code-idtoken_post': {
        "name": 'Basic Code flow with ID Token',
        "descr": ('Very basic test of a Provider using the authorization code ',
                  'flow. The test tool acting as a consumer is very relaxed',
                  'and tries to obtain an ID Token.'),
        "depends": ["basic-code-authn"],
        "sequence": ["login", "access-token-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint"]
    },
    'code-idtoken_get': {
        "name": 'Basic Code flow with ID Token',
        "descr": ('Very basic test of a Provider using the authorization code ',
                  'flow. The test tool acting as a consumer is very relaxed',
                  'and tries to obtain an ID Token.'),
        "depends": ["basic-code-authn"],
        "sequence": ["login", "access-token-request-get"],
        "endpoints": ["authorization_endpoint", "token_endpoint"]
    },
}
