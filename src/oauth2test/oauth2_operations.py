from oauth2test.check import CheckAuthorizationResponse
from oauth2test.check import VerifyAccessTokenResponse
from rrtest.check import CheckHTTPResponse
from rrtest.request import Request


class GetRequest(Request):
    method = "GET"


class AuthorizationRequest(GetRequest):
    request = "AuthorizationRequest"
    _request_args = {}
    tests = {"pre": [], "post": [CheckHTTPResponse]}


class AuthorizationRequestCode(AuthorizationRequest):
    _request_args = {"response_type": ["code"]}


class PostRequest(Request):
    method = "POST"


class AccessTokenRequest(PostRequest):
    request = "AccessTokenRequest"

    def __init__(self, conv):
        PostRequest.__init__(self, conv)
        self.tests["post"] = [CheckHTTPResponse]
        self.kw_args = {"authn_method": "client_secret_basic"}


class Response():
    response = ""
    tests = {}

    def __init__(self):
        pass

    def __call__(self, conv, response):
        pass


class UrlResponse(Response):
    where = "url"
    ctype = "urlencoded"


class AuthzResponse(UrlResponse):
    response = "AuthorizationResponse"
    tests = {"post": [CheckAuthorizationResponse]}


class BodyResponse(Response):
    where = "body"
    ctype = "json"


class AccessTokenResponse(BodyResponse):
    response = "AccessTokenResponse"

    def __init__(self):
        BodyResponse.__init__(self)
        self.tests = {"post": [VerifyAccessTokenResponse]}


PHASES = {
    "login": (AuthorizationRequestCode, AuthzResponse),
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