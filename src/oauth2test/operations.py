from oauth2test.check import CheckAuthorizationResponse
from oauth2test.check import CheckErrorResponseForInvalidType
from oauth2test.check import CheckSecondCodeUsageErrorResponse
from oauth2test.check import CheckPresenceOfStateParameter
from oauth2test.check import VerifyAccessTokenResponse
from rrtest.check import CheckHTTPResponse, VerifyError
from rrtest.request import BodyResponse
from rrtest.request import ErrorResponse
from rrtest.request import GetRequest
from rrtest.request import PostRequest
from rrtest.request import UrlResponse


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
    tests = {"post": [VerifyAccessTokenResponse]}


class AccessTokenSecondRequest(AccessTokenRequest):
    tests = {"post": [VerifyError]}


class AccessTokenSecondResponse(AccessTokenResponse):
    tests = {"post": [CheckSecondCodeUsageErrorResponse]}


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


PHASES = {
    "login": (AuthorizationRequestCode, AuthorizationResponse),
    "access-token-request": (AccessTokenRequest, AccessTokenResponse),
    "access-token-second-request": (AccessTokenSecondRequest,
                                    AccessTokenSecondResponse),
    "login-with-state": (AuthorizationRequestCodeWithState,
                         AuthorizationResponseWhichForcesState),
    "access-token-request-invalid-type": (AccessTokenInvalidTypeRequest,
                                          AccessTokenInvalidTypeResponse),
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
    'code-idtoken-double_post': {
        "name": 'Basic Code flow with two requests for ID Token',
        "descr": ('Very basic test of a Provider using the authorization code ',
                  'flow. The test tool acting as a consumer is very relaxed',
                  'and tries to obtain an ID Token.'),
        "depends": ["basic-code-authn"],
        "sequence": ["login", "access-token-request",
                     "access-token-second-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint"]
    },
    'code-presence-of-state': {
        'name': 'Basic Code flow with authentication which checks for state parameter',
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
}
