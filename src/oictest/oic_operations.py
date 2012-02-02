#!/usr/bin/env python
__author__ = 'rohe0002'

# ========================================================================

from oictest.check import *
# Used upstream not in this module so don't remove
from oictest.opfunc import *

# ========================================================================

RESPOND = {
    "method": "POST",
    }

AUTHZREQ_CODE = {
    "request": "AuthorizationRequest",
    "method": "GET",
    "args": {
        "request": {"response_type": "code",
                    "scope": ["openid"],
        },
    },
}

AUTHZRESP = {
    "response": "AuthorizationResponse",
    "where": "url",
    "type": "urlencoded",
    "tests": {"post": [CheckAuthorizationResponse]}
    }

OPENID_REQUEST_CODE = {
    "request": "OpenIDRequest",
    "method": "GET",
    "args": {"request": {"response_type": "code", "scope": ["openid"]}},
    "tests": {
        "pre": [CheckResponseType],
        "post": [CheckHTTPResponse]
    }
}

OPENID_REQUEST_TOKEN = {
    "request": "OpenIDRequest",
    "method": "GET",
    "args": {"request": {"response_type": "token", "scope": ["openid"]}},
    "tests": {
        "pre": [CheckResponseType],
        "post": [CheckHTTPResponse]
    }
}

# {"OpenIDRequest": {"request", {"response_type":["code","token"]}}}

OPENID_REQUEST_CODE_TOKEN = {
    "request": "OpenIDRequest",
    "method": "GET",
    "args": {"request": {"response_type": ["code","token"],
                         "scope": ["openid"]}},
    "tests": {
        "pre": [CheckResponseType],
        "post": [CheckHTTPResponse]
    }
}

OPENID_REQUEST_CODE_IDTOKEN = {
    "request": "OpenIDRequest",
    "method": "GET",
    "args": {"request": {"response_type": ["code","id_token"],
                         "scope": ["openid"]}},
    "tests": {
        "pre": [CheckResponseType],
        "post": [CheckHTTPResponse]
    }
}

OPENID_REQUEST_TOKEN_IDTOKEN = {
    "request": "OpenIDRequest",
    "method": "GET",
    "args": {"request": {"response_type": ["token","id_token"],
                         "scope": ["openid"]}},
    "tests": {
        "pre": [CheckResponseType],
        "post": [CheckHTTPResponse]
    }
}

OPENID_REQUEST_CODE_TOKEN_IDTOKEN = {
    "request": "OpenIDRequest",
    "method": "GET",
    "args": {"request": {"response_type": ["code", "token", "id_token"],
                         "scope": ["openid"]}},
    "tests": {
        "pre": [CheckResponseType],
        "post": [CheckHTTPResponse]
    }
}

# 2.1.2.1.2
# The User Identifier for which an ID Token is being requested.
# If the specified user is not currently authenticated to the Authorization
# Server, they may be prompted for authenticated, unless the prompt parameter
# in the Authorization Request is set to none. The Claim Value in the request
# is an object containing the single element value.
#"user_id": {"value":"248289761001"}

#OPENID_REQUEST_CODE_21212 = {
#    "request": "AuthorizationRequest",
#    "method": "GET",
#    "args": {
#        "request": {"response_type": "code",
#                    "scope": ["oic"],
#                    "prompt": "none"
#                    },
#        "kw": {
#            "idtoken_claims": {
#                "claims": {"user_id": {"value":"248289761001"}}
#            }
#        }
#    }
#}

ACCESS_TOKEN_RESPONSE = {
    "response": "AccessTokenResponse",
    "where": "body",
    "type": "json"
}

USER_INFO_RESPONSE = {
    "response": "OpenIDSchema",
    "where": "body",
    "type": "json"
}

ACCESS_TOKEN_REQUEST_PASSWD = {
    "request":"AccessTokenRequest",
    "method": "POST",
    "args": {
        "kw": {"authn_method": "client_secret_basic"}
    },
}

ACCESS_TOKEN_REQUEST_CLI_SECRET = {
    "request":"AccessTokenRequest",
    "method": "POST",
    "args": {
        "kw": {"authn_method": "client_secret_post"}
    },
}

USER_INFO_REQUEST = {
    "request":"UserInfoRequest",
    "method": "POST",
    "args": {
        "kw": {"authn_method": "bearer_header"}
    },
}

USER_INFO_REQUEST_BODY = {
    "request":"UserInfoRequest",
    "method": "POST",
    "args": {
        "kw": {"authn_method": "bearer_body"}
    },
}

USER_INFO_REQUEST_BODY_GET = {
    "request":"UserInfoRequest",
    "method": "GET",
    "args": {
        "kw": {"authn_method": "bearer_body"}
    },
}

PROVIDER_CONFIGURATION = {
    "request": "ProviderConfigurationRequest"
}

CHECK_ID_REQUEST = {
    "request": "CheckIDRequest",
    "method": "POST"
}

CHECK_ID_RESPONSE = {
    "response": "IdToken",
    "where": "body",
    "type": "json"
}

PHASES= {
    "login": (AUTHZREQ_CODE, AUTHZRESP),
    "oic-login": (OPENID_REQUEST_CODE, AUTHZRESP),
    "oic-login-token": (OPENID_REQUEST_TOKEN, AUTHZRESP),
    "oic-login-code+token": (OPENID_REQUEST_CODE_TOKEN, AUTHZRESP),
    "oic-login-code+idtoken": (OPENID_REQUEST_CODE_IDTOKEN, AUTHZRESP),
    "oic-login-idtoken+token": (OPENID_REQUEST_TOKEN_IDTOKEN, AUTHZRESP),
    "oic-login-code+idtoken+token": (OPENID_REQUEST_CODE_TOKEN_IDTOKEN,
                                     AUTHZRESP),
#
    "access-token-request":(ACCESS_TOKEN_REQUEST_CLI_SECRET,
                            ACCESS_TOKEN_RESPONSE),
    "check-id-request":(CHECK_ID_REQUEST, CHECK_ID_RESPONSE),
    "user-info-request":(USER_INFO_REQUEST_BODY, USER_INFO_RESPONSE)
}


FLOWS = {
    'oic-code': {
        "name": 'First phase in a OpenID Connect Code flow',
        "descr": ('Very basic test of a Provider using the authorization code ',
                  'flow. The test tool acting as a consumer is very relaxed',
                  'and tries to obtain an access code.'),
        "sequence": ["oic-login"],
        "endpoints": ["authorization_endpoint"]
    },
    'oic-token': {
        "name": 'Basic OpenID Connect implicit flow with authentication',
        "descr": ('Very basic test of a OIC Provider using the implicit ',
                  'flow. The test tool acting as a consumer is very relaxed',
                  'and tries to obtain an access token.'),
        "sequence": ["oic-login-token"],
        "endpoints": ["authorization_endpoint"]
    },
    'oic-code+token': {
        "name": 'Implicit flow with Code+Token ',
        "descr": ("Does an Authentication Request with",
            "response type = ['code','token']"),
        "sequence": ["oic-login-code+token"],
        "endpoints": ["authorization_endpoint"],
        },
    'oic-code+idtoken': {
        "name": 'Implicit flow with Code+IDToken ',
        "descr": ("Does an Authentication Request with",
                  "response type = ['code','idtoken']"),
        "sequence": ['oic-login-code+idtoken'],
        "endpoints": ["authorization_endpoint"],
        },
    'oic-idtoken+token': {
        "name": 'Implicit flow with Token+IDToken ',
        "descr": ("Does an Authentication Request with",
                  "response type = ['token','idtoken']"),
        "sequence": ['oic-login-idtoken+token'],
        "endpoints": ["authorization_endpoint"],
        },
    'oic-code+idtoken+token': {
        "name": 'Implicit flow with Code+Token+IDToken ',
        "descr": ("Does an Authentication Request with",
                  "response type = ['code','token','idtoken']"),
        "sequence": ['oic-login-code+idtoken+token'],
        "endpoints": ["authorization_endpoint",],
        },
    # -------------------------------------------------------------------------
    'oic-code-token': {
        "name": 'Basic Code flow with Token fetching',
        "descr": ("Does an Authentication Request and then using",
                  "the access code received asks for an access token.",
                  "Authentication method used is 'client_secret_post'"),
        "depends": ['oic-code'],
        "sequence": ["oic-login", "access-token-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint"],
        },
    'oic-code+token-token': {
        "name": ("Get an accesstoken using access code with 'token' in ",
                "response type"),
        "descr": ("Does an Authentication Request with",
                  "response type = ['code','token'] and then",
                  "does a Token request"),
        "depends": ['oic-code+token'],
        "sequence": ["oic-login-code+token", "access-token-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint"],
        },
    'oic-code+idtoken-token': {
        "name": ("Get an accesstoken using access code with 'idtoken' in ",
                 "response type"),
        "descr": ("Does an Authentication Request with",
                  "response type = ['code','idtoken'] and then",
                  "does a Token request"),
        "depends": ['oic-code+idtoken'],
        "sequence": ["oic-login-code+idtoken", "access-token-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint"],
        },
    'oic-code+idtoken+token-token': {
        "name": ("Get an accesstoken using access code with 'token' and ",
                 "'idtoken' in response type"),
        "descr": ("Does an Authentication Request with",
                  "response type = ['code','token','idtoken']",
                  "does a Token request"),
        "depends": ['oic-code+idtoken+token'],
        "sequence": ["oic-login-code+idtoken+token", "access-token-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint"],
        },
    # -------------------------------------------------------------------------
    'oic-code-token-userinfo': {
        "name": 'Basic Code flow with User info fetching',
        "descr": ("Does an Authentication request, an token request",
                  " and then an UserInfo request.",
                  "Authentication used is 'bearer_header'."),
        "depends": ['oic-code-token'],
        "sequence": ["oic-login", "access-token-request", "user-info-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint",
                      "userinfo_endpoint"],
        },
    'oic-token-userinfo': {
        "name": 'Token flow with ID Token and User data',
        "descr": ("Uses the implicit flow with the response type",
                  " 'token idtoken' and then uses the idtoken to get",
                  " some user info.",
                  "Authentication used is 'bearer_header'."),
        "depends": ['oic-token'],
        "sequence": ['oic-login-token', "user-info-request"],
        "endpoints": ["authorization_endpoint", "userinfo_endpoint"],
        },
    'oic-code+token-userinfo': {
        "name": 'Implicit flow with Code+IDToken ',
        "descr": ("Does an Authentication Request with",
                  "response type = ['code','idtoken']"),
        "depends": ['oic-code+token'],
        "sequence": ['oic-login-code+idtoken', "user-info-request"],
        "endpoints": ["authorization_endpoint", "userinfo_endpoint"],
        },
    'oic-code+idtoken-token-userinfo': {
        "name": 'Implicit flow with Code+IDToken ',
        "descr": ("Does an Authentication Request with",
                  "response type = ['code','idtoken']"),
        "depends": ['oic-code+idtoken-token'],
        "sequence": ['oic-login-code+idtoken', "access-token-request",
                     "user-info-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint",
                      "userinfo_endpoint"],
        },
    'oic-idtoken+token-userinfo': {
        "name": 'Implicit flow with Token+IDToken ',
        "descr": ("Does an Authentication Request with",
                  "response type = ['token','idtoken']"),
        "depends": ['oic-idtoken+token'],
        "sequence": ['oic-login-idtoken+token', "user-info-request"],
        "endpoints": ["authorization_endpoint", "userinfo_endpoint"],
        },
    'oic-code+idtoken+token-userinfo': {
        "name": 'Implicit flow with Code+Token+IDToken ',
        "descr": ("Does an Authentication Request with",
                  "response type = ['code','token','idtoken']"),
        "depends":["oic-code+idtoken+token"],
        "sequence": ['oic-login-code+idtoken+token', "user-info-request"],
        "endpoints": ["authorization_endpoint", "userinfo_endpoint"],
        },
    'oic-code+idtoken+token-token-userinfo': {
        "name": ("Get an accesstoken using access code with 'token' and ",
                 "'idtoken' in response type"),
        "descr": ("Does an Authentication Request with",
                  "response type = ['code','token','idtoken']",
                  "does a Token request"),
        "depends": ['oic-code+idtoken+token-token'],
        "sequence": ["oic-login-code+idtoken+token", "access-token-request",
                     'user-info-request'],
        "endpoints": ["authorization_endpoint", "token_endpoint",
                      "userinfo_endpoint"],
        },

    # -------------------------------------------------------------------------
    'oic-code-token-check_id': {
        "name": 'Basic Code flow with IdToken checking',
        "descr": ('Does an Authentication request, an token request',
                  ' and then an UserInfo request'),
        "depends": ['oic-code-token'],
        "sequence": ["oic-login", "access-token-request", "check-id-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint",
                      "check_id_endpoint"],
        },
    'oic-idtoken+token-check_id': {
        "name": 'OpenID Connect Token flow with check id',
        "descr": ("Very basic test of a OIC Provider using the token ",
                  "flow with response type ['token','idtoken'].",
                  "And then does a check ID request"),
        "depends": ['oic-idtoken+token'],
        "sequence": ['oic-login-idtoken+token', "check-id-request"],
        "endpoints": ["authorization_endpoint", "check_id_endpoint"],
        "tests": ["compare-idoken-received-with-check_id-response"]
    },
    'oic-code+idtoken-check_id': {
        "name": 'Implicit flow with Code+Token+IDToken ',
        "descr": ("Does an Authentication Request with",
                  "response type = ['code','token','idtoken']"),
        "depends":["oic-code+idtoken"],
        "sequence": ['oic-login-code+idtoken', "check-id-request"],
        "endpoints": ["authorization_endpoint", "check_id_endpoint"],
        "tests": ["compare-idoken-received-with-check_id-response"]
    },
    'oic-code+idtoken+token-check_id': {
        "name": 'Implicit flow with Code+Token+IDToken ',
        "descr": ("Does an Authentication Request with",
                  "response type = ['code','token','idtoken']"),
        "depends":["oic-code+idtoken+token"],
        "sequence": ['oic-login-code+idtoken+token', "check-id-request"],
        "endpoints": ["authorization_endpoint", "check_id_endpoint"],
        "tests": ["compare-idoken-received-with-check_id-response"]
    },
}

if __name__ == "__main__":
    for name, spec in FLOWS.items():
        try:
            for dep in spec["depends"]:
                try:
                    assert dep in FLOWS
                except AssertionError:
                    print "%s missing in FLOWS" % dep
                    raise
        except KeyError:
            pass
        for op in spec["sequence"]:
            try:
                assert op in PHASES
            except AssertionError:
                print "%s missing in PHASES" % op
                raise