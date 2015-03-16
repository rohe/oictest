#!/usr/bin/env python
from oic.oauth2 import ErrorResponse
from oic.oic import AccessTokenResponse
from oic.oic import AuthorizationResponse
from oic.oic import OpenIDSchema
from rrtest.status import ERROR
from rrtest.status import WARNING
from oictest.testfunc import id_token_hint
from oictest.testfunc import login_hint
from oictest.testfunc import ui_locales
from oictest.testfunc import acr_value
from testfunc import rm

__author__ = 'roland'

ORDDESC = ["GSMA-Response", "GSMA-acr_values", "GSMA-IDToken", "GSMA-scope",
           "GSMA-display", "GSMA-prompt", "GSMA-Req", "GSMA-OAuth"]

DESC = {
    "Response": "Response Type & Response Mode",
    "acr_values": "acr_values Request Parameter",
    "IDToken": "ID Token",
    "scope": "scope Request Parameter",
    "display": "display Request Parameter",
    "prompt": "prompt Request Parameter",
    "Req": "Misc Request Parameters",
    "OAuth": "OAuth behaviors",
}

FLOWS = {
    'GSMA-Response-code': {
        "desc": 'Request with response_type=code',
        "sequence": [
            '_discover_',
            "_register_",
            "_login_"
        ],
        "profile": "..",
        'tests': {"check-http-response": {}},
        "mti": {"all": "MUST"}
    },
    'GSMA-Response-Missing': {
        "desc": 'Authorization request missing the response_type parameter',
        "sequence": [
            '_discover_',
            '_register_',
            'note',
            ('_login_', {
                "request_args": {"acr_values": ["2"], "response_type": []},
            })
        ],
        "tests": {
            "verify-error": {"error": ["invalid_request",
                                       "unsupported_response_type"]}},
        "note": "There are two correct responses: 1) returning error response "
                "to the RP 2) returning error message to the User and that in "
                "case (2) occurs the tester must submit a screen shot as proof "
                "when sending in a certification application",
        "profile": "..",
        "mti": {"all": "MUST"}
    },
    "GSMA-acr_values-2": {
        "desc": 'Request with acr_values=["2"]',
        "sequence": [
            '_discover_',
            "_register_",
            ("_login_", {"request_args": {"acr_values": ["2"]}})
        ],
        "profile": "..",
        'tests': {"verify-response": {"response_cls": [AuthorizationResponse]}},
        "mti": {"all": "MUST"}
    },
    "GSMA-acr_values-3": {
        "desc": 'Request with acr_values=["3"]',
        "sequence": [
            '_discover_',
            "_register_",
            ("_login_", {"request_args": {"acr_values": ["3"]}})
        ],
        "profile": "..",
        'tests': {"verify-response": {"response_cls": [AuthorizationResponse]}},
        "mti": {"all": "MUST"}
    },
    'GSMA-IDToken-basic': {
        # RS256 is MTI
        "desc": 'End-to-end test case to include all the mandatory parameter '
                'in the authorization request and receive authorization code '
                'as well as ID Token and Access Token',
        "sequence": [
            '_discover_',
            "_register_",
            ("_login_", {"request_args": {"acr_values": ["3"]}}),
            '_accesstoken_'],
        "profile": "..",
        'tests': {"verify-response": {"response_cls": [AuthorizationResponse,
                                                       AccessTokenResponse]}},
    },
    'GSMA-IDToken-different-sub': {
        # RS256 is MTI
        "desc": "Verify that 2 RPs don't get the same sub",
        "sequence": ['_discover_', "_register_", "_login_", '_accesstoken_',
                     "_register_", "_login_", "_accesstoken_"],
        "profile": "..",
        "tests": {"check-http-response": {},
                  "verify-response": {"response_cls": [AuthorizationResponse,
                                                       AccessTokenResponse]},
                  "verify-different-sub": {}}
    },
    'GSMA-IDToken-Signature': {
        # RS256 is MTI
        "desc": 'If left to itself is the OP signing the ID Token and with '
                'what',
        "sequence": [
            '_discover_',
            "_login_",
            '_accesstoken_'],
        "profile": "..",
        "tests": {"is-idtoken-signed": {"alg": "RS256"},
                  "verify-response": {"response_cls": [AuthorizationResponse,
                                                       AccessTokenResponse]}}
    },
    'GSMA-IDToken-kid': {
        "desc": 'IDToken has kid',
        "sequence": ['_discover_', '_register_', "_login_", "_accesstoken_"],
        "mti": {"all": "MUST"},
        "profile": "..",
        "tests": {"verify-signed-idtoken-has-kid": {},
                  "verify-response": {"response_cls": [AuthorizationResponse,
                                                       AccessTokenResponse]}}
    },
    'GSMA-IDToken-max_age=1': {
        "desc": 'Requesting ID Token with max_age=1 seconds Restriction',
        "sequence": [
            '_discover_',
            '_register_',
            "_login_",
            "_accesstoken_",
            "note",
            '_register_',
            ("_login_", {"request_args": {"max_age": 1}}),
            "_accesstoken_"
        ],
        "note": "This is to allow some time to pass. At least 1 second. "
                "The result should be that you have to re-authenticate",
        "profile": "..",
        "tests": {"multiple-sign-on": {},
                  "verify-response": {"response_cls": [AuthorizationResponse,
                                                       AccessTokenResponse]},
                  "claims-check": {"id_token": ["auth_time"],
                                   "required": True}},
        "mti": {"all": "MUST"},
        "result": "The test passed if you were prompted to log in"
    },
    'GSMA-IDToken-max_age=1000': {
        "desc": 'Requesting ID Token with max_age=1000 seconds Restriction',
        "sequence": [
            '_discover_',
            '_register_',
            "_login_",
            "_accesstoken_",
            "_register_",
            ("_login_", {"request_args": {"max_age": 1000}}),
            "_accesstoken_"
        ],
        "profile": "..",
        "tests": {"same-authn": {},
                  "verify-response": {"response_cls": [AuthorizationResponse,
                                                       AccessTokenResponse]},
                  "claims-check": {"id_token": ["auth_time"],
                                   "required": True}},
        "mti": {"all": "MUST"}
    },
    'GSMA-IDToken-at_hash': {
        "desc": 'ID Token has at_hash when ID Token and Access Token returned '
                'from Authorization Endpoint',
        "sequence": ['_discover_', '_register_', '_login_'],
        "mti": {"all": "MUST"},
        "test": {'verify-athash': {},
                 "verify-response": {"response_cls": [AuthorizationResponse,
                                                      AccessTokenResponse]}},
        "profile": "IT,CIT..",
    },
    'GSMA-IDToken-nonce': {
        "desc": 'Request with nonce, verifies it was returned in id_token',
        "sequence": ['_discover_', '_register_', '_login_', '_accesstoken_'],
        "tests": {
            "verify-response": {"response_cls": [AuthorizationResponse,
                                                       AccessTokenResponse]},
            'check-idtoken-nonce': {}},
        "profile": "..",
        "mti": {"all": "MUST"}
    },
    'GSMA-IDToken-HS256': {
        "desc": 'Symmetric ID Token signature with HS256',
        "sequence": [
            '_discover_',
            ("oic-registration",
             {"request_args": {"id_token_signed_response_alg": "HS256"}}),
            "_login_", "_accesstoken_"],
        "profile": "..T.s",
        "tests": {"verify-idtoken-is-signed": {"alg": "HS256"},
                  "verify-response": {"response_cls": [AuthorizationResponse,
                                                       AccessTokenResponse]}}
    },
    'GSMA-IDToken-ES256': {
        "desc": 'Asymmetric ID Token signature with ES256',
        "sequence": [
            '_discover_',
            ("oic-registration",
             {"request_args": {"id_token_signed_response_alg": "ES256"}}),
            "_login_", "_accesstoken_"],
        "profile": "..T.s",
        "tests": {"verify-idtoken-is-signed": {"alg": "ES256"},
                  "verify-response": {"response_cls": [AuthorizationResponse,
                                                       AccessTokenResponse]}}
    },
    'GSMA-IDToken-SigEnc': {
        "desc": 'Signed and encrypted ID Token',
        "sequence": [
            '_discover_',
            ("oic-registration",
             {
                 "request_args": {
                     "id_token_signed_response_alg": "RS256",
                     "id_token_encrypted_response_alg": "RSA1_5",
                     "id_token_encrypted_response_enc": "A128CBC-HS256"
                 },
                 "support": {
                     "error": {
                         "id_token_signing_alg_values_supported": "RS256",
                         "id_token_encryption_alg_values_supported": "RSA1_5",
                         "id_token_encryption_enc_values_supported":
                             "A128CBC-HS256"}
                 }
             }
            ),
            "_login_", "_accesstoken_"],
        "profile": "..T.se.+",
        "tests": {"signed-encrypted-idtoken": {"sign_alg": "RS256",
                                               "enc_alg": "RSA1_5",
                                               "enc_enc": "A128CBC-HS256"},
                  "verify-response": {"response_cls": [AuthorizationResponse,
                                                       AccessTokenResponse]}}
    },
    'GSMA-scope-profile': {
        "desc": 'Scope Requesting profile Claims',
        "sequence": [
            '_discover_',
            '_register_',
            ('_login_',
             {
                 "request_args": {"scope": ["openid", "profile"]},
                 "support": {"warning": {"scopes_supported": ["profile"]}}
             }),
            "_accesstoken_",
            ("userinfo", {
                "kwargs_mod": {"authn_method": "bearer_header"},
                "method": "GET"
            })
        ],
        "profile": "..",
        "mti": {"all": "No err"},
        'tests': {"verify-claims": {},
                  "verify-response": {"response_cls": [OpenIDSchema]}}
    },
    'GSMA-scope-email': {
        "desc": 'Scope Requesting email Claims',
        "sequence": [
            '_discover_',
            '_register_',
            ('_login_',
             {
                 "request_args": {"scope": ["openid", "email"]},
                 "support": {"warning": {"scopes_supported": ["email"]}}
             }),
            "_accesstoken_",
            ("userinfo", {
                "kwargs_mod": {"authn_method": "bearer_header"},
                "method": "GET"
            })
        ],
        "profile": "..",
        "mti": "No err",
        'tests': {"verify-claims": {},
                  "verify-response": {"response_cls": [OpenIDSchema]}}
    },
    'GSMA-scope-address': {
        "desc": 'Scope Requesting address Claims',
        "sequence": [
            '_discover_',
            '_register_',
            ('_login_',
             {
                 "request_args": {"scope": ["openid", "address"]},
                 "support": {"warning": {"scopes_supported": ["address"]}}
             }),
            "_accesstoken_",
            ("userinfo", {
                "kwargs_mod": {"authn_method": "bearer_header"},
                "method": "GET"
            })
        ],
        "profile": "..",
        "mti": "No err",
        'tests': {"verify-claims": {},
                  "verify-response": {"response_cls": [OpenIDSchema]}}
    },
    'GSMA-scope-phone': {
        "desc": 'Scope Requesting phone Claims',
        "sequence": [
            '_discover_',
            '_register_',
            ('_login_',
             {
                 "request_args": {"scope": ["openid", "phone"]},
                 "support": {"warning": {"scopes_supported": ["phone"]}}
             }),
            "_accesstoken_",
            ("userinfo", {
                "kwargs_mod": {"authn_method": "bearer_header"},
                "method": "GET"
            })
        ],
        "profile": "..",
        "mti": "No err",
        'tests': {"verify-claims": {},
                  "verify-response": {"response_cls": [OpenIDSchema]}}
    },
    'GSMA-scope-All': {
        "desc": 'Scope Requesting all Claims',
        "sequence": [
            '_discover_',
            '_register_',
            ('_login_',
             {
                 "request_args": {"scope": ["openid", "profile", "email",
                                            "address", "phone"]},
                 "support": {
                     "warning": {"scopes_supported": ["profile", "email",
                                                      "address", "phone"]}}
             }),
            "_accesstoken_",
            ("userinfo", {
                "kwargs_mod": {"authn_method": "bearer_header"},
                "method": "GET"
            })
        ],
        "profile": "..",
        "mti": "No err",
        'tests': {"verify-claims": {},
                  "check-http-response": {},
                  "verify-response": {"response_cls": [OpenIDSchema]}}
    },
    'GSMA-display-page': {
        "desc": 'Request with display=page',
        "sequence": [
            'note',
            '_discover_',
            '_register_',
            ('_login_',
             {
                 "request_args": {"display": "page"},
                 "support": {"warning": {"display_values_supported": "page"}}
             })
        ],
        "note": "To make sure you get a login page please remove any cookies"
                "you have received from the OpenID Provider. "
                "You should get the normal User Agent page view.",
        "profile": "..",
        'tests': {"verify-response": {"response_cls": [AuthorizationResponse]}},
        "mti": {"all": "No err"}
    },
    'GSMA-display-popup': {
        "desc": 'Request with display=popup',
        "sequence": [
            'rm_cookie',
            '_discover_',
            '_register_',
            'note',
            ('_login_',
             {
                 "request_args": {"display": "popup"},
                 "support": {"warning": {"display_values_supported": "popup"}}
             })
        ],
        "note": "To make sure you get a login page please remove any cookies"
                "you have received from the OpenID Provider. "
                "You should get a popup User Agent window",
        "profile": "..",
        'tests': {"verify-response": {"response_cls": [AuthorizationResponse,
                                                       AccessTokenResponse]}},
        "mti": {"all": "No err"}
    },
    'GSMA-prompt-login': {
        "desc": 'Request with prompt=login',
        "sequence": [
            '_discover_',
            '_register_',
            "_login_",
            '_accesstoken_',
            "note",
            ('_login_', {"request_args": {"prompt": "login"}}),
            '_accesstoken_',
        ],
        "note": "You should get a request for re-authentication",
        "profile": "..",
        'tests': {"multiple-sign-on": {},
                  "verify-response": {"response_cls": [AccessTokenResponse,
                                                       AuthorizationResponse]}},
        "mti": {"all": "MUST"},
        # "result": "The test passed if you were prompted to log in"
    },
    'GSMA-prompt-none-NotLoggedIn': {
        "desc": 'Request with prompt=none when not logged in',
        "sequence": [
            'note',
            '_discover_',
            '_register_',
            ('_login_', {"request_args": {"prompt": "none"}})
        ],
        "note": "This test tests what happens if the authentication requests "
                "specifies that the user should not be allowed to login and no"
                "recent enough authentication is present. "
                "Please remove any cookies you may have received from the "
                "OpenID provider.",
        "mti": {"all": "MUST"},
        "profile": "..",
        "tests": {"verify-error": {"error": ["login_required",
                                             "interaction_required",
                                             "session_selection_required",
                                             "consent_required"]}},
    },
    'GSMA-prompt-none-LoggedIn': {
        "desc": 'Request with prompt=none when logged in',
        "sequence": [
            '_discover_',
            '_register_',
            '_login_',
            '_accesstoken_',
            ('_login_', {"request_args": {"prompt": "none"}}),
            '_accesstoken_'
        ],
        "mti": {"all": "MUST"},
        'tests': {"same-authn": {},
                  "verify-response": {"response_cls": [AccessTokenResponse,
                                                       AuthorizationResponse]}},
        "profile": "..",
        "result": "The test passed if you were not prompted to log in"
    },
    'GSMA-Req-No-state': {
        "desc": 'Request without state parameter',
        "sequence": [
            '_discover_',
            '_register_',
            ('_login_', {"function": (rm, {"args": ["state"]})})
        ],
        "profile": "..",
        'tests': {"verify-response": {"response_cls": [ErrorResponse]}},
        "mti": {"all": "MUST"},
    },
    'GSMA-Req-No-nonce': {
        "desc": 'Request without state parameter',
        "sequence": [
            '_discover_',
            '_register_',
            ('_login_', {"function": (rm, {"args": ["nonce"]})})
        ],
        "profile": "..",
        'tests': {"verify-response": {"response_cls": [ErrorResponse]}},
        "mti": {"all": "MUST"},
    },
    'GSMA-Req-No-acr_values': {
        "desc": 'Request without acr_values parameter',
        "sequence": [
            '_discover_',
            '_register_',
            ('_login_', {"function": (rm, {"args": ["acr_values"]})})
        ],
        "profile": "..",
        'tests': {"verify-response": {"response_cls": [ErrorResponse]}},
        "mti": {"all": "MUST"},
    },
    'GSMA-Req-No-redirect_uri': {
        "desc": 'Request without redirect_uri parameter',
        "sequence": [
            '_discover_',
            '_register_',
            ('_login_', {"function": (rm, {"args": ["redirect_uri"]})})
        ],
        "profile": "..",
        'tests': {"verify-response": {"response_cls": [ErrorResponse]}},
        "mti": {"all": "MUST"},
    },
    'GSMA-Req-extra-parameter': {
        "desc": 'Request with extra query component',
        "sequence": [
            '_discover_',
            '_register_',
            ('_login_', {"request_args": {"extra": "foobar"}})
        ],
        "profile": "..",
        'tests': {"verify-response": {"response_cls": [AuthorizationResponse]}},
        "mti": {"all": "MUST"},
    },
    'GSMA-Req-id_token_hint': {
        "desc": 'Using prompt=none with user hint through id_token_hint',
        "sequence": [
            '_discover_',
            '_register_',
            "_login_",
            "_accesstoken_",
            "cache-id_token",
            'note',
            '_discover_',
            '_register_',
            ('_login_', {
                "request_args": {"prompt": "none"},
                "function": id_token_hint}),
            "_accesstoken_",
        ],
        "note": "This test tests what happens if the authentication request "
                "specifies that the user should not be allowed to login and "
                "the RP has received an ID Token at a previous login by the "
                "user. The RP should send the ID Token to the OpenID provider "
                "as a hint to who the user is. "
                "Please remove any cookies you may have received from the "
                "OpenID provider.",
        "profile": "..",
        'tests': {"same-authn": {},
                  "verify-response": {"response_cls": [AuthorizationResponse,
                                                       AccessTokenResponse]}},
        "mti": {"all": "SHOULD"},
    },
    'GSMA-Req-login_hint': {
        "desc": 'Providing login_hint',
        "sequence": [
            'note',
            '_discover_',
            '_register_',
            ("_login_", {"function": login_hint})
        ],
        "note": "Please remove the cookies you have received from the "
                "provider. We are simulating that you want to log in as "
                "a specific user. So a fresh log-in page is needed.",
        "profile": "..",
        'tests': {"verify-response": {"response_cls": [AuthorizationResponse]}},
        "mti": {"all": "No err"},
        "result": "You should be requested to log in as a predefined user"
    },
    'GSMA-Req-ui_locales': {
        "desc": 'Providing ui_locales',
        "sequence": [
            'note',
            '_discover_',
            '_register_',
            ('_login_', {"request_args": {},
                         "function": ui_locales}),
        ],
        "note": "Please remove the cookies you have received from the "
                "provider. You need to do this so you can check that the "
                "log-in page is in the right locale. "
                "The use of this parameter in the request must not cause an "
                "error at the OP",
        "profile": "..",
        'tests': {"verify-response": {"response_cls": [AuthorizationResponse]}},
        "mti": {"all": "No err"}
    },
    'GSMA-Req-acr_values': {
        "desc": 'Providing acr_values',
        "sequence": [
            '_discover_',
            '_register_',
            ('_login_', {"request_args": {},
                         "function": acr_value}),
            "_accesstoken_",
        ],
        "mti": {"all": "No err"},
        "profile": "..",
        'tests': {"used-acr-value": {},
                  "verify-response": {"response_cls": [AuthorizationResponse,
                                                       AccessTokenResponse]}}
    },
    'GSMA-OAuth-2nd': {
        "desc": 'Trying to use access code twice should result in an error',
        "sequence": [
            '_discover_',
            '_register_',
            '_login_',
            "_accesstoken_",
            "_accesstoken_"
        ],
        "profile": "..",
        "tests": {"verify-bad-request-response": {"status": WARNING}},
        "mti": {"all": "SHOULD"},
        "reference": "http://tools.ietf.org/html/draft-ietf-oauth-v2-31"
                     "#section-4.1",
    },
    'GSMA-OAuth-2nd-30s': {
        "desc": 'Trying to use access code twice with 30 seconds in between '
                'must result in an error',
        "sequence": [
            'note',
            '_discover_',
            '_register_',
            '_login_',
            "_accesstoken_",
            "intermission",
            "_accesstoken_"
        ],
        "profile": "..",
        "tests": {"verify-bad-request-response": {"status": ERROR}},
        "mti": {"all": "SHOULD"},
        "note": "An 30 second delay is added between the first and the second "
                "access token request.",
        "reference": "http://tools.ietf.org/html/draft-ietf-oauth-v2-31"
                     "#section-4.1",
    },
}