#!/usr/bin/env python
from rrtest.status import ERROR
from rrtest.status import WARNING
from oictest.testfunc import id_token_hint
from oictest.testfunc import login_hint
from oictest.testfunc import ui_locales
from oictest.testfunc import acr_value

__author__ = 'roland'

ORDDESC = ["OP-Response", "OP-IDToken", "OP-nonce", "OP-scope",
           "OP-display", "OP-prompt", "OP-Req", "OP-OAuth"]

DESC = {
    "Response": "Response Type & Response Mode",
    "IDToken": "ID Token",
    "nonce": "nonce Request Parameter",
    "scope": "scope Request Parameter",
    "display": "display Request Parameter",
    "prompt": "prompt Request Parameter",
    "Req": "Misc Request Parameters",
    "OAuth": "OAuth behaviors",
}

FLOWS = {
    'OP-Response-code': {
        "desc": 'Request with response_type=code',
        "sequence": ['_discover_', "_register_", "_login_"],
        "profile": "..",
        'tests': {"check-http-response": {}},
        "mti": {"all": "MUST"}
    },
    'OP-Response-Missing': {
        "desc": 'Authorization request missing the response_type parameter',
        "sequence": [
            '_discover_',
            '_register_',
            'note',
            ('_login_', {
                "request_args": {"response_type": []},
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
    'OP-IDToken-Signature': {
        # RS256 is MTI
        "desc": 'If left to itself is the OP signing the ID Token and with '
                'what',
        "sequence": [
            '_discover_',
            "_login_",
            '_accesstoken_'],
        "profile": "..",
        "tests": {"is-idtoken-signed": {"alg": "RS256"},
                  "check-http-response": {}}
    },
    'OP-IDToken-kid': {
        "desc": 'IDToken has kid',
        "sequence": ['_discover_', '_register_', "_login_", "_accesstoken_"],
        "mti": {"all": "MUST"},
        "profile": "..",
        "tests": {"verify-signed-idtoken-has-kid": {},
                  "check-http-response": {}}
    },
    'OP-IDToken-nonce-code': {
        "desc": 'ID Token has nonce when requested for code flow',
        "sequence": [
            '_discover_',
            '_register_',
            ('_login_', {"request_args": {"nonce": "godmorgon"}}),
            '_accesstoken_'],
        "mti": {"all": "MUST"},
        "profile": "..",
        "tests": {"verify-nonce": {}, "check-http-response": {}}
    },
    'OP-IDToken-max_age=1': {
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
                  "check-http-response": {},
                  "claims-check": {"id_token": ["auth_time"],
                                   "required": True}},
        "mti": {"all": "MUST"},
        "result": "The test passed if you were prompted to log in"
    },
    'OP-IDToken-max_age=1000': {
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
                  "check-http-response": {},
                  "claims-check": {"id_token": ["auth_time"],
                                   "required": True}},
        "mti": {"all": "MUST"}
    },
    'OP-IDToken-at_hash': {
        "desc": 'ID Token has at_hash when ID Token and Access Token returned '
                'from Authorization Endpoint',
        "sequence": ['_discover_', '_register_', '_login_'],
        "mti": {"all": "MUST"},
        "test": {'verify-athash': {}, "check-http-response": {}},
        "profile": "IT,CIT..",
    },
    'OP-IDToken-nonce-noncode': {
        "desc": 'Request with nonce, verifies it was returned in id_token',
        "sequence": ['_discover_', '_register_', '_login_', '_accesstoken_'],
        "tests": {"check-http-response": {}, 'check-idtoken-nonce': {}},
        "profile": "..",
        "mti": {"all": "MUST"}
    },
    'OP-IDToken-HS256': {
        "desc": 'Symmetric ID Token signature with HS256',
        "sequence": [
            '_discover_',
            ("oic-registration",
             {"request_args": {"id_token_signed_response_alg": "HS256"}}),
            "_login_", "_accesstoken_"],
        "profile": "..T.s",
        "tests": {"verify-idtoken-is-signed": {"alg": "HS256"},
                  "check-http-response": {}}
    },
    'OP-IDToken-ES256': {
        "desc": 'Asymmetric ID Token signature with ES256',
        "sequence": [
            '_discover_',
            ("oic-registration",
             {"request_args": {"id_token_signed_response_alg": "ES256"}}),
            "_login_", "_accesstoken_"],
        "profile": "..T.s",
        "tests": {"verify-idtoken-is-signed": {"alg": "ES256"},
                  "check-http-response": {}}
    },
    'OP-IDToken-SigEnc': {
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
                  "check-http-response": {}}
    },
    'OP-nonce-NoReq-code': {
        "desc": 'Login no nonce, code flow',
        "sequence": [
            '_discover_',
            '_register_',
            ('_login_', {"request_args": {"nonce": ""}})
        ],
        "profile": "C,CT..",
        'tests': {"check-http-response": {}},
        "mti": {"all": "MUST"}
    },
    'OP-scope-profile': {
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
        'tests': {"verify-claims": {}, "check-http-response": {}}
    },
    'OP-scope-email': {
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
        'tests': {"verify-claims": {}, "check-http-response": {}}
    },
    'OP-scope-address': {
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
        'tests': {"verify-claims": {}, "check-http-response": {}}
    },
    'OP-scope-phone': {
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
        'tests': {"verify-claims": {}, "check-http-response": {}}
    },
    'OP-scope-All': {
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
        'tests': {"verify-claims": {}, "check-http-response": {}}
    },
    'OP-display-page': {
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
        'tests': {"check-http-response": {}},
        "mti": {"all": "No err"}
    },
    'OP-display-popup': {
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
        'tests': {"check-http-response": {}},
        "mti": {"all": "No err"}
    },
    'OP-prompt-login': {
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
        'tests': {"multiple-sign-on": {}, "check-http-response": {}},
        "mti": {"all": "MUST"},
        # "result": "The test passed if you were prompted to log in"
    },
    'OP-prompt-none-NotLoggedIn': {
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
    'OP-prompt-none-LoggedIn': {
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
        'tests': {"same-authn": {}, "check-http-response": {}},
        "profile": "..",
        "result": "The test passed if you were not prompted to log in"
    },
    'OP-Req-NotUnderstood': {
        "desc": 'Request with extra query component',
        "sequence": [
            '_discover_',
            '_register_',
            ('_login_', {"request_args": {"extra": "foobar"}})
        ],
        "profile": "..",
        'tests': {"check-http-response": {}},
        "mti": {"all": "MUST"},
    },
    'OP-Req-id_token_hint': {
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
        'tests': {"same-authn": {}, "check-http-response": {}},
        "mti": {"all": "SHOULD"},
    },
    'OP-Req-login_hint': {
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
        'tests': {"check-http-response": {}},
        "mti": {"all": "No err"},
        "result": "You should be requested to log in as a predefined user"
    },
    'OP-Req-ui_locales': {
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
        'tests': {"check-http-response": {}},
        "mti": {"all": "No err"}
    },
    'OP-Req-acr_values': {
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
        'tests': {"used-acr-value": {}, "check-http-response": {}}
    },
    'OP-OAuth-2nd': {
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
    'OP-OAuth-2nd-30s': {
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