#!/usr/bin/env python
from rrtest.status import ERROR
from rrtest.status import WARNING
from oictest.testfunc import store_sector_redirect_uris
from oictest.testfunc import get_principal
from oictest.testfunc import id_token_hint
from oictest.testfunc import request_in_file
from oictest.testfunc import sub_claims
from oictest.testfunc import specific_acr_claims
from oictest.testfunc import login_hint
from oictest.testfunc import policy_uri
from oictest.testfunc import logo_uri
from oictest.testfunc import tos_uri
from oictest.testfunc import static_jwk
from oictest.testfunc import redirect_uris_with_query_component
from oictest.testfunc import redirect_uris_with_fragment
from oictest.testfunc import ui_locales
from oictest.testfunc import claims_locales
from oictest.testfunc import acr_value
from oictest.testfunc import mismatch_return_uri
from oictest.testfunc import multiple_return_uris
from oictest.testfunc import redirect_uri_with_query_component

__author__ = 'roland'

USERINFO_REQUEST_AUTH_METHOD = (
    "userinfo", {
        "kwargs_mod": {"authn_method": "bearer_header"},
        "method": "GET"
    })

ORDDESC = ["OP-Response", "OP-IDToken", "OP-UserInfo", "OP-nonce", "OP-scope",
           "OP-display", "OP-prompt", "OP-Req", "OP-OAuth", "OP-redirect_uri",
           "OP-ClientAuth", "OP-Discovery", "OP-Registration", "OP-Rollover",
           "OP-request_uri", "OP-request", "OP-claims"]

DESC = {
    "Response": "Response Type & Response Mode",
    "IDToken": "ID Token",
    "UserInfo": "Userinfo Endpoint",
    "nonce": "nonce Request Parameter",
    "scope": "scope Request Parameter",
    "display": "display Request Parameter",
    "prompt": "prompt Request Parameter",
    "Req": "Misc Request Parameters",
    "OAuth": "OAuth behaviors",
    "redirect_uri": "redirect_uri",
    "ClientAuth": "Client Authentication",
    "Discovery": "Discovery",
    "Registration": "Dynamic Client Registration",
    "Rollover": "Key Rollover",
    "request_uri": "request_uri Request Parameter",
    "request": "request Request Parameter",
    "claims": "claims Request Parameter",
}

FLOWS = {
    'OP-Response-code': {
        "desc": 'Request with response_type=code',
        "sequence": ['_discover_', "_register_", "_login_"],
        "profile": "C..",
        'tests': {"verify-authn-response": {}},
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
    'OP-Response-id_token': {
        "desc": 'Request with response_type=id_token',
        "sequence": [
            '_discover_',
            '_register_',
            ("_login_", {
                "request_args": {"response_type": ["id_token"]}
            }),
        ],
        "profile": "I..",
        'tests': {"verify-authn-response": {}},
        "mti": {"dynamic": "MUST"},
        # "tests": {"check-authorization-response": {}},
    },
    'OP-Response-id_token+token': {
        "desc": 'Request with response_type=id_token token',
        "sequence": [
            '_discover_',
            '_register_',
            ('_login_',
             {"request_args": {"response_type": ["id_token", "token"]}})
        ],
        "profile": "IT..",
        'tests': {"verify-authn-response": {}},
        "mti": {"dynamic": "MUST"}
    },
    'OP-Response-code+id_token': {
        "desc": 'Request with response_type=code id_token',
        "sequence": ['_discover_', '_register_', '_login_'],
        "tests": {"verify-authn-response": {}, 'check-idtoken-nonce': {}},
        "profile": "CI..",
    },
    'OP-Response-code+token': {
        "desc": 'Request with response_type=code token',
        "sequence": [
            '_discover_',
            '_register_',
            ('_login_',
             {"request_args": {"response_type": ["code", "token"]}})
        ],
        "profile": "CT..",
        'tests': {"verify-authn-response": {}},
    },
    'OP-Response-code+id_token+token': {
        "desc": 'Request with response_type=code id_token token',
        "sequence": [
            '_discover_',
            '_register_',
            ('_login_',
             {"request_args": {"response_type": ["code", "id_token", "token"]}})
        ],
        "profile": "CIT..",
        'tests': {"verify-authn-response": {}},
    },
    'OP-Response-form_post': {
        "desc": 'Request with response_mode=form_post',
        "sequence": [
            '_discover_',
            '_register_',
            ('_login_',
             {"request_args": {"response_mode": ["form_post"]}})
        ],
        "profile": "....+",
        'tests': {"verify-authn-response": {}},
    },
    'OP-IDToken-RS256': {
        "desc": 'Asymmetric ID Token signature with rs256',
        "sequence": [
            '_discover_',
            ("oic-registration",
             {"request_args": {"id_token_signed_response_alg": "RS256"}}),
            "_login_", "_accesstoken_"],
        "profile": "..T.s",
        "mti": {"all": "MUST"},
        "tests": {"verify-idtoken-is-signed": {"alg": "RS256"},
                  "verify-authn-response": {}}
    },
    'OP-IDToken-Signature': {
        # RS256 is MTI
        "desc": 'If left to itself is the OP signing the ID Token and with '
                'what',
        "sequence": [
            '_discover_',
            "_login_",
            '_accesstoken_'],
        "profile": "..F",
        "tests": {"is-idtoken-signed": {"alg": "RS256"},
                  "check-http-response": {}}
    },
    'OP-IDToken-kid': {
        "desc": 'IDToken has kid',
        "sequence": ['_discover_', '_register_', "_login_", "_accesstoken_"],
        "mti": {"all": "MUST"},
        "profile": "...s",
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
        "profile": "C..",
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
    'OP-IDToken-none': {
        "desc": 'Unsecured ID Token signature with none',
        "sequence": [
            '_discover_',
            ("oic-registration",
             {
                 "request_args": {"id_token_signed_response_alg": "none"},
                 "support": {
                     "error": {
                         "id_token_signing_alg_values_supported": "none"}},
             }
            ),
            "_login_",
            "_accesstoken_"
        ],
        "tests": {"unsigned-idtoken": {}, "check-http-response": {}},
        "profile": "C.T.T.n",
    },
    'OP-IDToken-at_hash': {
        "desc": 'ID Token has at_hash when ID Token and Access Token returned '
                'from Authorization Endpoint',
        "sequence": ['_discover_', '_register_', '_login_'],
        "mti": {"all": "MUST"},
        "test": {"verify-authn-response": {}},
        "profile": "IT,CIT..",
    },
    'OP-IDToken-c_hash': {
        "desc": 'ID Token has c_hash when ID Token and Authorization Code '
                'returned from Authorization Endpoint',
        "sequence": ['_discover_', '_register_', '_login_'],
        "tests": {"verify-authn-response": {}},
        "profile": "CI,CIT..",
        "mti": {"all": "MUST"}
    },
    'OP-IDToken-nonce-noncode': {
        "desc": 'Request with nonce, verifies it was returned in id_token',
        "sequence": ['_discover_', '_register_', '_login_', '_accesstoken_'],
        "tests": {"check-http-response": {}, 'check-idtoken-nonce': {}},
        "profile": "I,IT,CI,CT,CIT..",
        "mti": {"all": "MUST"}
    },
    'OP-IDToken-HS256': {
        "desc": 'Symmetric ID Token signature with HS256',
        "sequence": [
            '_discover_',
            ("oic-registration",
             {"request_args": {"id_token_signed_response_alg": "HS256"}}),
            "_login_",
            "_accesstoken_"],
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
            "_login_",
            "_accesstoken_"],
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
                  "verify-authn-response": {}}
    },
    'OP-UserInfo-Endpoint': {
        "desc": 'UserInfo Endpoint Access with GET and bearer_header',
        "sequence": ['_discover_', '_register_', '_login_',
                     "_accesstoken_",
                     ("userinfo",
                      {
                          "kwargs_mod": {"authn_method": "bearer_header"},
                          "method": "GET"
                      })],
        "profile": "C,IT,CI,CT,CIT..",
        'tests': {"check-http-response": {}},
        "mti": {"all": "SHOULD"}
    },
    'OP-UserInfo-Header': {
        "desc": 'UserInfo Endpoint Access with POST and bearer_header',
        "sequence": ['_discover_', '_register_', '_login_',
                     "_accesstoken_",
                     ("userinfo",
                      {
                          "kwargs_mod": {"authn_method": "bearer_header"},
                          "method": "POST"
                      })],
        "profile": "C,IT,CI,CT,CIT..",
        'tests': {"check-http-response": {}},
    },
    'OP-UserInfo-Body': {
        "desc": 'UserInfo Endpoint Access with POST and bearer_body',
        "sequence": ['_discover_', '_register_', '_login_',
                     "_accesstoken_",
                     ("userinfo",
                      {
                          "kwargs_mod": {"authn_method": "bearer_body"},
                          "method": "POST"
                      })],
        "profile": "C,IT,CI,CT,CIT..",
        'tests': {"check-http-response": {}},
    },
    'OP-UserInfo-RS256': {
        "desc": 'RP registers userinfo_signed_response_alg to signal that it '
                'wants signed UserInfo returned',
        "sequence": ['_discover_',
                     ("oic-registration",
                      {
                          "request_args": {
                              "userinfo_signed_response_alg": "RS256"},
                          "support": {
                              "warning": {
                                  "userinfo_signing_alg_values_supported":
                                      "RS256"}}
                      }
                     ),
                     '_login_',
                     "_accesstoken_",
                     ("userinfo",
                      {
                          "kwargs_mod": {"authn_method": "bearer_header"},
                          "method": "GET",
                          "ctype": "jwt"
                      })],
        "tests": {"asym-signed-userinfo": {"alg": "RS256"},
                  "check-http-response": {}},
        "profile": "C,IT,CI,CT,CIT..T.s",
        "mti": {"all": "MUST"}
    },
    'OP-UserInfo-Enc': {
        "desc": 'Can Provide Encrypted UserInfo Response',
        "sequence": [
            '_discover_',
            ("oic-registration",
             {
                 "request_args": {
                     "userinfo_signed_response_alg": "none",
                     "userinfo_encrypted_response_alg": "RSA1_5",
                     "userinfo_encrypted_response_enc": "A128CBC-HS256"
                 },
                 "support": {
                     "error": {
                         "userinfo_signing_alg_values_supported": "none",
                         "userinfo_encryption_alg_values_supported": "RSA1_5",
                         "userinfo_encryption_enc_values_supported":
                             "A128CBC-HS256"
                     }}
             }
            ),
            '_login_',
            "_accesstoken_",
            ("userinfo",
             {
                 "kwargs_mod": {"authn_method": "bearer_header"},
                 "method": "GET"
             })
        ],
        "profile": "C,IT,CI,CT,CIT...e.+",
        "tests": {"encrypted-userinfo": {}, "check-http-response": {}},
    },
    'OP-UserInfo-SigEnc': {
        "desc": 'Can Provide Signed and Encrypted UserInfo Response',
        "sequence": [
            '_discover_',
            ("oic-registration",
             {
                 "request_args": {
                     "userinfo_signed_response_alg": "RS256",
                     "userinfo_encrypted_response_alg": "RSA1_5",
                     "userinfo_encrypted_response_enc": "A128CBC-HS256"},
                 "support": {
                     "error": {
                         "userinfo_signing_alg_values_supported": "RS256",
                         "userinfo_encryption_alg_values_supported": "RSA1_5",
                         "userinfo_encryption_enc_values_supported":
                             "A128CBC-HS256"
                     }
                 }
             }
            ),
            '_login_',
            "_accesstoken_",
            ("userinfo",
             {
                 "kwargs_mod": {"authn_method": "bearer_header"},
                 "method": "GET"
             })
        ],
        "profile": "C,IT,CI,CT,CIT...se.+",
        "tests": {
            "encrypted-userinfo": {},
            "asym-signed-userinfo": {"alg": "RS256"},
            "check-http-response": {}},
    },
    'OP-nonce-NoReq-code': {
        "desc": 'Login no nonce, code flow',
        "sequence": [
            '_discover_',
            '_register_',
            ('_login_', {"request_args": {"nonce": ""}})
        ],
        "profile": "C,CT..",
        'tests': {"verify-authn-response": {}},
        "mti": {"all": "MUST"}
    },
    'OP-nonce-NoReq-noncode': {
        "desc": 'Reject requests without nonce unless using the code flow',
        "sequence": [
            '_discover_',
            '_register_',
            ('_login_', {"request_args": {"nonce": ""}})
        ],
        "tests": {"verify-error": {"error": ["invalid_request"]}},
        "profile": "I,IT..",
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
        "profile": "C,IT,CT,CI,CIT..",
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
        "profile": "C,IT,CT,CI,CIT..",
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
        "profile": "C,IT,CT,CI,CIT..",
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
        "profile": "C,IT,CT,CI,CIT..",
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
        "profile": "C,IT,CT,CI,CIT..",
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
        "note": "To make sure you get a login page please remove any cookies "
                "you have received from the OpenID Provider. "
                "You should get the normal User Agent page view.",
        "profile": "..",
        'tests': {"verify-authn-response": {}},
        "mti": {"all": "No err"}
    },
    'OP-display-popup': {
        "desc": 'Request with display=popup',
        "sequence": [
            '_discover_',
            '_register_',
            'note',
            ('_login_',
             {
                 "request_args": {"display": "popup"},
                 "support": {"warning": {"display_values_supported": "popup"}}
             })
        ],
        "note": "To make sure you get a login page please remove any cookies "
                "you have received from the OpenID Provider. "
                "You should get a popup User Agent window now",
        "profile": "..",
        'tests': {"verify-authn-response": {}},
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
                "specifies that the user should not be allowed to login and no "
                "recent enough authentication is present. "
                "Please remove any cookies you may have received from the "
                "OpenID provider.",
        "mti": {"all": "MUST"},
        "profile": "..",
        "tests": {"verify-error-response": {
            "error": ["login_required", "interaction_required",
                      "session_selection_required", "consent_required"]}},
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
        'tests': {"verify-authn-response": {}},
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
        'tests': {"verify-authn-response": {}},
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
        'tests': {"verify-authn-response": {}},
        "mti": {"all": "No err"}
    },
    'OP-Req-claims_locales': {
        "desc": 'Providing claims_locales',
        "sequence": [
            "note",
            '_discover_',
            '_register_',
            ('_login_', {"request_args": {},
                         "function": claims_locales}),
            "_accesstoken_",
            USERINFO_REQUEST_AUTH_METHOD,
            'display_userinfo'],
        "note": "Claims may now be returned in the locale of choice "
                "The use of this parameter in the request must not cause an "
                "error at the OP",
        "profile": "C,IT,CI,CT,CIT..",
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
        "profile": "C,CI,CT,CIT..",
        "tests": {"verify-error-response": {"status": WARNING}},
        "mti": {"all": "SHOULD"},
        "reference": "http://tools.ietf.org/html/draft-ietf-oauth-v2-31"
                     "#section-4.1",
    },
    'OP-OAuth-2nd-Revokes': {
        "desc": 'Trying to use access code twice should result in '
                'revoking previous issued tokens',
        "sequence": [
            '_discover_',
            '_register_',
            '_login_',
            '_accesstoken_',
            ('_accesstoken_', {
                "expect_error": {"error": ["invalid_grant"], "stop": True}}),
            USERINFO_REQUEST_AUTH_METHOD
        ],
        "profile": "C,CI,CT,CIT..",
        "tests": {"verify-error-response": {"status": WARNING}},
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
        "profile": "C,CI,CT,CIT..",
        "tests": {"verify-bad-request-response": {"status": ERROR}},
        "mti": {"all": "SHOULD"},
        "note": "An 30 second delay is added between the first and the second "
                "access token request.",
        "reference": "http://tools.ietf.org/html/draft-ietf-oauth-v2-31"
                     "#section-4.1",
    },
    'OP-redirect_uri-NotReg': {
        "desc": 'The sent redirect_uri does not match the registered',
        "sequence": [
            '_discover_',
            '_register_',
            "expect_err",
            ("_login_", {"function": mismatch_return_uri})
        ],
        "profile": "..",
        "note": "The next request should result in the OpenID Connect Provider "
                "returning an error message to your web browser.",
        'tests': {"verify-authn-response": {}},
        "mti": {"all": "MUST"},
    },
    'OP-redirect_uri-Missing': {
        "desc": 'Reject request without redirect_uri when multiple registered',
        "sequence": [
            '_discover_',
            ('_register_', {"function": multiple_return_uris}),
            "expect_err",
            ("_login_", {"request_args": {"redirect_uri": ""}})
        ],
        "profile": "..T",
        'tests': {"verify-authn-response": {}},
        "note": "The next request should result in the OpenID Connect Provider "
                "returning an error message to your web browser.",
        "mti": {"all": "MUST"},
    },
    'OP-redirect_uri-Query': {
        "desc": 'Request with redirect_uri with query component',
        "sequence": [
            '_discover_',
            '_register_',
            ("_login_",
             {"function": (redirect_uri_with_query_component, {"foo": "bar"})})
        ],
        "profile": "..T",
        "mti": {"all": "MUST"},
        'tests': {"verify-redirect_uri-query_component": {"foo": "bar"},
                  "verify-authn-response": {}}
    },
    'OP-redirect_uri-RegQuery': {
        "desc": 'Registration where a redirect_uri has a query component',
        "sequence": [
            '_discover_',
            ('_register_',
             {"function": (
                 redirect_uris_with_query_component, {"foo": "bar"})}),
        ],
        "profile": "..T",
        "mti": {"all": "MUST"},
        "reference": "http://tools.ietf.org/html/draft-ietf-oauth-v2-31"
                     "#section-3.1.2",
        'tests': {"check-http-response": {}},
    },
    'OP-redirect_uri-BadQuery': {
        "desc": 'Rejects redirect_uri when Query Parameter Does Not Match',
        "sequence": [
            '_discover_',
            ('_register_',
             {
                 "function": (
                     redirect_uris_with_query_component, {"foo": "bar"})}),
            'expect_err',
            ("_login_", {
                # different from the one registered
                "function": (redirect_uri_with_query_component, {"bar": "foo"})
            })
        ],
        "profile": "..T",
        "reference": "http://tools.ietf.org/html/draft-ietf-oauth-v2-31"
                     "#section-3.1.2",
        'tests': {"verify-authn-response": {}},
        "mti": {"all": "MUST"},
    },
    'OP-redirect_uri-RegFrag': {
        "desc": 'Reject registration where a redirect_uri has a fragment',
        "sequence": [
            '_discover_',
            ('_register_', {
                "function": (redirect_uris_with_fragment, {"foo": "bar"})})
        ],
        "profile": "..T",
        "tests": {"verify-bad-request-response": {}},
        "mti": {"all": "MUST"},
        "reference": "http://tools.ietf.org/html/draft-ietf-oauth-v2-31"
                     "#section-3.1.2",
    },
    'OP-redirect_uri-MissingOK': {
        "desc": 'No redirect_uri in request with one registered',
        "sequence": [
            '_discover_',
            '_register_',
            "expect_err",
            ('_login_', {"request_args": {"redirect_uri": ""}})
        ],
        "profile": "....+",
        'tests': {"verify-authn-response": {}},
    },
    'OP-ClientAuth-Basic-Dynamic': {
        "desc": 'Access token request with client_secret_basic authentication',
        # Register token_endpoint_auth_method=client_secret_basic
        "sequence": [
            '_discover_',
            ('_register_',
             {
                 "request_args": {
                     "token_endpoint_auth_method": "client_secret_basic"},
             }),
            '_login_',
            ("_accesstoken_",
             {
                 "kwargs_mod": {"authn_method": "client_secret_basic"},
                 "support": {
                     "warning": {
                         "token_endpoint_auth_methods_supported":
                             "client_secret_basic"}}
             }),
        ],
        "profile": "C,CI,CIT,CT..T",
        'tests': {"check-http-response": {}},
    },
    'OP-ClientAuth-Basic-Static': {
        "desc": 'Access token request with client_secret_basic authentication',
        # client_secret_basic is the default
        "sequence": [
            '_discover_',
            '_login_',
            ("_accesstoken_",
             {
                 "kwargs_mod": {"authn_method": "client_secret_basic"},
                 "support": {
                     "warning": {
                         "token_endpoint_auth_methods_supported":
                             "client_secret_basic"}}
             }),
        ],
        "profile": "C,CI,CIT,CT..F",
        'tests': {"check-http-response": {}},
    },
    'OP-ClientAuth-SecretPost-Dynamic': {
        "desc": 'Access token request with client_secret_post authentication',
        # Should register token_endpoint_auth_method=client_secret_post
        "sequence": [
            '_discover_',
            ('_register_',
             {
                 "request_args": {
                     "token_endpoint_auth_method": "client_secret_post"},
             }),
            '_login_',
            ("_accesstoken_",
             {
                 "kwargs_mod": {"authn_method": "client_secret_post"},
                 "support": {
                     "warning": {
                         "token_endpoint_auth_methods_supported":
                             "client_secret_post"}}
             }),
        ],
        "profile": "C,CI,CIT,CT..T",
        'tests': {"check-http-response": {}},
    },
    'OP-ClientAuth-SecretPost-Static': {
        "desc": 'Access token request with client_secret_post authentication',
        # Should register token_endpoint_auth_method=client_secret_post
        "sequence": [
            '_discover_',
            '_login_',
            ("_accesstoken_",
             {
                 "kwargs_mod": {"authn_method": "client_secret_post"},
                 "support": {
                     "warning": {
                         "token_endpoint_auth_methods_supported":
                             "client_secret_post"}}
             }),
        ],
        "profile": "C,CI,CIT,CT..F",
        'tests': {"check-http-response": {}},
    },
    'OP-ClientAuth-PublicJWT': {
        "desc": 'Access token request with private_key_jwt authentication',
        "sequence": [
            '_discover_',
            ('_register_',
             {
                 "request_args": {
                     "token_endpoint_auth_method": "private_key_jwt"},
             }),
            '_login_',
            ("_accesstoken_",
             {
                 "kwargs_mod": {"authn_method": "private_key_jwt"},
                 "support": {
                     "warning": {
                         "token_endpoint_auth_methods_supported":
                             "private_key_jwt"}}
             }),
        ],
        "profile": "C,CI,CT,CIT...s.+",
        'tests': {"check-http-response": {}},
    },
    'OP-ClientAuth-SecretJWT': {
        "desc": 'Access token request with client_secret_jwt authentication',
        "sequence": [
            '_discover_',
            ('_register_',
             {
                 "request_args": {
                     "token_endpoint_auth_method": "client_secret_jwt"},
             }),
            '_login_',
            ("_accesstoken_",
             {
                 "kwargs_mod": {"authn_method": "client_secret_jwt"},
                 "support": {
                     "warning": {
                         "token_endpoint_auth_methods_supported":
                             "client_secret_jwt"}}
             }),
        ],
        "profile": "C,CI,CT,CIT...s.+",
        'tests': {"check-http-response": {}},
    },
    'OP-Discovery-Config': {
        "desc": 'Publish openid-configuration discovery information',
        "sequence": ['_discover_'],
        "profile": ".T.",
        'tests': {"check-http-response": {}},
        "mti": {"Dynamic": "MUST"}
    },
    'OP-Discovery-Values': {
        "desc": 'Verify that jwks_uri and claims_supported are published',
        "sequence": ['_discover_'],
        "tests": {"providerinfo-has-jwks_uri": {},
                  "providerinfo-has-claims_supported": {},
                  "bare-keys": {},
                  "check-http-response": {}},
        "profile": ".T.",
        "mti": {"Dynamic": "SHOULD"}
    },
    'OP-Discovery-JWKs': {
        "desc": 'Keys in OP JWKs well formed',
        "sequence": ['_discover_'],
        "profile": ".T.",
        "tests": {"verify-base64url": {"err_status": ERROR},
                  "check-http-response": {}},
        "mti": {"Dynamic": "MUST"}
    },
    'OP-Discovery-WebFinger-Email': {
        "desc": 'Can Discover Identifiers using E-Mail Syntax',
        "profile": ".T...+",
        "sequence": [
            ("webfinger",
             {"kwarg_func": (get_principal, {"param": "webfinger_email"})})],
        "tests": {},
    },
    'OP-Discovery-WebFinger': {
        "desc": 'Can Discover Identifiers using URL Syntax',
        "profile": ".T...+",
        "sequence": [
            ("webfinger",
             {"kwarg_func": (get_principal, {"param": "webfinger_url"})})],
        "tests": {},
    },
    'OP-Registration-Endpoint': {
        "desc": 'Verify that registration_endpoint is published',
        "sequence": ['_discover_'],
        "profile": ".T.T",
        "tests": {"verify-op-has-registration-endpoint": {}},
        "mti": {"Dynamic": "MUST"}
    },
    'OP-Registration-Dynamic': {
        "desc": 'Client registration Request',
        "sequence": [
            '_discover_',
            "_register_"
        ],
        "profile": "..T",
        "tests": {"check-http-response": {}},
        "mti": {"Dynamic": "MUST"}
    },
    'OP-Registration-policy_uri': {
        "desc": 'Registration with policy_uri',
        "sequence": [
            'note',
            "rm_cookie",
            '_discover_',
            ('oic-registration', {"function": policy_uri}),
            "_login_"
        ],
        "profile": "..T",
        'note': "When you get the login page this time you should have a "
                "link to the client policy",
        "tests": {"check-http-response": {}},
    },
    'OP-Registration-logo_uri': {
        "desc": 'Registration with logo_uri',
        "sequence": [
            'note',
            "rm_cookie",
            '_discover_',
            ('oic-registration', {"function": logo_uri}),
            "_login_"
        ],
        "profile": "..T",
        'note': "When you get the login page this time you should have the "
                "clients logo on the page",
        "tests": {"verify-authn-response": {}},
    },
    'OP-Registration-tos_uri': {
        "desc": 'Registration with tos_uri',
        "sequence": [
            'note',
            'rm_cookie',
            '_discover_',
            ('oic-registration', {"function": tos_uri}),
            '_login_'
        ],
        "profile": "..T",
        'note': "When you get the login page this time you should have a "
                "link to the clients Terms of Service",
        "tests": {"verify-authn-response": {}},
    },
    'OP-Registration-jwks': {
        "desc": 'Uses Keys Registered with jwks Value',
        "sequence": [
            '_discover_',
            ('_register_',
             {
                 "request_args": {
                     "token_endpoint_auth_method": "private_key_jwt"},
                 "function": static_jwk
             }),
            '_login_',
            ("_accesstoken_",
             {
                 "kwargs_mod": {"authn_method": "private_key_jwt"},
                 "support": {
                     "warning": {
                         "token_endpoint_auth_methods_supported":
                             "client_secret_jwt"}}
             }),
        ],
        "profile": "C,CI,CT,CIT..T",
        "tests": {"check-http-response": {}},
    },
    'OP-Registration-jwks_uri': {
        "desc": 'Uses Keys Registered with jwks_uri Value',
        "sequence": [
            '_discover_',
            ('_register_',
             {"request_args": {
                 "token_endpoint_auth_method": "private_key_jwt"}}),
            '_login_',
            ("_accesstoken_",
             {
                 "kwargs_mod": {"authn_method": "private_key_jwt"},
                 "support": {
                     "warning": {
                         "token_endpoint_auth_methods_supported":
                             "private_key_jwt"}}
             }),
        ],
        "profile": "C,CI,CT,CIT..T",
        'tests': {"check-http-response": {}}
    },
    'OP-Registration-Sector-Bad': {
        "desc": 'Incorrect registration of sector_identifier_uri',
        "sequence": [
            '_discover_',
            ('_register_',
             {
                 "request_args": {},
                 "function": (store_sector_redirect_uris,
                              {"other_uris": ["https://example.com/op"]})
             })
        ],
        "profile": "..T",
        "tests": {"verify-error": {
            "error": ["invalid_configuration_parameter",
                      "invalid_client_metadata"]},
                  "verify-bad-request-response": {}},
    },
    'OP-Registration-Read': {
        "desc": 'Registering and then read the client info',
        "sequence": [
            '_discover_',
            '_register_',
            "read-registration"
        ],
        "profile": "..T..+",
        "tests": {"check-http-response": {}},
    },
    'OP-Registration-Sub-Public': {
        "desc": 'Registration of wish for public sub',
        "sequence": [
            '_discover_',
            ('_register_',
             {
                 "request_args": {"subject_type": "public"},
                 "support": {"error": {"subject_types_supported": "public"}}
             }),
            "_login_",
            "_accesstoken_"
        ],
        "profile": "..T..+",
        "tests": {"check-http-response": {}},
    },
    'OP-Registration-Sub-Pairwise': {
        "desc": 'Registration of wish for pairwise sub',
        "sequence": [
            '_discover_',
            ('_register_',
             {
                 "request_args": {"subject_type": "pairwise"},
                 "support": {"error": {"subject_types_supported": "pairwise"}}
             }),
            "_login_",
            "_accesstoken_"
        ],
        "profile": "..T..+",
        "tests": {"check-http-response": {}},
    },
    'OP-Registration-Sub-Differ': {
        "desc": 'Public and pairwise sub values differ',
        "sequence": [
            '_discover_',
            ('_register_',
             {
                 "request_args": {"subject_type": "public"},
                 "support": {"error": {"subject_types_supported": "public"}}
             }),
            "_login_",
            "_accesstoken_",
            ('_register_',
             {
                 "request_args": {"subject_type": "pairwise"},
                 "support": {"error": {"subject_types_supported": "pairwise"}}
             }),
            "_login_",
            "_accesstoken_"
        ],
        "profile": "..T..+",
        'tests': {"different_sub": {}, "check-http-response": {}}
    },
    'OP-Rollover-OP-Sig': {
        "desc": "Can Rollover OP Signing Key",
        "sequence": [
            '_discover_',
            'fetch_keys',
            "note",
            '_discover_',
            'fetch_keys',
        ],
        "note": "Please make your OP roll over signing keys. "
                'If you are not able to cause the server to roll over the key '
                'while running the test, then you will have to self-assert '
                'that your deployment can do OP signing key rollover.',
        "profile": ".T.T.s",
        # "profile": ".T.T.s.+",
        "tests": {"new-signing-keys": {}, "check-http-response": {}}
    },
    'OP-Rollover-RP-Sig': {
        "desc": 'Request access token, change RSA signing key and request another '
                'access token',
        "sequence": [
            '_discover_',
            ('_register_',
             {
                 "request_args": {
                     "token_endpoint_auth_method": "private_key_jwt"},
                 "support": {"error": {
                     "token_endpoint_auth_methods_supported":
                         "private_key_jwt"}}
             }),
            '_login_',
            ("_accesstoken_",
             {
                 "kwargs_mod": {"authn_method": "private_key_jwt"},
             }),
            "rotate_sign_keys",
            ("refresh-access-token",
             {
                 "kwargs_mod": {"authn_method": "private_key_jwt"},
             })
        ],
        "profile": "C,CI,CT,CIT..T.s",
        "tests": {"check-http-response": {}}
    },
    'OP-Rollover-OP-Enc': {
        "desc": "Can Rollover OP Encryption Key",
        "sequence": [
            '_discover_',
            'fetch_keys',
            "note",
            '_discover_',
            'fetch_keys',
        ],
        "note": "Please make your OP roll over encryption keys."
                'If you are not able to cause the server to roll over the keys '
                'while running the test, then you will have to self-assert '
                'that your deployment can do OP encryption key rollover.',
        # "profile": ".T..e.+",
        "profile": ".T..e",
        "tests": {"new-encryption-keys": {}, "check-http-response": {}}
    },
    'OP-Rollover-RP-Enc': {
        # where is the RPs encryption keys used => userinfo encryption
        "desc": 'Request encrypted user info, change RSA enc key and request '
                'UserInfo again',
        "sequence": [
            '_discover_',
            ("oic-registration",
             {
                 "request_args": {
                     "userinfo_signed_response_alg": "none",
                     "userinfo_encrypted_response_alg": "RSA1_5",
                     "userinfo_encrypted_response_enc": "A128CBC-HS256"
                 },
                 "support": {
                     "warning": {
                         "userinfo_signing_alg_values_supported": "none",
                         "userinfo_encryption_alg_values_supported": "RSA1_5",
                         "userinfo_encryption_enc_values_supported":
                             "A128CBC-HS256"
                     }
                 }
             }
            ),
            '_login_',
            "_accesstoken_",
            "rotate_sign_keys",
            "userinfo"
        ],
        "profile": "C,CI,CT,CIT..T.se.+",
        "tests": {"check-http-response": {}}
    },
    'OP-request_uri-Support': {
        "desc": 'Support request_uri Request Parameter',
        "sequence": [
            '_discover_',
        ],
        "profile": "..T",
        "tests": {"check-http-response": {},
                  "check-request_uri-parameter-supported-support": {}}
    },
    'OP-request_uri-Unsigned': {
        "desc": 'Support request_uri Request Parameter with unSigned Request',
        "sequence": [
            '_discover_',
            ("_register_",
             {
                 "request_args": {
                     "request_object_signing_alg": "none"},
                 "support": {
                     "warning": {
                         "request_uri_parameter_supported": True,
                         "request_object_signing_alg_values_supported": "none"}}
             }),
            ("_login_", {
                "kwargs_mod": {"request_method": "file", "local_dir": "export",
                               "algorithm": "none"},
                "kwarg_func": request_in_file,
                "support": {"error": {"request_uri_parameter_supported": True}}
            })
        ],
        "profile": "...n",
        "tests": {"verify-authn-response": {}}
    },
    'OP-request_uri-Sig': {
        "desc": 'Support request_uri Request Parameter with Signed Request',
        "sequence": [
            '_discover_',
            ("_register_",
             {
                 "request_args": {
                     "request_object_signing_alg": "RS256"},
                 "support": {
                     "warning": {
                         "request_uri_parameter_supported": True,
                         "request_object_signing_alg_values_supported": "RS256"
                     }}
             }),
            ("_login_", {
                "kwargs_mod": {"request_method": "file", "local_dir": "export"},
                "kwarg_func": request_in_file,
                "support": {"error": {"request_parameter_supported": True}}})
        ],
        "profile": "..T.s",
        "tests": {"verify-authn-response": {}}
    },
    'OP-request_uri-Enc': {
        "desc": 'Support request_uri Request Parameter with Encrypted Request',
        "sequence": [
            '_discover_',
            ("oic-registration",
             {
                 "request_args": {
                     "request_object_signing_alg": "none",
                     "request_object_encryption_alg": "RSA1_5",
                     "request_object_encryption_enc": "A128CBC-HS256"
                 },
                 "support": {
                     "warning": {
                         "request_uri_parameter_supported": True,
                         "request_object_signing_alg_values_supported": "none",
                         "request_object_encryption_alg_values_supported":
                             "RSA1_5",
                         "request_object_encryption_enc_values_supported":
                             "A128CBC-HS256"}
                 }
             }
            ),
            ("_login_", {
                "kwargs_mod": {"request_method": "file", "local_dir": "export"},
                "kwarg_func": request_in_file,
                "support": {"error": {"request_uri_parameter_supported": True}}
            })
        ],
        "profile": "..T.se.+",
        "tests": {"verify-authn-response": {}}
    },
    'OP-request_uri-SigEnc': {
        "desc": 'Support request_uri Request Parameter with Signed and '
                'Encrypted Request',
        "sequence": [
            '_discover_',
            ("oic-registration",
             {
                 "request_args": {
                     "request_object_signing_alg": "RS256",
                     "request_object_encryption_alg": "RSA1_5",
                     "request_object_encryption_enc": "A128CBC-HS256"
                 },
                 "support": {
                     "warning": {
                         "request_uri_parameter_supported": True,
                         "request_object_signing_alg_values_supported": "RS256",
                         "request_object_encryption_alg_values_supported":
                             "RSA1_5",
                         "request_object_encryption_enc_values_supported":
                             "A128CBC-HS256"}
                 }
             }
            ),
            ("_login_", {
                "kwarg_func": request_in_file,
                "support": {"error": {"request_uri_parameter_supported": True}}
            })
        ],
        "profile": "..T.se.+",
        "tests": {"verify-authn-response": {}}
    },
    'OP-request-Support': {
        "desc": 'Support request Request Parameter',
        "sequence": [
            '_discover_',
            # ("_register_",
            #  {"support": {"warning": {"request_parameter_supported": True}}}),
            # ("_login_", {"kwargs_mod": {"request_method": "request"}})
        ],
        "profile": "....+",
        "tests": {"check-http-response": {},
                  "check-request-parameter-supported-support": {}}
    },
    'OP-request-Unsigned': {
        "desc": 'Support request Request Parameter with unSigned Request',
        "sequence": [
            '_discover_',
            ("_register_",
             {
                 "request_args": {
                     "request_object_signing_alg": "none"},
                 "support": {
                     "warning": {
                         "request_parameter_supported": True,
                         "request_object_signing_alg_values_supported": "none"}}
             }),
            ("_login_", {
                "kwargs_mod": {"request_method": "request"},
                "support": {"error": {"request_parameter_supported": True}}})
        ],
        "profile": "...n",
        "tests": {"verify-authn-response": {}}
    },
    'OP-request-Sig': {
        "desc": 'Support request Request Parameter with Signed Request',
        "sequence": [
            '_discover_',
            ("_register_",
             {
                 "request_args": {
                     "request_object_signing_alg": "RS256"},
                 "support": {
                     "warning": {
                         "request_parameter_supported": True,
                         "request_object_signing_alg_values_supported": "RS256"
                     }}
             }),
            ("_login_", {
                "kwargs_mod": {"request_method": "request"},
                "support": {
                    "error": {
                        "request_parameter_supported": True,
                        "request_object_signing_alg_values_supported": "RS256"
                    }}
            })
        ],
        "profile": "...s.+",
        "tests": {"verify-authn-response": {}}
    },
    'OP-claims-essential': {
        "desc": 'Claims Request with Essential name Claim',
        "sequence": [
            '_discover_',
            '_register_',
            ("_login_", {
                "request_args": {
                    "claims": {"userinfo": {"name": {"essential": True}}}}
            }),
            "_accesstoken_",
            USERINFO_REQUEST_AUTH_METHOD
        ],
        "profile": "C,CI,CT,CIT..",
        'tests': {"verify-claims": {"userinfo": {"name": None}},
                  "check-http-response": {}}
    },
    'OP-claims-sub': {
        "desc": 'Support claims request specifying sub value',
        "sequence": [
            '_discover_',
            '_register_',
            '_login_',
            "_accesstoken_",
            'rm_cookie',
            ("_login_", {"function": sub_claims}),
        ],
        "profile": "....+",
        "tests": {"verify-authn-response": {}},
    },
    'OP-claims-sub-none': {
        "desc": 'Using prompt=none with user hint through sub in request',
        "sequence": [
            '_discover_',
            '_register_',
            '_login_',
            "_accesstoken_",
            'rm_cookie',
            ("_login_", {
                "request_args": {"prompt": "none"},
                "function": sub_claims
            }),
        ],
        "profile": "....+",
        "tests": {"verify-authn-response": {}}
    },
    'OP-claims-IDToken': {
        "desc": 'Requesting ID Token with Email claims',
        "sequence": [
            '_discover_',
            '_register_',
            ("_login_", {
                "request_args": {
                    "claims": {
                        "id_token": {"email": {"essential": True}},
                    }}
            }),
            "_accesstoken_",
        ],
        "profile": "....+",
        'tests': {"verify-claims": {"id_token": {"email": None}},
                  "check-http-response": {}}
    },
    'OP-claims-Split': {
        "desc": 'Supports Returning Different Claims in ID Token and UserInfo '
                'Endpoint',
        "sequence": [
            '_discover_',
            '_register_',
            ("_login_", {
                "request_args": {
                    "claims": {
                        "id_token": {"email": {"essential": True}},
                        "userinfo": {"name": {"essential": True}}
                    }}
            }),
            "_accesstoken_",
            USERINFO_REQUEST_AUTH_METHOD],
        "profile": "C,IT,CI,CIT,CT....+",
        'tests': {"verify-claims": {"userinfo": {"name": None},
                                    "id_token": {"email": None}},
                  "check-http-response": {}}
    },
    'OP-claims-Combined': {
        "desc": 'Supports Combining Claims Requested with scope and claims '
                'Request Parameter',
        "sequence": [
            '_discover_',
            '_register_',
            ("_login_", {
                "request_args": {
                    "scopes": ["openid", "phone"],
                    "claims": {
                        "id_token": {"email": {"essential": True}},
                    }},
                "support": {
                    "warning": {
                        "scopes_supported": ["phone"]}},
            }),
            "_accesstoken_",
            USERINFO_REQUEST_AUTH_METHOD
        ],
        "profile": "C,IT,CI,CIT,CT....+",
        'tests': {"verify-claims": {"userinfo": {"phone": None},
                                    "id_token": {"email": None}},
                  "check-http-response": {}}
    },
    'OP-claims-voluntary': {
        "desc": 'Claims Request with Voluntary email and picture Claims',
        "sequence": [
            '_discover_',
            '_register_',
            ("_login_", {
                "request_args": {
                    "claims": {"userinfo": {"picture": None, "email": None}}}
            }),
            "_accesstoken_",
            USERINFO_REQUEST_AUTH_METHOD],
        "profile": "C,IT,CI,CIT,CT....+",
        'tests': {"verify-claims": {"userinfo": {"picture": None,
                                                 "email": None}},
                  "check-http-response": {}}
    },
    'OP-claims-essential+voluntary': {
        "desc": (
            'Claims Request with Essential name and Voluntary email and '
            'picture Claims'),
        "sequence": [
            '_discover_',
            '_register_',
            ("_login_", {
                "request_args": {
                    "claims": {"userinfo": {
                        "name": {"essential": True},
                        "picture": None,
                        "email": None}}}
            }),
            "_accesstoken_",
            USERINFO_REQUEST_AUTH_METHOD
        ],
        "profile": "C,IT,CI,CIT,CT....+",
        'tests': {"verify-claims": {"userinfo": {"picture": None,
                                                 "name": None,
                                                 "email": None}},
                  "check-http-response": {}}
    },
    'OP-claims-auth_time-essential': {
        "desc": 'Requesting ID Token with Essential auth_time Claim',
        "sequence": [
            '_discover_',
            '_register_',
            ("_login_", {
                "request_args": {
                    "claims": {"id_token": {"auth_time": {"essential": True}}}}
            }),
            "_accesstoken_",
        ],
        "profile": "....+",
        "mti": {"all": "MUST"},
        'tests': {"verify-claims": {"id_token": {"auth_time": None}},
                  "check-http-response": {}}
    },
    'OP-claims-acr-essential': {
        "desc": 'Requesting ID Token with Essential acr Claim',
        "sequence": [
            '_discover_',
            '_register_',
            ("_login_", {
                "request_args": {
                    "claims": {"id_token": {"acr": {"essential": True}}}}
            }),
            "_accesstoken_",
        ],
        "profile": "....+",
        'tests': {"verify-claims": {"id_token": {"acr": None}},
                  "check-http-response": {}}
    },
    'OP-claims-acr-voluntary': {
        "desc": 'Requesting ID Token with Voluntary acr Claim',
        "sequence": [
            '_discover_',
            '_register_',
            ("_login_", {
                "request_args": {
                    "claims": {"id_token": {"acr": None}}}
            }),
            "_accesstoken_",
        ],
        "profile": "....+",
        'tests': {"verify-claims": {"id_token": {"acr": None}},
                  "check-http-response": {}}
    },
    'OP-claims-acr=1': {
        "desc": 'Requesting ID Token with Essential specific acr Claim',
        "sequence": [
            '_discover_',
            '_register_',
            ("_login_", {"function": specific_acr_claims}),
            "_accesstoken_",
        ],
        "profile": "....+",
        'tests': {"verify-claims": {"id_token": {"acr": None}},
                  "check-http-response": {}}
    },
}