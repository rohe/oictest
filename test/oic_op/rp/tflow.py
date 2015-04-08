#!/usr/bin/env python
from oic.oauth2 import ErrorResponse
from oic.oic import AccessTokenResponse
from oic.oic import AuthorizationResponse
from oic.oic import OpenIDSchema
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
    "_userinfo_", {
        "kwargs_mod": {"authn_method": "bearer_header"},
        "method": "GET"
    })

ORDDESC = ["OP-Response", "OP-IDToken", "OP-UserInfo", "OP-nonce", "OP-scope",
           "OP-display", "OP-prompt", "OP-Req", "OP-OAuth", "OP-redirect_uri",
           "OP-ClientAuth", "OP-Discovery", "OP-Registration", "OP-Rotation",
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
    "Rotation": "Key Rotation",
    "request_uri": "request_uri Request Parameter",
    "request": "request Request Parameter",
    "claims": "claims Request Parameter",
}

FLOWS = {
    'OP-Response-code': {
        "desc": 'Request with response_type=code [Basic]',
        "sequence": ['_discover_', "_register_", "_login_"],
        "profile": "C..",
        'tests': {"verify-authn-response": {}},
        "mti": {"all": "MUST"}
    },
    'OP-Response-id_token': {
        "desc": 'Request with response_type=id_token [Implicit]',
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
        "desc": 'Request with response_type=id_token token [Implicit]',
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
        "desc": 'Request with response_type=code id_token [Hybrid]',
        "sequence": ['_discover_', '_register_', '_login_'],
        "tests": {"verify-authn-response": {}, 'check-idtoken-nonce': {}},
        "profile": "CI..",
    },
    'OP-Response-code+token': {
        "desc": 'Request with response_type=code token [Hybrid]',
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
        "desc": 'Request with response_type=code id_token token [Hybrid]',
        "sequence": [
            '_discover_',
            '_register_',
            ('_login_',
             {"request_args": {"response_type": ["code", "id_token", "token"]}})
        ],
        "profile": "CIT..",
        'tests': {"verify-authn-response": {}},
    },
    'OP-Response-Missing': {
        "desc": 'Authorization request missing the response_type parameter ['
                'Basic, Implicit, Hybrid]',
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
        "note": "There are two acceptable outcomes: (1) returning an error "
                "response "
                "to the RP or (2) returning an error message to the End-User. "
                "In case (2), you must submit a screen shot of the error shown "
                "as part of your certification application.",
        "profile": "..",
        "mti": {"all": "MUST"}
    },
    'OP-Response-form_post': {
        "desc": 'Request with response_mode=form_post [Extra]',
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
        "desc": 'Asymmetric ID Token signature with RS256 [Dynamic]',
        "sequence": [
            '_discover_',
            ("oic-registration",
             {"request_args": {"id_token_signed_response_alg": "RS256"}}),
            "_login_", "_accesstoken_"],
        "profile": "..T.s",
        "mti": {"all": "MUST"},
        "tests": {"verify-idtoken-is-signed": {"alg": "RS256"},
                  "verify-response": {
                      "response_cls": [AccessTokenResponse,
                                       AuthorizationResponse]}}
    },
    'OP-IDToken-Signature': {
        # RS256 is MTI
        "desc": 'Does the OP sign the ID Token and with what [Basic, '
                'Implicit, Hybrid]',
        "sequence": [
            '_discover_',
            "_login_",
            '_accesstoken_'],
        "profile": "..F",
        "tests": {"is-idtoken-signed": {"alg": "RS256"},
                  "verify-response": {
                      "response_cls": [AccessTokenResponse,
                                       AuthorizationResponse]}}
    },
    'OP-IDToken-kid': {
        "desc": 'IDToken has kid [Basic, Implicit, Hybrid]',
        "sequence": ['_discover_', '_register_', "_login_", "_accesstoken_"],
        "mti": {"all": "MUST"},
        "profile": "...s",
        "tests": {"verify-signed-idtoken-has-kid": {},
                  "verify-response": {
                      "response_cls": [AccessTokenResponse,
                                       AuthorizationResponse]}}
    },
    'OP-IDToken-none': {
        "desc": 'Unsecured ID Token signature with none [Basic]',
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
        "tests": {"unsigned-idtoken": {},
                  "verify-response": {
                      "response_cls": [AccessTokenResponse,
                                       AuthorizationResponse]}},
        "profile": "C.T.T.n",
    },
    'OP-IDToken-at_hash': {
        "desc": 'ID Token has at_hash when ID Token and Access Token returned '
                'from Authorization Endpoint [Implicit, Hybrid]',
        "sequence": ['_discover_', '_register_', '_login_'],
        "mti": {"all": "MUST"},
        "test": {"verify-authn-response": {}},
        "profile": "IT,CIT..",
    },
    'OP-IDToken-c_hash': {
        "desc": 'ID Token has c_hash when ID Token and Authorization Code '
                'returned from Authorization Endpoint [Hybrid]',
        "sequence": ['_discover_', '_register_', '_login_'],
        "tests": {"verify-authn-response": {}},
        "profile": "CI,CIT..",
        "mti": {"all": "MUST"}
    },
    'OP-IDToken-HS256': {
        "desc": 'Symmetric ID Token signature with HS256 [Extra]',
        "sequence": [
            '_discover_',
            ("oic-registration",
             {"request_args": {"id_token_signed_response_alg": "HS256"}}),
            "_login_",
            "_accesstoken_"],
        "profile": "..T.s.+",
        "tests": {"verify-idtoken-is-signed": {"alg": "HS256"},
                  "verify-response": {
                      "response_cls": [AccessTokenResponse,
                                       AuthorizationResponse]}}
    },
    'OP-IDToken-ES256': {
        "desc": 'Asymmetric ID Token signature with ES256 [Extra]',
        "sequence": [
            '_discover_',
            ("oic-registration",
             {"request_args": {"id_token_signed_response_alg": "ES256"}}),
            "_login_",
            "_accesstoken_"],
        "profile": "..T.s.+",
        "tests": {"verify-idtoken-is-signed": {"alg": "ES256"},
                  "verify-response": {
                      "response_cls": [AccessTokenResponse,
                                       AuthorizationResponse]}}
    },
    'OP-IDToken-SigEnc': {
        "desc": 'Signed and encrypted ID Token [Extra]',
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
            "_login_",
            "_accesstoken_"],
        "profile": "..T.se.+",
        "tests": {"signed-encrypted-idtoken": {"sign_alg": "RS256",
                                               "enc_alg": "RSA1_5",
                                               "enc_enc": "A128CBC-HS256"},
                  "verify-response": {"response_cls": [AuthorizationResponse,
                                                       AccessTokenResponse]}}
    },
    'OP-UserInfo-Endpoint': {
        "desc": 'UserInfo Endpoint access with GET and bearer header [Basic, '
                'Implicit, Hybrid]',
        "sequence": ['_discover_', '_register_', '_login_',
                     "_accesstoken_",
                     ("userinfo",
                      {
                          "kwargs_mod": {"authn_method": "bearer_header"},
                          "method": "GET"
                      })],
        "profile": "C,IT,CI,CT,CIT..",
        'tests': {"verify-response": {"response_cls": [OpenIDSchema]}},
        "mti": {"all": "SHOULD"}
    },
    'OP-UserInfo-Header': {
        "desc": 'UserInfo Endpoint access with POST and bearer header [Basic, '
                'Implicit, Hybrid]',
        "sequence": ['_discover_', '_register_', '_login_',
                     "_accesstoken_",
                     ("userinfo",
                      {
                          "kwargs_mod": {"authn_method": "bearer_header"},
                          "method": "POST"
                      })],
        "profile": "C,IT,CI,CT,CIT..",
        'tests': {"verify-response": {"response_cls": [OpenIDSchema]}},
    },
    'OP-UserInfo-Body': {
        "desc": 'UserInfo Endpoint access with POST and bearer body [Basic, '
                'Implicit, Hybrid]',
        "sequence": ['_discover_', '_register_', '_login_',
                     "_accesstoken_",
                     ("userinfo",
                      {
                          "kwargs_mod": {"authn_method": "bearer_body"},
                          "method": "POST"
                      })],
        "profile": "C,IT,CI,CT,CIT..",
        'tests': {"verify-response": {"response_cls": [OpenIDSchema],
                                      "status": WARNING}},
        "mti": {"all": "MAY"}
    },
    'OP-UserInfo-RS256': {
        "desc": 'RP registers userinfo_signed_response_alg to signal that it '
                'wants signed UserInfo returned [Dynamic]',
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
                  "verify-response": {"response_cls": [OpenIDSchema]}},
        "profile": "C,IT,CI,CT,CIT..T.s",
        "mti": {"all": "MUST"}
    },
    'OP-UserInfo-Enc': {
        "desc": 'Can provide encrypted UserInfo response [Extra]',
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
        "tests": {"encrypted-userinfo": {},
                  "verify-response": {"response_cls": [OpenIDSchema]}},
    },
    'OP-UserInfo-SigEnc': {
        "desc": 'Can provide signed and encrypted UserInfo response [Extra]',
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
            "verify-response": {"response_cls": [OpenIDSchema]}},
    },
    'OP-nonce-NoReq-code': {
        "desc": 'Login no nonce, code flow [Basic, Hybrid]',
        "sequence": [
            '_discover_',
            '_register_',
            ('_login_', {"request_args": {"nonce": ""}})
        ],
        "profile": "C,CT..",
        'tests': {"verify-response": {"response_cls": [AuthorizationResponse]}},
        "mti": {"all": "MUST"}
    },
    'OP-nonce-NoReq-noncode': {
        "desc": 'Reject requests without nonce unless using the code flow ['
                'Implicit, Hybrid]',
        "sequence": [
            '_discover_',
            '_register_',
            ('_login_', {"request_args": {"nonce": ""}})
        ],
        "tests": {
            "verify-response": {
                "error": ["invalid_request"],
                "response_cls": [ErrorResponse]}},
        "profile": "I,IT..",
        "mti": {"all": "MUST"}
    },
    'OP-nonce-code': {
        "desc": 'ID Token has nonce when requested for code flow [Basic]',
        "sequence": [
            '_discover_',
            '_register_',
            ('_login_', {"request_args": {"nonce": "godmorgon"}}),
            '_accesstoken_'],
        "mti": {"all": "MUST"},
        "profile": "C..",
        "tests": {"verify-nonce": {},
                  "verify-response": {
                      "response_cls": [AccessTokenResponse,
                                       AuthorizationResponse]}}
    },
    'OP-nonce-noncode': {
        "desc": 'Request with nonce, verifies it was returned in ID Token ['
                'Implicit, Hybrid]',
        "sequence": ['_discover_', '_register_', '_login_', '_accesstoken_'],
        "tests": {'check-idtoken-nonce': {},
                  "verify-response": {
                      "response_cls": [AccessTokenResponse,
                                       AuthorizationResponse]}},
        "profile": "I,IT,CI,CT,CIT..",
        "mti": {"all": "MUST"}
    },
    'OP-scope-profile': {
        "desc": 'Scope requesting profile claims [Basic, Implicit, Hybrid]',
        "sequence": [
            '_discover_',
            '_register_',
            ('_login_',
             {
                 "request_args": {"scope": ["openid", "profile"]},
                 "support": {"warning": {"scopes_supported": ["profile"]}}
             }),
            "_accesstoken_",
            ("_userinfo_", {
                "kwargs_mod": {"authn_method": "bearer_header"},
                "method": "GET"
            })
        ],
        "profile": "..",
        "mti": {"all": "No err"},
        'tests': {"verify-response": {"response_cls": [OpenIDSchema,
                                                       AuthorizationResponse]},
                  "verify-scopes": {},
                  "check-http-response": {}}
    },
    'OP-scope-email': {
        "desc": 'Scope requesting email claims [Basic, Implicit, Hybrid]',
        "sequence": [
            '_discover_',
            '_register_',
            ('_login_',
             {
                 "request_args": {"scope": ["openid", "email"]},
                 "support": {"warning": {"scopes_supported": ["email"]}}
             }),
            "_accesstoken_",
            ("_userinfo_", {
                "kwargs_mod": {"authn_method": "bearer_header"},
                "method": "GET"
            })
        ],
        "profile": "..",
        "mti": "No err",
        'tests': {"verify-response": {"response_cls": [OpenIDSchema,
                                                       AuthorizationResponse]},
                  "verify-scopes": {},
                  "check-http-response": {}}
    },
    'OP-scope-address': {
        "desc": 'Scope requesting address claims [Basic, Implicit, Hybrid]',
        "sequence": [
            '_discover_',
            '_register_',
            ('_login_',
             {
                 "request_args": {"scope": ["openid", "address"]},
                 "support": {"warning": {"scopes_supported": ["address"]}}
             }),
            "_accesstoken_",
            ("_userinfo_", {
                "kwargs_mod": {"authn_method": "bearer_header"},
                "method": "GET"
            })
        ],
        "profile": "..",
        "mti": "No err",
        'tests': {"verify-response": {"response_cls": [OpenIDSchema,
                                                       AuthorizationResponse]},
                  "verify-scopes": {},
                  "check-http-response": {}}
    },
    'OP-scope-phone': {
        "desc": 'Scope requesting phone claims [Basic, Implicit, Hybrid]',
        "sequence": [
            '_discover_',
            '_register_',
            ('_login_',
             {
                 "request_args": {"scope": ["openid", "phone"]},
                 "support": {"warning": {"scopes_supported": ["phone"]}}
             }),
            "_accesstoken_",
            ("_userinfo_", {
                "kwargs_mod": {"authn_method": "bearer_header"},
                "method": "GET"
            })
        ],
        "profile": "..",
        "mti": "No err",
        'tests': {"verify-response": {"response_cls": [OpenIDSchema,
                                                       AuthorizationResponse]},
                  "verify-scopes": {},
                  "check-http-response": {}}
    },
    'OP-scope-All': {
        "desc": 'Scope requesting all claims [Basic, Implicit, Hybrid]',
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
            ("_userinfo_", {
                "kwargs_mod": {"authn_method": "bearer_header"},
                "method": "GET"
            })
        ],
        "profile": "..",
        "mti": "No err",
        'tests': {"verify-response": {"response_cls": [OpenIDSchema,
                                                       AuthorizationResponse]},
                  "verify-scopes": {},
                  "check-http-response": {}}
    },
    'OP-display-page': {
        "desc": 'Request with display=page [Basic, Implicit, Hybrid]',
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
        "note": "To make sure you get a login page, please remove any cookies "
                "you may have received from the OpenID Provider before "
                "proceeding. "
                "You should get a normal user agent login page view.",
        "profile": "..",
        'tests': {"verify-response": {"response_cls": [AuthorizationResponse]}},
        "mti": {"all": "No err"}
    },
    'OP-display-popup': {
        "desc": 'Request with display=popup [Basic, Implicit, Hybrid]',
        "sequence": [
            'note',
            '_discover_',
            '_register_',
            ('_login_',
             {
                 "request_args": {"display": "popup"},
                 "support": {"warning": {"display_values_supported": "popup"}}
             })
        ],
        "note": "To make sure you get a login page, please remove any cookies "
                "you may have received from the OpenID Provider before "
                "proceeding. "
                "You should get a popup user agent login window.",
        "profile": "..",
        'tests': {"verify-response": {"response_cls": [AuthorizationResponse]}},
        "mti": {"all": "No err"}
    },
    'OP-prompt-login': {
        "desc": 'Request with prompt=login [Basic, Implicit, Hybrid]',
        "sequence": [
            '_discover_',
            '_register_',
            "_login_",
            '_accesstoken_',
            "note",
            ('_login_', {"request_args": {"prompt": "login"}}),
            '_accesstoken_',
        ],
        "note": "You should be prompted to authenticate or re-authenticate. "
                "Please submit a screen shot of any authentication user "
                "interaction "
                "that occurred as part of your certification application.",
        "profile": "..",
        'tests': {
            "multiple-sign-on": {},
            "verify-response": {"response_cls": [AuthorizationResponse,
                                                 AccessTokenResponse]}},
        "mti": {"all": "MUST"},
        # "result": "The test passed if you were prompted to log in."
    },
    'OP-prompt-none-NotLoggedIn': {
        "desc": 'Request with prompt=none when not logged in [Basic, '
                'Implicit, Hybrid]',
        "sequence": [
            'note',
            '_discover_',
            '_register_',
            ('_login_', {"request_args": {"prompt": "none"}})
        ],
        "note": "This tests what happens if the authentication request "
                "specifies that no interaction may occur with the End-User "
                "and no recent enough authentication is present to enable a "
                "silent login. "
                "Please remove any cookies you may have received from the "
                "OpenID Provider before proceeding.",
        "mti": {"all": "MUST"},
        "profile": "..",
        "tests": {"verify-error-response": {
            "error": ["login_required", "interaction_required",
                      "session_selection_required", "consent_required"]}},
    },
    'OP-prompt-none-LoggedIn': {
        "desc": 'Request with prompt=none when logged in [Basic, Implicit, '
                'Hybrid]',
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
                  "verify-response": {"response_cls": [AuthorizationResponse,
                                                       AccessTokenResponse]}},
        "profile": "..",
        "result": "The test passed if you were not prompted to log in."
    },
    'OP-Req-NotUnderstood': {
        "desc": 'Request with extra query component [Basic, Implicit, Hybrid]',
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
        "desc": 'Using prompt=none with user hint through id_token_hint ['
                'Basic, Implicit, Hybrid]',
        "sequence": [
            '_discover_',
            '_register_',
            "_login_",
            "_accesstoken_",
            # "cache-id_token",
            ('_login_', {
                "request_args": {"prompt": "none"},
                "function": id_token_hint}),
            "_accesstoken_",
        ],
        "profile": "..",
        'tests': {"same-authn": {},
                  "verify-response": {
                      "response_cls": [AuthorizationResponse,
                                       AccessTokenResponse]}},
        "mti": {"all": "SHOULD"},
    },
    'OP-Req-login_hint': {
        "desc": 'Providing login_hint [Basic, Implicit, Hybrid]',
        "sequence": [
            'note',
            '_discover_',
            '_register_',
            ("_login_", {"function": login_hint})
        ],
        "note": "Please remove any cookies you may have received from the "
                "OpenID Provider before proceeding. This test requests that "
                "you log in as "
                "a specific user, so a fresh login page is needed.",
        "profile": "..",
        'tests': {"verify-authn-response": {}},
        "mti": {"all": "No err"},
        "result": "You should be requested to log in as a predefined user"
    },
    'OP-Req-ui_locales': {
        "desc": 'Providing ui_locales [Basic, Implicit, Hybrid]',
        "sequence": [
            'note',
            '_discover_',
            '_register_',
            ('_login_', {"request_args": {},
                         "function": ui_locales}),
        ],
        "note": "Please remove any cookies you may have received from the "
                "OpenID Provider before proceeding. You need to do this so "
                "you can check that the "
                "login page is displayed using one of the requested locales. "
                "The use of this parameter in the request must not cause an "
                "error at the OP.",
        "profile": "..",
        'tests': {"verify-authn-response": {}},
        "mti": {"all": "No err"}
    },
    'OP-Req-claims_locales': {
        "desc": 'Providing claims_locales [Basic, Implicit, Hybrid]',
        "sequence": [
            "note",
            '_discover_',
            '_register_',
            ('_login_', {"request_args": {},
                         "function": claims_locales}),
            "_accesstoken_",
            USERINFO_REQUEST_AUTH_METHOD,
            '_display_userinfo_'],
        "note": "This test requests that claims be returned using the "
                "specified locale(s). "
                "The use of this parameter in the request must not cause an "
                "error at the OP.",
        "profile": "..",
        'tests': {"check-http-response": {}},
        "mti": {"all": "No err"}
    },
    'OP-Req-acr_values': {
        "desc": 'Providing acr_values [Basic, Implicit, Hybrid]',
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
    'OP-Req-max_age=1': {
        "desc": 'Requesting ID Token with max_age=1 seconds restriction ['
                'Basic, Implicit, Hybrid]',
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
        "note": "Wait at least one second before proceeding so that the "
                "max_age=1 period expires. "
                "You should be prompted to authenticate or re-authenticate. "
                "Please submit a screen shot of any authentication user "
                "interaction that occurred as part of your certification "
                "application.",
        "profile": "..",
        "tests": {"multiple-sign-on": {"status": WARNING},
                  "verify-response": {
                      "response_cls": [AccessTokenResponse,
                                       AuthorizationResponse]},
                  "claims-check": {"id_token": ["auth_time"],
                                   "required": True},
                  "auth_time-check": {"max_age": 1}},
        "mti": {"all": "MUST"},
        "result": "The test passed if you were prompted to log in."
    },
    'OP-Req-max_age=10000': {
        "desc": 'Requesting ID Token with max_age=10000 seconds restriction ['
                'Basic, Implicit, Hybrid]',
        "sequence": [
            '_discover_',
            '_register_',
            "_login_",
            "_accesstoken_",
            ("_login_", {"request_args": {"max_age": 10000}}),
            "_accesstoken_"
        ],
        "profile": "..",
        "tests": {"same-authn": {},
                  "verify-response": {
                      "response_cls": [AccessTokenResponse,
                                       AuthorizationResponse]},
                  "claims-check": {"id_token": ["auth_time"],
                                   "required": True},
                  "auth_time-check": {"max_age": 10000}},
        "mti": {"all": "MUST"}
    },
    'OP-OAuth-2nd': {
        "desc": 'Trying to use authorization code twice should result in an '
                'error ['
                'Basic, Hybrid]',
        "sequence": [
            '_discover_',
            '_register_',
            '_login_',
            "_accesstoken_",
            "_accesstoken_"
        ],
        "profile": "C,CI,CT,CIT..",
        "tests": {
            "verify-response": {
                "response_cls": [ErrorResponse],
                "error": ["invalid_grant", "access_denied"],
                "status": WARNING,
            }},
        "mti": {"all": "SHOULD"},
        "reference": "http://tools.ietf.org/html/draft-ietf-oauth-v2-31"
                     "#section-4.1",
    },
    'OP-OAuth-2nd-Revokes': {
        "desc": 'Trying to use authorization code twice should result in '
                'revoking '
                'previously issued access tokens [Basic, Hybrid]',
        "sequence": [
            '_discover_',
            '_register_',
            '_login_',
            '_accesstoken_',
            ('_accesstoken_', {
                "expect_error": {"error": ["invalid_grant", "access_denied"],
                                 "stop": False}}),
            USERINFO_REQUEST_AUTH_METHOD
        ],
        "profile": "C,CI,CT,CIT..",
        "tests": {
            "verify-response": {
                "response_cls": [ErrorResponse],
                "error": ["access_denied", "invalid_token"],
                "status": WARNING}},
        "mti": {"all": "SHOULD"},
        "reference": "http://tools.ietf.org/html/draft-ietf-oauth-v2-31"
                     "#section-4.1",
    },
    'OP-OAuth-2nd-30s': {
        "desc": 'Trying to use authorization code twice with 30 seconds in '
                'between uses must result in an error [Basic, Hybrid]',
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
        "tests": {
            "verify-response": {
                "response_cls": [ErrorResponse],
                "error": ["access_denied", "invalid_grant"],
                "status": ERROR}},
        "mti": {"all": "SHOULD"},
        "note": "A 30 second delay is added between the first and the second "
                "use of the authorization code.",
        "reference": "http://tools.ietf.org/html/draft-ietf-oauth-v2-31"
                     "#section-4.1",
    },
    'OP-redirect_uri-NotReg': {
        "desc": 'Sent redirect_uri does not match a registered redirect_uri ['
                'Basic, Implicit, Hybrid]',
        "sequence": [
            '_discover_',
            '_register_',
            "note",
            ("_login_", {"function": mismatch_return_uri})
        ],
        "profile": "..",
        "note": "This test should result in the OpenID Provider "
                "displaying an error message in your user agent. "
                "You should ignore the status of this test "
                "in the test tool, since it will be incomplete. "
                "You must submit a screen shot of the error shown "
                "as part of your certification application.",
        'tests': {"verify-response": {"response_cls": [ErrorResponse]}},
        "mti": {"all": "MUST"},
    },
    'OP-redirect_uri-Missing': {
        "desc": 'Reject request without redirect_uri when multiple registered '
                '[Dynamic]',
        "sequence": [
            '_discover_',
            ('_register_', {"function": multiple_return_uris}),
            "note",
            ("_login_", {"request_args": {"redirect_uri": ""}})
        ],
        "profile": "..T",
        'tests': {"verify-response": {"response_cls": [ErrorResponse]}},
        "note": "This test should result in the OpenID Provider "
                "displaying an error message in your user agent. "
                "You should ignore the status of this test "
                "in the test tool, since it will be incomplete. "
                "You must submit a screen shot of the error shown "
                "as part of your certification application.",
        "mti": {"all": "MUST"},
    },
    'OP-redirect_uri-Query-Added': {
        "desc": "Request with redirect_uri with query component "
                "when registered redirect_uri has no query component "
                "[Dynamic]",
        "sequence": [
            '_discover_',
            '_register_',
            'note',
            ("_login_",
             {"function": (redirect_uri_with_query_component, {"foo": "bar"})})
        ],
        "profile": "..T",
        "note": "This test should result in the OpenID Provider "
                "displaying an error message in your user agent. "
                "You should ignore the status of this test "
                "in the test tool, since it will be incomplete. "
                "You must submit a screen shot of the error shown "
                "as part of your certification application.",
        "mti": {"all": "MUST"},
        'tests': {
            "verify-response": {
                "response_cls": [ErrorResponse],
                "error": ["access_denied"]}}
    },
    'OP-redirect_uri-Query-OK': {
        "desc": 'Request with a redirect_uri with a query component '
                'when a redirect_uri with the same query component is '
                'registered [Dynamic]',
        "sequence": [
            '_discover_',
            ('_register_',
             {"function": (
                 redirect_uris_with_query_component, {"foo": "bar"})}),
            ("_login_",
             {"function": (redirect_uri_with_query_component, {"foo": "bar"})})
        ],
        "profile": "..T",
        "mti": {"all": "MUST"},
        "reference": "http://tools.ietf.org/html/draft-ietf-oauth-v2-31"
                     "#section-3.1.2",
        'tests': {"verify-response": {"response_cls": [AuthorizationResponse]},
                  "check-query-part": {"foo": "bar"}},
    },
    'OP-redirect_uri-Query-Mismatch': {
        "desc": 'Rejects redirect_uri when query parameter does not match '
                'what is registed [Dynamic]',
        "sequence": [
            '_discover_',
            ('_register_',
             {
                 "function": (
                     redirect_uris_with_query_component, {"foo": "bar"})}),
            'note',
            ("_login_", {
                # different from the one registered
                "function": (redirect_uri_with_query_component, {"bar": "foo"})
            })
        ],
        "profile": "..T",
        "reference": "http://tools.ietf.org/html/draft-ietf-oauth-v2-31"
                     "#section-3.1.2",
        "note": "This test should result in the OpenID Provider "
                "displaying an error message in your user agent. "
                "You should ignore the status of this test "
                "in the test tool, since it will be incomplete. "
                "You must submit a screen shot of the error shown "
                "as part of your certification application.",
        'tests': {
            "verify-response": {
                "response_cls": [ErrorResponse],
                "error": ["access_denied"]}},
        "mti": {"all": "MUST"},
    },
    'OP-redirect_uri-RegFrag': {
        "desc": 'Reject registration where a redirect_uri has a fragment ['
                'Dynamic]',
        "sequence": [
            '_discover_',
            ('_register_', {
                "function": (redirect_uris_with_fragment, {"foo": "bar"})})
        ],
        "profile": "..T",
        'tests': {
            "verify-response": {
                "response_cls": [ErrorResponse],
                "error": ["invalid_request",
                          "invalid_configuration_parameter",
                          "invalid_redirect_uri"]}},
        "mti": {"all": "MUST"},
        "reference": "http://tools.ietf.org/html/draft-ietf-oauth-v2-31"
                     "#section-3.1.2",
    },
    'OP-redirect_uri-MissingOK': {
        "desc": 'No redirect_uri in request with one registered [Extra]',
        "sequence": [
            '_discover_',
            '_register_',
            "note",
            ('_login_', {"request_args": {"redirect_uri": ""}})
        ],
        "note": "This test may result in the OpenID Provider "
                "displaying an error message in your user agent. "
                "You should ignore the status of this test "
                "in the test tool if this happens, since it will be "
                "incomplete. "
                "It is also legal for the OP to successfully process "
                "this authentication request.",
        "profile": "....+",
        'tests': {
            "verify-response": {"response_cls": [AuthorizationResponse]}},
    },
    'OP-ClientAuth-Basic-Dynamic': {
        "desc": 'Access token request with client_secret_basic authentication '
                '[Basic, Hybrid]',
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
        'tests': {"verify-response": {"response_cls": [AuthorizationResponse,
                                                       AccessTokenResponse]}},
    },
    'OP-ClientAuth-Basic-Static': {
        "desc": 'Access token request with client_secret_basic authentication '
                '[Basic, Hybrid]',
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
        'tests': {"verify-response": {"response_cls": [AuthorizationResponse,
                                                       AccessTokenResponse]}},
    },
    'OP-ClientAuth-SecretPost-Dynamic': {
        "desc": 'Access token request with client_secret_post authentication '
                '[Basic, Hybrid]',
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
        'tests': {"verify-response": {"response_cls": [AuthorizationResponse,
                                                       AccessTokenResponse]}},
    },
    'OP-ClientAuth-SecretPost-Static': {
        "desc": 'Access token request with client_secret_post authentication '
                '[Basic, Hybrid]',
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
        'tests': {"verify-response": {"response_cls": [AuthorizationResponse,
                                                       AccessTokenResponse]}},
    },
    'OP-ClientAuth-PrivateJWT': {
        "desc": 'Access token request with private_key_jwt authentication ['
                'Extra]',
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
        'tests': {"verify-response": {"response_cls": [AuthorizationResponse,
                                                       AccessTokenResponse]}},
    },
    'OP-ClientAuth-SecretJWT': {
        "desc": 'Access token request with client_secret_jwt authentication ['
                'Extra]',
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
        'tests': {"verify-response": {"response_cls": [AuthorizationResponse,
                                                       AccessTokenResponse]}},
    },
    'OP-Discovery-Config': {
        "desc": 'Publishes openid-configuration discovery information [Config, '
                'Dynamic]',
        "sequence": ['_discover_'],
        "profile": ".T.",
        'tests': {"check-http-response": {}},
        "mti": {"Dynamic": "MUST"}
    },
    'OP-Discovery-jwks_uri': {
        "desc": 'Verify that jwks_uri is published ['
                'Config, Dynamic]',
        "sequence": ['_discover_'],
        "tests": {"providerinfo-has-jwks_uri": {},
                  "bare-keys": {},
                  "check-http-response": {}},
        "profile": ".T..s",
        "mti": {"Dynamic": "SHOULD"}
    },
    'OP-Discovery-claims_supported': {
        "desc": 'Verify that claims_supported is published ['
                'Config, Dynamic]',
        "sequence": ['_discover_'],
        "tests": {"providerinfo-has-claims_supported": {},
                  "check-http-response": {}},
        "profile": ".T.",
        "mti": {"Dynamic": "SHOULD"}
    },
    'OP-Discovery-JWKs': {
        "desc": 'Keys in OP JWKs well formed [Config, Dynamic]',
        "sequence": ['_discover_'],
        "profile": ".T.",
        "tests": {"verify-base64url": {"err_status": ERROR},
                  "check-http-response": {}},
        "mti": {"Dynamic": "MUST"}
    },
    'OP-Discovery-WebFinger-Email': {
        "desc": 'Can discover identifiers using e-mail syntax [Dynamic]',
        "profile": ".T...+",
        "sequence": [
            ("webfinger",
             {"kwarg_func": (get_principal, {"param": "webfinger_email"})})],
        "tests": {},
    },
    'OP-Discovery-WebFinger': {
        "desc": 'Can discover identifiers using URL syntax [Dynamic]',
        "profile": ".T...+",
        "sequence": [
            ("webfinger",
             {"kwarg_func": (get_principal, {"param": "webfinger_url"})})],
        "tests": {},
    },
    'OP-Registration-Endpoint': {
        "desc": 'Verify that registration_endpoint is published [Dynamic]',
        "sequence": ['_discover_'],
        "profile": ".T.T",
        "tests": {"verify-op-has-registration-endpoint": {}},
        "mti": {"Dynamic": "MUST"}
    },
    'OP-Registration-Dynamic': {
        "desc": 'Client registration request [Dynamic]',
        "sequence": [
            '_discover_',
            "_register_"
        ],
        "profile": "..T",
        "tests": {"check-http-response": {}},
        "mti": {"Dynamic": "MUST"}
    },
    'OP-Registration-policy_uri': {
        "desc": 'Registration with policy_uri [Dynamic]',
        "sequence": [
            'note',
            '_discover_',
            ('oic-registration', {"function": policy_uri}),
            "_login_"
        ],
        "profile": "..T",
        "note": "This test verifies that an OP displays a link "
                "to the RP's policy document. "
                "To make sure you get a fresh login page, "
                "you need to remove any cookies you may have received from "
                "the OP before proceeding.",
        "tests": {"verify-authn-response": {}},
    },
    'OP-Registration-logo_uri': {
        "desc": 'Registration with logo_uri [Dynamic]',
        "sequence": [
            'note',
            '_discover_',
            ('oic-registration', {"function": logo_uri}),
            "_login_"
        ],
        "profile": "..T",
        "note": "This test verifies that an OP displays the RP's logo. "
                "To make sure you get a fresh login page, "
                "you need to remove any cookies you may have received from "
                "the OP before proceeding.",
        "tests": {"verify-authn-response": {}},
    },
    'OP-Registration-tos_uri': {
        "desc": 'Registration with tos_uri [Dynamic]',
        "sequence": [
            'note',
            '_discover_',
            ('oic-registration', {"function": tos_uri}),
            '_login_'
        ],
        "profile": "..T",
        "note": "This test verifies that an OP displays a link "
                "to the RP's terms of service. "
                "To make sure you get a fresh login page, "
                "you need to remove any cookies you may have received from "
                "the OP before proceeding.",
        "tests": {"verify-authn-response": {}},
    },
    'OP-Registration-jwks': {
        "desc": 'Uses keys registered with jwks value [Dynamic]',
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
        "tests": {"verify-response": {"response_cls": [AuthorizationResponse,
                                                       AccessTokenResponse]}},
    },
    'OP-Registration-jwks_uri': {
        "desc": 'Uses keys registered with jwks_uri value [Dynamic]',
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
        'tests': {"verify-response": {"response_cls": [AuthorizationResponse,
                                                       AccessTokenResponse]}}
    },
    'OP-Registration-Sector-Bad': {
        "desc": 'Incorrect registration of sector_identifier_uri [Dynamic]',
        "sequence": [
            '_discover_',
            ('_register_',
             {
                 "support": {"error": {"subject_types_supported": "pairwise"}},
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
        "desc": 'Registering and then reading the registered client metadata '
                '[Extra]',
        "sequence": [
            '_discover_',
            '_register_',
            "read-registration"
        ],
        "profile": "..T..+",
        "tests": {"check-http-response": {}},
    },
    'OP-Registration-Sub-Public': {
        "desc": 'Registration of wish for public sub [Extra]',
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
        "tests": {"verify-response": {"response_cls": [AuthorizationResponse,
                                                       AccessTokenResponse]}},
    },
    'OP-Registration-Sub-Pairwise': {
        "desc": 'Registration of wish for pairwise sub [Extra]',
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
        "tests": {"verify-response": {"response_cls": [AuthorizationResponse,
                                                       AccessTokenResponse]}},
    },
    'OP-Registration-Sub-Differ': {
        "desc": 'Public and pairwise sub values differ [Extra]',
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
        'tests': {"different_sub": {},
                  "verify-response": {"response_cls": [AuthorizationResponse,
                                                       AccessTokenResponse]}}
    },
    'OP-Rotation-OP-Sig': {
        "desc": 'Can rotate OP signing keys [Dynamic]',
        "sequence": [
            '_discover_',
            'fetch_keys',
            "note",
            '_discover_',
            'fetch_keys',
        ],
        "note": "Please make your OP rotate its signing keys now. "
                "If you are not able to cause the server to rotate the keys "
                "while running the test, then you will have to self-assert "
                "that your deployment can do OP signing key rotation "
                "as part of your certification application.",
        "profile": ".T.T.s",
        # "profile": ".T.T.s.+",
        "tests": {"new-signing-keys": {},
                  "check-http-response": {}}
    },
    'OP-Rotation-RP-Sig': {
        "desc": 'Request access token, change RSA signing key and request '
                'another access token [Dynamic]',
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
    'OP-Rotation-OP-Enc': {
        "desc": 'Can rotate OP encryption keys [Extra]',
        "sequence": [
            '_discover_',
            'fetch_keys',
            "note",
            '_discover_',
            'fetch_keys',
        ],
        "note": "Please make your OP rotate its encryption keys now."
                "If you are not able to cause the server to rotate the keys "
                "while running the test, then you will have to self-assert "
                "that your deployment can do OP encryption key rotation "
                "as part of your certification application.",
        # "profile": ".T..e.+",
        "profile": ".T..e",
        "tests": {"new-encryption-keys": {}, "check-http-response": {}}
    },
    'OP-Rotation-RP-Enc': {
        # where is the RPs encryption keys used => userinfo encryption
        "desc": 'Request encrypted UserInfo, change RSA encryption key and '
                'request '
                'UserInfo again [Extra]',
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
            "rotate_enc_keys",
            "userinfo"
        ],
        "profile": "C,CI,CT,CIT..T.se.+",
        "tests": {"check-http-response": {}}
    },
    'OP-request_uri-Support': {
        "desc": 'Support request_uri request parameter [Dynamic]',
        "sequence": [
            '_discover_',
        ],
        "profile": "..T",
        "tests": {"check-http-response": {},
                  "check-request_uri-parameter-supported-support": {}}
    },
    'OP-request_uri-Unsigned': {
        "desc": 'Support request_uri request parameter with unsigned request '
                '[Basic, Implicit, Hybrid]',
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
                "kwargs_mod": {"request_method": "file",
                               "local_dir": "export",
                               "request_object_signing_alg": "none"},
                "kwarg_func": request_in_file,
            })
        ],
        "profile": "..F",
        "tests": {"authn-response-or-error": {
            "error": ["request_uri_not_supported"]}}
    },
    'OP-request_uri-Unsigned-Dynamic': {
        "desc": 'Support request_uri request parameter with unsigned request '
                '[Basic, Implicit, Hybrid, Dynamic]',
        "sequence": [
            '_discover_',
            ("_register_",
             {
                 "request_args": {
                     "request_object_signing_alg": "none"},
                 "support": {
                     "error": {
                         "request_uri_parameter_supported": True,
                         "request_object_signing_alg_values_supported": "none"}}
             }),
            ("_login_", {
                "kwargs_mod": {"request_method": "file",
                               "local_dir": "export",
                               "request_object_signing_alg": "none"},
                "kwarg_func": request_in_file,
            })
        ],
        "profile": "..T",
        "tests": {"verify-response": {"response_cls": [AuthorizationResponse]}}
    },
    'OP-request_uri-Sig': {
        "desc": 'Support request_uri request parameter with signed request ['
                'Dynamic]',
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
                "kwargs_mod": {
                    "request_method": "file",
                    "local_dir": "export",
                    "request_object_signing_alg": "RS256"},
                "kwarg_func": request_in_file,
            })
        ],
        "profile": "..T.s",
        "tests": {"authn-response-or-error": {
            "error": ["request_uri_not_supported"]}}
    },
    'OP-request_uri-Enc': {
        "desc": 'Support request_uri request parameter with encrypted request '
                '[Extra]',
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
                "kwargs_mod": {
                    "request_method": "file",
                    "local_dir": "export",
                    "request_object_signing_alg": "none",
                    "request_object_encryption_alg": "RSA1_5",
                    "request_object_encryption_enc": "A128CBC-HS256"},
                "kwarg_func": request_in_file,
            })
        ],
        "profile": "..T.se.+",
        "tests": {"authn-response-or-error": {
            "error": ["request_uri_not_supported"]}}
    },
    'OP-request_uri-SigEnc': {
        "desc": 'Support request_uri request parameter with signed and '
                'encrypted request [Extra]',
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
                "kwargs_mod": {
                    "request_method": "file",
                    "local_dir": "export",
                    "request_object_signing_alg": "RS256",
                    "request_object_encryption_alg": "RSA1_5",
                    "request_object_encryption_enc": "A128CBC-HS256"},
                "kwarg_func": request_in_file})
        ],
        "profile": "..T.se.+",
        "tests": {"authn-response-or-error": {
            "error": ["request_uri_not_supported"]}}
    },
    'OP-request-Support': {
        "desc": 'Support request request parameter [Extra]',
        "sequence": [
            '_discover_',
            # ("_register_",
            # {"support": {"warning": {"request_parameter_supported": True}}}),
            # ("_login_", {"kwargs_mod": {"request_method": "request"}})
        ],
        "profile": "....+",
        "tests": {"check-http-response": {},
                  "check-request-parameter-supported-support": {}}
    },
    'OP-request-Unsigned': {
        "desc": 'Support request request parameter with unsigned request ['
                'Basic, Implicit, Hybrid, Dynamic]',
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
                "kwargs_mod": {
                    "request_method": "request",
                    "request_object_signing_alg": "none"}})
        ],
        "profile": "...",
        "tests": {"authn-response-or-error": {
            "error": ["request_not_supported"]}}
    },
    'OP-request-Sig': {
        "desc": 'Support request request parameter with signed request [Extra]',
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
                "kwargs_mod": {
                    "request_method": "request",
                    "request_object_signing_alg": "RS256"}})
        ],
        "profile": "...s.+",
        "tests": {"authn-response-or-error": {
            "error": ["request_not_supported"]}}
    },
    'OP-claims-essential': {
        "desc": 'Claims request with essential name claim [Basic, Implicit, '
                'Hybrid]',
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
        "profile": "C,IT,CI,CT,CIT..",
        'tests': {"verify-claims": {"userinfo": {"name": None}},
                  "check-http-response": {}}
    },
    'OP-claims-sub': {
        "desc": 'Support claims request specifying sub value [Extra]',
        "sequence": [
            '_discover_',
            '_register_',
            '_login_',
            "_accesstoken_",
            "cache",
            'note',
            ("_login_", {"function": sub_claims}),
            "_accesstoken_",
        ],
        "note": "This test does one login to get a sub claim value. Then it "
                "does a fresh login using that sub value in a claims request. "
                "Please remove any cookies you received from the OpenID "
                "Provider before proceeding.",
        "profile": "....+",
        "tests": {"verify-response": {"response_cls": [AuthorizationResponse,
                                                       AccessTokenResponse]},
                  "verify-sub-value": {}}
    },
    # 'OP-claims-sub-none': {
    # "desc": 'Using prompt=none with user hint through sub in request [Extra]',
    # "sequence": [
    #         '_discover_',
    #         '_register_',
    #         '_login_',
    #         "_accesstoken_",
    #         'note',
    #         ("_login_", {
    #             "request_args": {"prompt": "none"},
    #             "function": sub_claims
    #         }),
    #     ],
    #     "note": "This test does one login to get a sub claim value.  Then it "
    #             "does a fresh login using that sub value in a claims
    # request. "
    #             "Please remove any cookies you received from the OpenID
    # Provider before proceeding.",
    #     "profile": "....+",
    #     "tests": {"verify-response": {"response_cls": [
    # AuthorizationResponse]}}
    # },
    'OP-claims-IDToken': {
        "desc": 'Requesting ID Token with email claim [Extra]',
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
                  "verify-response": {
                      "response_cls": [AccessTokenResponse,
                                       AuthorizationResponse]}}
    },
    'OP-claims-Split': {
        "desc": 'Supports returning different claims in ID Token and UserInfo '
                'Endpoint [Extra]',
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
        "desc": 'Supports combining claims requested with scope and claims '
                'request parameter [Extra]',
        "sequence": [
            '_discover_',
            '_register_',
            ("_login_", {
                "request_args": {
                    "scope": ["openid", "phone"],
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
        "desc": 'Claims request with voluntary email and picture claims ['
                'Extra]',
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
            'Claims request with essential name and voluntary email and '
            'picture claims [Extra]'),
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
        "desc": 'Requesting ID Token with essential auth_time claim [Extra]',
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
                  "verify-response": {
                      "response_cls": [AccessTokenResponse,
                                       AuthorizationResponse]}}
    },
    'OP-claims-acr-essential': {
        "desc": 'Requesting ID Token with essential acr claim [Extra]',
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
                  "verify-response": {
                      "response_cls": [AccessTokenResponse,
                                       AuthorizationResponse]}}
    },
    'OP-claims-acr-voluntary': {
        "desc": 'Requesting ID Token with voluntary acr claim [Extra]',
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
                  "verify-response": {
                      "response_cls": [AccessTokenResponse,
                                       AuthorizationResponse]}}
    },
    'OP-claims-acr=1': {
        "desc": 'Requesting ID Token with essential specific acr claim [Extra]',
        "sequence": [
            '_discover_',
            '_register_',
            ("_login_", {
                "function": specific_acr_claims,
                "support": {"error": {"acr_values_supported": ["1"]}}}),
            "_accesstoken_",
        ],
        "profile": "....+",
        'tests': {"verify-claims": {"id_token": {"acr": None}},
                  "verify-response": {
                      "response_cls": [AccessTokenResponse,
                                       AuthorizationResponse,
                                       ErrorResponse],
                      "error": ["access_denied"]}}
    },
}
