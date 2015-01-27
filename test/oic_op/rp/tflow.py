#!/usr/bin/env python
from testfunc import store_sector_redirect_uris, get_principal
from testfunc import id_token_hint
from testfunc import request_in_file
from testfunc import sub_claims
from testfunc import specific_acr_claims
from testfunc import login_hint
from testfunc import policy_uri
from testfunc import logo_uri
from testfunc import tos_uri
from testfunc import static_jwk
from testfunc import redirect_uris_with_query_component
from testfunc import redirect_uris_with_fragment
from testfunc import ui_locales
from testfunc import claims_locales
from testfunc import acr_value
from testfunc import mismatch_return_uri
from testfunc import multiple_return_uris
from testfunc import redirect_uri_with_query_component

__author__ = 'roland'

USERINFO_REQUEST_AUTH_METHOD = (
    "userinfo", {
        "kwargs_mod": {"authn_method": "bearer_header"},
        "method": "GET"
    })

FLOWS = {
    'OP-A-01': {
        "desc": 'Request with response_type=code',
        "sequence": ['_discover_', "_register_", "_login_"],
        "profile": "C..",
        'tests': {"check-http-response": {}},
        "mti": "MUST"
    },
    'OP-A-02': {
        "desc": 'Authorization request missing the response_type parameter',
        "sequence": [
            '_discover_',
            '_register_',
            ('_login_', {
                "request_args": {"response_type": []},
            })
        ],
        "tests": {
            "verify-error": {"error": ["invalid_request",
                                       "unsupported_response_type"]}},
        "profile": "..",
        "mti": "MUST"
    },
    'OP-A-03': {
        "desc": 'Request with response_type=id_token',
        "sequence": [
            '_discover_',
            '_register_',
            ("_login_", {
                "request_args": {"response_type": ["id_token"]}
            }),
        ],
        "profile": "I..",
        'tests': {"check-http-response": {}},
        "mti": "MUST",
        # "tests": {"check-authorization-response": {}},
    },
    'OP-A-04': {
        "desc": 'Request with response_type=id_token token',
        "sequence": [
            '_discover_',
            '_register_',
            ('_login_',
             {"request_args": {"response_type": ["id_token", "token"]}})
        ],
        "profile": "IT..",
        'tests': {"check-http-response": {}},
        "mti": "MUST"
    },
    'OP-A-05': {
        "desc": 'Request with response_type=code id_token',
        "sequence": ['_discover_', '_register_', '_login_'],
        "tests": {"check-http-response": {}, 'check-nonce': {}},
        "profile": "CI..",
        "mti": "MUST"
    },
    'OP-A-06': {
        "desc": 'Request with response_type=code token',
        "sequence": [
            '_discover_',
            '_register_',
            ('_login_',
             {"request_args": {"response_type": ["code", "token"]}})
        ],
        "profile": "CT..",
        'tests': {"check-http-response": {}},
        "mti": "MUST"
    },
    'OP-A-07': {
        "desc": 'Request with response_type=code id_token token',
        "sequence": [
            '_discover_',
            '_register_',
            ('_login_',
             {"request_args": {"response_type": ["code", "id_token", "token"]}})
        ],
        "profile": "CIT..",
        'tests': {"check-http-response": {}},
        "mti": "MUST"
    },
    'OP-A-08': {
        "desc": 'Request with response_mode=form_post',
        "sequence": [
            '_discover_',
            '_register_',
            ('_login_',
             {"request_args": {"response_mode": ["form_post"]}})
        ],
        "profile": "....+",
        'tests': {"check-http-response": {}},
        "mti": "MUST"
    },
    'OP-B-01d': {
        "desc": 'Asymmetric ID Token signature with rs256',
        "sequence": [
            '_discover_',
            ("oic-registration",
             {"request_args": {"id_token_signed_response_alg": "RS256"}}),
            "_login_", "_accesstoken_"],
        "profile": "..T.s",
        "mti": "MUST",
        "tests": {"verify-idtoken-is-signed": {"alg": "RS256"},
                  "check-http-response": {}}
    },
    'OP-B-01s': {
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
    'OP-B-02': {
        "desc": 'IDToken has kid',
        "sequence": ['_discover_', '_register_', "_login_", "_accesstoken_"],
        "mti": "MUST",
        "profile": "...s",
        "tests": {"verify-signed-idtoken-has-kid": {},
                  "check-http-response": {}}
    },
    'OP-B-03': {
        "desc": 'ID Token has nonce when requested for code flow',
        "sequence": [
            '_discover_',
            '_register_',
            ('_login_', {"request_args": {"nonce": "godmorgon"}}),
            '_accesstoken_'],
        "mti": "MUST",
        "profile": "C..",
        "tests": {"verify-nonce": {}, "check-http-response": {}}
    },
    'OP-B-04': {
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
        "mti": "MUST",
        "result": "The test passed if you were prompted to log in"
    },
    'OP-B-05': {
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
        "mti": "MUST"
    },
    'OP-B-06': {
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
        "mti": "MUST"
    },
    'OP-B-07': {
        "desc": 'ID Token has at_hash when ID Token and Access Token returned '
                'from Authorization Endpoint',
        "sequence": ['_discover_', '_register_', '_login_'],
        "mti": "MUST",
        "test": {'verify-athash': {}, "check-http-response": {}},
        "profile": "IT,CIT..",
    },
    'OP-B-08': {
        "desc": 'ID Token has c_hash when ID Token and Authorization Code '
                'returned from Authorization Endpoint',
        "sequence": ['_discover_', '_register_', '_login_'],
        "tests": {'verify-chash': {}, "check-http-response": {}},
        "profile": "CI,CIT..",
        "mti": "MUST"
    },
    'OP-B-09': {
        "desc": 'Request with nonce, verifies it was return in id_token',
        "sequence": ['_discover_', '_register_', '_login_', '_accesstoken_'],
        "tests": {"check-http-response": {}, 'check-nonce': {}},
        "profile": "I,IT,CI,CT,CIT..",
        "mti": "MUST"
    },
    'OP-C-01': {
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
        "mti": "MUST"
    },
    'OP-C-02': {
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
        "mti": "MUST"
    },
    'OP-C-03': {
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
        "mti": "MUST"
    },
    'OP-C-04': {
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
        "mti": "MUST"
    },
    'OP-C-05': {
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
    'OP-C-06': {
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
    'OP-D-01': {
        "desc": 'Login no nonce, code flow',
        "sequence": [
            '_discover_',
            '_register_',
            ('_login_', {"request_args": {"nonce": ""}})
        ],
        "profile": "C,CT..",
        'tests': {"check-http-response": {}},
        "mti": "MUST"
    },
    'OP-D-02': {
        "desc": 'Reject requests without nonce unless using the code flow',
        "sequence": [
            '_discover_',
            '_register_',
            ('_login_', {"request_args": {"nonce": ""}})
        ],
        "tests": {"verify-error": {"error": ["invalid_request"]}},
        "profile": "I,IT..",
        "mti": "MUST"
    },
    'OP-E-01': {
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
        "mti": "No err",
        'tests': {"verify-claims": {}, "check-http-response": {}}
    },
    'OP-E-02': {
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
    'OP-E-03': {
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
    'OP-E-04': {
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
    'OP-E-05': {
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
    'OP-F-01': {
        "desc": 'Request with display=page',
        "sequence": [
            'rm_cookie',
            '_discover_',
            '_register_',
            'note',
            ('_login_',
             {
                 "request_args": {"display": "page"},
                 "support": {"warning": {"display_values_supported": "page"}}
             })
        ],
        "note": "You should get the normal User Agent page view.",
        "profile": "..",
        'tests': {"check-http-response": {}},
        "mti": "No err"
    },
    'OP-F-02': {
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
        "note": "You should get a popup User Agent window",
        "profile": "..",
        'tests': {"check-http-response": {}},
        "mti": "No err"
    },
    'OP-G-01': {
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
        "mti": "MUST",
        # "result": "The test passed if you were prompted to log in"
    },
    'OP-G-02': {
        "desc": 'Request with prompt=none when not logged in',
        "sequence": [
            'rm_cookie',
            '_discover_',
            '_register_',
            ('_login_', {"request_args": {"prompt": "none"}})
        ],
        "mti": "MUST",
        "profile": "..",
        "tests": {"verify-error": {"error": ["login_required",
                                             "interaction_required",
                                             "session_selection_required",
                                             "consent_required"]}},
    },
    'OP-G-03': {
        "desc": 'Request with prompt=none when logged in',
        "sequence": [
            '_discover_',
            '_register_',
            '_login_',
            ('_login_', {"request_args": {"prompt": "none"}})
        ],
        "mti": "MUST",
        'tests': {"same-authn": {}, "check-http-response": {}},
        "profile": "..",
        "result": "The test passed if you were not prompted to log in"
    },
    'OP-H-01': {
        "desc": 'Request with extra query component',
        "sequence": [
            '_discover_',
            '_register_',
            ('_login_', {"request_args": {"extra": "foobar"}})
        ],
        "profile": "..",
        'tests': {"check-http-response": {}},
        "mti": "MUST",
    },
    'OP-H-02': {
        "desc": 'Using prompt=none with user hint through id_token_hint',
        "sequence": [
            '_discover_',
            '_register_',
            "_login_",
            "_accesstoken_",
            "cache-id_token",
            'rm_cookie',
            '_discover_',
            '_register_',
            ('_login_', {
                "request_args": {"prompt": "none"},
                "function": id_token_hint}
            )
        ],
        "profile": "..",
        'tests': {"same-authn": {}, "check-http-response": {}},
        "mti": "SHOULD",
    },
    'OP-H-03': {
        "desc": 'Giving a login hint',
        "sequence": [
            'rm_cookie',
            '_discover_',
            '_register_',
            ("_login_", {"function": login_hint})
        ],
        "profile": "..",
        'tests': {"check-http-response": {}},
        "mti": "No err",
        "result": "You should be requested to log in as a predefined user"
    },
    'OP-H-04': {
        "desc": 'Providing ui_locales',
        "sequence": [
            'rm_cookie',
            'note',
            '_discover_',
            '_register_',
            ('_login_', {"request_args": {},
                         "function": ui_locales}),
        ],
        "note": "The user interface may now use the locale of choice",
        "profile": "..",
        'tests': {"check-http-response": {}},
        "mti": "No err"
    },
    'OP-H-05': {
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
        "note": "Claims may now be returned in the locale of choice",
        "profile": "..",
        'tests': {"check-http-response": {}},
        "mti": "No err"
    },
    'OP-H-06': {
        "desc": 'Providing preferred acr_values',
        "sequence": [
            '_discover_',
            '_register_',
            ('_login_', {"request_args": {},
                         "function": acr_value}),
            "_accesstoken_",
        ],
        "mti": "No err",
        "profile": "..",
        'tests': {"used-acr-value": {}, "check-http-response": {}}
    },
    'OP-I-01': {
        "desc": 'Trying to use access code twice should result in an error',
        "sequence": [
            '_discover_',
            '_register_',
            '_login_',
            "_accesstoken_",
            "_accesstoken_"
        ],
        "profile": "C,CI,CT,CIT..",
        "tests": {"verify-bad-request-response": {}},
        "mti": "SHOULD",
        "reference": "http://tools.ietf.org/html/draft-ietf-oauth-v2-31"
                     "#section-4.1",
    },
    'OP-I-02': {
        "desc": 'Trying to use access code twice should result in '
                'revoking previous issued tokens',
        "sequence": [
            '_discover_',
            '_register_',
            '_login_',
            "_accesstoken_",
            "_accesstoken_",
            USERINFO_REQUEST_AUTH_METHOD
        ],
        "profile": "C,CI,CT,CIT..",
        "tests": {"verify-bad-request-response": {}},
        "mti": "SHOULD",
        "reference": "http://tools.ietf.org/html/draft-ietf-oauth-v2-31"
                     "#section-4.1",
    },
    'OP-J-01': {
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
        'tests': {"check-http-response": {}},
        "mti": "MUST",
    },
    'OP-J-02': {
        "desc": 'Reject request without redirect_uri when multiple registered',
        "sequence": [
            '_discover_',
            ('_register_', {"function": multiple_return_uris}),
            "expect_err",
            ("_login_", {"request_args": {"redirect_uri": ""}})
        ],
        "profile": "..T",
        'tests': {"check-http-response": {}},
        "note": "The next request should result in the OpenID Connect Provider "
                "returning an error message to your web browser.",
        "mti": "MUST",
    },
    'OP-J-03': {
        "desc": 'Request with redirect_uri with query component',
        "sequence": [
            '_discover_',
            '_register_',
            ("_login_",
             {"function": (redirect_uri_with_query_component, {"foo": "bar"})})
        ],
        "profile": "..T",
        "mti": "MUST",
        'tests': {"verify-redirect_uri-query_component": {"foo": "bar"},
                  "check-http-response": {}}
    },
    'OP-J-04': {
        "desc": 'Registration where a redirect_uri has a query component',
        "sequence": [
            '_discover_',
            ('_register_',
             {"function": (
                 redirect_uris_with_query_component, {"foo": "bar"})}),
        ],
        "profile": "..T",
        "mti": "MUST",
        "reference": "http://tools.ietf.org/html/draft-ietf-oauth-v2-31"
                     "#section-3.1.2",
        'tests': {"check-http-response": {}},
    },
    'OP-J-05': {
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
        'tests': {"check-http-response": {}},
        "mti": "MUST",
    },
    'OP-J-06': {
        "desc": 'Reject registration where a redirect_uri has a fragment',
        "sequence": [
            '_discover_',
            ('_register_', {
                "function": (redirect_uris_with_fragment, {"foo": "bar"})})
        ],
        "profile": "..T",
        "tests": {"verify-bad-request-response": {}},
        "mti": "MUST",
        "reference": "http://tools.ietf.org/html/draft-ietf-oauth-v2-31"
                     "#section-3.1.2",
    },
    'OP-J-07': {
        "desc": 'No redirect_uri in request with one registered',
        "sequence": [
            '_discover_',
            '_register_',
            "expect_err",
            ('_login_', {"request_args": {"redirect_uri": ""}})
        ],
        "profile": "....+",
        'tests': {"check-http-response": {}},
    },
    'OP-K-01d': {
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
    'OP-K-01s': {
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
    'OP-K-02d': {
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
    'OP-K-02s': {
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
    'OP-K-03': {
        "desc": 'Access token request with public_key_jwt authentication',
        "sequence": [
            '_discover_',
            ('_register_',
             {
                 "request_args": {
                     "token_endpoint_auth_method": "public_key_jwt"},
             }),
            '_login_',
            ("_accesstoken_",
             {
                 "kwargs_mod": {"authn_method": "public_key_jwt"},
                 "support": {
                     "warning": {
                         "token_endpoint_auth_methods_supported":
                             "public_key_jwt"}}
             }),
        ],
        "profile": "...s.+",
        'tests': {"check-http-response": {}},
    },
    'OP-K-04': {
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
        "profile": "...s.+",
        'tests': {"check-http-response": {}},
    },
    'OP-L-01': {
        "desc": 'Publish openid-configuration discovery information',
        "sequence": ['_discover_'],
        "profile": ".T.",
        'tests': {"check-http-response": {}},
    },
    'OP-L-02': {
        "desc": 'Verify that jwks_uri and claims_supported are published',
        "sequence": ['_discover_'],
        "tests": {"providerinfo-has-jwks_uri": {},
                  "providerinfo-has-claims_supported": {},
                  "check-http-response": {}},
        "profile": ".T.",
    },
    'OP-L-03': {
        "desc": 'Keys in OP JWKs well formed',
        "sequence": ['_discover_'],
        "profile": ".T.",
        "tests": {"verify-base64url": {}, "check-http-response": {}},
    },
    'OP-L-05': {
        "desc": 'Can Discover Identifiers using E-Mail Syntax',
        "profile": ".T...+",
        #"profile": ".T.",
        "sequence": [
            ("webfinger",
             {"kwarg_func": (get_principal, {"param": "webfinger_email"})})],
        "tests": {"check-http-response": {}},
    },
    'OP-L-06': {
        "desc": 'Can Discover Identifiers using URL Syntax',
        "profile": ".T...+",
        "sequence": [
            ("webfinger",
             {"kwarg_func": (get_principal, {"param": "webfinger_url"})})],
        "tests": {"check-http-response": {}},
    },
    'OP-M-01': {
        "desc": 'Verify that registration_endpoint is published',
        "sequence": ['_discover_'],
        "profile": ".T.",
        "tests": {"verify-op-has-registration-endpoint": {}},
    },
    'OP-M-02': {
        "desc": 'Client registration Request',
        "sequence": [
            '_discover_',
            "_register_"
        ],
        "profile": "..T",
        "tests": {"check-http-response": {}},
    },
    'OP-M-03': {
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
    'OP-M-04': {
        "desc": 'Registration with logo uri',
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
        "tests": {"check-http-response": {}},
    },
    'OP-M-05': {
        "desc": 'Registration with tos url',
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
        "tests": {"check-http-response": {}},
    },
    'OP-M-06': {
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
        "profile": "..T",
        "tests": {"check-http-response": {}},
    },
    'OP-M-07': {
        "desc": 'Uses Keys Registered with jwks_uri Value',
        "sequence": [
            '_discover_',
            '_register_',
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
        "profile": "..T",
        'tests': {"check-http-response": {}}
    },
    'OP-M-08': {
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
        "tests": {"check-http-response": {}},
    },
    'OP-M-09': {
        "desc": 'Registering and then read the client info',
        "sequence": [
            '_discover_',
            '_register_',
            "read-registration"
        ],
        "profile": "..T..+",
        "tests": {"check-http-response": {}},
    },
    'OP-M-10': {
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
    'OP-M-11': {
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
    'OP-M-12': {
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
    'OP-N-01': {
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
    'OP-N-02': {
        "desc": 'Request access token, change RSA sign key and request another '
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
        "profile": "..T.s",
        "tests": {"check-http-response": {}}
    },
    'OP-N-03': {
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
    'OP-N-04': {
        # where is the RPs encryption keys used => userinfo encryption
        "desc": 'Request encrypted user info, change RSA enc key and request '
                'user info again',
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
        "profile": "..T.se.+",
        "tests": {"check-http-response": {}}
    },
    'OP-O-01': {
        "desc": 'Support request_uri Request Parameter',
        "sequence": [
            '_discover_',
        ],
        "profile": "..T",
        "tests": {"check-http-response": {},
                  "check-request_uri-parameter-supported-support": {}}
    },
    'OP-O-02': {
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
            ("_login_", {"kwargs_mod": {"request_method": "file",
                                        "local_dir": "export",
                                        "algorithm": "none"},
                         "kwarg_func": request_in_file})
        ],
        "profile": "...n",
        "tests": {"check-http-response": {}}
    },
    'OP-O-03': {
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
            ("_login_", {"kwargs_mod": {"request_method": "file",
                                        "local_dir": "export"},
                         "kwarg_func": request_in_file})
        ],
        "profile": "..T.s",
        "tests": {"check-http-response": {}}
    },
    'OP-O-04': {
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
            ("_login_", {"kwargs_mod": {"request_method": "file",
                                        "local_dir": "export"},
                         "kwarg_func": request_in_file})
        ],
        "profile": "..T.se.+",
        "tests": {"check-http-response": {}}
    },
    'OP-O-05': {
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
            ("_login_", {"kwarg_func": request_in_file})
        ],
        "profile": "..T.se.+",
        "tests": {"check-http-response": {}}
    },
    'OP-P-01': {
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
    'OP-P-02': {
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
            ("_login_", {"kwargs_mod": {"request_method": "request"}})
        ],
        "profile": "...n",
        "tests": {"check-http-response": {}}
    },
    'OP-P-03': {
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
            ("_login_", {"kwargs_mod": {"request_method": "request"}})
        ],
        "profile": "...s.+",
        "tests": {"check-http-response": {}}
    },
    'OP-Q-01': {
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
        "profile": "..",
        'tests': {"verify-claims": {"userinfo": {"name": None}},
                  "check-http-response": {}}
    },
    'OP-Q-02': {
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
        "tests": {"check-http-response": {}},
    },
    'OP-Q-03': {
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
        "tests": {"check-http-response": {}}
    },
    'OP-Q-04': {
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
    'OP-Q-05': {
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
        "profile": "....+",
        'tests': {"verify-claims": {"userinfo": {"name": None},
                                    "id_token": {"email": None}},
                  "check-http-response": {}}
    },
    'OP-Q-06': {
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
                    }}
            }),
            "_accesstoken_",
        ],
        "profile": "....+",
        'tests': {"verify-claims": {"userinfo": {"phone": None},
                                    "id_token": {"email": None}},
                  "check-http-response": {}}
    },
    'OP-Q-07': {
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
        "profile": "....+",
        'tests': {"verify-claims": {"userinfo": {"picture": None},
                                    "id_token": {"email": None}},
                  "check-http-response": {}}
    },
    'OP-Q-08': {
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
        "profile": "....+",
        'tests': {"verify-claims": {"userinfo": {"picture": None,
                                                 "name": None,
                                                 "email": None}},
                  "check-http-response": {}}
    },
    'OP-Q-09': {
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
        'tests': {"verify-claims": {"id_token": {"auth_time": None}},
                  "check-http-response": {}}
    },
    'OP-Q-10': {
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
    'OP-Q-11': {
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
    'OP-Q-12': {
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
    # TODO R and S tests to be added
}

