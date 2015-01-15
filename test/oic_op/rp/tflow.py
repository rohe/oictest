import copy
import importlib
from oic.oauth2 import rndstr
from oic.oic.message import factory as message_factory

from oictest.oidcrp import OIDCTestSetup
from oictest.check import factory as check_factory

from rrtest import Trace

from testclass import PHASES
from testfunc import store_sector_redirect_uris
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

PMAP = {"B": "Basic", "I": "Implicit", "H": "Hybrid"}

PROFILEMAP = {
    "Basic": {
        "_login_": ("oic-login", {"request_args": {"response_type": ["code"]}}),
        "_accesstoken_": "access-token-request",
        "flows": [
            'OP-A-02',
            'OP-B-01', 'OP-B-02', 'OP-B-03', 'OP-B-04', 'OP-B-05', 'OP-B-06',
            'OP-C-01', 'OP-C-02', 'OP-C-03',
            'OP-D-01',
            'OP-E-01', 'OP-E-02', 'OP-E-03', 'OP-E-04', 'OP-E-05',
            'OP-F-01', 'OP-F-02',
            'OP-G-01', 'OP-G-02',
            'OP-H-01', 'OP-H-02', 'OP-H-03', 'OP-H-04', 'OP-H-05', 'OP-H-06',
            'OP-I-01', 'OP-I-02',
            'OP-J-01', 'OP-J-02', 'OP-J-03', 'OP-J-05',
            'OP-K-01', 'OP-K-02',
            'OP-M-03', 'OP-M-04', 'OP-M-05',
            'OP-O-01', 'OP-O-02',
            'OP-P-01', 'OP-P-02',
            'OP-Q-01'
        ]
    },
    "Implicit": {
        "_login_": ("oic-login",
                    {"request_args": {"response_type": ["id_token", "token"]}}),
        "_accesstoken_": None,
        "flows": [
            'OP-A-02', 'OP-A-03', 'OP-A-04',
            'OP-B-01', 'OP-B-02', 'OP-B-04', 'OP-B-07',
            'OP-C-01', 'OP-C-02', 'OP-C-03',
            'OP-D-02',
            'OP-E-01', 'OP-E-02', 'OP-E-03', 'OP-E-04', 'OP-E-05',
            'OP-F-01', 'OP-F-02',
            'OP-G-01', 'OP-G-02',
            'OP-H-01', 'OP-H-02', 'OP-H-03', 'OP-H-04', 'OP-H-05', 'OP-H-06',
            'OP-J-01', 'OP-J-02', 'OP-J-03', 'OP-J-05',
            'OP-M-03', 'OP-M-04', 'OP-M-05',
            'OP-O-01', 'OP-O-02',
            'OP-P-01', 'OP-P-02',
            'OP-Q-01'
        ]
    },
    "Hybrid": {
        "_login_": ("oic-login",
                    {"request_args": {"response_type": ["code", "id_token"]}}),
        "_accesstoken_": None,
        "flows": [
            'OP-A-02', 'OP-A-05', 'OP-A-06', 'OP-A-07',
            'OP-B-01', 'OP-B-02', 'OP-B-04', 'OP-B-07', 'OP-B-08',
            'OP-C-01', 'OP-C-02', 'OP-C-03',
            'OP-D-02',
            'OP-E-01', 'OP-E-02', 'OP-E-03', 'OP-E-04', 'OP-E-05',
            'OP-F-01', 'OP-F-02',
            'OP-G-01', 'OP-G-02',
            'OP-H-01', 'OP-H-02', 'OP-H-03', 'OP-H-04', 'OP-H-05', 'OP-H-06',
            'OP-I-01', 'OP-I-02',
            'OP-J-01', 'OP-J-02', 'OP-J-03', 'OP-J-05',
            'OP-M-03', 'OP-M-04', 'OP-M-05',
            'OP-O-01', 'OP-O-02',
            'OP-P-01', 'OP-P-02',
            'OP-Q-01'
        ]
    },
    "Discover": {
        "flow": {
            "Basic": [
                'OP-B-06',
                'OP-L-01', 'OP-L-02', 'OP-L-03',
                'OP-M-01', 'OP-M-06', 'OP-M-07', 'OP-M-08',
                'OP-N-01', 'OP-N-02',
                'OP-O-01', 'OP-O-02', 'OP-O-03'
            ],
            "Implicit": [
                'OP-B-06',
                'OP-L-01', 'OP-L-02', 'OP-L-03',
                'OP-M-01', 'OP-M-08',
                'OP-N-01',
                'OP-O-01', 'OP-O-02', 'OP-O-03'
            ],
            "Hybrid": [
                'OP-B-06',
                'OP-L-01', 'OP-L-02', 'OP-L-03',
                'OP-M-01', 'OP-M-06', 'OP-M-07', 'OP-M-08',
                'OP-N-01', 'OP-N-02',
                'OP-O-01', 'OP-O-02', 'OP-O-03'
            ],
        },
        "flows": [
            'OP-B-06',
            'OP-L-01', 'OP-L-02', 'OP-L-03',
            'OP-M-01', 'OP-M-06', 'OP-M-07', 'OP-M-08',
            'OP-N-01', 'OP-N-02',
            'OP-O-01', 'OP-O-02', 'OP-O-03'
        ],
        "*": ("provider-discovery", {})
    },
    "Register": {
        "flows": [
            'OP-B-06',
            'OP-C-04',
            'OP-J-04', 'OP-J-06', 'OP-J-07',
            'OP-L-01', 'OP-L-02', 'OP-L-03',
            'OP-N-01'
        ],
        "Basic": (
            "oic-registration",
            {"request_args": {
                "response_types": ["code"],
                # don't register any
                "token_endpoint_auth_method": [],
                "userinfo_signed_response_alg": [],
                "id_token_signed_response_alg": [],
                "request_object_signing_alg": [],
                "grant_types": ["authorization_code"]
            }}
        ),
        "Implicit": (
            "oic-registration",
            {"request_args": {
                "response_types": ["id_token", "id_token token"],
                # don't register any
                "token_endpoint_auth_method": [],
                "userinfo_signed_response_alg": [],
                "id_token_signed_response_alg": [],
                "request_object_signing_alg": [],
                "grant_types": ["implicit"]
            }}
        ),
        "Hybrid": (
            "oic-registration",
            {"request_args": {
                "response_types": ["code id_token", "code token",
                                   "code id_token token"],
                # don't register any
                "token_endpoint_auth_method": [],
                "userinfo_signed_response_alg": [],
                "id_token_signed_response_alg": [],
                "request_object_signing_alg": [],
                "grant_types": []
            }}
        ),
    }
}

USERINFO_REQUEST_AUTH_METHOD = (
    "userinfo", {
        "kwargs_mod": {"authn_method": "bearer_header"},
        "method": "GET"
    })


FLOWS = {
    'OP-A-01': {
        "desc": 'Request with response_type=code',
        "sequence": ['_discover_', "_register_", "_login_"],
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
        "mti": "MUST"
    },
    'OP-A-03': {
        "desc": 'Request with response_type=id_token',
        "sequence": [
            '_discover_',
            '_register_',
            "_login_"
        ],
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
        "endpoints": ["authorization_endpoint"],
        "mti": "MUST"
    },
    'OP-A-05': {
        "desc": 'Request with response_type=code id_token',
        "sequence": ['_discover_', '_register_', '_login_'],
        "tests": {'check-nonce': {}},
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
        "mti": "MUST"
    },
    'OP-A-08': {
        "desc": 'Request with response_type=form_post',
        "sequence": [
            '_discover_',
            '_register_',
            ('_login_',
             {"request_args": {"response_type": ["form_post"]}})
        ],
        "mti": "MUST"
    },
    'OP-B-01': {
        "desc": 'Asymmetric ID Token signature with rs256',
        "sequence": [
            '_discover_',
            ("oic-registration",
             {"request_args": {"id_token_signed_response_alg": "RS256"}}),
            "_login_", "_accesstoken_"],
        "mti": "MUST",
        "tests": {"verify-idtoken-is-signed": {"alg": "RS256"}}
    },
    'OP-B-02': {
        "desc": 'IDToken has kid',
        "sequence": ['_discover_', '_register_', "_login_", "_accesstoken_"],
        "mti": "MUST",
        "tests": {"verify-signed-idtoken-has-kid": {}}
    },
    'OP-B-03': {
        "desc": 'ID Token has nonce when requested for code flow',
        "sequence": ['_discover_', "_register_", "_login_", "_accesstoken_"],
        "mti": "MUST",
        "tests": {"verify-nonce": {}}
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
        "tests": {"multiple-sign-on": {}},
        "mti": "MUST"
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
        "tests": {"same-authn": {}},
        "mti": "MUST"
    },
    'OP-B-06': {
        "desc": 'Unsecured ID Token signature with none',
        "sequence": [
            '_discover_',
            ("oic-registration",
             {
                 "request_args": {"id_token_signed_response_alg": "none"},
                 "support": {"id_token_signing_alg_values_supported": "none"},
             }
            ),
            "_login_",
            "_accesstoken_"
        ],
        "tests": {"unsigned-idtoken": {}},
        "mti": "MUST"
    },
    'OP-B-07': {
        "desc": 'Includes at_hash in ID Token when Implicit Flow is Used',
        "sequence": ['_discover_', '_register_', '_login_'],
        "mti": "MUST",
        "test": {'verify-athash': {}}
    },
    'OP-B-08': {
        "desc": 'Includes c_hash in ID Token when Code Flow is Used',
        "sequence": ['_discover_', '_register_', '_login_'],
        "tests": {'verify-chash': {}},
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
                              "userinfo_signing_alg_values_supported": "RS256"}
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
        "tests": {"asym-signed-userinfo": {"alg": "RS256"}},
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
                     "userinfo_signing_alg_values_supported": "none",
                     "userinfo_encryption_alg_values_supported": "RSA1_5",
                     "userinfo_encryption_enc_values_supported": "A128CBC-HS256"
                 }
             }
            ),
            '_login_',
            "_accesstoken_",
            ("userinfo",
             {
                 "kwargs_mod": {"authn_method": "bearer_header"},
                 "method": "GET"
             }
            )],
        "tests": {"encrypted-userinfo": {}},
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
                     "userinfo_signing_alg_values_supported": "none",
                     "userinfo_encryption_alg_values_supported": "RSA1_5",
                     "userinfo_encryption_enc_values_supported": "A128CBC-HS256"
                 }
             }
            ),
            '_login_',
            "_accesstoken_",
            ("userinfo",
             {
                 "kwargs_mod": {"authn_method": "bearer_header"},
                 "method": "GET"
             }
            )
        ],
        "tests": {
            "encrypted-userinfo": {},
            "asym-signed-userinfo": {"alg": "RS256"}},
    },
    'OP-D-01': {
        "desc": 'Login no nonce, code flow',
        "sequence": [
            '_discover_',
            '_register_',
            ('_login_', {"request_args": {"nonce": ""}})
        ],
        "mti": "MUST"
    },
    'OP-D-02': {
        "desc": 'Login no nonce, implicit flow',
        "sequence": [
            '_discover_',
            '_register_',
            ('_login_', {"request_args": {"nonce": ""}})
        ],
        "tests": [("verify-error", {"error": ["invalid_request"]})],
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
                 "support": {"scopes_supported": ["profile"]}
             }),
            "_accesstoken_",
            ("userinfo", {
                "kwargs_mod": {"authn_method": "bearer_header"},
                "method": "GET"
            })
        ],
        "mti": "No err"
    },
    'OP-E-02': {
        "desc": 'Scope Requesting email Claims',
        "sequence": [
            '_discover_',
            '_register_',
            ('_login_',
             {
                 "request_args": {"scope": ["openid", "email"]},
                 "support": {"scopes_supported": ["email"]}
             }),
            "_accesstoken_",
            ("userinfo", {
                "kwargs_mod": {"authn_method": "bearer_header"},
                "method": "GET"
            })
        ],
        "mti": "No err"
    },
    'OP-E-03': {
        "desc": 'Scope Requesting address Claims',
        "sequence": [
            '_discover_',
            '_register_',
            ('_login_',
             {
                 "request_args": {"scope": ["openid", "address"]},
                 "support": {"scopes_supported": ["address"]}
             }),
            "_accesstoken_",
            ("userinfo", {
                "kwargs_mod": {"authn_method": "bearer_header"},
                "method": "GET"
            })
        ],
        "mti": "No err"
    },
    'OP-E-04': {
        "desc": 'Scope Requesting phone Claims',
        "sequence": [
            '_discover_',
            '_register_',
            ('_login_',
             {
                 "request_args": {"scope": ["openid", "phone"]},
                 "support": {"scopes_supported": ["phone"]}
             }),
            "_accesstoken_",
            ("userinfo", {
                "kwargs_mod": {"authn_method": "bearer_header"},
                "method": "GET"
            })
        ],
        "mti": "No err"
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
                 "support": {"scopes_supported": ["profile", "email", "address",
                                                  "phone"]}
             }),
            "_accesstoken_",
            ("userinfo", {
                "kwargs_mod": {"authn_method": "bearer_header"},
                "method": "GET"
            })
        ],
        "mti": "No err"
    },
    'OP-F-01': {
        "desc": 'Request with display=page',
        "sequence": [
            '_discover_',
            '_register_',
            ('_login_',
             {
                 "request_args": {"display": "page"},
                 "support": {"display_values_supported": "page"}
             })
        ],
        "mti": "No err"
    },
    'OP-F-02': {
        "desc": 'Request with display=popup',
        "sequence": [
            '_discover_',
            '_register_',
            ('_login_',
             {
                 "request_args": {"display": "popup"},
                 "support": {"display_values_supported": "popup"}
             })
        ],
        "mti": "No err"
    },
    'OP-G-01': {
        "desc": 'Request with prompt=login',
        "sequence": [
            '_discover_',
            '_register_',
            "_login_",
            "note",
            ('_login_', {"request_args": {"prompt": "login"}})
        ],
        "note": "You should get a request for authentication even though you "
                "already are",
        "mti": "MUST"
    },
    'OP-G-02': {
        "desc": 'Request with prompt=none',
        "sequence": [
            'rm_cookie',
            '_discover_',
            '_register_',
            ('_login_', {"request_args": {"prompt": "none"}})
        ],
        "mti": "MUST",
        "tests": {"verify-error": {"error": ["login_required",
                                             "interaction_required",
                                             "session_selection_required",
                                             "consent_required"]}}
    },
    'OP-H-01': {
        "desc": 'Request with extra query component',
        "sequence": [
            '_discover_',
            '_register_',
            ('_login_', {"request_args": {"extra": "foobar"}})
        ],
        "mti": "MUST",
    },
    'OP-H-02': {
        "desc": 'Using prompt=none with user hint through id_token_hint',
        "sequence": [
            '_discover_',
            '_register_',
            "_login_",
            "_accesstoken_",
            'rm_cookie',
            ('_login_', {
                "request_args": {"prompt": "none"},
                "function": id_token_hint}
            )
        ],
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
        "mti": "No err"
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
        'tests': {"used-acr-value": {}}
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
        "note": "The next request should result in the OpenID Connect Provider "
                "returning an error message to your web browser.",
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
        "mti": "MUST",
        'tests': {"verify-redirect_uri-query_component": {"foo": "bar"}}
    },
    'OP-J-04': {
        "desc": 'Registration where a redirect_uri has a query component',
        "sequence": [
            '_discover_',
            ('_register_',
             {"function": (
                 redirect_uris_with_query_component, {"foo": "bar"})}),
        ],
        "mti": "MUST",
        "reference": "http://tools.ietf.org/html/draft-ietf-oauth-v2-31"
                     "#section-3.1.2",
    },
    'OP-J-05': {
        "desc": 'Rejects redirect_uri when Query Parameter Does Not Match',
        "sequence": [
            '_discover_',
            ('_register_',
             {
             "function": (redirect_uris_with_query_component, {"foo": "bar"})}),
            'expect_err',
            ("_login_", {
                # different from the one registered
                "function": (redirect_uri_with_query_component, {"bar": "foo"})
            })
        ],
        "reference": "http://tools.ietf.org/html/draft-ietf-oauth-v2-31"
                     "#section-3.1.2",
        "mti": "MUST",
    },
    'OP-J-06': {
        "desc": 'Reject registration where a redirect_uri has a fragment',
        "sequence": [
            '_discover_',
            ('_register_', {
                "function": (redirect_uris_with_fragment, {"foo": "bar"})})
        ],
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
    },
    'OP-K-01': {
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
                     "token_endpoint_auth_methods_supported":
                         "client_secret_basic"}
             }),
        ],
        "profile": {"Basic": "MUST"}
    },
    'OP-K-02': {
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
                     "token_endpoint_auth_methods_supported":
                         "client_secret_post"}
             }),
        ],
        "profile": {"Basic": "MUST"}
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
                     "token_endpoint_auth_methods_supported":
                         "public_key_jwt"}
             }),
        ],
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
                     "token_endpoint_auth_methods_supported":
                         "client_secret_jwt"}
             }),
        ],
    },
    'OP-L-01': {
        "desc": 'Publish openid-configuration discovery information',
        "sequence": ['_discover_'],
    },
    'OP-L-02': {
        "desc": 'Verify that jwks_uri and claims_supported are published',
        "sequence": ['_discover_'],
        "tests": [("providerinfo-has-jwks_uri", {}),
                  ("providerinfo-has-claims_supported", {})],
    },
    'OP-L-03': {
        "desc": 'Keys in OP JWKs well formed',
        "sequence": ['_discover_'],
        "tests": [("verify-base64url", {})],
    },
    'OP-L-04': {
        "desc": 'Verify that registration_endpoint is published',
        "sequence": ['_discover_'],
        "tests": [("verify-op-has-registration-endpoint", {})],
    },
    'OP-L-05': {
        "desc": 'Can Discover Identifiers using E-Mail/URL Syntax',
        "sequence": ["webfinger"],
    },
    'OP-M-01': {
        "desc": 'Client registration Request',
        "sequence": [
            '_discover_',
            "_register_"
        ],
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
        'note': "When you get the login page this time you should have a "
                "link to the client policy"
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
        'note': "When you get the login page this time you should have the "
                "clients logo on the page"
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
        'note': "When you get the login page this time you should have a "
                "link to the clients Terms of Service"
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
                     "token_endpoint_auth_methods_supported":
                         "client_secret_jwt"}
             }),
        ]
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
                     "token_endpoint_auth_methods_supported":
                         "client_secret_jwt"}
             }),
        ]
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
    },
    'OP-M-09': {
        "desc": 'Registering and then read the client info',
        "sequence": [
            '_discover_',
            '_register_',
            "read-registration"
        ],
    },
    'OP-M-10': {
        "desc": 'Registration of wish for public sub',
        "sequence": [
            '_discover_',
            ('_register_',
             {
                 "request_args": {"subject_type": "public"},
                 "support": {"subject_types_supported": "public"}
             }),
            "_login_",
            "_accesstoken_"
        ],
    },
    'OP-M-11': {
        "desc": 'Registration of wish for pairwise sub',
        "sequence": [
            '_discover_',
            ('_register_',
             {
                 "request_args": {"subject_type": "pairwise"},
                 "support": {"subject_types_supported": "pairwise"}
             }),
            "_login_",
            "_accesstoken_"
        ],
    },
    'OP-M-12': {
        "desc": 'Registration of wish for pairwise sub',
        "sequence": [
            '_discover_',
            ('_register_',
             {
                 "request_args": {"subject_type": "public"},
                 "support": {"subject_types_supported": "public"}
             }),
            "_login_",
            "_accesstoken_",
            ('_register_',
             {
                 "request_args": {"subject_type": "pairwise"},
                 "support": {"subject_types_supported": "pairwise"}
             }),
            "_login_",
            "_accesstoken_"
        ],
        'tests': {"different_sub": {}}
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
        "note": "Please make your OP roll over signing keys",
        "tests": {"new-signing-keys": {}}
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
                 "support": {
                     "token_endpoint_auth_methods_supported":
                         "private_key_jwt"}
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
        "note": "Please make your OP roll over signing keys",
        "tests": {"new-encryption-keys": {}}
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
                     "userinfo_signing_alg_values_supported": "none",
                     "userinfo_encryption_alg_values_supported": "RSA1_5",
                     "userinfo_encryption_enc_values_supported": "A128CBC-HS256"
                 }
             }
            ),
            '_login_',
            "_accesstoken_",
            "rotate_sign_keys",
            "_userinfo_"
        ],
    },
    'OP-O-01': {
        "desc": 'Support request_uri Request Parameter',
        "sequence": [
            '_discover_',
            ("_register_",
             {"support": {"request_uri_parameter_supported": True}}),
        ],
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
                     "request_uri_parameter_supported": True,
                     "request_object_signing_alg_values_supported": "none"}
             }),
            ("_login_", {"kwarg_func": request_in_file})
        ],
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
                     "request_uri_parameter_supported": True,
                     "request_object_signing_alg_values_supported": "RS256"}
             }),
            ("_login_", {"kwarg_func": request_in_file})
        ],
        "profile": {"Dynamic": "MUST"}
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
                     "request_uri_parameter_supported": True,
                     "request_object_signing_alg_values_supported": "none",
                     "request_object_encryption_alg_values_supported": "RSA1_5",
                     "request_object_encryption_enc_values_supported":
                         "A128CBC-HS256"
                 }
             }
            ),
            ("_login_", {"kwarg_func": request_in_file})
        ],
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
                     "request_uri_parameter_supported": True,
                     "request_object_signing_alg_values_supported": "RS256",
                     "request_object_encryption_alg_values_supported": "RSA1_5",
                     "request_object_encryption_enc_values_supported":
                         "A128CBC-HS256"
                 }
             }
            ),
            ("_login_", {"kwarg_func": request_in_file})
        ],
    },
    'OP-P-01': {
        "desc": 'Support request Request Parameter',
        "sequence": [
            '_discover_',
            ("_register_",
             {"support": {"request_parameter_supported": True}}),
        ],
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
                     "request_parameter_supported": True,
                     "request_object_signing_alg_values_supported": "none"}
             }),
        ],
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
                     "request_parameter_supported": True,
                     "request_object_signing_alg_values_supported": "RS256"}
             }),
        ],
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
        'tests': {"verify-claims": {"userinfo": {"name": None}}}
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
        'tests': {"verify-claims": {"id_token": {"email": None}}}
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
        'tests': {"verify-claims": {
            "userinfo": {"name": None},
            "id_token": {"email": None}}}
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
        'tests': {"verify-claims": {
            "userinfo": {"phone": None},
            "id_token": {"email": None}}}
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
        'tests': {"verify-claims": {
            "userinfo": {"picture": None},
            "id_token": {"email": None}}}
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
        'tests': {"verify-claims": {
            "userinfo": {"picture": None, "name": None, "email": None}}
        },
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
        'tests': {"verify-claims": {"id_token": {"auth_time": None}}}
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
        'tests': {"verify-claims": {"id_token": {"acr": None}}}
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
        'tests': {"verify-claims": {"id_token": {"acr": None}}}
    },
    'OP-Q-12': {
        "desc": 'Requesting ID Token with Essential specific acr Claim',
        "sequence": [
            '_discover_',
            '_register_',
            ("_login_", {"function": specific_acr_claims}),
            "_accesstoken_",
        ],
        'tests': {"verify-claims": {"id_token": {"acr": None}}}
    },
}


def flows(specific):
    """
    Return all flows that is defined for the specific profile

    :param specific: dictionary
    All dynamic => {"profile": "Basic", "discover": True, "register": True}
    All static => {"profile": "Basic", "discover": False, "register": False}
    :return:
    """
    _profile = specific["profile"]
    prelim = PROFILEMAP[_profile]["flows"]

    if specific["discover"]:
        prelim.extend(PROFILEMAP["Discover"]["flow"][_profile])

    if specific["register"]:
        prelim.extend(PROFILEMAP["Register"]["flows"])

    result = list(set(prelim))
    result.sort()
    return result


def _update(dic1, dic2):
    for key in ["request_args", "kw", "req_tests", "resp_tests"]:
        if key not in dic1:
            try:
                dic1[key] = dic2[key]
            except KeyError:
                pass
        elif key not in dic2:
            pass
        else:
            dic2[key].update(dic1[key])
            dic1[key] = dic2[key]

    return dic1


def get_sequence(flowid, spec):
    """
    Return a sequence of request/responses that together defined the test flow.

    :param flowid: Flow id
    :param spec: dictionary
    All dynamic => {"profile": "Basic", "discover": True, "register": True}
    All static => {"profile": "Basic", "discover": False, "register": False}
    :return: list of request/responses and their arguments
    """

    _profile = spec["profile"]
    seq = []

    for op in FLOWS[flowid]["sequence"]:
        if isinstance(op, tuple):
            _op, _args = op
        else:
            _op = op
            _args = {}

        if _op == "_discover_":
            if spec["discover"]:
                _op, arg = PROFILEMAP["Discover"]["*"]
                _args = _update(_args, arg)
                seq.append((PHASES[_op], _args))
            continue

        if _op == "_register_":
            if spec["register"]:
                _op, arg = PROFILEMAP["Register"][_profile]
                _args = _update(_args, arg)
                seq.append((PHASES[_op], _args))
            continue

        _args = {}
        while True:
            if isinstance(op, tuple):
                _op, orig_arg = op
                args = copy.deepcopy(orig_arg)  # decouple

                if _args == {}:
                    _args = args
                else:
                    _args = _update(_args, args)
            else:
                _op = op

            try:
                op = PROFILEMAP[_profile][_op]
            except KeyError:
                break

        if _op is None:
            continue

        if _op == "oic-registration":  # default minimal registration info
            _, b = PROFILEMAP["Register"][_profile]
            _args = _update(_args, b)

        seq.append((PHASES[_op], _args))

    return seq


if __name__ == "__main__":
    from oictest.base import Conversation
    from testclass import Discover

    def setup():
        conf = importlib.import_module("localhost_basic")
        ots = OIDCTestSetup(conf, {}, "80")
        trace = Trace()
        client_conf = ots.config.CLIENT
        conv = Conversation(ots.client, client_conf, trace, None,
                            message_factory, check_factory)
        conv.cache = {}
        return conv


    spec = {"profile": "Basic", "discover": True, "register": False}
    _flows = flows(spec)
    for _flow in _flows:
        print _flow
        conv = setup()
        conv.client.authorization_endpoint = "https://example.com/authz"
        conv.client.registration_endpoint = "https://example.com/reg"
        requests = []
        for item in get_sequence(_flow, spec):
            op, args = item
            (req, resp) = PHASES[op]

            if req.request == "AuthorizationRequest":
                # New state for each request
                try:
                    args["request_args"].update({"state": rndstr()})
                except KeyError:
                    args["request_args"] = {"state": rndstr()}
            elif req.request in ["AccessTokenRequest", "UserInfoRequest",
                                 "RefreshAccessTokenRequest"]:
                try:
                    args.update({"state": conv.AuthorizationRequest["state"]})
                except KeyError:
                    args = {"state": conv.AuthorizationRequest["state"]}
            else:
                kwargs = {}

            _req = req(conv)
            if isinstance(_req, Discover):
                print "-- discover --"
            else:
                print _req.construct_request(conv.client, **args)
