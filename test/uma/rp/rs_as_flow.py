#!/usr/bin/env python
from uma import PAT, AAT
from oictest.testfunc import policy_uri
from oictest.testfunc import logo_uri
from oictest.testfunc import tos_uri
from oictest.testfunc import mismatch_return_uri
from oictest.testfunc import multiple_return_uris
from oictest.testfunc import redirect_uri_with_query_component
from oictest.testfunc import redirect_uris_with_query_component
from oictest.testfunc import redirect_uris_with_fragment

__author__ = 'roland'

URL = "https://oictest.umdc.umu.se/static/players/%s"

USERINFO_REQUEST_AUTH_METHOD = (
    "userinfo", {
        "kwargs_mod": {"authn_method": "bearer_header"},
        "method": "GET"
    })

ORDDESC = ["UMA-DiscoveryUMA", "UMA-DiscoveryOIDC", "UMA-RegOAuth2",
           "UMA-RegOIDC", "UMA-Request", "UMA-redirect_uri", "UMA-token",
           "UMA-resourceset"]

DESC = {
    "DiscoveryUMA": "UMA Dynamic Discovery",
    "DiscoveryOIDC": "OIDC Dynamic Discovery",
    "RegOAuth2": "OAuth2 Dynamic Client Registration",
    "RegOIDC": "OIDC Dynamic Client Registration",
    "Request": "Misc Request Parameters",
    "redirect_uri": "redirect_uri",
    "token": "Accessing tokens",
    "resourceset": "Resource Set Registration Endpoint"
}

RESOURCE = {
    "AL2014": {
        "name": "American League Roster All Star game 2014",
        "scopes": ["get", "delete", "post", "put"],
    },
    "Jeter": {
        "name": "Derek Jeter",
        "icon_uri": URL % "Jeter",
        "scopes": ["get", "delete", "put"],
        "type": "Shortstop"
    },
    "Cabrera": {
        "name": "Miguel Cabrera",
        "icon_uri": URL % "Cabrera",
        "scopes": ["get", "delete", "put"],
        "type": "First Base"},
    "martinez": {
        "name": "Victor Martinez",
        "icon_uri": URL % "Martinez",
        "scopes": ["read", "delete", "put"],
        "type": "Designated hitter"
    },
    "scherzer": {
        "name": "Max Scherzer",
        "icon_uri": URL % "Scherzer",
        "scopes": ["get", "delete", "put"],
        "type": "Pitcher"},
}

FLOWS = {
    'UMA-DiscoveryUMA-basic': {
        "desc": 'Verify UMA discovery',
        "sequence": ['_uma_discover_'],
        "profile": ".T.",
        "tests": {"verify-op-has-dynamic-client-endpoint": {}},
    },
    'UMA-DiscoveryOIDC-basic': {
        "desc": 'Verify OIDC discovery',
        "sequence": ['_discover_'],
        "profile": ".T.",
        "tests": {"verify-op-has-registration-endpoint": {}},
    },
    'UMA-RegOAuth2-basic': {
        "desc": 'Dynamic OAuth2 Client registration Request',
        "sequence": [
            '_uma_discover_',
            "_oauth_register_"
        ],
        "profile": "..T",
        "tests": {"check-http-response": {}},
    },
    'UMA-RegOAuth2-policy_uri': {
        "desc": 'Registration with policy_uri',
        "sequence": [
            'note',
            "rm_cookie",
            '_uma_discover_',
            ('oauth-registration', {"function": policy_uri}),
            "_login_"
        ],
        "profile": "..T",
        'note': "When you get the login page this time you should have a "
                "link to the client policy",
        "tests": {"check-http-response": {}},
    },
    'UMA-RegOAuth2-logo_uri': {
        "desc": 'Registration with logo uri',
        "sequence": [
            'note',
            "rm_cookie",
            '_uma_discover_',
            ('oauth-registration', {"function": logo_uri}),
            "_login_"
        ],
        "profile": "..T",
        'note': "When you get the login page this time you should have the "
                "clients logo on the page",
        "tests": {"check-http-response": {}},
    },
    'UMA-RegOAuth2-tos_url': {
        "desc": 'Registration with tos url',
        "sequence": [
            'note',
            'rm_cookie',
            '_uma_discover_',
            ('oauth-registration', {"function": tos_uri}),
            '_login_'
        ],
        "profile": "..T",
        'note': "When you get the login page this time you should have a "
                "link to the clients Terms of Service",
        "tests": {"check-http-response": {}},
    },
    'UMA-RegOAuth2-read': {
        "desc": 'Register and then read the client info',
        "sequence": [
            '_uma_discover_',
            '_oauth_register_',
            "oauth-read-registration"
        ],
        "profile": "..T",
        "tests": {"check-http-response": {}},
    },
    "UMA-RegOAuth2-modify": {
        "desc": "Modify client registration",
        "sequence": [
            '_uma_discover_',
            '_oauth_register_',
            "modify-registration"
        ],
        "profile": "..T",
        "tests": {"check-http-response": {}},
    },
    "UMA-RegOAuth2-delete": {
        "desc": "Delete client registration",
        "sequence": [
            '_uma_discover_',
            '_oauth_register_',
            "delete-registration"
        ],
        "profile": "..T",
        "tests": {"check-http-response": {}},
    },
    'UMA-RegOIDC-basic': {
        "desc": 'Dynamic OpenID Connect Client registration Request',
        "sequence": [
            '_discover_',
            "_register_"
        ],
        "profile": "..T",
        "tests": {"check-http-response": {}},
    },
    'UMA-RegOIDC-policy_uri': {
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
    'UMA-RegOIDC-logo_uri': {
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
    'UMA-RegOIDC-tos_uri': {
        "desc": 'Registration with tos uri',
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
    'UMA-RegOIDC-read': {
        "desc": 'Registering and then read the client info',
        "sequence": [
            '_discover_',
            '_register_',
            "read-registration"
        ],
        "profile": "..T..+",
        "tests": {"check-http-response": {}},
    },
    'UMA-Request-response_type=code': {
        "desc": 'Request with response_type=code',
        "sequence": ['_uma_discover_', "_oauth_register_", "_login_"],
        "profile": "C..",
        'tests': {"check-http-response": {}},
        "mti": "MUST"
    },
    'UMA-Request-no-response_type': {
        "desc": 'Authorization request missing the response_type parameter',
        "sequence": [
            '_uma_discover_',
            '_oauth_register_',
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
        "mti": "MUST"
    },
    'UMA-Request-response_type=token': {
        "desc": 'Request with response_type=token',
        "sequence": ['_uma_discover_', "_oauth_register_", "_login_"],
        "profile": "T..",
        'tests': {"check-http-response": {}},
        "mti": "MUST"
    },
    'UMA-redirect_uri-NotReg': {
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
    'UMA-redirect_uri-Missing': {
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
    'UMA-redirect_uri-Query': {
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
    'UMA-redirect_uri-RegQuery': {
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
    'UMA-redirect_uri-BadQuery': {
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
    'UMA-redirect_uri-RegFrag': {
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
    'UMA-redirect_uri-MissingOK': {
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
    'UMA-token-PAT': {
        "desc": 'Acquire PAT',
        "sequence": [
            '_uma_discover_',
            '_oauth_register_',
            ('_login_', {"request_args": {"scope": [PAT]}}),
            '_accesstoken_',
            'store_pat'
        ],
        "profile": "C..",
        'tests': {"check-http-response": {}},
    },
    'UMA-token-AAT': {
        "desc": 'Acquire AAT',
        "sequence": [
            '_uma_discover_',
            '_oauth_register_',
            ('_login_',
             {
                 "request_args": {"scope": [AAT]},
             }),
            '_accesstoken_'
        ],
        "profile": "C..",
        'tests': {"check-http-response": {}},
    },
    'UMA-resourceset-create': {
        "desc": "Create resource set",
        "sequence": [
            'retrieve_pat',
            ('create_resource_set', {"request_args": RESOURCE["AL2014"],
                                     "rsid": "AL2014"})
        ],
        "profile": "C..",
        "tests": {},
    },
    # 'UMA-resourceset-read': {
    #     "desc": "Read resource set"
    # },
    # 'UMA-resourceset-update': {
    # },
    # 'UMA-resourceset-list': {
    # },
    # 'UMA-resourceset-delete': {
    # },
}

