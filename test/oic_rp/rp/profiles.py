from oper import Authn, Registration
from oper import AccessToken
from oper import UserInfo
from oper import DisplayUserInfo

from testfunc import set_request_args

__author__ = 'roland'

PMAP = {"C": "Basic",
        "I": "Implicit (id_token)", "IT": "Implicit (id_token+token)",
        "CI": "Hybrid (code+id_token)", "CT": "Hybrid (code+token)",
        "CIT": "Hybrid (code+id_token+token)"}

CRYPT = {"n": "none", "s": "signing", "e": "encryption"}

PROFILEMAP = {
    Authn: {
        "C": {set_request_args: {"response_type": ["code"],
                                 "scope": ["openid"]}},
        "I": {set_request_args: {"response_type": ["id_token"],
                                 "scope": ["openid"]}},
        "IT": {set_request_args: {"response_type": ["id_token", "token"],
                                  "scope": ["openid"]}},
        "CI": {set_request_args: {"response_type": ["code", "id_token"],
                                  "scope": ["openid"]}},
        "CT": {set_request_args: {"response_type": ["code", "token"],
                                  "scope": ["openid"]}},
        "CIT": {set_request_args:
                 {"response_type": ["code", "id_token", "token"],
                  "scope": ["openid"]}},
    },
    AccessToken: {
        "C": {},
        "CI": {},
        "CT": {},
        "CIT": {},
    },
    UserInfo: {
        "C": {},
        "IT": {},
        "CI": {},
        "CT": {},
        "CIT": {},
    },
    DisplayUserInfo: {
        "C": {},
        "IT": {},
        "CI": {},
        "CT": {},
        "CIT": {},
    },
    Registration: {
        "C": {
            set_request_args: {
                "response_types": ["code"],
                # don't register any
                "token_endpoint_auth_method": {},
                "userinfo_signed_response_alg": {},
                "id_token_signed_response_alg": {},
                "request_object_signing_alg": {},
                "grant_types": ["authorization_code"]}},
        "I": {
            set_request_args: {
                "response_types": ["id_token"],
                # don't register any
                "token_endpoint_auth_method": {},
                "userinfo_signed_response_alg": {},
                "id_token_signed_response_alg": {},
                "request_object_signing_alg": {},
                "grant_types": ["implicit"]
            }},
        "IT": {
            set_request_args: {
                "response_types": ["id_token token"],
                # don't register any
                "token_endpoint_auth_method": {},
                "userinfo_signed_response_alg": {},
                "id_token_signed_response_alg": {},
                "request_object_signing_alg": {},
                "grant_types": ["implicit"]
            }},
        "CI": {
            set_request_args: {
                "response_types": ["code id_token"],
                # don't register any
                "token_endpoint_auth_method": {},
                "userinfo_signed_response_alg": {},
                "id_token_signed_response_alg": {},
                "request_object_signing_alg": {},
                "grant_types": ["authorization_code", "implicit"]
            }
        },
        "CT": {
            set_request_args: {
                "response_types": ["code token"],
                # don't register any
                "token_endpoint_auth_method": {},
                "userinfo_signed_response_alg": {},
                "id_token_signed_response_alg": {},
                "request_object_signing_alg": {},
                "grant_types": ["authorization_code", "implicit"]
            }
        },
        "CIT": {
            set_request_args: {
                "response_types": ["code id_token token"],
                # don't register any
                "token_endpoint_auth_method": {},
                "userinfo_signed_response_alg": {},
                "id_token_signed_response_alg": {},
                "request_object_signing_alg": {},
                "grant_types": ["authorization_code", "implicit"]
            }
        }
    }
}


SUBPROF = {"n": "none", "s": "sign", "e": "encrypt"}