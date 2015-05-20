from oper import Webfinger, AccessToken
from oper import Discovery
from oper import Registration
from oper import Authn
from testfunc import resource, set_jwks_uri, set_op_args
from testfunc import expect_exception
from testfunc import set_request_args

from oic.exception import IssuerMismatch

__author__ = 'roland'

ORDDESC = ["rp-webfinger", "rp-disc", "rp-dynreg", "rp-rtyp", "rp-rmod",
           "rp-tok", "rp-idt"]

FLOWS = {
    # "rp-webfinger-url": {
    #     "sequence": [Webfinger],
    #     "desc": "Can Discover Identifiers using URL Syntax",
    #     "profile": ".T..",
    # },
    # "rp-webfinger-email": {
    #     "sequence": [(Webfinger, {resource: {"pattern": "acct:{}@{}"}})],
    #     "desc": "Can Discover Identifiers using acct Syntax",
    #     "profile": ".T..",
    # },
    # "rp-disc-config": {
    #     "sequence": [
    #         Webfinger,
    #         Discovery
    #     ],
    #     "profile": "..T.",
    #     "desc": "Uses openid-configuration Discovery Information"
    # },
    # "rp-disc-jwks_uri": {
    #     "sequence": [
    #         Webfinger,
    #         Discovery
    #     ],
    #     "profile": "..T.",
    #     "desc": "Can read and understand jwks_uri",
    #     "tests": {
    #         "providerinfo-has-jwks_uri": {},
    #         "bare-keys": {}
    #     }
    # },
    # "rp-disc-faulty-issuer": {
    #     "sequence": [
    #         Webfinger,
    #         (Discovery, {expect_exception: IssuerMismatch})
    #     ],
    #     "profile": "..T.",
    #     "desc": "Will detect a faulty issuer claim in OP config"
    # },
    # "rp-dynreg-0": {
    #     "sequence": [
    #         Webfinger,
    #         Discovery,
    #         Registration
    #     ],
    #     "profile": "...T",
    #     "desc": "Uses Dynamic Registration"
    # },
    "rp-rtyp-code": {
        "sequence": [
            Webfinger,
            Discovery,
            Registration,
            Authn
        ],
        "profile": "C...",
        "desc": "Can Make Request with 'code' Response Type"
    },
     "rp-rtyp-idt": {
        "sequence": [
            Webfinger,
            Discovery,
            (Registration,
             {set_request_args: {"id_token_signed_response_alg": "RS256"}}),
            Authn
        ],
        "desc": "Can Make Request with 'id_token' Response Type",
        "profile": "I...",
    },
    "rp-rtyp-idt_token": {
        "sequence": [
            Webfinger,
            Discovery,
            (Registration,
             {set_request_args: {"id_token_signed_response_alg": "RS256"}}),
            Authn
        ],
        "profile": "I,IT...",
        "desc": "Can Make Request with 'id_token token' Response Type"
    },
    "rp-rmod-form": {
        "sequence": [
            Webfinger,
            Discovery,
            (Registration,
             {set_request_args: {"id_token_signed_response_alg": "RS256"}}),
            (Authn, {set_request_args: {"response_mode": ["form_post"]}})
        ],
        "profile": "I,IT...",
        "desc": "Can Make Request with response_mode=form_post"
    },
    "rp-tok-csbasic": {
        "sequence": [
            Webfinger,
            Discovery,
            Registration,
            Authn,
            (AccessToken,
             {set_request_args: {"authn_method": "client_secret_basic"}})
        ],
        "profile": "C,CI,CIT...",
        "desc": "Can Make Access Token Request with 'client_secret_basic' "
                "Authentication"
    },
    #client_secret_post
    "rp-tok-cspost": {
        "sequence": [
            Webfinger,
            Discovery,
            (Registration,
             {set_request_args: {
                 "token_endpoint_auth_method": "client_secret_post"}}),
            Authn,
            (AccessToken,
             {set_request_args: {"authn_method": "client_secret_post"}})
        ],
        "profile": "C,CI,CIT...",
        "desc": "Can Make Access Token Request with 'client_secret_post' "
                "Authentication"
    },
    # client_secret_jwt
    "rp-tok-csjwt": {
        "sequence": [
            Webfinger,
            Discovery,
            (Registration,
             {set_request_args: {
                 "token_endpoint_auth_method": "client_secret_jwt"}}),
            Authn,
            (AccessToken,
             {set_request_args: {"authn_method": "client_secret_jwt"}})
        ],
        "profile": "C,CI,CIT...",
        "desc": "Can Make Access Token Request with 'client_secret_jwt' "
                "Authentication"
    },
    # private_key_jwt
    "rp-tok-pkjwt": {
        "sequence": [
            Webfinger,
            Discovery,
            (Registration,
             {set_request_args: {
                 "token_endpoint_auth_method": "private_key_jwt",
                 "jwks_uri": "https://localhost:8088/static/jwk.json"}}),
            Authn,
            (AccessToken,
             {set_request_args: {"authn_method": "private_key_jwt"}})
        ],
        "profile": "C,CI,CIT...",
        "desc": "Can Make Access Token Request with 'private_key_jwt' "
                "Authentication"
    },
    "rp-idt-sigenc": {
        "sequence": [
            Webfinger,
            Discovery,
            (Registration, {
                set_request_args: {
                    "id_token_signed_response_alg": "HS256",
                    "id_token_encrypted_response_alg": "RSA1_5",
                    "id_token_encrypted_response_enc": "A128CBC-HS256"},
                set_jwks_uri: {}
            }),
            (Authn, {set_op_args: {"response_type": ["id_token"]}}),
        ],
        "profile": "I...T",
        "desc": "Can Request and Use Signed and Encrypted ID Token Response",
    },
}
