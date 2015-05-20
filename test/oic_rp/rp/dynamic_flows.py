from jwkest import BadSignature
from oic.exception import IssuerMismatch
from oic.oic.message import AtHashError
from oic.oic.message import CHashError

__author__ = 'roland'

MODE = {}

ORDDESC = ["rp-webfinger", "rp-disc", "rp-dynreg", "rp-rtyp", "rp-rmod",
           "rp-tok", "rp-idt"]

FLOWS = {
    # "rp-webfinger-url": {
    #     "flow": [{"action": "discover", "args": {}}],
    #     "desc": "Can Discover Identifiers using URL Syntax"
    # },
    # "rp-webfinger-email": {
    #     "flow": [{"action": "discover", "args": "acct:{}@{}"}],
    #     "desc": "Can Discover Identifiers using acct Syntax"
    # },
    # "rp-disc-config": {
    #     "flow": [{"action": "discover", "args": {}},
    #              {"action": "provider_info", "args": {}}],
    #     "desc": "Uses openid-configuration Discovery Information"
    # },
    # "rp-disc-jwks_uri": {
    #     "flow": [{"action": "discover", "args": {}},
    #              {"action": "provider_info", "args": {}}],
    #     "desc": "Can read and understand jwks_uri"
    # },
    # "rp-disc-faulty-issuer": {
    #     "flow": [{"action": "discover", "args": {}},
    #              {"action": "provider_info", "args": {},
    #               "error": IssuerMismatch}],
    #     "desc": "Will detect a faulty issuer claim in OP config"
    # },
    # "rp-dynreg": {
    #     "flow": [{"action": "discover", "args": {}},
    #              {"action": "provider_info", "args": {}},
    #              {"action": "registration", "args": {}}],
    #     "desc": "Uses Dynamic Registration"
    # },
    # "rp-rtyp-code": {
    #     "flow": [{"action": "discover", "args": {}},
    #              {"action": "provider_info", "args": {}},
    #              {"action": "registration", "args": {}},
    #              {"action": "authn_req",
    #               "args": {"scope": "openid", "response_type": ["code"]}}],
    #     "desc": "Can Make Request with 'code' Response Type"
    # },
    # "rp-rtyp-idt": {
    #     "flow": [{"action": "discover", "args": {}},
    #              {"action": "provider_info", "args": {}},
    #              {"action": "registration",
    #               "args": {"id_token_signed_response_alg": "RS256"}},
    #              {"action": "authn_req",
    #               "args": {"scope": "openid", "response_type": ["id_token"]}}],
    #     "desc": "Can Make Request with 'id_token' Response Type"
    # },
    # "rp-rtyp-idt_token": {
    #     "flow": [{"action": "discover", "args": {}},
    #              {"action": "provider_info", "args": {}},
    #              {"action": "registration",
    #               "args": {"id_token_signed_response_alg": "RS256"}},
    #              {"action": "authn_req",
    #               "args": {"scope": "openid",
    #                        "response_type": ["id_token", "token"]}}],
    #     "desc": "Can Make Request with 'id_token token' Response Type"
    # },
    # "rp-rmod-form": {
    #     "flow": [{"action": "discover", "args": {}},
    #              {"action": "provider_info", "args": {}},
    #              {"action": "registration",
    #               "args": {"id_token_signed_response_alg": "RS256"}},
    #              {"action": "authn_req",
    #               "args": {"scope": "openid",
    #                        "response_type": ["id_token", "token"],
    #                        "response_mode": ["form_post"]}}],
    #     "desc": "Can Make Request with response_mode=form_post"
    # },
    # "rp-tok-csbasic": {
    #     "flow": [{"action": "discover", "args": {}},
    #              {"action": "provider_info", "args": {}},
    #              {"action": "registration", "args": {}},
    #              {"action": "authn_req",
    #               "args": {"scope": "openid", "response_type": ["code"]}},
    #              {"action": "token_req",
    #               "args": {"authn_method": "client_secret_basic"}}],
    #     "desc": "Can Make Access Token Request with 'client_secret_basic' "
    #             "Authentication"
    # },
    # client_secret_post
    # "rp-tok-cspost": {
    #     "flow": [
    #         {"action": "discover", "args": {}},
    #         {"action": "provider_info", "args": {}},
    #         {"action": "registration",
    #          "args": {"token_endpoint_auth_method": "client_secret_post"}},
    #         {"action": "authn_req",
    #          "args": {"scope": "openid", "response_type": ["code"]}},
    #         {"action": "token_req",
    #          "args": {"authn_method": "client_secret_post"}}
    #     ],
    #     "desc": "Can Make Access Token Request with 'client_secret_post' "
    #             "Authentication"
    # },
    # # client_secret_jwt
    # "rp-tok-csjwt": {
    #     "flow": [{"action": "discover", "args": {}},
    #              {"action": "provider_info", "args": {}},
    #              {"action": "registration",
    #               "args": {"token_endpoint_auth_method": "client_secret_jwt"}},
    #              {"action": "authn_req",
    #               "args": {"scope": "openid", "response_type": ["code"]}},
    #              {"action": "token_req",
    #               "args": {"authn_method": "client_secret_jwt"}}
    #     ],
    #     "desc": "Can Make Access Token Request with 'client_secret_jwt' "
    #             "Authentication"
    # },
    # # private_key_jwt
    # "rp-tok-pkjwt": {
    #     "flow": [{"action": "discover", "args": {}},
    #              {"action": "provider_info", "args": {}},
    #              {"action": "registration",
    #               "args": {"token_endpoint_auth_method": "private_key_jwt",
    #                        "jwks_uri": "https://localhost:8088/static/jwk.json"}},
    #              {"action": "authn_req",
    #               "args": {"scope": "openid", "response_type": ["code"]}},
    #              {"action": "token_req",
    #               "args": {"authn_method": "private_key_jwt"}}
    #     ],
    #     "desc": "Can Make Access Token Request with 'private_key_jwt' "
    #             "Authentication"
    # },
    ### === Accept Valid ? ID Token Signature	===
    # Asymmetric
    # "rp-idt-asym_sig": {
    #     "flow": [
    #         {"action": "discover", "args": {}},
    #         {"action": "provider_info", "args": {}},
    #         {"action": "registration",
    #          "args": {"id_token_signed_response_alg": "RS256"}},
    #         {"action": "authn_req",
    #          "args": {"scope": "openid", "response_type": ["id_token"]}}
    #     ],
    #     "desc": "Accept Valid Asymmetric ID Token Signature"
    # },
    # Symmetric
    # "rp-idt-sym_sig": {
    #     "flow": [
    #         {"action": "discover", "args": {}},
    #         {"action": "provider_info", "args": {}},
    #         {"action": "registration",
    #          "args": {"id_token_signed_response_alg": "HS256"}},
    #         {"action": "authn_req",
    #          "args": {"scope": "openid", "response_type": ["id_token"]}}
    #     ],
    #     "desc": "Accept Valid Symmetric ID Token Signature"
    # },
    ### === Reject Invalid ? ID Token Signature ===
    # Asymmetric
    # "rp-idt-invalid-asym_sig": {
    #     "flow": [
    #         {"action": "discover", "args": {}},
    #         {"action": "provider_info", "args": {}},
    #         {"action": "registration",
    #          "args": {"id_token_signed_response_alg": "RS256"}},
    #         {"action": "authn_req",
    #          "args": {"scope": "openid", "response_type": ["id_token"]},
    #          "error": BadSignature}
    #     ],
    #     "desc": "Reject Invalid Asymmetric ID Token Signature"
    # },
    # "rp-idt-invalid-ec_sig": {
    #     "flow": [
    #         {"action": "discover", "args": {}},
    #         {"action": "provider_info", "args": {}},
    #         {"action": "registration",
    #          "args": {"id_token_signed_response_alg": "ES256"}},
    #         {"action": "authn_req",
    #          "args": {"scope": "openid", "response_type": ["id_token"]},
    #          "error": BadSignature}
    #     ],
    #     "desc": "Reject Invalid Asymmetric ID Token Signature"
    # },
    # # Symmetric
    # "rp-idt-invalid-sym_sig": {
    #     "flow": [
    #         {"action": "discover", "args": {}},
    #         {"action": "provider_info", "args": {}},
    #         {"action": "registration",
    #          "args": {"id_token_signed_response_alg": "HS256"}},
    #         {"action": "authn_req",
    #          "args": {"scope": "openid", "response_type": ["id_token"]},
    #          "error": BadSignature}
    #     ],
    #     "desc": "Reject Invalid Symmetric ID Token Signature"
    # },
    ### === Can Request and Use ? ID Token Response ===
    # Signed and Encrypted
    # *signed is already tested*
    "rp-idt-sigenc": {
        "flow": [
            {"action": "discover", "args": {}},
            {"action": "provider_info", "args": {}},
            {"action": "registration",
             "args": {
                 "id_token_signed_response_alg": "HS256",
                 "id_token_encrypted_response_alg": "RSA1_5",
                 "id_token_encrypted_response_enc": "A128CBC-HS256",
                 "jwks_uri": None}},
            {"action": "authn_req",
             "args": {"scope": "openid", "response_type": ["id_token"]}}
        ],
        "desc": "Can Request and Use Signed and Encrypted ID Token Response"
    },
    # Unsigned
    # "rp-idt-none": {
    #     "flow": [
    #         {"action": "discover", "args": {}},
    #         {"action": "provider_info", "args": {}},
    #         {"action": "registration",
    #          "args": {"id_token_signed_response_alg": "none"}},
    #         {"action": "authn_req",
    #          "args": {"scope": "openid", "response_type": ["code"]}},
    #         {"action": "token_req", "args": {}}
    #     ],
    #     "desc": "Can Request and Use unSigned ID Token Response"
    # },
}
