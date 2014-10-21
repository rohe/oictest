from tests import *


class ResourceSetRegistrationNoPAT(PostRequest):
    request = "ResourceSetDescription"

    def __init__(self, conv):
        PostRequest.__init__(self, conv)
        self.kw_args = {"authn_method": ""}


PHASES = {
    "login": (AuthorizationRequestCode, AuthzResponse),
    "oic-login": (AuthorizationRequestCode, AuthzResponse),
    "oic-login-aat": (AuthorizationRequestCodeAAT, ImplicitAuthzResponse),
    "oic-login-pat": (AuthorizationRequestCodePAT, ImplicitAuthzResponse),
    "access-token-request_csp": (AccessTokenRequestCSPost, AccessTokenResponse),
    "access-token-request": (AccessTokenRequest, AccessTokenResponse),
    "access-token-request_csj": (AccessTokenRequestCSJWT, AccessTokenResponse),
    "access-token-request_pkj": (AccessTokenRequestPKJWT, AccessTokenResponse),
    "oic-registration": (RegistrationRequest, RegistrationResponse),
    "provider-discovery": (Discover, ProviderConfigurationResponse),
    "provider-info": (ProviderRequest, ProviderConfigurationResponse),
    "read-registration": (ReadRegistration, RegistrationResponse),
    "intermission": TimeDelay,
    "rotate_keys": RotateKeys,
    "notice": Notice,
    "rm_cookie": RmCookie,
    "expect_err": ExpectError,
    "webfinger_email": (WebfingerEmail, None),
    "webfinger_url": (WebfingerURL, None),
    "resource_set_registration-no-pat": (ResourceSetRegistrationNoPAT,
                                         ErrorResponse)
}
OWNER_OPS = []

FLOWS = {
    'webfinger-email': {
        "name": 'Can Discover Identifiers using E-Mail Syntax',
        "sequence": ["webfinger_email"],
        "block": ["registration", "key_export"],
    },
    'webfinger-url': {
        "name": 'Can Discover Identifiers using URL Syntax',
        "sequence": ["webfinger_url"],
        "block": ["registration", "key_export"],
    },
    'FT-as-config-endpt':{
        "name": "AS makes config data available through "
                "https://as_uri/.well-known/uma-configuration.",
        "sequence": ["webfinger"]
    },
    'FT-c-get_config-data': {
        "name": 'Uses openid-configuration Discovery Information',
        "sequence": ["provider-discovery"],
        "block": ["registration", "key_export"],
    },
    'FT-c-get-dyn-client-creds': {
        "name": 'Uses Dynamic Registration',
        "sequence": ["provider-discovery", "oic-registration"],
        "block": ["registration", "key_export"],
    },
    'FT-c-get-aat': {
        "name": "Can Make Access Token Request with 'client_secret_basic' "
                "Authentication and receive a PAT",
        "sequence": ["oic-login-pat", 'access-token-request']
    },
    'FT-as-require-aat': {
        "name": "AS allows RSs to make protection API calls IFF they present "
                "protection API scope",
        "sequence": ["resource_set_registration-no-pat"]
    },
    'FT-c-use-aat': {
        "name": "Can Make Access Token Request with 'client_secret_basic' "
                "Authentication and receive a AAT",
        "sequence": ["oic-login-aat", 'access-token-request']
    },
}