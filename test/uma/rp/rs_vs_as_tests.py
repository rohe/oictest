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
                                         ErrorResponse),
    "resource_set_registration": (ResourceSetRegistration, ErrorResponse)
}
OWNER_OPS = []

FLOWS = {
    'uma.1': {
        "name": 'Can Discover Identifiers using E-Mail Syntax',
        "sequence": ["webfinger_email"],
        "block": ["registration", "key_export"],
    },
    'uma.2': {
        "name": 'Can Discover Identifiers using URL Syntax',
        "sequence": ["webfinger_url"],
        "block": ["registration", "key_export"],
    },
    'uma.3': {
        "name": 'Uses openid-configuration Discovery Information',
        'id': 'FT-rs-get_config-data',
        "sequence": ["provider-discovery"],
        "block": ["registration", "key_export"],
    },
    'uma.4': {
        "name": 'Uses Dynamic Registration',
        'id': 'FT-rs-get-dyn-client-creds',
        "sequence": ["provider-discovery", "oic-registration"],
        "block": ["registration", "key_export"],
    },
    'uma.5': {
        "name": "Can Make Access Token Request with 'client_secret_basic' "
                "Authentication and receive a PAT",
        'id': 'FT-rs-get-pat',
        "sequence": ["oic-login-pat", 'access-token-request']
    },
    'uma.6': {
        "name": "AS allows RSs to make protection API calls IFF they present "
                "protection API scope",
        'id': 'FT-as-require-pat',
        "sequence": ["oic-login-pat", 'access-token-request',
                     "resource_set_registration-no-pat"]
    },
    'uma.7':{
        "name": "PUT with unique ID to register new resource set description",
        'id': 'FT-as-rsr_put_uniqueid',
        "sequence": ["oic-login-pat", 'access-token-request',
                     'resource_set_registration'],
    },
    'uma.8':{
        "name": "GET with unique ID to read already-registered resource set "
                "description, handling the presence of any policy_uri property "
                "in AS's response",
        'id': 'FT-as-rsr_get_uniqueid',
        "sequence": ["oic-login-pat", 'access-token-request',
                     'resource_set_registration-read'],
    },
    'uma.9':{
        "name": "DELETE with a unique ID to delete an already-registered "
                "resource set description",
        'id': 'FT-as-rsr_delete_uniqueid',
        "sequence": [],
    },
    'uma.10':{
        "name": "PUT with If-Match and unique ID to update already-registered "
                "resource set description, handling the presence of any "
                "policy_uri property in AS's response",
        'id': 'FT-as-rsr_put_uniqueid_ifmatch',
        "sequence": [],
    },
    'uma.11':{
        "name": "GET on resource_set path to read list of already-registered "
                "resource set descriptions",
        'id': 'FT-as-rsr_get_resource_set_path',
        "sequence": [],
    },
}