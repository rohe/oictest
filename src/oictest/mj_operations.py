
txt = """
Request with response_type=code
Request with response_type=token
Request with response_type=id_token
Request with response_type=code id_token
Request with response_type=token id_token
Request with response_type=code token
Request with response_type=code token id_token
Check ID Endpoint Access with Header Method
Check ID Endpoint Access with Form-Encoded Body Method
UserInfo Endpoint Access with Header Method
UserInfo Endpoint Access with Form-Encoded Body Method
CheckID Endpoint Signature Validation
Scope Requesting No Specific Claims
    Request with scope=openid
Scope Requesting profile Claims
    Request with scope=openid profile
Scope Requesting email Claims
    Request with scope=openid email
Scope Requesting address Claims
    Request with scope=openid address
Scope Requesting phone Claims
    Request with scope=openid phone
Scope Requesting All Basic Claims
    Request with scope=openid profile email address phone
Requesting Specific Required Claims
    Use OpenID Request Object with Required name Claim
Requesting Specific Optional Claims
    OpenID Request Object with Optional email and picture Claims
Requesting Specific Required and Optional Claims
    OpenID Request Object with Required name and Optional email and picture Claims
Requesting ID Token with auth_time Claim
Requesting ID Token with Required acr Claim
    Request two specific acr claim values (values TBD)
Requesting ID Token with Optional acr Claim
    Request two specific optional acr claim values (values TBD)
Requesting ID Token with max_age Restriction
    Use max_age request value of 10 seconds
Request with display=page
Request with display=popup
Request with prompt=none
Request with prompt=login
Uses Symmetric ID Token Signatures
Uses Asymmetric ID Token Signatures
Enables Discovery
Enables Dymamic Registration
Can Provide Distributed Claims
Can Provide public user_id Values
Can Provide pairwise user_id Values
Request with request_uri
"""

FLOWS = {
    '1': {
        "name": 'Request with response_type=code',
        "sequence": ["oic-login"],
        "endpoints": ["authorization_endpoint"]
    },
    '2': {
        "name": 'Request with response_type=token',
        "sequence": ["oic-login-token"],
        "endpoints": ["authorization_endpoint"]
    },
    '3': {
        "name": 'Request with response_type=id_token',
        "sequence": ["oic-login-idtoken"],
        "endpoints": ["authorization_endpoint"]
    },
    '4': {
        "name": 'Request with response_type=code token',
        "sequence": ["oic-login-code+token"],
        "endpoints": ["authorization_endpoint"],
        },
    '5': {
        "name": 'Request with response_type=code id_token',
        "sequence": ['oic-login-code+idtoken'],
        "endpoints": ["authorization_endpoint"],
        },
    '6': {
        "name": 'Request with response_type=id_token token',
        "sequence": ['oic-login-idtoken+token'],
        "endpoints": ["authorization_endpoint"],
        },
    '7': {
        "name": 'Request with response_type=code id_token token',
        "sequence": ['oic-login-code+idtoken+token'],
        "endpoints": ["authorization_endpoint",],
        },
    # -------------------------------------------------------------------------
    '8': {
        "name": 'Check ID Endpoint Access with GET and bearer_header',
        "sequence": ["oic-login", "access-token-request", "check-id-request_gbh"],
        "endpoints": ["authorization_endpoint", "token_endpoint",
                      "check_id_endpoint"],
        },
    '9': {
        "name": 'Check ID Endpoint Access with POST and bearer_header',
        "sequence": ["oic-login", "access-token-request",
                     "check-id-request_pbh"],
        "endpoints": ["authorization_endpoint", "token_endpoint",
                      "check_id_endpoint"],
        },
    '10': {
        "name": 'Check ID Endpoint Access with POST and bearer_body',
        "sequence": ["oic-login", "access-token-request",
                     "check-id-request_pbb"],
        "endpoints": ["authorization_endpoint", "token_endpoint",
                      "check_id_endpoint"],
        },
    # -------------------------------------------------------------------------
    '11': {
        "name": 'UserInfo Endpoint Access with GET and bearer_header',
        "sequence": ["oic-login", "access-token-request", "user-info-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint",
                      "userinfo_endpoint"],
        },
    '12': {
        "name": 'UserInfo Endpoint Access with POST and bearer_header',
        "sequence": ["oic-login", "access-token-request",
                     "user-info-request_bb"],
        "endpoints": ["authorization_endpoint", "token_endpoint",
                      "userinfo_endpoint"],
        },
    '13': {
        "name": 'UserInfo Endpoint Access with POST and bearer_body',
        "sequence": ["oic-login", "access-token-request",
                     "user-info-request_bb"],
        "endpoints": ["authorization_endpoint", "token_endpoint",
                      "userinfo_endpoint"],
        },
    # -------------------------------------------------------------------------
    '14': {
        "name": 'Scope Requesting profile Claims',
        "sequence": ["oic-login+profile", "access-token-request",
                     "user-info-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint"],
        },
    '15': {
        "name": 'Scope Requesting email Claims',
        "sequence": ["oic-login+email", "access-token-request",
                     "user-info-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint"],
        },
    '16': {
        "name": 'Scope Requesting address Claims',
        "sequence": ["oic-login+address", "access-token-request",
                     "user-info-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint"],
        },
    '17': {
        "name": 'Scope Requesting phone Claims',
        "sequence": ["oic-login+phone", "access-token-request",
                     "user-info-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint"],
        },
    '18': {
        "name": 'Scope Requesting all Claims',
        "sequence": ["oic-login+all", "access-token-request",
                     "user-info-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint"],
        },
    '19': {
        "name": 'OpenID Request Object with Required name Claim',
        "sequence": ["oic-login+spec1", "access-token-request",
                     "user-info-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint"],
        },
    '20': {
        "name": 'OpenID Request Object with Optional email and picture Claim',
        "sequence": ["oic-login+spec2", "access-token-request",
                     "user-info-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint"],
        },
    '21': {
        "name": ('OpenID Request Object with Required name and Optional ',
                 'email and picture Claim'),
        "sequence": ["oic-login+spec3", "access-token-request",
                     "user-info-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint"],
        },
    '22': {
        "name": 'Requesting ID Token with auth_time Claim',
        "sequence": ["oic-login+idtc1", "access-token-request",
                     "user-info-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint"],
        },
    '23': {
        "name": 'Requesting ID Token with Required acr Claim',
        "sequence": ["oic-login+idtc2", "access-token-request",
                     "user-info-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint"],
        },
    '24': {
        "name": 'Requesting ID Token with Optional acr Claim',
        "sequence": ["oic-login+idtc3", "access-token-request",
                     "user-info-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint"],
        },
    '25': {
        "name": 'Requesting ID Token with max_age=10 seconds Restriction',
        "sequence": ["oic-login+idtc4", "access-token-request",
                     "user-info-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint"],
        },
    # ---------------------------------------------------------------------
    '26': {
        "name": 'Request with display=page',
        "sequence": ["oic-login+disp_page", "access-token-request",
                     "user-info-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint"],
        },
    '27': {
        "name": 'Request with display=popup',
        "sequence": ["oic-login+disp_popup", "access-token-request",
                     "user-info-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint"],
        },
    '28': {
        "name": 'Request with prompt=none',
        "sequence": ["oic-login+prompt_none", "access-token-request",
                     "user-info-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint"],
        },
    '29': {
        "name": 'Request with prompt=login',
        "sequence": ["oic-login+prompt_login", "access-token-request",
                     "user-info-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint"],
        },
    # ---------------------------------------------------------------------
}
