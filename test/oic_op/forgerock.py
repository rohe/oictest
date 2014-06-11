#!/usr/bin/env python

import json

from default import DEFAULT

info = DEFAULT.copy()

# NO key export
info["features"]["key_export"] = False
info["features"]["discovery"] = False  # if this is True, I think I need info["provider"] = {"dynamic": "..."}
info["features"]["registration"] = True  # False avoids initial attempt to register a client

# can be obtained from openam/.well-known/openid-configuration endpoint
# info["provider"] = {"dynamic": "http://demo.forgerock.com:8443/openam"}
info["provider"] = {
    "response_types_supported": [
        # "id_token|org.forgerock.restlet.ext.oauth2.flow.responseTypes.IDTokenResponseType",
        "id_token",
        # "token|org.forgerock.restlet.ext.oauth2.flow.responseTypes.TokenResponseType",
        "token",
        # "code|org.forgerock.restlet.ext.oauth2.flow.responseTypes.CodeResponseType"
        "code"
    ],
    "registration_endpoint": "http://demo.forgerock.com:8443/openam/oauth2/connect/register",
    "token_endpoint": "http://demo.forgerock.com:8443/openam/oauth2/access_token",
    "end_session_endpoint": "http://demo.forgerock.com:8443/openam/oauth2/connect/endSession",
    "version": "3.0",
    "userinfo_endpoint": "http://demo.forgerock.com:8443/openam/oauth2/userinfo",
    "subject_types_supported": ["public"],
    "issuer": "https://demo.forgerock.com:8443/openam",
    # "issuer": "https://self-issued.me",
    # "jwks_uri": "https://dl.dropboxusercontent.com/u/42180662/test.json",
    "jwks_uri": "",
    "check_session_iframe": "http://demo.forgerock.com:8443/openam/oauth2/connect/checkSession",
    "claims_supported": [
        "phone",
        "email",
        "address",
        "openid",
        "profile"
    ],
    "id_token_signing_alg_values_supported": [
        # "HmacSHA256",
        "HS256",
        # "HmacSHA512",
        "HS512",
        # "HmacSHA384"
        "HS384"
    ],
    "authorization_endpoint": "http://demo.forgerock.com:8443/openam/oauth2/authorize",
    "token_endpoint_auth_method": []
}

# info["client"]["contacts"] = ["Garyl.Erickson@forgerock.com"]
# info["client"]["key_export_url"] = ["http://%s:8080/"]
# info["client"]["client_id"] = "OpenIdClient"
# info["client"]["client_secret"] = "password"
info["client"]["client_type"] = "Confidential"
# info["client"]["contacts"]
# info["client"]["preferences"]["client_id"] = ["OpenIdTestClient"]
# info["client"]["preferences"]["grant_types"] = [""]
# info["client"]["preferences"]["id_token_signed_response_algs"] = ["RS256"]
# info["client"]["preferences"]["request_object_signing_algs"] = ["RS256"]
# info["client"]["preferences"]["require_auth_time"] = ""
# info["client"]["preferences"]["response_types"] = [""]
# info["client"]["preferences"]["subject_types"] = ["public"]
# info["client"]["preferences"]["token_endpoint_auth_methods"] = ["client_secret_basic", "client_secret_post"]
# info["client"]["preferences"]["userinfo_signed_response_algs"] = []
info["client"]["redirect_uris"] = ["http://%s:8443/openam/oauth2c/OAuthProxy.jsp",
                                   "http://%s:8443/openam/oauth2c/OAuthProxy2.jsp"]
info["client"]["RegistrationRequest"] = {"authn_method": "bearer_header",
                                         "access_token": "cfcce762-6b6d-48e4-ba12-d3f5b0d431d6"}

# info["extra_args"] = {
#     "AuthorizationRequest": {"client_id": "OpenIdTestClient"}
# }
info["interaction"] = [
    {
        "matches": {
            "url": "http://demo.forgerock.com:8443/openam/UI/Login"
        },
        "page-type": "login",
        "control": {
            "type": "form",
            "set": {"IDToken1": "OAuth2User",
                    "IDToken2": "password"}
        }
    },
    {
        "matches": {
            "url": "http://demo.forgerock.com:8443/openam/oauth2/authorize"
        },
        "page-type": "user-consent",
        "control": {
            "type": "form",
            "click": "Allow"
        }
    }
]
# do we need a click on the login page?


print json.dumps(info)