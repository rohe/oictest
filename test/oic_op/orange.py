#!/usr/bin/env python

import json
from default import DEFAULT

info = DEFAULT.copy()

# NO key export
info["features"]["key_export"] = False

#del info["client"]["key_export_url"]

info["provider"] = {"dynamic": "http://pub-openid-int.orange.fr/"}

info["interaction"] = [
    {
        "matches": {
            "url": "http://id-natnext.orange.fr/auth_user/bin/authNuser.cgi",
            },
        "page-type": "login",
        "control": {
            "type": "form",
            "set": {"credential":"0692411424","pwd": "723CBP"}
        }
    }
]

print json.dumps(info)


RES="""
* (oic-verify)Special flow used to find necessary user interactions - OK
* (oic-discovery)Provider configuration discovery - OK
* (mj-00)Client registration Request - OK
* (mj-01)Request with response_type=code - OK
* (mj-02)Request with response_type=token - OK
* (mj-51)Login no nonce - OK
* (oic-token-userinfo)Implicit flow and Userinfo request - OK
* (oic-token-userinfo_bb)Implicit flow, UserInfo request using POST and bearer body
    authentication - OK
* (mj-03)Request with response_type=id_token - OK
* (mj-04)Request with response_type=code token - OK
* (oic-code+token-token)Flow with response_type='code token' - OK
* (oic-code+token-userinfo)Flow with response_type='code token' and Userinfo request - OK
* (mj-05)Request with response_type=code id_token - OK
* (oic-code+idtoken-token)Flow with response_type='code idtoken' - OK
* (oic-code+idtoken-token-userinfo)Flow with response_type='code idtoken' and Userinfo request - OK
* (mj-06)Request with response_type=id_token token - OK
* (oic-idtoken+token-userinfo)Flow with response_type='token idtoken' and Userinfo request - OK
* (mj-07)Request with response_type=code id_token token - OK
* (oic-code+idtoken+token-token)Flow with response_type='code token idtoken' - OK
* (oic-code+idtoken+token-token-userinfo)Flow with response_type='code idtoken token'
    grab a second token using the code and then do a Userinfo
    request - OK
* (oic-code+idtoken+token-userinfo)Flow with response_type='code idtoken token' and Userinfo
    request - OK
* (mj-12)UserInfo Endpoint Access with POST and bearer_header - OK
* (mj-64)Can Provide Encrypted UserInfo Response - CRITICAL (Signed Id Token algorithm not supported)
* (mj-13)UserInfo Endpoint Access with POST and bearer_body - OK
* (mj-14)Scope Requesting profile Claims - OK
* (mj-15)Scope Requesting email Claims - OK
* (mj-16)Scope Requesting address Claims - OK
* (mj-17)Scope Requesting phone Claims - OK
* (mj-18)Scope Requesting all Claims - OK
* (mj-19)OpenID Request Object with Required name Claim - ERROR (required attribute 'name' missing)
* (mj-20)OpenID Request Object with Optional email and picture Claim - OK
* (mj-21)OpenID Request Object with Required name and Optional email and picture Claim - ERROR (required attribute 'name' missing)
* (mj-22)Requesting ID Token with auth_time Claim - OK
* (mj-56)Supports Combining Claims Requested with scope and Request Object - CRITICAL (OP error)
* (mj-23)Requesting ID Token with Required specific acr Claim - OK
* (mj-24)Requesting ID Token with Optional acr Claim - OK
* (mj-25)Requesting ID Token with max_age=1 seconds Restriction - ERROR (Only one authentication when more than one was expected)
* (mj-26)Request with display=page - OK
* (mj-27)Request with display=popup - OK
* (mj-28)Request with prompt=none - CRITICAL (str: Missing required attribute 'error')
* (mj-29)Request with prompt=login - OK
* (mj-30)Access token request with client_secret_basic authentication - OK
* (mj-31)Request with response_type=code and extra query component - OK
* (mj-32)Request with redirect_uri with query component - CRITICAL (OP error)
* (mj-33)Registration where a redirect_uri has a query component - OK
* (mj-34)Registration where a redirect_uri has a fragment - OK
* (mj-35)Authorization request missing the 'response_type' parameter - OK
* (mj-36)The sent redirect_uri does not match the registered - OK
* (mj-37)Access token request with client_secret_jwt authentication - CRITICAL ({"error": "invalid_client"})
* (mj-38)Access token request with public_key_jwt authentication - CRITICAL (Auth type not supported)
* (mj-41)Registration and later registration update - OK
* (mj-42)Registration and later secret rotate - OK
{u'status': 3, u'id': u'policy_url_on_page', u'name': u''}
{u'status': 3, u'id': u'logo_url_on_page', u'name': u''}
* (mj-45)Registration with policy_url and logo_url - ERROR
* (mj-46)Registration of wish for public user_id - CRITICAL (User_id type not supported)
"""