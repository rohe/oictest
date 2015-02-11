#!/usr/bin/env python
from base64 import b64encode
from urllib import urlencode, quote
from oic.oic import OIDCONF_PATTERN, ProviderConfigurationResponse
from oic.utils.keyio import KeyBundle
from oic.utils.keyio import dump_jwks
from oic.utils.http_util import Response
from oic.utils.webfinger import WebFinger
from oic.utils.webfinger import OIC_ISSUER

import copy
from oic.oauth2.message import SchemeError
from uma import PAT, AAT
from rrtest.check import CheckHTTPResponse
from uma.client import UMACONF_PATTERN
from uma.message import ProviderConfiguration

from rrtest.request import BodyResponse
from rrtest.request import DeleteRequest
from rrtest.request import GetRequest
from rrtest.request import PostRequest
from rrtest.request import Process
from rrtest.request import PutRequest
from rrtest.request import UrlResponse

__author__ = 'rohe0002'

# ========================================================================

import time

from oic.oauth2 import JSON_ENCODED
from oic.oauth2 import PBase
from oic.oauth2 import dynreg

# Used upstream, not in this module so don't remove
from oictest.check import *
from rrtest.opfunc import *

# ========================================================================

LOCAL_PATH = "export/"


class MissingResponseClaim(Exception):
    pass


class NotSupported(Exception):
    pass


class RequirementsNotMet(Exception):
    pass


def get_base(cconf=None):
    """
    Make sure a '/' terminated URL is returned
    """
    try:
        part = urlparse(cconf["_base_url"])
    except KeyError:
        part = urlparse(cconf["base_url"])
    # part = urlparse(cconf["redirect_uris"][0])

    if part.path:
        if not part.path.endswith("/"):
            _path = part.path[:] + "/"
        else:
            _path = part.path[:]
    else:
        _path = "/"

    return "%s://%s%s" % (part.scheme, part.netloc, _path, )


def response_claim(conv, respcls, claim):
    for (instance, msg) in conv.protocol_response:
        if isinstance(instance, respcls):
            return instance[claim]

    return None


# -----------------------------------------------------------------------------


class TimeDelay(Process):
    def __init__(self):
        self.delay = 30
        self.tests = {"post": [], "pre": []}

    def __call__(self, *args, **kwargs):
        time.sleep(self.delay)
        return None


class Notice(Process):
    def __init__(self):
        self.tests = {"post": [], "pre": []}
        self.template = ""

    def __call__(self, lookup, environ, start_response, **kwargs):
        resp = Response(mako_template=self.template,
                        template_lookup=lookup,
                        headers=[])
        return resp(environ, start_response, **kwargs)

    def cache(self, cache, conv, items):
        return None


class StoreX(Process):
    id = "X"
    scope = ""

    def __call__(self, conv, **kwargs):
        cli = conv.client
        _grant = cli.grant.values()[0]
        token = _grant.tokens[0].access_token
        name = self.id + b64encode(str(cli.client_config["srv_discovery_url"]))
        f = open(name, 'w')
        f.write(token)
        f.close()


class StorePAT(StoreX):
    id = "PAT"
    scope = PAT


class StoreAAT(StoreX):
    id = "AAT"
    scope = AAT


class RetrieveX(Process):
    id = "X"
    scope = ""

    def __call__(self, conv, **kwargs):
        cli = conv.client
        name = b64encode(str(cli.client_config["srv_discovery_url"]))
        f = open(self.id + name)
        token = f.read()
        f.close()
        cli.token[self.scope] = token


class RetrievePAT(RetrieveX):
    id = "PAT"
    scope = PAT


class RetrieveAAT(RetrieveX):
    id = "AAT"
    scope = AAT


class ExpectError(Notice):
    def __init__(self):
        Notice.__init__(self)
        self.template = "expect_err.mako"


class RmCookie(Notice):
    def __init__(self):
        Notice.__init__(self)
        self.template = "rmcookie.mako"

    def cache(self, cache, conv, items):
        pack = {}
        for item in items:
            if item == "id_token":
                pack[item] = conv.id_token

        key = hash("%s%f" % (items, time.time()))
        cache[str(key)] = pack
        return key


class Note(Notice):
    def __init__(self):
        Notice.__init__(self)
        self.template = "note.mako"


class DisplayUserInfo(Notice):
    def __init__(self):
        Notice.__init__(self)
        self.template = "userinfo.mako"


class DisplayIDToken(Notice):
    def __init__(self):
        Notice.__init__(self)
        self.template = "idtoken.mako"


class FetchKeys(Process):
    def __call__(self, conv, **kwargs):
        pi = conv.client.provider_info
        kb = KeyBundle(source=pi["jwks_uri"])
        kb.verify_ssl = False
        kb.update()

        try:
            conv.keybundle.append(kb)
        except AttributeError:
            conv.keybundle = [kb]


class CacheIdToken(Process):
    def __call__(self, conv, **kwargs):
        res = get_id_tokens(conv)
        try:
            conv.cache["id_token"] = res
        except KeyError:
            conv.cache = {"id_token": res}


class RotateKeys(Process):
    def __init__(self):
        self.jwk_name = "export/jwk.json"
        self.tests = {"post": [], "pre": []}
        self.new_key = {}
        self.kid_template = "_%d"
        self.key_usage = ""

    def __call__(self, conv, **kwargs):
        # find the name of the file to which the JWKS should be written
        try:
            _uri = conv.client.registration_response["jwks_uri"]
        except KeyError:
            raise RequirementsNotMet("No dynamic key handling")

        r = urlparse(_uri)
        # find the old key for this key usage and mark that as inactive
        for kb in conv.client.keyjar.issuer_keys[""]:
            for key in kb.keys():
                if key.use in self.new_key["use"]:
                    key.inactive = True

        kid = 0
        # only one key
        _nk = self.new_key
        _typ = _nk["type"].upper()

        if _typ == "RSA":
            kb = KeyBundle(source="file://%s" % _nk["key"],
                           fileformat="der", keytype=_typ,
                           keyusage=_nk["use"])
        else:
            kb = {}

        for k in kb.keys():
            k.serialize()
            k.kid = self.kid_template % kid
            kid += 1
            conv.client.kid[k.use][k.kty] = k.kid
        conv.client.keyjar.add_kb("", kb)

        dump_jwks(conv.client.keyjar[""], r.path[1:])


class RotateSigKeys(RotateKeys):
    def __init__(self):
        RotateKeys.__init__(self)
        self.new_key = {"type": "RSA", "key": "../keys/second_sig.key",
                        "use": ["sig"]}
        self.kid_template = "sig%d"


class RotateEncKeys(RotateKeys):
    def __init__(self):
        RotateKeys.__init__(self)
        self.new_key = {"type": "RSA", "key": "../keys/second_enc.key",
                        "use": ["enc"]}
        self.kid_template = "enc%d"


class OIDCRegistrationRequest(PostRequest):
    request = "RegistrationRequest"
    module = "oic.oic.message"
    endpoint = "registration_endpoint"
    content_type = JSON_ENCODED
    _request_args = {}

    def __init__(self, conv):
        PostRequest.__init__(self, conv)

        for arg in message.RegistrationRequest().parameters():
            try:
                val = conv.client_config["provider_info"][arg]
            except KeyError:
                try:
                    val = conv.client_config["preferences"][arg]
                except KeyError:
                    try:
                        val = conv.client_config["client_info"][arg]
                    except KeyError:
                        try:
                            val = conv.client_config["client_registration"][arg]
                        except KeyError:
                            continue
            self.request_args[arg] = copy.copy(val)
        try:
            del self.request_args["key_export_url"]
        except KeyError:
            pass

        # verify the registration info
        self.tests["post"].append(RegistrationInfo)

    def call_setup(self):
        _client = self.conv.client
        self.kw_args["endpoint"] = _client.provider_info["registration_endpoint"]


class OAuthRegistrationRequest(PostRequest):
    request = "RegistrationRequest"
    module = "oic.oauth2.dynreg"
    endpoint = "dynamic_client_endpoint"
    content_type = JSON_ENCODED
    _request_args = {}

    def __init__(self, conv):
        PostRequest.__init__(self, conv)

        for arg in dynreg.RegistrationRequest().parameters():
            try:
                val = conv.client_config["provider_info"][arg]
            except KeyError:
                try:
                    val = conv.client_config["preferences"][arg]
                except KeyError:
                    try:
                        val = conv.client_config["client_info"][arg]
                    except KeyError:
                        try:
                            val = conv.client_config["client_registration"][arg]
                        except KeyError:
                            continue
            self.request_args[arg] = copy.copy(val)
        try:
            del self.request_args["key_export_url"]
        except KeyError:
            pass

        # verify the registration info
        self.tests["post"].extend([RegistrationInfo, CheckHTTPResponse])


class AuthorizationRequest(GetRequest):
    request = "AuthorizationRequest"
    endpoint = "authorization_endpoint"
    _request_args = {"scope": ["openid"]}
    _tests = {"pre": [CheckResponseType],
              "post": []}
    interaction_check = True


class AccessTokenRequest(PostRequest):
    request = "AccessTokenRequest"
    endpoint = "token_endpoint"

    def __init__(self, conv):
        PostRequest.__init__(self, conv)
        self.tests["post"] = []
        # self.kw_args = {"authn_method": "client_secret_basic"}

    def call_setup(self):
        _pinfo = self.conv.client.provider_info
        try:
            _supported = _pinfo["token_endpoint_auth_methods_supported"]
        except KeyError:
            _supported = None

        if "authn_method" not in self.kw_args:
            if _supported:
                for meth in ["client_secret_basic", "client_secret_post",
                             "client_secret_jwt", "private_key_jwt"]:
                    if meth in _supported:
                        self.kw_args = {"authn_method": meth}
                        break
            else:
                self.kw_args = {"authn_method": "client_secret_basic"}
        elif _supported:
            try:
                assert self.kw_args["authn_method"] in _supported
            except AssertionError:
                raise NotSupported("Authn_method '%s' not supported" % (
                    self.kw_args["authn_method"]))


class DResponse(object):
    def __init__(self, status, ctype, text=""):
        self.content_type = ctype
        self.status = status
        self.text = text

    def __getattr__(self, item):
        if item == "content-type":
            return self.content_type


class Discover(Operation):
    conv_param = "provider_info"
    request = "DiscoveryRequest"
    pattern = ""
    response_cls = ""

    def __init__(self, conv, **kwargs):
        Operation.__init__(self, conv, **kwargs)
        self.request = "DiscoveryRequest"
        self.function = self.discover
        self.do_postop = True
        self.tests = {}

    def discover(self, client, issuer=""):
        # Allow statically over-riding dynamic info
        over_ride = client.provider_info
        self.trace.info("Provider info discover from '%s'" % issuer)
        if issuer.endswith("/"):
            self.trace.request("URL: %s" % self.pattern % issuer[:-1])
        else:
            self.trace.request("URL: %s" % self.pattern % issuer)

        pcr = client.provider_config(issuer,
                                     response_cls=self.response_cls,
                                     serv_pattern=self.pattern)
        if over_ride:
            pcr.update(over_ride)
            for key, val in over_ride.items():
                setattr(client, key, val)

        self.trace.response(pcr)

        try:
            pcr.verify()
        except SchemeError:
            try:
                if client.allow["no_https_issuer"]:
                    pass
                else:
                    raise
            except KeyError:
                raise

        return "", DResponse(200, "application/json"), pcr

    def post_op(self, result, conv, args):
        # Update the conv with the provider information
        # This overwrites what's there before. In some cases this might not
        # be preferable.

        if self.do_postop:
            attr = getattr(conv, self.conv_param, None)
            if attr is None:
                setattr(conv, self.conv_param, result[2].to_dict())
            else:
                attr.update(result[2].to_dict())


class OIDCDiscover(Discover):
    conv_param = "provider_info"
    request = "DiscoveryRequest"
    pattern = OIDCONF_PATTERN
    response_cls = ProviderConfigurationResponse


class UMADiscover(Discover):
    conv_param = "provider_info"
    request = "DiscoveryRequest"
    pattern = UMACONF_PATTERN
    response_cls = ProviderConfiguration


class Webfinger(Operation):
    # tests = {"post": [OidcIssuer]}
    request = None
    tests = {"post": [], "pre": []}

    def __init__(self, conv, **kwargs):
        Operation.__init__(self, conv, **kwargs)
        self.request = "WebFinger"
        self.function = self.discover
        self.do_postop = False

    def discover(self, *arg, **kwargs):
        wf = WebFinger(OIC_ISSUER)
        wf.httpd = PBase()
        _url = wf.query(kwargs["principal"])
        self.trace.request("URL: %s" % _url)
        url = wf.discovery_query(kwargs["principal"])
        return url

    def call_setup(self):
        pass


class UserInfoRequestGetBearerHeader(GetRequest):
    request = "UserInfoRequest"
    endpoint = "userinfo_endpoint"

    def __init__(self, conv):
        GetRequest.__init__(self, conv)
        self.kw_args = {"authn_method": "bearer_header"}
        #self.tests["post"] = [VerifyIDTokenUserInfoSubSame]


class RefreshAccessToken(PostRequest):
    request = "RefreshAccessTokenRequest"
    endpoint = "token_endpoint"


class ReadRegistration(GetRequest):
    def call_setup(self):
        _client = self.conv.client
        _rresp = _client.registration_response
        self.request_args["access_token"] = _rresp["registration_access_token"]
        self.kw_args["authn_method"] = "bearer_header"
        self.kw_args["endpoint"] = _rresp["registration_client_uri"]


class ClientUpdateRequest(PutRequest):
    request = "ClientUpdateRequest"
    module = "oic.oauth2.dynreg"
    endpoint = "dynamic_client_endpoint"

    def call_setup(self):
        _client = self.conv.client
        _rresp = _client.registration_response
        self.request_args["access_token"] = _rresp["registration_access_token"]
        self.kw_args["authn_method"] = "bearer_header"
        self.kw_args["endpoint"] = _rresp["registration_client_uri"]
        self.kw_args["content_type"] = JSON_ENCODED
        self.request_args["contacts"] = ["roland@example.com"]


class ClientDeleteRequest(DeleteRequest):
    request = "Message"
    endpoint = "dynamic_client_endpoint"

    def call_setup(self):
        _client = self.conv.client
        _rresp = _client.registration_response
        self.request_args["access_token"] = _rresp["registration_access_token"]
        self.kw_args["authn_method"] = "bearer_header"
        self.kw_args["endpoint"] = _rresp["registration_client_uri"]


class CreateResourceSetRequest(PostRequest):
    request = "ResourceSetDescription"
    endpoint = "resource_set_registration_endpoint"

    def call_setup(self):
        _client = self.conv.client
        self.request_args["access_token"] = _client.token["pat"]
        self.kw_args["authn_method"] = "bearer_header"
        self.kw_args["endpoint"] = _client.registration_response[
            "registration_client_uri"]
        self.kw_args["content_type"] = JSON_ENCODED


# ========== RESPONSE MESSAGES ========

class OIDCProviderConfigurationResponse(BodyResponse):
    response = "ProviderConfigurationResponse"
    module = "oic.oic.message"


class UMAProviderConfigurationResponse(BodyResponse):
    response = "ProviderConfiguration"
    module = "uma.message"


class OIDCRegistrationResponse(BodyResponse):
    response = "RegistrationResponse"
    module = "oic.oic.message"

    def __call__(self, conv, response):
        _client = conv.client
        for prop in ["client_id"]:
            try:
                setattr(_client, prop, response[prop])
            except KeyError:
                pass


class OAuthRegistrationResponse(BodyResponse):
    response = "ClientInfoResponse"
    module = "oic.oauth2.dynreg"

    def __call__(self, conv, response):
        _client = conv.client
        for prop in ["client_id"]:
            try:
                setattr(_client, prop, response[prop])
            except KeyError:
                pass


class AuthzResponse(UrlResponse):
    response = "AuthorizationResponse"
    module = "oic.oic.message"


class AccessTokenResponse(BodyResponse):
    response = "AccessTokenResponse"
    module = "oic.oic.message"

    def __init__(self):
        BodyResponse.__init__(self)


class UserinfoResponse(BodyResponse):
    response = "OpenIDSchema"
    module = "oic.oic.message"

    def __init__(self):
        BodyResponse.__init__(self)


class NoneResponse(BodyResponse):
    response = "Message"
    module = "oic.oic.message"


class CreateResourceSetResponse(BodyResponse):
    response = "Message"
    module = "oic.oic.message"


# ============================================================================

PHASES = {
    "oic-discovery": (OIDCDiscover, OIDCProviderConfigurationResponse),
    "uma-discovery": (UMADiscover, UMAProviderConfigurationResponse),
    "oic-registration": (OIDCRegistrationRequest, OIDCRegistrationResponse),
    "oauth-registration": (OAuthRegistrationRequest, OAuthRegistrationResponse),
    "oic-login": (AuthorizationRequest, AuthzResponse),
    "access-token-request": (AccessTokenRequest, AccessTokenResponse),
    "refresh-access-token": (RefreshAccessToken, AccessTokenResponse),
    "userinfo": (UserInfoRequestGetBearerHeader, UserinfoResponse),
    "oauth-read-registration": (ReadRegistration, OAuthRegistrationResponse),
    "modify-registration": (ClientUpdateRequest, OAuthRegistrationResponse),
    "delete-registration": (ClientDeleteRequest, NoneResponse),
    'create_resource_set': (CreateResourceSetRequest,
                            CreateResourceSetResponse),
    "intermission": TimeDelay,
    "rotate_sign_keys": RotateSigKeys,
    "rotate_enc_keys": RotateEncKeys,
    "note": Note,
    "rm_cookie": RmCookie,
    "expect_err": ExpectError,
    "webfinger": (Webfinger, None),
    "display_userinfo": DisplayUserInfo,
    "display_idtoken": DisplayIDToken,
    "fetch_keys": FetchKeys,
    "cache-id_token": CacheIdToken,
    'store_pat': StorePAT,
    'retrieve_pat': RetrievePAT,
    'store_aat': StoreAAT,
    'retrieve_aat': RetrieveAAT
}