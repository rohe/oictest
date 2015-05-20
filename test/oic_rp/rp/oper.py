import json
import logging
import os
from urlparse import urlparse
from bs4 import BeautifulSoup

from oic.oauth2 import rndstr
from oic.oic import AuthorizationRequest
from oic.oic import ProviderConfigurationResponse
from oic.oic import RegistrationResponse
from oic.oic import AuthorizationResponse
from oic.oic import AccessTokenResponse
from prof_util import WEBFINGER, RESPONSE
from prof_util import DISCOVER
from prof_util import REGISTER

__author__ = 'roland'

logger = logging.getLogger(__name__)


def include(url, test_id):
    p = urlparse(url)
    if p.path[1:].startswith(test_id):
        if len(p.path[1:].split("/")) <= 1:
            return os.path.join(url, "_/_/_/normal")
        else:
            return url

    return "%s://%s/%s%s_/_/_/normal" % (p.scheme, p.netloc, test_id, p.path)


def print_result(resp):
    try:
        cl_name = resp.__class__.__name__
    except AttributeError:
        cl_name = ""
        txt = resp
    else:
        txt = json.dumps(resp.to_dict(), sort_keys=True, indent=2,
                         separators=(',', ': '))

    logging.info("{}: {}".format(cl_name, txt))


class Operation(object):
    def __init__(self, conv, profile, test_id, conf, funcs):
        self.conv = conv
        self.funcs = funcs
        self.test_id = test_id
        self.conf = conf
        self.profile = profile.split('.')
        self.req_args = {}
        self.op_args = {}
        self.expect_exception = None

    def __call__(self, *args, **kwargs):
        pass

    def _setup(self):
        for op, arg in self.funcs.items():
            op(self, arg)

    def map_profile(self, profile_map):
        try:
            funcs = profile_map[self.__class__][self.profile[RESPONSE]]
        except KeyError:
            pass
        else:
            for op, arg in funcs.items():
                op(self, arg)

    def setup(self, profile_map):
        self.map_profile(profile_map)
        self._setup()

    def catch_exception(self, func, **kwargs):
        try:
            self.conv.trace.info(
                "Running {} with kwargs: {}".format(func, kwargs))
            res = func(**kwargs)
        except Exception as err:
            res = None
            if not self.expect_exception: # No exception expected, propagate it
                raise
            else:
                assert isinstance(err, self.expect_exception)
        else:
            self.conv.trace.reply(res)

        return res


class Webfinger(Operation):
    def __init__(self, conv, profile, test_id, conf, funcs):
        Operation.__init__(self, conv, profile, test_id, conf, funcs)
        self.resource = ""
        self.dynamic = self.profile[WEBFINGER] == "T"

    def __call__(self):
        if not self.dynamic:
            self.conv["issuer"] = self.conf.INFO["srv_discovery_url"]
        else:
            self.conv.trace.info(
                "Discovery of resource: {}".format(self.resource))
            issuer = self.conv.client.discover(self.resource)
            self.conv.trace.reply(issuer)
            self.conv.info["issuer"] = issuer

    def setup(self, profile_map):
        self.map_profile(profile_map)
        self._setup()

        try:
            self.resource = self.op_args["resource"]
        except KeyError:
            self.resource = self.conf.ISSUER+self.test_id


class Discovery(Operation):
    def __init__(self, conv, session, test_id, conf, funcs):
        Operation.__init__(self, conv, session, test_id, conf, funcs)

        self.dynamic = self.profile[DISCOVER] == "T"

    def __call__(self):
        if self.dynamic:
            self.catch_exception(self.conv.client.provider_config,
                                 **self.op_args)
        else:
            self.conv.client.provider_info = ProviderConfigurationResponse(
                **self.conf.INFO["provider_info"]
            )

    def setup(self, profile_map):
        self.map_profile(profile_map)
        self._setup()

        if self.dynamic:
            try:
                _issuer = include(self.op_args["issuer"], self.test_id)
            except KeyError:
                _issuer = include(self.conv.info["issuer"], self.test_id)

            self.op_args["issuer"] = _issuer


class Registration(Operation):
    def __init__(self, conv, session, test_id, conf, funcs):
        Operation.__init__(self, conv, session, test_id, conf, funcs)

        self.dynamic = self.profile[REGISTER] == "T"

    def __call__(self):
        if self.dynamic:
            self.catch_exception(self.conv.client.register, **self.req_args)
        else:
            self.conv.client.store_registration_info(
                RegistrationResponse(**self.conf.INFO["registered"]))

    def setup(self, profile_map):
        self.map_profile(profile_map)
        self._setup()

        if self.dynamic:
            self.req_args.update(self.conf.INFO["client"])
            self.req_args["url"] = self.conv.client.provider_info[
                "registration_endpoint"]


class Request(Operation):
    def __init__(self, conv, session, test_id, conf, funcs):
        Operation.__init__(self, conv, session, test_id, conf, funcs)

    
class Authn(Request):
    def __init__(self, conv, session, test_id, conf, funcs):
        Request.__init__(self, conv, session, test_id, conf, funcs)

        self.op_args["endpoint"] = conv.client.provider_info[
            "authorization_endpoint"]
            
        conv.state = rndstr()
        self.req_args["state"] = conv.state
        conv.nonce = rndstr()
        self.req_args["nonce"] = conv.nonce

    def setup(self, profile_map):
        self.map_profile(profile_map)
        self._setup()

        self.req_args["redirect_uri"] = self.conv.callback_uris[0]

    def __call__(self):
        url, body, ht_args, csi = self.conv.client.request_info(
            AuthorizationRequest, method="GET", request_args=self.req_args,
            **self.op_args)

        self.catch_exception(self.do_authentication_request, url=url,
                             ht_args=ht_args, csi=csi)

    def do_authentication_request(self, url, ht_args, csi):
        self.conv.trace.request(url)
        self.conv.trace.request("HT_ARGS: {}".format(ht_args))
        r = self.conv.client.http_request(url, **ht_args)
        resp = None
        if 300 < r.status_code < 400:
            r = self.conv.intermit(r)
            resp = self.conv.parse_request_response(
                r, AuthorizationResponse, body_type="urlencoded",
                state=self.conv.state, keyjar=self.conv.client.keyjar)
        elif r.status_code == 200:
            resp = AuthorizationResponse()
            if "response_mode" in csi and csi["response_mode"] == "form_post":
                forms = BeautifulSoup(r.content).findAll('form')
                for inp in forms[0].find_all("input"):
                    resp[inp.attrs["name"]] = inp.attrs["value"]
            resp.verify(keyjar=self.conv.client.keyjar)

        self.conv.trace.response(resp)
        return resp


class AccessToken(Request):
    def __init__(self, conv, session, test_id, conf, args):
        Request.__init__(self, conv, session, test_id, conf, args)
        self.op_args["state"] = conv.state
        self.req_args["redirect_uri"] = conv.client.redirect_uris[0]

    def __call__(self):
        self.conv.trace.info(
            "Access Token Request with args: {}".format(self.args))
        atr = self.conv.client.do_access_token_request(
            request_args=self.req_args, **self.op_args)
        self.conv.trace.response(atr)
        assert isinstance(atr, AccessTokenResponse)


class UserInfo(Request):
    def __init__(self, conv, session, test_id, conf, args):
        Request.__init__(self, conv, session, test_id, conf, args)
        self.op_args["state"] = conv.state

    def __call__(self):
        user_info = self.conv.client.do_user_info_request(**self.args)
        assert user_info
        self.conv.client.userinfo = user_info


class DisplayUserInfo(Operation):
    pass


# NAME2CLASS = {
#     "webfinger": Webfinger,
#     "static_webfinger": StaticWebFinger,
#     "provider-discovery": Discovery,
#     "static_discovery": StaticDiscovery,
#     "oic-registration": Registration,
#     "static_registration": StaticRegistration,
#     "oic-login": Authn,
#     "access-token-request": AccessToken,
#     "userinfo": UserInfo,
#     "display_userinfo": DisplayUserInfo
# }