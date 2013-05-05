#!/usr/bin/env python
import time
from urlparse import urlparse
from oauth2test import OAuth2

from oic.utils.keyio import KeyBundle
from oic.utils.keyio import dump_jwks
from rrtest import start_script

__author__ = 'rohe0002'

from oic.oic.message import ProviderConfigurationResponse
from oic.oic.message import RegistrationRequest

from oictest.check import CheckRegistrationResponse
from oictest.check import factory as check_factory

QUERY2RESPONSE = {
    "AuthorizationRequest": "AuthorizationResponse",
    "OpenIDRequest": "OpenIDResponse",
    "AccessTokenRequest": "AccessTokenResponse",
    "UserInfoRequest": "OpenIDSchema",
    "RegistrationRequest": "RegistrationResponse"
}


KEY_EXPORT_ARGS = {
    "script": "static_provider.py",
    "local_path": "export",
    "vault": "keys",
    "sig": {
        "alg": "rsa",
        "create_if_missing": True,
        "format": ["jwk", "x509"]
        #"name": "jwk.json",
    }
}


def start_key_server(url):
    part = urlparse(url)
    # start the server
    try:
        (host, port) = part.netloc.split(":")
    except ValueError:
        host = part.netloc
        port = 80

    return start_script(KEY_EXPORT_ARGS["script"], host, port)


URL_TYPES = ["jwks_uri"]


class OIC(OAuth2):
    client_args = ["client_id", "redirect_uris", "password", "client_secret"]

    def __init__(self, operations_mod, client_class, consumer_class,
                 msgfactory, chk_factory, conversation_cls):
        OAuth2.__init__(self, operations_mod, client_class, msgfactory,
                        chk_factory, conversation_cls)

        #self._parser.add_argument('-R', dest="rsakey")
        self._parser.add_argument(
            '-i', dest="internal_server", action='store_true',
            help="Whether or not an internal web server to handle key export should be forked")
        self._parser.add_argument(
            '-e', dest="external_server", action='store_true',
            help="A external web server are used to handle key export")

        self.consumer_class = consumer_class

    def parse_args(self):
        OAuth2.parse_args(self)

        if self.args.external_server:
            self.environ["keyprovider"] = None

        _keyjar = self.client.keyjar
        pcr = ProviderConfigurationResponse()
        n = 0
        for param in URL_TYPES:
            if param in self.pinfo:
                n += 1
                pcr[param] = self.pinfo[param]

        if n:
            _keyjar.load_keys(pcr, self.pinfo["issuer"])

        #self.register()

    def discover(self, principal):
        c = self.consumer_class(None, None)
        return c.discover(principal)

    def _register(self, endpoint, info):
        c = self.consumer_class(None, None)
        return c.register(endpoint, **info)

    def register_args(self):
        info = {}
        for prop in RegistrationRequest.c_param.keys():
            try:
                info[prop] = self.cconf[prop]
            except KeyError:
                pass
        return info

    def provider_info(self):
        # Should provide a Metadata class
        res = {}
        _jc = self.json_config["provider"]

        # Backward compatible
        if "endpoints" in _jc:
            try:
                for endp, url in _jc["endpoints"].items():
                    res[endp] = url
            except KeyError:
                pass

        for key in ProviderConfigurationResponse.c_param.keys():
            try:
                res[key] = _jc[key]
            except KeyError:
                pass

        return res

    def register(self):
        # should I register the client ?
        if "register" in self.json_config["client"]:
            info = {}
            for prop in RegistrationRequest.c_param.keys():
                try:
                    info[prop] = self.cconf[prop]
                except KeyError:
                    pass

            self.reg_resp = self._register(self.pinfo["registration_endpoint"],
                                           info)

            for prop in ["client_id", "client_secret"]:
                try:
                    _val = getattr(self.reg_resp, prop)
                    setattr(self.client, prop, _val)
                except KeyError:
                    pass

            self.environ["registration_response"] = self.reg_resp
            chk = CheckRegistrationResponse()
            chk(self.environ, self.test_log)

            self.trace.info("REGISTRATION INFORMATION: %s" % self.reg_resp)

    def do_features(self, interact, _seq, block):
        try:
            self.cconf["_base_url"] = self.cconf["key_export_url"] % (
                self.args.host,)
        except KeyError:
            pass

        if "key_export" not in block:
            if "key_export" in self.features and self.features["key_export"]:
                self.export()

#        if "sector_identifier_url" in self.features and \
#            self.features["sector_identifier_url"]:
#            self.do_sector_identifier_url(self.cconf["key_export_url"])

        if "registration" not in block:
            if "registration" in self.features and self.features[
                    "registration"]:
                _register = True
            elif "register" in self.cconf and self.cconf["register"]:
                _register = True
            else:
                _register = False
        else:
            _register = False

        if _register:
            for sq in _seq:
                if sq[0].request == "RegistrationRequest":
                    _register = False
            if _register:
                _ext = self.operations_mod.PHASES["oic-registration"]
                _seq.insert(0, _ext)
                interact.append({"matches": {"class": "RegistrationRequest"},
                                 "args": {"request": self.register_args()}})
        else:  # don't try to register
            for sq in _seq:
                if sq[0].request == "RegistrationRequest":
                    raise Exception(
                        "RegistrationRequest in the test should not be run")

        if "discovery" not in block:
            if "discovery" in self.features and self.features["discovery"]:
                _discover = True
            elif "dynamic" in self.json_config["provider"]:
                _discover = True
            else:
                _discover = False

            if _discover:
                op_spec = self.operations_mod.PHASES["provider-discovery"]
                if op_spec not in _seq:
                    _seq.insert(0, op_spec)
                interact.append({
                    "matches": {"class": op_spec[0].__name__},
                    "args": {"issuer":
                             self.json_config["provider"]["dynamic"]}})

            else:
                self.trace.info("SERVER CONFIGURATION: %s" % self.pinfo)

    def export(self):
        # has to be there
        self.trace.info("EXPORT")

        kbl = []
        for typ, info in self.cconf["keys"].items():
            kb = KeyBundle(source="file://%s" % info["key"], fileformat="der",
                           keytype=typ)
            self.client.keyjar.add_kb("", kb)
            kbl.append(kb)

        try:
            new_name = "static/jwks.json"
            dump_jwks(kbl, new_name)
            self.client.jwks_uri = "%s%s" % (self.cconf["_base_url"], new_name)
        except KeyError:
            pass

        if self.args.internal_server:
            self._pop = start_key_server(self.cconf["_base_url"])
            self.environ["keyprovider"] = self._pop
            self.trace.info("Started key provider")
            time.sleep(1)
