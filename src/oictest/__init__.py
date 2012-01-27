#!/usr/bin/env python
__author__ = 'rohe0002'

import sys
import argparse
import json
import httplib2

from oic.utils import exception_trace
from oic.utils import jwt

from oictest import httplib2cookie
from oictest.base import *

QUERY2RESPONSE = {
    "AuthorizationRequest": "AuthorizationResponse",
    "OpenIDRequest": "OpenIDResponse",
    "AccessTokenRequest": "AccessTokenResponse",
    "UserInfoRequest": "OpenIDSchema",
    "RegistrationRequest": "RegistrationResponse"
}

class HTTP_ERROR(Exception):
    pass

def get_page(url):
    http = httplib2.Http()
    resp, content = http.request(url)
    if resp.status == 200:
        return content
    else:
        raise HTTP_ERROR(resp.status)

class OAuth2(object):
    client_args = ["client_id", "redirect_uri", "password"]
    def __init__(self, operations_mod, message_mod, client_class):
        self.operations_mod = operations_mod
        self.message_mod = message_mod
        self.client_class = client_class
        self.client = None
        self.trace = Trace()

        self._parser = argparse.ArgumentParser()
        self._parser.add_argument('-v', dest='verbose', action='store_true')
        self._parser.add_argument('-d', dest='debug', action='store_true')
        self._parser.add_argument('-C', dest="ca_certs")
        self._parser.add_argument('-J', dest="json_config_file")
        self._parser.add_argument('-I', dest="interactions")
        self._parser.add_argument("-l", dest="list", action="store_true")
        self._parser.add_argument("-T", dest="traceback", action="store_true")
        self._parser.add_argument("flow")

        self.args = None
        self.pinfo = None
        self.sequences = []
        self.function_args = {}
        self.signing_key = None
        self.encryption_key = None

    def parse_args(self):
        self.json_config= self.json_config_file()

        self.pinfo = self.provider_info()
        self.client_conf(self.client_args)

    def json_config_file(self):
        if self.args.json_config_file == "-":
            return json.loads(sys.stdin.read())
        else:
            return json.loads(open(self.args.json_config_file).read())

    def run(self):
        self.args = self._parser.parse_args()

        self.args.flow = self.args.flow.strip("'")
        self.args.flow = self.args.flow.strip('"')
        if self.args.list:
            return self.operations()
        else:
            self.parse_args()
            self.trace.info("SERVER CONFIGURATION: %s" % self.pinfo)
            _seq = self.make_sequence()
            interact = self.get_interactions()
            tests = self.get_test()
            self.client.state = "STATE0"

            try:
                run_sequence(self.client, _seq, self.trace, interact,
                             self.message_mod, self.args.verbose, tests,
                             self.pinfo)
            except Exception, err:
                print self.trace
                print err
                if self.args.traceback:
                    exception_trace("RUN", err)

    def operations(self):
        lista = []
        for key,val in self.operations_mod.FLOWS.items():
            item = {"id": key,
                    "name": val["name"],
                    "descr": "".join(val["descr"])}
            lista.append(item)

        return json.dumps(lista)

    def provider_info(self):
        # Should provide a Metadata class
        res = {}
        _jc = self.json_config["provider"]
        for key in ["version", "issuer", "endpoints", "scopes_supported",
                    "schema", "user_id_types_supported",
                    "userinfo_algs_supported",
                    "id_token_algs_supported",
                    "request_object_algs_supported",
                    "provider_trust"]:
            if key == "endpoints":
                try:
                    for endp, url in _jc[key].items():
                        res[endp] = url
                except KeyError:
                    pass
            else:
                try:
                    res[key] = _jc[key]
                except KeyError:
                    pass

        return res

    def client_conf(self, cprop):
        _htclass = httplib2cookie.CookiefulHttp
        if self.args.ca_certs:
            self.client = self.client_class(ca_certs=self.args.ca_certs,
                                            httpclass=_htclass)
        else:
            try:
                self.client = self.client_class(
                    ca_certs=self.json_config["ca_certs"],
                    httpclass=_htclass)
            except (KeyError, TypeError):
                self.client = self.client_class(
                    disable_ssl_certificate_validation=True,
                    httpclass=_htclass)

        self.client.http_request = self.client.http.crequest

        # set the endpoints in the Client from the provider information
        for key, val in self.pinfo.items():
            if key.endswith("_endpoint"):
                setattr(self.client, key, val)

        # Client configuration
        self.cconf = self.json_config["client"]

        # set necessary information in the Client
        for prop in cprop:
            try:
                setattr(self.client, prop, self.cconf[prop])
            except KeyError:
                pass

    def make_sequence(self):
        # Whatever is specified on the command line takes precedences
        if self.args.flow:
            sequence = flow2sequence(self.operations_mod, self.args.flow)
        elif self.json_config and "flow" in self.json_config:
            sequence = flow2sequence(self.operations_mod,
                                     self.json_config["flow"])
        else:
            sequence = None

        return sequence

    def get_interactions(self):
        interactions = {}

        if self.json_config:
            try:
                interactions = self.json_config["interaction"]
            except KeyError:
                pass

        if self.args.interactions:
            _int = self.args.interactions.replace("\'", '"')
            if interactions:
                interactions.update(json.loads(_int))
            else:
                interactions = json.loads(_int)

        for url, spec in interactions.items():
            try:
                func_name, args = spec
                func = getattr(self.operations_mod, func_name)
                interactions[url] = (func, args)
            except ValueError:
                interactions[url] = spec

        return interactions

    def get_test(self):
        if self.args.flow:
            flow = self.operations_mod.FLOWS[self.args.flow]
        elif self.json_config and "flow" in self.json_config:
            flow = self.operations_mod.FLOWS[self.json_config["flow"]]
        else:
            flow = None

        try:
            return [getattr(self.operations_mod, t) for t in flow["tests"]]
        except KeyError:
            return []

class OIC(OAuth2):
    client_args = ["client_id", "redirect_uri", "password", "client_secret"]

    def __init__(self, operations_mod, message_mod, client_class,
                 consumer_class):
        OAuth2.__init__(self, operations_mod, message_mod, client_class)

        self._parser.add_argument('-P', dest="provider_conf_url")
        self._parser.add_argument('-p', dest="principal")
        self._parser.add_argument('-R', dest="register", action="store_true")

        self.consumer_class = consumer_class

    def parse_args(self):
        OAuth2.parse_args(self)

        if "x509_url" in self.pinfo:
            _txt = get_page(self.pinfo["x509_url"])
            self.client.srv_sig_key["rsa"] = jwt.x509_rsa_loads(_txt)
        if "x509_encryption_url" in self.pinfo:
            _txt = get_page(self.pinfo["x509_encryption_url"])
            self.client.srv_enc_key["rsa"] = jwt.x509_rsa_loads(_txt)
        elif self.signing_key:
            self.client.srv_enc_key = self.client.srv_sig_key

        #        if "jwk_url" in self.pinfo:
        #            self.signing_key = http.request(self.pinfo["jwk_url"])
        #        if "jwk_encryption_url" in self.pinfo:
        #            self.encryption_key = http.request(self.pinfo["jwk_encryption_url"])
        #        elif self.signing_key:
        #            self.encryption_key = self.signing_key

        self.register()

    def discover(self, principal):
        c = self.consumer_class(None, None)
        return c.discover(principal)

    def provider_config(self, issuer):
        c = self.consumer_class(None, None)
        return c.provider_config(issuer)

    def _register(self, endpoint, info):
        c = self.consumer_class(None, None)
        return c.register(endpoint, **info)

    def provider_info(self):
        if "conf_url" in self.json_config["provider"]:
            _url = self.json_config["provider"]["conf_url"]
            return self.provider_config(_url).dictionary()
        else:
            return OAuth2.provider_info(self)

    def register(self):
        # should I register the client ?
        if self.args.register or "register" in self.json_config["client"]:
            info = {}
            for prop in self.message_mod.RegistrationRequest.c_attributes.keys():
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
                    if prop == "client_secret":
                        self.client.srv_sig_key["hmac"] = _val
                except KeyError:
                    pass

            self.trace.info("REGISTRATION INFORMATION: %s" % self.reg_resp)
            if self.client.srv_sig_key is None:
                self.client.srv_sig_key = self.client.client_secret

if __name__ == "__main__":
    from oictest import OAuth2
    from oictest import oauth2_operations
    from oic.oauth2 import Client
    from oic.oauth2 import message

    cli = OAuth2(oauth2_operations, message, Client)

    cli.run()