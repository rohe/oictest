#!/usr/bin/env python
import signal

__author__ = 'rohe0002'

import argparse
import sys
import json
import os
import requests

from subprocess import Popen, PIPE
import urlparse

from oic.utils import jwt
from oic.utils import exception_trace
from oic.utils.jwt import construct_rsa_jwk
from oic.oic.message import ProviderConfigurationResponse
from oic.oic.message import RegistrationRequest

from oictest.check import CheckRegistrationResponse
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

def start_script(path, *args):
    popen_args = [path]
    popen_args.extend(args)
    return Popen(popen_args, stdout=PIPE, stderr=PIPE)

def stop_script_by_name(name):
    import subprocess, signal, os

    p = subprocess.Popen(['ps', '-A'], stdout=subprocess.PIPE)
    out, err = p.communicate()

    for line in out.splitlines():
        if name in line:
            pid = int(line.split(None, 1)[0])
            os.kill(pid, signal.SIGKILL)

def stop_script_by_pid(pid):
    import signal, os

    os.kill(pid, signal.SIGKILL)

def get_page(url):
    resp = requests.get(url)
    if resp.status_code == 200:
        return resp.text
    else:
        raise HTTP_ERROR(resp.status)

KEY_EXPORT_ARGS = {
    "script": "../../script/static_provider.py",
#    "server": "http://%s:8090/export" % HOST,
    "local_path": "./keys",
    "sign": {
        "alg":"rsa",
        "create_if_missing": True,
        "format": "jwk",
        #"name": "jwk.json",
    }
}

def key_export(server_url):
    part = urlparse.urlsplit(server_url)

    # deal with the export directory
    if part.path.endswith("/"):
        _path = part.path[:-1]
    else:
        _path = part.path[:]

        # Check if the dir is there
    if not os.path.exists(".%s" % _path):
        # otherwise create it
        os.makedirs(".%s" % _path)

    local_path = KEY_EXPORT_ARGS["local_path"]
    if not os.path.exists(local_path):
        os.makedirs(local_path)

    res = {}
    # For each usage type
    for usage in ["sign", "enc"]:
        if usage in KEY_EXPORT_ARGS:
            _keys = {}

            if KEY_EXPORT_ARGS[usage]["format"] == "jwk":
                if usage == "sign":
                    _name = ("jwk.json", "jwk_url")
                else:
                    _name = ("jwk_enc.json", "jwk_encryption_url")
            else: # must be 'x509'
                if usage == "sign":
                    _name = ("x509.pub", "x509_url")
                else:
                    _name = ("x509_enc.pub", "x509_encryption_url")

            _new_path = ".%s/%s" % (_path, _name[0])

            if os.path.exists(_new_path): # If it's already there ..
                _keys["rsa"] = jwt.rsa_load("%s/%s" % (local_path, "pyoidc"))
            else:
                if KEY_EXPORT_ARGS[usage]["alg"] == "rsa":
                    _keys["rsa"] = jwt.create_and_store_rsa_key_pair(path=local_path)

                if KEY_EXPORT_ARGS[usage]["format"] == "jwk":
                    _jwk = []
                    for typ, key in _keys.items():
                        if typ == "rsa":
                            _jwk.append(construct_rsa_jwk(key))

                    _jwk = {"jwk": _jwk}

                    f = open(_new_path, "w")
                    f.write(json.dumps(_jwk))
                    f.close()

            keyspec = []
            for typ, key in _keys.items():
                keyspec.append([key, typ, usage])

            _url = "%s://%s%s" % (part.scheme, part.netloc, _new_path[1:])
            res[_name[1]] = (_url, keyspec)

        return part, res

def start_key_server(part):
    # start the server
    try:
        (host, port) = part.netloc.split(":")
    except ValueError:
        host = part.netloc
        port = 80

    return start_script(KEY_EXPORT_ARGS["script"], host, port)

class OAuth2(object):
    client_args = ["client_id", "redirect_uris", "password"]

    def __init__(self, operations_mod, client_class, msgfactory):
        self.operations_mod = operations_mod
        self.client_class = client_class
        self.client = None
        self.trace = Trace()
        self.msgfactory = msgfactory

        self._parser = argparse.ArgumentParser()
        #self._parser.add_argument('-v', dest='verbose', action='store_true')
        self._parser.add_argument('-d', dest='debug', action='store_true',
                                  help="Print debug information")
        self._parser.add_argument('-C', dest="ca_certs",
                                  help="CA certs to use to verify HTTPS server certificates, if HTTPS is used and no server CA certs are defined then no cert verification is done")
        self._parser.add_argument('-J', dest="json_config_file",
                                  help="Script configuration")
        self._parser.add_argument('-I', dest="interactions",
                                  help="Extra interactions not defined in the script configuration file")
        self._parser.add_argument("-l", dest="list", action="store_true",
                                  help="List all the test flows as a JSON object")
        self._parser.add_argument("-H", dest="host", default="example.com",
                                  help="Which host the script is running on, used to construct the key export URL")
        self._parser.add_argument("flow", nargs="?", help="Which test flow to run")

        self.args = None
        self.pinfo = None
        self.sequences = []
        self.function_args = {}
        self.signing_key = None
        self.encryption_key = None
        self.test_log = []
        self.environ = {}
        self._pop = None

    def parse_args(self):
        self.json_config= self.json_config_file()

        try:
            self.features = self.json_config["features"]
        except KeyError:
            self.features = {}

        self.pinfo = self.provider_info()
        self.client_conf(self.client_args)

    def json_config_file(self):
        if self.args.json_config_file == "-":
            return json.loads(sys.stdin.read())
        else:
            return json.loads(open(self.args.json_config_file).read())

    def test_summation(self, id):
        status = 0
        for item in self.test_log:
            if item["status"] > status:
                status = item["status"]

        sum = {
            "id": id,
            "status": status,
            "tests": self.test_log
        }

        if status == 5:
            sum["url"] = self.test_log[-1]["url"]
            sum["htmlbody"] = self.test_log[-1]["message"]

        return sum

    def run(self):
        self.args = self._parser.parse_args()

        if self.args.list:
            return self.operations()
        else:
            if not self.args.flow:
                raise Exception("Missing flow specification")
            self.args.flow = self.args.flow.strip("'")
            self.args.flow = self.args.flow.strip('"')

            flow_spec = self.operations_mod.FLOWS[self.args.flow]
            if "block" in flow_spec and flow_spec["block"] == "key_export":
                allow_key_export = False
            else:
                allow_key_export = True

            self.parse_args()
            _seq = self.make_sequence()
            interact = self.get_interactions()

            try:
                self.do_features(interact, _seq, allow_key_export)
            except Exception,exc:
                _output = {"status": 4,
                           "tests": [{"status": 4,
                                      "message":"Couldn't run testflow: %s" % exc,
                                      "id": "verify_features",
                                      "name": "Make sure you don't do things you shouldn't"}]}
                print >> sys.stdout, json.dumps(_output)
                return

            tests = self.get_test()
            self.client.state = "STATE0"

            self.environ.update({"provider_info": self.pinfo,
                                 "client": self.client})

            try:
                testres, trace = run_sequence(self.client, _seq, self.trace,
                                              interact, self.msgfactory,
                                              self.environ, tests,
                                              self.json_config["features"])
                self.test_log.extend(testres)
                sum = self.test_summation(self.args.flow)
                print >>sys.stdout, json.dumps(sum)
                if sum["status"] > 1 or self.args.debug:
                    print >>sys.stderr, trace
            except Exception, err:
                print >> sys.stderr, self.trace
                print err
                exception_trace("RUN", err)

            if self._pop is not None:
                self._pop.terminate()
            elif "keyprovider" in self.environ:
                os.kill(self.environ["keyprovider"].pid, signal.SIGTERM)
                #self.environ["keyprovider"].terminate()

    def operations(self):
        lista = []
        for key,val in self.operations_mod.FLOWS.items():
            item = {"id": key,
                    "name": val["name"],}
            try:
                _desc = val["descr"]
                if isinstance(_desc, basestring):
                    item["descr"] = _desc
                else:
                    item["descr"] = "\n".join(_desc)
            except KeyError:
                pass

            for key in ["depends", "endpoints"]:
                try:
                    item[key] = val[key]
                except KeyError:
                    pass

            lista.append(item)

        print json.dumps(lista)

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

    def do_features(self, *args):
        pass

    def export(self, url):
        pass

    def client_conf(self, cprop):
        if self.args.ca_certs:
            self.client = self.client_class(ca_certs=self.args.ca_certs)
        else:
            try:
                self.client = self.client_class(
                                        ca_certs=self.json_config["ca_certs"])
            except (KeyError, TypeError):
                self.client = self.client_class()

        #self.client.http_request = self.client.http.crequest

        # set the endpoints in the Client from the provider information
        # If they are statically configured, if dynamic it happens elsewhere
        for key, val in self.pinfo.items():
            if key.endswith("_endpoint"):
                setattr(self.client, key, val)

        # Client configuration
        self.cconf = self.json_config["client"]
        # replace pattern with real value
        _h = self.args.host
        self.cconf["redirect_uris"] = [p % _h for p in self.cconf["redirect_uris"]]

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
        interactions = []

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

#        res = {}
#        for var in ["title", "url", "class"]:
#            if var not in interactions:
#                continue
#            res[var] = {}
#            for url, spec in interactions[var].items():
#                try:
#                    func_name, args, typ = spec
#                    func = getattr(self.operations_mod, func_name)
#                    res[var][url] = (func, args, typ)
#                except ValueError:
#                    res[var][url] = spec

        return interactions

    def get_test(self):
        if self.args.flow:
            flow = self.operations_mod.FLOWS[self.args.flow]
        elif self.json_config and "flow" in self.json_config:
            flow = self.operations_mod.FLOWS[self.json_config["flow"]]
        else:
            flow = None

        try:
            return flow["tests"]
        except KeyError:
            return []

    def register_args(self):
        pass

class OIC(OAuth2):
    client_args = ["client_id", "redirect_uris", "password", "client_secret"]

    def __init__(self, operations_mod, client_class,
                 consumer_class, msgfactory):
        OAuth2.__init__(self, operations_mod, client_class, msgfactory)

        #self._parser.add_argument('-R', dest="rsakey")
        self._parser.add_argument('-i', dest="internal_server",
                                  action='store_true',
                                  help="Whether or not an internal web server to handle key export should be forked")

        self.consumer_class = consumer_class

    def parse_args(self):
        OAuth2.parse_args(self)

        _keystore = self.client.keystore
        pcr = ProviderConfigurationResponse()
        n = 0
        for param in _keystore.url_types:
            if param in self.pinfo:
                n += 1
                pcr[param] = self.pinfo[param]

        if n:
            _keystore.load_keys(pcr, self.pinfo["issuer"])

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

    def do_features(self, interact, _seq, allow_key_export=True):
        if allow_key_export:
            if "key_export" in self.features and self.features["key_export"]:
                self.export(self.cconf["key_export_url"])

        if "registration" in self.features and self.features["registration"]:
            _register = True
        elif "register" in self.cconf and self.cconf["register"]:
            _register = True
        else:
            _register = False

        if _register:
            for sq in _seq:
                if sq[0].request == "RegistrationRequest":
                    _register = False
            if _register:
                _ext = self.operations_mod.PHASES["oic-registration"]
                _seq.insert(0, _ext)
                interact.append({"matches": {"class":"RegistrationRequest"},
                                 "args":{"request":self.register_args()}})
        else: # don't try to register
            for sq in _seq:
                if sq[0].request == "RegistrationRequest":
                    raise Exception("RegistrationRequest in the test should not be run")

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
            interact.append({"matches": {"class": op_spec[0].__name__},
                             "args":{"issuer":
                                         self.json_config["provider"]["dynamic"]}})

        else:
            self.trace.info("SERVER CONFIGURATION: %s" % self.pinfo)

    def export(self, server_url_pattern):
        # has to be there
        self.trace.info("EXPORT")

        part, res = key_export(server_url_pattern % self.args.host)

        for name, (url, key_specs) in res.items():
            self.cconf[name] = url
            for key, typ, usage in key_specs:
                self.client.keystore.add_key(key, typ, usage)

        if self.args.internal_server:
            self._pop = start_key_server(part)
            self.trace.info("Started key provider")
            time.sleep(1)

if __name__ == "__main__":
    from oictest import OAuth2
    from oictest import oauth2_operations
    from oic.oauth2 import Client
    from oic.oauth2 import factory

    cli = OAuth2(oauth2_operations, Client, factory)

    cli.run()