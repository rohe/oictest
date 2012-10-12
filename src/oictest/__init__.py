#!/usr/bin/env python
__author__ = 'rohe0002'

import argparse
import sys
import json
import requests

from subprocess import Popen, PIPE

from oic.utils import exception_trace
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
    "script": "static_provider.py",
#    "server": "http://%s:8090/export" % HOST,
    "local_path": "export",
    "vault": "keys",
    "sig": {
        "alg":"rsa",
        "create_if_missing": True,
        "format": ["jwk", "x509"]
        #"name": "jwk.json",
    }
}


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
        self._parser.add_argument('-v', dest='verbose', action='store_true',
                                  help="Print runtime information")
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

        if status == 0:
            status = 1

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
            try:
                block = flow_spec["block"]
            except KeyError:
                block = {}

            self.parse_args()
            _seq = self.make_sequence()
            interact = self.get_interactions()

            try:
                self.do_features(interact, _seq, block)
            except Exception,exc:
                exception_trace("do_features", exc)
                _output = {"status": 4,
                           "tests": [{"status": 4,
                                      "message":"Couldn't run testflow: %s" % exc,
                                      "id": "verify_features",
                                      "name": "Make sure you don't do things you shouldn't"}]}
                #print >> sys.stdout, json.dumps(_output)
                return

            tests = self.get_test()
            self.client.state = "STATE0"

            self.environ.update({"provider_info": self.pinfo,
                                 "client": self.client})

            try:
                except_exception = flow_spec["except_exception"]
            except KeyError:
                except_exception = False

            try:
                if self.args.verbose:
                    print >> sys.stderr, "Set up done, running sequence"
                testres, trace = run_sequence(self.client, _seq, self.trace,
                                              interact, self.msgfactory,
                                              self.environ, tests,
                                              self.json_config["features"],
                                              self.args.verbose, self.cconf,
                                              except_exception)
                self.test_log.extend(testres)
                sum = self.test_summation(self.args.flow)
                print >>sys.stdout, json.dumps(sum)
                if sum["status"] > 1 or self.args.debug:
                    print >>sys.stderr, trace
            except Exception, err:
                print >> sys.stderr, self.trace
                print err
                exception_trace("RUN", err)

            #if self._pop is not None:
            #    self._pop.terminate()
            if "keyprovider" in self.environ and self.environ["keyprovider"]:
                # os.kill(self.environ["keyprovider"].pid, signal.SIGTERM)
                self.environ["keyprovider"].terminate()

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

    def export(self):
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

        try:
            self.client.client_prefs = self.cconf["preferences"]
        except KeyError:
            pass

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

URL_TYPES = ["jwk_url", "jwk_encryption_url", "x509_url", "x509_encryption_url"]

class OIC(OAuth2):
    client_args = ["client_id", "redirect_uris", "password", "client_secret"]

    def __init__(self, operations_mod, client_class,
                 consumer_class, msgfactory):
        OAuth2.__init__(self, operations_mod, client_class, msgfactory)

        #self._parser.add_argument('-R', dest="rsakey")
        self._parser.add_argument('-i', dest="internal_server",
                                  action='store_true',
                                  help="Whether or not an internal web server to handle key export should be forked")
        self._parser.add_argument('-e', dest="external_server",
                                  action='store_true',
                                  help="A external web server are used to handle key export")

        self.consumer_class = consumer_class

    def parse_args(self):
        OAuth2.parse_args(self)

        if self.args.external_server:
            self.environ["keyprovider"] = None

        _keystore = self.client.keystore
        pcr = ProviderConfigurationResponse()
        n = 0
        for param in URL_TYPES:
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

    def do_features(self, interact, _seq, block):
        self.cconf["_base_url"] = self.cconf["key_export_url"] % (self.args.host,)

        if "key_export" not in block:
            if "key_export" in self.features and self.features["key_export"]:
                self.export()

#        if "sector_identifier_url" in self.features and \
#            self.features["sector_identifier_url"]:
#            self.do_sector_identifier_url(self.cconf["key_export_url"])

        if "registration" not in block:
            if "registration" in self.features and self.features["registration"]:
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
                interact.append({"matches": {"class":"RegistrationRequest"},
                                 "args":{"request":self.register_args()}})
        else: # don't try to register
            for sq in _seq:
                if sq[0].request == "RegistrationRequest":
                    raise Exception("RegistrationRequest in the test should not be run")

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
                interact.append({"matches": {"class": op_spec[0].__name__},
                                 "args":{"issuer":
                                    self.json_config["provider"]["dynamic"]}})

            else:
                self.trace.info("SERVER CONFIGURATION: %s" % self.pinfo)

    def export(self):
        # has to be there
        self.trace.info("EXPORT")

        #self.cconf["_base_url"] = server_url_pattern % (self.args.host,)
        part, res = self.client.keystore.key_export(
                                        server_url_pattern % (self.args.host,),
                                        **KEY_EXPORT_ARGS)

        for name, url in res.items():
            self.cconf[name] = url

        if self.args.internal_server:
            self._pop = start_key_server(part)
            self.environ["keyprovider"] = self._pop
            self.trace.info("Started key provider")
            time.sleep(1)

if __name__ == "__main__":
    from oictest import OAuth2
    from oictest import oauth2_operations
    from oic.oauth2 import Client
    from oic.oauth2 import factory

    cli = OAuth2(oauth2_operations, Client, factory)

    cli.run()