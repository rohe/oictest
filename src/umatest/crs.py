import json
import argparse
import sys
from oic.oauth2 import UnSupported
from oic.utils import exception_trace
from oic.utils.authn.client import CLIENT_AUTHN_METHOD
from oic.utils.keyio import KeyJar, KeyBundle, dump_jwks
import time
from oictest import start_key_server
from rrtest import Trace, FatalError

__author__ = 'rolandh'


def flow2sequence(operations, item):
    flow = operations.FLOWS[item]
    return [operations.PHASES[phase] for phase in flow["sequence"]]

ROLES = ["C", "RS"]


class UMACRS(object):
    client_args = ["client_id", "redirect_uris", "password", "client_secret"]

    def __init__(self, operations_mod, uma_c, uma_rs, msg_factory, chk_factory,
                 conversation_cls):
        self.operations_mod = operations_mod

        self.uma = {"C": uma_c, "RS": uma_rs}
        self.client = {}
        self.cconf = {}
        self.pinfo = {}

        self.trace = Trace()
        self.msg_factory = msg_factory
        self.chk_factory = chk_factory
        self.conversation_cls = conversation_cls

        self._parser = argparse.ArgumentParser()
        #self._parser.add_argument('-v', dest='verbose', action='store_true')
        self._parser.add_argument('-d', dest='debug', action='store_true',
                                  help="Print debug information")
        self._parser.add_argument('-v', dest='verbose', action='store_true',
                                  help="Print runtime information")
        self._parser.add_argument(
            '-C', dest="ca_certs",
            help=("CA certs to use to verify HTTPS server certificates,",
                  "if HTTPS is used and no server CA certs are defined then",
                  " no cert verification is done"))
        self._parser.add_argument('-J', dest="json_config_file",
                                  help="Script configuration")
        self._parser.add_argument(
            '-I', dest="interactions",
            help=("Extra interactions not defined in the script ",
                  "configuration file"))
        self._parser.add_argument(
            "-l", dest="list", action="store_true",
            help="List all the test flows as a JSON object")
        self._parser.add_argument(
            "-H", dest="host",
            help=("Which host the script is running on, used to construct the ",
                  "key export URL"))
        self._parser.add_argument(
            "-x", dest="not_verify_ssl", action="store_true",
            help="Don't verify SSL certificates")
        self._parser.add_argument("flow", nargs="?",
                                  help="Which test flow to run")
        self._parser.add_argument(
            '-e', dest="external_server", action='store_true',
            help="A external web server are used to handle key export")

        self.args = None
        self.sequences = []
        self.function_args = {}
        self.signing_key = None
        self.encryption_key = None
        self.test_log = []
        self.environ = {}
        self._pop = None
        self.json_config = None
        self.features = {}
        self.keysrv_running = False

    def parse_args(self):
        self.json_config = self.json_config_file()

        for role in ROLES:
            try:
                self.features[role] = self.json_config[role]["features"]
            except KeyError:
                self.features[role] = {}

            self.pinfo[role] = self.provider_info(role)

            self.cconf[role] = self.client_conf(role, self.client_args)

    def json_config_file(self):
        if self.args.json_config_file == "-":
            return json.loads(sys.stdin.read())
        else:
            return json.loads(open(self.args.json_config_file).read())

    def provider_info(self, role):
        res = {}
        try:
            _jc = self.json_config[role]["provider"]
        except KeyError:
            pass
        else:
            # Backward compatible
            if "endpoints" in _jc:
                try:
                    for endp, url in _jc["endpoints"].items():
                        res[endp] = url
                except KeyError:
                    pass

        return res

    def test_summation(self, sid):
        status = 0
        for item in self.test_log:
            if item["status"] > status:
                status = item["status"]

        if status == 0:
            status = 1

        info = {
            "id": sid,
            "status": status,
            "tests": self.test_log
        }

        if status == 5:
            for log in reversed(self.test_log):
                if log["status"] == 5:
                    info["url"] = log["url"]
                    info["htmlbody"] = log["message"]
                    break

        return info

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
            _spec = self.make_sequence()
            interact = self.get_interactions()

            try:
                self.do_features(interact, _spec["sequence"], block)
            except Exception, exc:
                exception_trace("do_features", exc)
                return

            #tests = self.get_test()
            for role in ROLES:
                self.client[role].state = "STATE0"

            try:
                expect_exception = flow_spec["expect_exception"]
            except KeyError:
                expect_exception = False

            conv = None
            try:
                # for role in ROLES:
                #     for key, val in self.pinfo[role].items():
                #         self.client[role][key].provider_info = {"": val}

                if self.args.verbose:
                    print >> sys.stderr, "Set up done, running sequence"

                args = {}
                for arg in ["extra_args", "kwargs_mod"]:
                    try:
                        args[arg] = self.json_config[arg]
                    except KeyError:
                        args[arg] = {}

                conv = self.conversation_cls(
                    self.client, self.cconf, self.trace, interact,
                    resource_owner=self.json_config["RS"]["resource_owner"],
                    requester=self.json_config["C"]["requester"],
                    msg_factory=self.msg_factory,
                    check_factory=self.chk_factory,
                    expect_exception=expect_exception, **args)
                try:
                    conv.ignore_check = self.json_config["ignore_check"]
                except KeyError:
                    pass

                conv.do_sequence(_spec)
                #testres, trace = do_sequence(oper,
                self.test_log = conv.test_output
                tsum = self.test_summation(self.args.flow)
                if tsum["status"] > 1 or self.args.debug:
                    print >> sys.stdout, json.dumps(tsum)
                    print >> sys.stderr, self.trace
            except (FatalError, UnSupported), err:
                self.test_log = conv.test_output
                tsum = self.test_summation(self.args.flow)
                print >> sys.stdout, json.dumps(tsum)
                print >> sys.stderr, self.trace
                # try:
                #     print >> sys.stderr, err.trace
                # except AttributeError:
                #     pass
                # print err
                #exception_trace("RUN", err)
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
        for key, val in self.operations_mod.FLOWS.items():
            item = {"id": key, "name": val["name"]}
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

    def _features(self, interact, _seq, block, cconf, features, jconf, pinfo,
                  client, role):
        try:
            cconf["_base_url"] = cconf["key_export_url"] % (self.args.host,)
        except KeyError:
            pass

        if "key_export" not in block:
            if "key_export" in features and features["key_export"]:
                self.export(client, cconf, role)

#        if "sector_identifier_url" in features and \
#            features["sector_identifier_url"]:
#            self.do_sector_identifier_url(self.cconf["key_export_url"])

        if "registration" not in block:
            if "registration" in features and features[
                    "registration"]:
                _register = True
            elif "register" in cconf and cconf["register"]:
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
            if "discovery" in features and features["discovery"]:
                _discover = True
            elif "dynamic" in jconf["provider"]:
                _discover = True
            else:
                _discover = False

            if _discover:
                _txt = "provider-discovery"
                _role = role.lower()
                op_spec = self.operations_mod.PHASES["%s-%s" % (_role, _txt)]
                if op_spec in _seq:
                    interact.append({
                        "matches": {"class": op_spec[0].__name__},
                        "args": {"issuer":
                                 self.json_config["provider"]["dynamic"]}})
            else:
                self.trace.info("SERVER CONFIGURATION: %s" % pinfo)

    def do_features(self, interact, _seq, block):
        for role in ROLES:
            self._features(interact[role], _seq, block,
                           self.cconf[role], self.features[role],
                           self.json_config[role], self.pinfo[role],
                           self.client[role], role)

    def export(self, client, cconf, role):
        # has to be there
        self.trace.info("EXPORT")

        if client.keyjar is None:
            client.keyjar = KeyJar()

        kbl = []
        for typ, info in cconf["keys"].items():
            kb = KeyBundle(source="file://%s" % info["key"],
                           fileformat="der", keytype=typ)
            for k in kb.keys():
                k.serialize()
            client.keyjar.add_kb("", kb)
            kbl.append(kb)

        try:
            new_name = "static/%s_jwks.json" % role
            dump_jwks(kbl, new_name)
            client.jwks_uri = "%s%s" % (cconf["_base_url"], new_name)
        except KeyError:
            pass

        if not self.args.external_server and not self.keysrv_running:
            self._pop = start_key_server(cconf["_base_url"])

            self.environ["keyprovider"] = self._pop
            self.trace.info("Started key provider")
            time.sleep(1)
            self.keysrv_running = True

    @staticmethod
    def init_dataset(conf):
        _module = __import__(conf["cls"][0], globals(), locals(),
                             [conf["cls"][1]], -1)
        ci = getattr(_module, conf["cls"][1])
        return ci(**conf["args"])

    def client_conf(self, role, cprop):
        kwargs = {"client_authn_method": CLIENT_AUTHN_METHOD}

        if self.args.ca_certs:
            kwargs["ca_certs"] = self.args.ca_certs
        elif "ca_certs" in self.json_config:
            kwargs["ca_certs"] = self.json_config["ca_certs"]

        if role == "RS":  # need dataset
            kwargs["dataset"] = self.init_dataset(
                self.json_config["RS"]["dataset"])

        self.client[role] = self.uma[role](**kwargs)

        _client = self.client[role]

        if self.args.not_verify_ssl:
            _client.verify_ssl = False
            if _client.keyjar:
                _client.keyjar.verify_ssl = False

        # set the endpoints in the Client from the provider information
        # if they are statically configured, if dynamic it happens elsewhere
        for key, val in self.pinfo[role].items():
            if key.endswith("_endpoint"):
                setattr(_client, key, val)

        try:
            for item in self.json_config[role]["deviate"]:
                _client.allow[item] = True
        except KeyError:
            pass

        # Client configuration
        _cconf = self.json_config[role]["client"]
        # replace pattern with real value
        _h = self.args.host
        if _h:
            _uris = _cconf["registration_info"]["redirect_uris"]
            _cconf["registration_info"]["redirect_uris"] = [p % _h for p in
                                                            _uris]

        try:
            _client.client_prefs = _cconf["preferences"]
        except KeyError:
            pass

        # set necessary information in the Client
        for prop in cprop:
            try:
                if prop == "client_secret":
                    _client.set_client_secret(_cconf[prop])
                else:
                    setattr(_client, prop, _cconf[prop])
            except KeyError:
                pass

        return _cconf

    def make_sequence(self):
        # Whatever is specified on the command line takes precedences
        if self.args.flow:
            sequence = flow2sequence(self.operations_mod, self.args.flow)
            _flow = self.args.flow
        else:
            sequence = None
            _flow = ""

        res = {"sequence": sequence, "tests": {"pre": [], "post": []}}

        if _flow:
            try:
                res["tests"]["post"] = self.operations_mod.FLOWS[_flow]["tests"]
            except KeyError:
                pass

        return res

    def get_interactions(self):
        interactions = {}

        if self.json_config:
            for role in ["C", "RS"]:
                try:
                    interactions[role] = self.json_config[role]["interaction"]
                except KeyError:
                    pass

        #if self.args.interactions:
        #    _int = self.args.interactions.replace("\'", '"')
        #    if interactions:
        #        interactions.update(json.loads(_int))
        #    else:
        #        interactions = json.loads(_int)

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
