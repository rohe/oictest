import json
import argparse
import sys
from oic.utils import exception_trace
from oic.utils.authn.client import CLIENT_AUTHN_METHOD
from rrtest import Trace, FatalError

__author__ = 'rolandh'


def flow2sequence(operations, item):
    flow = operations.FLOWS[item]
    return [operations.PHASES[phase] for phase in flow["sequence"]]


class OAuth2(object):
    client_args = ["client_id", "redirect_uris", "password", "client_secret"]

    def __init__(self, operations_mod, client_class, msg_factory, chk_factory,
                 conversation_cls):
        self.operations_mod = operations_mod
        self.client_class = client_class
        self.client = None
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
        self._parser.add_argument("flow", nargs="?",
                                  help="Which test flow to run")

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
        self.json_config = self.json_config_file()

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
            info["url"] = self.test_log[-1]["url"]
            info["htmlbody"] = self.test_log[-1]["message"]

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
            self.client.state = "STATE0"

            try:
                expect_exception = flow_spec["expect_exception"]
            except KeyError:
                expect_exception = False

            conv = None
            try:
                if self.args.verbose:
                    print >> sys.stderr, "Set up done, running sequence"
                conv = self.conversation_cls(self.client, self.cconf,
                                             self.trace, interact,
                                             msg_factory=self.msg_factory,
                                             check_factory=self.chk_factory,
                                             expect_exception=expect_exception)
                conv.do_sequence(_spec)
                #testres, trace = do_sequence(oper,
                self.test_log = conv.test_output
                tsum = self.test_summation(self.args.flow)
                print >>sys.stdout, json.dumps(tsum)
                if tsum["status"] > 1 or self.args.debug:
                    print >> sys.stderr, self.trace
            except FatalError, err:
                self.test_log = conv.test_output
                tsum = self.test_summation(self.args.flow)
                print >>sys.stdout, json.dumps(tsum)
                print >> sys.stderr, self.trace
                try:
                    print >> sys.stderr, err.trace
                except AttributeError:
                    pass
                print err
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

    def do_features(self, *args):
        pass

    def export(self):
        pass

    def client_conf(self, cprop):
        if self.args.ca_certs:
            self.client = self.client_class(
                ca_certs=self.args.ca_certs,
                client_authn_method=CLIENT_AUTHN_METHOD)
        else:
            try:
                self.client = self.client_class(
                    ca_certs=self.json_config["ca_certs"])
            except (KeyError, TypeError):
                self.client = self.client_class(
                    client_authn_method=CLIENT_AUTHN_METHOD)

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
        if _h:
            self.cconf["redirect_uris"] = [p % _h for p in
                                           self.cconf["redirect_uris"]]

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
            _flow = self.args.flow
        elif self.json_config and "flow" in self.json_config:
            sequence = flow2sequence(self.operations_mod,
                                     self.json_config["flow"])
            _flow = self.json_config["flow"]
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
