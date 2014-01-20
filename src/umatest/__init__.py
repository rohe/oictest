import json
import sys

from oic.oauth2 import UnSupported
from oic.utils.authn.client import CLIENT_AUTHN_METHOD
from uma.userinfo import IdmUserInfo
from uma.json_resource_server import JsonResourceServer

from oauth2test import OAuth2
from rrtest import exception_trace, FatalError

__author__ = 'roland'


class UMA(OAuth2):
    def __init__(self, operations_mod, client_class, msgfactory, chk_factory,
                 conversation_cls):
        OAuth2.__init__(self, operations_mod, client_class, msgfactory,
                        chk_factory, conversation_cls)

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
                _ext = self.operations_mod.PHASES["registration"]
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


class UMARS(UMA):
    def __init__(self, operations_mod, client_class, msgfactory, chk_factory,
                 conversation_cls):
        OAuth2.__init__(self, operations_mod, client_class, msgfactory,
                        chk_factory, conversation_cls)

        self._parser.add_argument(
            '-a', dest="authsrv", help="The authsrv URL")

    def provider_info(self):
        return {}

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
                _ext = self.operations_mod.PHASES["registration"]
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

    def client_conf(self, cprop):
        self.cconf = self.json_config["client"]

        self.cconf["client_authn_method"] = dict([
            (s, CLIENT_AUTHN_METHOD[s]) for s in
            self.cconf["client_authn_method"]])

        self.cconf["registration_info"]["redirect_uris"] = [
            s % self.args.host for s in self.cconf["registration_info"][
                "redirect_uris"]]

        if self.json_config["dataset"][0] == "IdmUserInfo":
            _dataset = IdmUserInfo(**self.json_config["dataset"][1])
        elif self.json_config["dataset"][0] == "JsonResourceServer":
            _dataset = JsonResourceServer(**self.json_config["dataset"][1])
        else:
            _dataset = None

        # Init the resource server/client
        self.client = self.client_class(_dataset, **self.cconf)
        #baseurl=self.args.host

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
            #self.client.state = "STATE0"

            try:
                expect_exception = flow_spec["expect_exception"]
            except KeyError:
                expect_exception = False

            conv = None
            try:
                if self.pinfo:
                    self.client.provider_info = {"": self.pinfo}
                if self.args.verbose:
                    print >> sys.stderr, "Set up done, running sequence"
                try:
                    extra_args = self.json_config["extra_args"]
                except KeyError:
                    extra_args = {}
                conv = self.conversation_cls(
                    self.client, self.cconf, self.trace, interact,
                    msg_factory=self.msg_factory,
                    check_factory=self.chk_factory,
                    expect_exception=expect_exception,
                    extra_args=extra_args,
                    resource_owner=self.json_config["resource_owner"])
                try:
                    conv.ignore_check = self.json_config["ignore_check"]
                except KeyError:
                    pass

                conv.do_sequence(_spec)
                #testres, trace = do_sequence(oper,
                self.test_log = conv.test_output
                tsum = self.test_summation(self.args.flow)
                print >>sys.stdout, json.dumps(tsum)
                if tsum["status"] > 1 or self.args.debug:
                    print >> sys.stderr, self.trace
            except (FatalError, UnSupported), err:
                self.test_log = conv.test_output
                tsum = self.test_summation(self.args.flow)
                print >>sys.stdout, json.dumps(tsum)
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

