#!/usr/bin/env python

import importlib
import json
import logging
import argparse
import rrtest
import time

from urlparse import urlparse
from rrtest import FatalError

from oic.oauth2 import SUCCESSFUL
from oic.oauth2 import verify_header
from oic.oauth2 import ParseError
from oic.oauth2 import ErrorResponse
from oic.oauth2 import HttpError
from oic.oauth2 import OtherError

from oic.oic import Client
from oic.utils.authn.client import CLIENT_AUTHN_METHOD
from oic.utils.authn.client import BearerHeader
from oic.utils.keyio import build_keyjar

from oictest import NotSupported
from oictest import ConfigurationError

from oictest.check import factory as check_factory
from oic.oic.message import factory as message_factory
from prof_util import map_prof

from verify import Verify

__author__ = 'roland'


logger = None


class Trace(rrtest.Trace):
    @staticmethod
    def format(resp):
        _d = {"claims": resp.to_dict()}
        if resp.jws_header:
            _d["jws header parameters"] = resp.jws_header
        if resp.jwe_header:
            _d["jwe header parameters"] = resp.jwe_header
        return _d

    def response(self, resp):
        delta = time.time() - self.start
        try:
            cl_name = resp.__class__.__name__
        except AttributeError:
            cl_name = ""

        if cl_name == "IdToken":
            txt = json.dumps({"id_token": self.format(resp)},
                             sort_keys=True, indent=2, separators=(',', ': '))
            self.trace.append("%f %s: %s" % (delta, cl_name, txt))
        else:
            try:
                dat = resp.to_dict()
            except AttributeError:
                txt = resp
                self.trace.append("%f %s" % (delta, txt))
            else:
                if cl_name == "OpenIDSchema":
                    cl_name = "UserInfo"
                    if resp.jws_header or resp.jwe_header:
                        dat = self.format(resp)
                elif "id_token" in dat:
                    dat["id_token"] = self.format(resp["id_token"])

                txt = json.dumps(dat, sort_keys=True, indent=2,
                                 separators=(',', ': '))

                self.trace.append("%f %s: %s" % (delta, cl_name, txt))


def setup_logger(log_file_name="rprp.log"):
    logger = logging.getLogger("")
    hdlr = logging.FileHandler(log_file_name)
    base_formatter = logging.Formatter(
        "%(asctime)s %(name)s:%(levelname)s %(message)s")

    hdlr.setFormatter(base_formatter)
    logger.addHandler(hdlr)
    logger.setLevel(logging.DEBUG)


def get_claims(client):
    resp = {}
    for src in client.userinfo["_claim_names"].values():
        spec = client.userinfo["_claim_sources"][src]
        ht_args = BearerHeader(client).construct(**spec)

        try:
            part = client.http_request(spec["endpoint"], "GET", **ht_args)
        except Exception:
            raise
        resp.update(json.loads(part.content))

    return resp


class Conversation(object):
    def __init__(self, flow, client, cb_uris):
        self.flow = flow
        self.client = client
        self.callback_uris = cb_uris
        self.trace = Trace()
        self.response = []
        self.last_url = ""
        self.test_id = ""
        self.info = {}

    def for_me(self, url):
        for cb in self.callback_uris:
            if url.startswith(cb):
                return True
        return False

    def intermit(self, response):
        if response.status_code >= 400:
            done = True
        else:
            done = False
    
        rdseq = []
        while not done:
            url = response.url
    
            while response.status_code in [302, 301, 303]:
                url = response.headers["location"]
                if url in rdseq:
                    raise FatalError("Loop detected in redirects")
                else:
                    rdseq.append(url)
                    if len(rdseq) > 8:
                        raise FatalError(
                            "Too long sequence of redirects: %s" % rdseq)
    
                self.trace.reply("REDIRECT TO: %s" % url)
    
                # If back to me
                if self.for_me(url):
                    done = True
                    self.response.append(response)
                    break
                else:
                    try:
                        response = self.client.send(
                            url, "GET", headers={"Referer": self.last_url})
                    except Exception, err:
                        raise FatalError("%s" % err)
    
                    content = response.text
                    self.trace.reply("CONTENT: %s" % content)
                    self.response.append(response)
    
                    if response.status_code >= 400:
                        done = True
                        break
    
            if done or url is None:
                break

            if response.status_code < 300 or response.status_code >= 400:
                break

        return response
    
    def parse_request_response(self, reqresp, response, body_type, state="",
                               **kwargs):

        text = reqresp.text
        if reqresp.status_code in SUCCESSFUL:
            body_type = verify_header(reqresp, body_type)
        elif reqresp.status_code == 302:  # redirect
            text = reqresp.headers["location"]
        elif reqresp.status_code == 500:
            logger.error("(%d) %s" % (reqresp.status_code, reqresp.text))
            raise ParseError("ERROR: Something went wrong: %s" % reqresp.text)
        elif reqresp.status_code in [400, 401]:
            #expecting an error response
            if issubclass(response, ErrorResponse):
                pass
        else:
            logger.error("(%d) %s" % (reqresp.status_code, reqresp.text))
            raise HttpError("HTTP ERROR: %s [%s] on %s" % (
                reqresp.text, reqresp.status_code, reqresp.url))

        if body_type:
            if response:
                return self.client.parse_response(response, text,
                                                  body_type, state, **kwargs)
            else:
                raise OtherError("Didn't expect a response body")
        else:
            return reqresp


def endpoint_support(client, endpoint):
    if endpoint in client.provider_info:
        return True
    else:
        return False


def run_func(spec, conv, req_args):
    if isinstance(spec, tuple):
        func, args = spec
    else:
        func = spec
        args = {}

    try:
        req_args = func(req_args, conv, args)
    except KeyError as err:
        conv.trace.error("function: %s failed" % func)
        conv.trace.error(str(err))
        raise NotSupported
    except ConfigurationError:
        raise
    else:
        return req_args


def run_flow(profiles, conv, test_id, conf, profile):
    print(20*"="+test_id+20*"=")
    conv.test_id = test_id
    conv.conf = conf

    for item in conv.flow["sequence"]:
        if isinstance(item, tuple):
            cls, funcs = item
        else:
            cls = item
            funcs = {}

        _oper = cls(conv, profile, test_id, conf, funcs)
        _oper.setup(profiles.PROFILEMAP)
        _oper()

    try:
        if conv.flow["tests"]:
            _ver = Verify(check_factory, message_factory, conv)
            _ver.test_sequence(conv.flow["tests"])
    except KeyError:
        pass
    except Exception as err:
        raise

    return None


def make_client(**kw_args):
    _cli = Client(client_authn_method=CLIENT_AUTHN_METHOD,
                  keyjar=kw_args["keyjar"])
    _cli.kid = kw_args["kidd"]
    _cli.jwks_uri = kw_args["jwks_uri"]

    try:
        _cli_info = kw_args["conf"].INFO["client"]
    except KeyError:
        pass
    else:
        for arg, val in _cli_info.items():
            setattr(_cli, arg, val)

    return _cli


def main(flows, profile, conf, profiles, **kw_args):
    f_names = flows.keys()
    f_names.sort()
    flow_names = []
    for k in kwargs["orddesc"]:
        k += '-'
        l = [z for z in f_names if z.startswith(k)]
        flow_names.extend(l)

    try:
        redirs = kw_args["cinfo"]["client"]["redirect_uris"]
    except KeyError:
        redirs = kw_args["cinfo"]["registered"]["redirect_uris"]

    sprofile = profile.split(".")
    for tid in flow_names:
        _flow = flows[tid]

        if not map_prof(sprofile, _flow["profile"].split(".")):
            continue

        _cli = make_client(**kw_args)
        conversation = Conversation(_flow, _cli, redirs)
        # noinspection PyTypeChecker
        run_flow(profiles, conversation, tid, conf, profile)
        print conversation.trace


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', dest='flows')
    parser.add_argument('-l', dest="log_name")
    parser.add_argument('-p', dest="profile")
    parser.add_argument(dest="config")
    cargs = parser.parse_args()

    FLOWS = importlib.import_module(cargs.flows)
    CONF = importlib.import_module(cargs.config)
    PROFILES = importlib.import_module("profiles")
    OPERS = importlib.import_module("oper")

    if cargs.log_name:
        setup_logger(cargs.log_name)
    else:
        setup_logger()

    # Add own keys for signing/encrypting JWTs
    try:
        jwks, keyjar, kidd = build_keyjar(CONF.keys)
    except KeyError:
        pass
    else:
        # export JWKS
        p = urlparse(CONF.KEY_EXPORT_URL)
        f = open("."+p.path, "w")
        f.write(json.dumps(jwks))
        f.close()
        jwks_uri = p.geturl()

        kwargs = {"base_url": CONF.BASE, "kidd": kidd, "keyjar": keyjar,
                  "jwks_uri": jwks_uri, "flows": FLOWS.FLOWS, "conf": CONF,
                  "cinfo": CONF.INFO,
                  "orddesc": FLOWS.ORDDESC,
                  "profiles": PROFILES, "operations": OPERS,
                  "profile": cargs.profile}

        main(**kwargs)