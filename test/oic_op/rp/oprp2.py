#!/usr/bin/env python
import importlib
import os
from urllib import quote_plus
from urlparse import parse_qs
import argparse
import logging
import sys

from mako.lookup import TemplateLookup

from oic.oic.message import factory as message_factory

from oic.oauth2 import ResponseError
from oic.utils import exception_trace
from oic.utils.http_util import Redirect
from oic.utils.http_util import get_post
from oic.utils.http_util import BadRequest
from oictest.oprp import setup_logging
from oictest.oprp import static
from oictest.oprp import OPRP
from oictest.oprp import CRYPTSUPPORT
from oictest.oprp import post_tests

LOGGER = logging.getLogger("")

RP_ARGS = None


def application(environ, start_response):
    LOGGER.info("Connection from: %s" % environ["REMOTE_ADDR"])
    session = environ['beaker.session']

    path = environ.get('PATH_INFO', '').lstrip('/')
    LOGGER.info("path: %s" % path)

    if path == "robots.txt":
        return static(environ, start_response, "static/robots.txt")
    elif path == "favicon.ico":
        return static(environ, start_response, "static/favicon.ico")

    if path.startswith("static/"):
        return static(environ, start_response, path)

    if path.startswith("export/"):
        return static(environ, start_response, path)

    oprp = OPRP(**RP_ARGS)

    oprp.environ = environ
    oprp.start_response = start_response

    if path == "":  # list
        try:
            if oprp.session_init(session):
                return oprp.flow_list(session)
            else:
                try:
                    resp = Redirect("%sopresult#%s" % (
                        oprp.conf.BASE, session["testid"][0]))
                except KeyError:
                    return oprp.flow_list(session)
                else:
                    return resp(environ, start_response)
        except Exception as err:
            return oprp.err_response(session, "session_setup", err)
    elif path == "logs":
        return oprp.display_log("log", "log")
    elif path.startswith("log"):
        if path == "log":
            path = os.path.join(
                path, quote_plus(oprp.conf.CLIENT["srv_discovery_url"]))
            tail = path
        else:
            head, tail = os.path.split(path)
        return oprp.display_log(path, tail)
    elif "flow_names" not in session:
        oprp.session_init(session)

    if path == "reset":
        oprp.reset_session(session)
        return oprp.flow_list(session)
    elif path == "pedit":
        return oprp.profile_edit(session)
    elif path == "profile":
        info = parse_qs(get_post(environ))
        cp = session["profile"].split(".")
        cp[0] = info["rtype"][0]

        crsu = []
        for name, cs in CRYPTSUPPORT.items():
            try:
                if info[name] == ["on"]:
                    crsu.append(cs)
            except KeyError:
                pass

        if len(cp) == 3:
            if len(crsu) == 3:
                pass
            else:
                cp.append("".join(crsu))
        else:  # len >= 4
            cp[3] = "".join(crsu)

        try:
            if info["extra"] == ['on']:
                if len(cp) == 3:
                    cp.extend(["", "+"])
                elif len(cp) == 4:
                    cp.append("+")
                elif len(cp) == 5:
                    cp[4] = "+"
            else:
                if len(cp) == 5:
                    cp = cp[:-1]
        except KeyError:
            if len(cp) == 5:
                cp = cp[:-1]

        # reset all testsflows
        oprp.reset_session(session, ".".join(cp))
        return oprp.flow_list(session)
    elif path.startswith("test_info"):
        p = path.split("/")
        try:
            return oprp.test_info(p[1], session)
        except KeyError:
            return oprp.not_found()
    elif path == "continue":
        try:
            sequence_info = session["seq_info"]
        except KeyError:  # Cookie delete broke session
            query = parse_qs(environ["QUERY_STRING"])
            path = query["path"][0]
            index = int(query["index"][0])
            conv, sequence_info, ots, trace, index = oprp.session_setup(
                session, path, index)
            try:
                conv.cache_key = query["key"][0]
            except KeyError:
                pass
        except Exception as err:
            return oprp.err_response(session, "session_setup", err)
        else:
            index = session["index"]
            ots = session["ots"]
            conv = session["conv"]

        index += 1
        try:
            return oprp.run_sequence(sequence_info, session, conv, ots,
                                     conv.trace, index)
        except Exception, err:
            return oprp.err_response(session, "run_sequence", err)
    elif path == "opresult":

        try:
            conv = session["conv"]
        except KeyError as err:
            homepage = ""
            return oprp.sorry_response(homepage, err)

        return oprp.opresult(conv, session)
    # expected path format: /<testid>[/<endpoint>]
    elif path in session["flow_names"]:
        LOGGER.info("<=<=<=<=< %s >=>=>=>=>" % path)
        conv, sequence_info, ots, trace, index = oprp.session_setup(session,
                                                                    path)
        session["node"].complete = False
        try:
            return oprp.run_sequence(sequence_info, session, conv, ots,
                                     trace, index)
        except Exception as err:
            return oprp.err_response(session, "run_sequence", err)
    elif path in ["authz_cb", "authz_post"]:
        try:
            sequence_info = session["seq_info"]
            index = session["index"]
            ots = session["ots"]
            conv = session["conv"]
        except KeyError as err:
            # Todo: find out which port I'm listening on
            return oprp.sorry_response(oprp.conf.BASE, err)
        (req_c, resp_c), _ = sequence_info["sequence"][index]
        try:
            response_mode = conv.AuthorizationRequest["response_mode"]
        except KeyError:
            response_mode = None

        if path == "authz_cb":
            if response_mode == "form_post":
                pass
            elif session["response_type"] and not \
                    session["response_type"] == ["code"]:
                # but what if it's all returned as a query ?
                try:
                    qs = environ["QUERY_STRING"]
                except KeyError:
                    qs = ""
                if qs:
                    session["conv"].trace.response("QUERY_STRING:%s" % qs)
                    session["conv"].info(
                        "Didn't expect response as query parameters")

                return oprp.opresult_fragment()

        if resp_c:  # None in cases where no OIDC response is expected
            _ctype = resp_c.ctype

            # parse the response
            if response_mode == "form_post":
                info = parse_qs(get_post(environ))
                _ctype = "dict"
            elif path == "authz_post":
                query = parse_qs(get_post(environ))
                try:
                    info = query["fragment"][0]
                except KeyError:
                    return oprp.sorry_response(oprp.conf.BASE,
                                               "missing fragment ?!")
                _ctype = "urlencoded"
            elif resp_c.where == "url":
                info = environ["QUERY_STRING"]
                _ctype = "urlencoded"
            else:  # resp_c.where == "body"
                info = get_post(environ)

            LOGGER.info("Response: %s" % info)
            conv.trace.reply(info)
            resp_cls = message_factory(resp_c.response)
            algs = ots.client.sign_enc_algs("id_token")
            try:
                response = ots.client.parse_response(
                    resp_cls, info, _ctype,
                    conv.AuthorizationRequest["state"],
                    keyjar=ots.client.keyjar, algs=algs)
            except ResponseError as err:
                return oprp.err_response(session, "run_sequence", err)
            except Exception as err:
                return oprp.err_response(session, "run_sequence", err)

            LOGGER.info("Parsed response: %s" % response.to_dict())
            conv.protocol_response.append((response, info))
            conv.trace.response(response)

        try:
            post_tests(conv, req_c, resp_c)
        except Exception as err:
            return oprp.err_response(session, "post_test", err)

        index += 1
        try:
            return oprp.run_sequence(sequence_info, session, conv, ots,
                                     conv.trace, index)
        except Exception as err:
            return oprp.err_response(session, "run_sequence", err)
    else:
        resp = BadRequest()
        return resp(environ, start_response)


if __name__ == '__main__':
    from beaker.middleware import SessionMiddleware
    from cherrypy import wsgiserver

    parser = argparse.ArgumentParser()
    parser.add_argument('-m', dest='mailaddr')
    parser.add_argument('-t', dest='testflows')
    parser.add_argument('-c', dest='testclass')
    parser.add_argument('-d', dest='directory')
    parser.add_argument('-p', dest='profile')
    parser.add_argument('-P', dest='profiles')
    parser.add_argument(dest="config")
    args = parser.parse_args()

    # global ACR_VALUES
    # ACR_VALUES = CONF.ACR_VALUES

    session_opts = {
        'session.type': 'memory',
        'session.cookie_expires': True,
        'session.auto': True,
        'session.timeout': 900
    }

    sys.path.insert(0, ".")
    CONF = importlib.import_module(args.config)

    setup_logging("rp_%s.log" % CONF.PORT, LOGGER)

    try:
        if args.testflows:
            TEST_FLOWS = importlib.import_module(args.testflows)
        else:
            TEST_FLOWS = importlib.import_module("tflow")
    except ImportError as ex:
        exception_trace("importing_test_flows", ex, LOGGER)
        raise

    if args.profiles:
        PROFILES = importlib.import_module(args.profiles)
    else:
        PROFILES = importlib.import_module("profiles")

    if args.testclass:
        TEST_CLASS = importlib.import_module(args.testclass)
    else:
        from oictest import testclass as TEST_CLASS

    if args.directory:
        _dir = args.directory
        if not _dir.endswith("/"):
            _dir += "/"
    else:
        _dir = "./"

    if args.profile:
        TEST_PROFILE = args.profile
    else:
        TEST_PROFILE = "C.T.T.ns"

    LOOKUP = TemplateLookup(directories=[_dir + 'templates', _dir + 'htdocs'],
                            module_directory=_dir + 'modules',
                            input_encoding='utf-8',
                            output_encoding='utf-8')

    RP_ARGS = {"lookup": LOOKUP, "conf": CONF, "test_flows": TEST_FLOWS,
               "cache": {}, "test_profile": TEST_PROFILE, "profiles": PROFILES,
               "test_class": TEST_CLASS}

    SRV = wsgiserver.CherryPyWSGIServer(('0.0.0.0', CONF.PORT),
                                        SessionMiddleware(application,
                                                          session_opts))

    if CONF.BASE.startswith("https"):
        from cherrypy.wsgiserver import ssl_pyopenssl

        SRV.ssl_adapter = ssl_pyopenssl.pyOpenSSLAdapter(
            CONF.SERVER_CERT, CONF.SERVER_KEY, CONF.CA_BUNDLE)
        extra = " using SSL/TLS"
    else:
        extra = ""

    txt = "RP server starting listening on port:%s%s" % (CONF.PORT, extra)
    LOGGER.info(txt)
    print txt
    try:
        SRV.start()
    except KeyboardInterrupt:
        SRV.stop()
