import copy

from testclass import PHASES

__author__ = 'roland'

PMAP = {"C": "Basic",
        "I": "Implicit (id_token)", "IT": "Implicit (id_token+token)",
        "CI": "Hybrid (code+id_token)", "CT": "Hybrid (code+token)",
        "CIT": "Hybrid (code+id_token+token)"}

CRYPT = {"n": "none", "s": "signing", "e": "encryption"}

PROFILEMAP = {
    "C": {
        "_login_": ("oic-login", {"request_args": {"response_type": ["code"]}}),
        "_accesstoken_": "access-token-request",
    },
    "T": {
        "_login_": ("oic-login",
                    {"request_args": {"response_type": ["token"]}}),
        "_accesstoken_": None,
    },
    "Discover": {
        "*": {
            "_discover_": ("oic-discovery", {}),
            "_uma_discover_": ("uma-discovery", {})
            }
    },
    "Register": {
        "C": {
            "_register_":
                (
                    "oic-registration",
                    {"request_args": {
                        "response_types": ["code"],
                        # don't register any
                        "token_endpoint_auth_method": [],
                        "userinfo_signed_response_alg": [],
                        "id_token_signed_response_alg": [],
                        "request_object_signing_alg": [],
                        "grant_types": ["authorization_code"]
                    }}),
            "_oauth_register_":
                (
                    "oauth-registration",
                    {"request_args": {
                        "response_types": ["code"],
                        # don't register any
                        "token_endpoint_auth_method": [],
                        "userinfo_signed_response_alg": [],
                        "id_token_signed_response_alg": [],
                        "request_object_signing_alg": [],
                        "grant_types": ["authorization_code"]
                    }}),
        },
        "T": {
            "_register_": (
                "oic-registration",
                {"request_args": {
                    "response_types": ["token"],
                    # don't register any
                    "token_endpoint_auth_method": [],
                    "userinfo_signed_response_alg": [],
                    "id_token_signed_response_alg": [],
                    "request_object_signing_alg": [],
                    "grant_types": ["implicit"]
                }}),
            "_oauth_register_": (
                "oauth-registration",
                {"request_args": {
                    "response_types": ["token"],
                    # don't register any
                    "token_endpoint_auth_method": [],
                    "userinfo_signed_response_alg": [],
                    "id_token_signed_response_alg": [],
                    "request_object_signing_alg": [],
                    "grant_types": ["implicit"]
                }}),
        }
    }
}


def from_code(code):
    # Of the form <typ>.<disc>.<reg>.*['+'/'n'/'s'/'se']
    # for example:
    # C.T.T..  - code response_type, dynamic discovery & registration
    # CIT.T.F.. - response_type=["code","id_token","token"], dynamic discovery
    #           and static client registration

    p = code.split('.')

    _prof = {"profile": p[0], "discover": (p[1] == 'T'),
             "register": (p[2] == 'T'), "extra": False, "sub": None}

    if len(p) > 3:
        if '+' in p[3]:
            _prof["extra"] = True
        if 'n' in p[3]:
            _prof["sub"] = "none"
        elif 's' in p[3] and 'e' in p[3]:
            _prof["sub"] = "sign and encrypt"
        elif 's' in p[3]:
            _prof["sub"] = "sign"

    return _prof


def to_code(pdict):
    code = pdict["profile"]

    for key in ["discover", "register"]:
        if pdict[key]:
            code += ".T"
        else:
            code += ".F"

    try:
        if pdict["extra"]:
            code += ".+"
    except KeyError:
        if pdict["sub"]:
            code += ".." + pdict["sub"]
    else:
        if pdict["sub"]:
            code += "." + pdict["sub"]

    return "".join(code)


def map_prof(a, b):
    if a == b:
        return True

    # basic, implicit, hybrid
    if b[0] != "":
        if a[0] not in b[0].split(','):
            return False

    # dynamic discovery & registry
    f = True
    for n in [1, 2]:
        if b[n] != "":
            if a[n] != b[n]:
                f = False
    if not f:
        return False

    if len(a) > 3:
        if len(b) > 3:
            if b[3] != '':
                if not set(a[3]).issuperset(set(b[3])):
                    return False

    if len(b) == 5:
        if len(a) == 5:
            if a[4] != b[4]:
                return False
        elif len(a) < 5:
            return False

    return True


def flows(code, flowset):
    res = []
    p = code.split('.')

    for key, flow in flowset.items():
        sp = flow["profile"].split('.')

        if map_prof(p, sp):
            res.append(key)

    res.sort()
    return res


def _update(dic1, dic2):
    for key in ["request_args", "kw", "req_tests", "resp_tests"]:
        if key not in dic1:
            try:
                dic1[key] = dic2[key]
            except KeyError:
                pass
        elif key not in dic2:
            pass
        else:
            dic2[key].update(dic1[key])
            dic1[key] = dic2[key]

    return dic1

RESPONSE = 0
DISCOVER = 1
REGISTER = 2


def get_sequence(flowid, spec, flowset):
    """
    Return a sequence of request/responses that together defined the test flow.

    :param flowid: Flow id
    :param spec: string or form <response_type><discovery><registration>...
    :return: list of request/responses and their arguments
    """

    _p = spec.split('.')
    seq = []

    _profile = _p[RESPONSE]
    for op in flowset[flowid]["sequence"]:
        if isinstance(op, tuple):
            _op, _args = op
        else:
            _op = op
            _args = {}

        if _op in ["_discover_", "_uma_discover_"]:
            if _p[DISCOVER] == "T":
                _op, arg = PROFILEMAP["Discover"]["*"][_op]
                _args = _update(_args, arg)
                seq.append((PHASES[_op], _args))
            continue

        if _op in ["_register_", "_oauth_register_"]:
            if _p[REGISTER] == "T":
                _op, arg = PROFILEMAP["Register"][_profile][_op]
                _args = _update(_args, arg)
                seq.append((PHASES[_op], _args))
            continue

        _args = {}
        while True:
            if isinstance(op, tuple):
                _op, orig_arg = op
                args = copy.deepcopy(orig_arg)  # decouple

                if _args == {}:
                    _args = args
                else:
                    _args = _update(_args, args)
            else:
                _op = op

            try:
                op = PROFILEMAP[_profile][_op]
            except KeyError:
                break

        if _op is None:
            continue

        if _op == "oic-registration":  # default minimal registration info
            _, b = PROFILEMAP["Register"][_profile]
            _args = _update(_args, b)

        seq.append((PHASES[_op], _args))

    return seq


def extras(flowset):
    all = flowset.keys()
    for prof in ["Basic", "Implicit", "Hybrid"]:
        for _flow in PROFILEMAP[prof]["flows"]:
            if _flow in all:
                all.remove(_flow)

        for mode in ["Discover", "Register"]:
            for _flow in PROFILEMAP[mode]["flows"]:
                if _flow in all:
                    all.remove(_flow)
            try:
                for _flow in PROFILEMAP[mode]["flow"][prof]:
                    if _flow in all:
                        all.remove(_flow)
            except KeyError:
                pass

    all.sort()
    return all


if __name__ == "__main__":
    from rs_as_flow import FLOWS

    print get_sequence("OP-A-01", "C.T.F", FLOWS)

    # for fid in FLOWS.keys():
    #     print id
    #     for rt in ["C", "I", "IT", "CI", "CT", "CIT"]:
    #         for d in ["T", "F"]:
    #             for r in ["T", "F"]:
    #                 seq = ".".join([rt, d, r])
    #                 get_sequence(fid, seq)
    #                 seq += '.+'
    #                 get_sequence(fid, seq)


    # from oictest.base import Conversation
    # from testclass import Discover
    #
    # def setup():
    #     conf = importlib.import_module("localhost_basic")
    #     ots = OIDCTestSetup(conf, {}, "80")
    #     trace = Trace()
    #     client_conf = ots.config.CLIENT
    #     conv = Conversation(ots.client, client_conf, trace, None,
    #                         message_factory, check_factory)
    #     conv.cache = {}
    #     return conv
    #
    #
    # spec = {"profile": "Basic", "discover": True, "register": False}
    # _flows = flows(spec)
    # for _flow in _flows:
    #     print _flow
    #     conv = setup()
    #     conv.client.authorization_endpoint = "https://example.com/authz"
    #     conv.client.registration_endpoint = "https://example.com/reg"
    #     requests = []
    #     for item in get_sequence(_flow, spec):
    #         op, args = item
    #         (req, resp) = PHASES[op]
    #
    #         if req.request == "AuthorizationRequest":
    #             # New state for each request
    #             try:
    #                 args["request_args"].update({"state": rndstr()})
    #             except KeyError:
    #                 args["request_args"] = {"state": rndstr()}
    #         elif req.request in ["AccessTokenRequest", "UserInfoRequest",
    #                              "RefreshAccessTokenRequest"]:
    #             try:
    #                 args.update({"state": conv.AuthorizationRequest["state"]})
    #             except KeyError:
    #                 args = {"state": conv.AuthorizationRequest["state"]}
    #         else:
    #             kwargs = {}
    #
    #         _req = req(conv)
    #         if isinstance(_req, Discover):
    #             print "-- discover --"
    #         else:
    #             print _req.construct_request(conv.client, **args)
