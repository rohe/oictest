import copy
from tests import FLOWS

from oictest.testclass import PHASES

__author__ = 'roland'

PMAP = {"C": "Basic"}

CRYPT = {"n": "none", "s": "signing", "e": "encryption"}

PROFILEMAP = {
    "C": {
        "_login_": ("oic-login", {"request_args": {"response_type": ["code"]}}),
        "_accesstoken_": "access-token-request",
    },
    "Discover": {
        "*": ("provider-discovery", {})
    },
    "Register": {
        "C": (
            "oic-registration",
            {"request_args": {
                "response_types": ["code"],
                # don't register any
                "token_endpoint_auth_method": [],
                "userinfo_signed_response_alg": [],
                "id_token_signed_response_alg": [],
                "request_object_signing_alg": [],
                "grant_types": ["authorization_code"]
            }}
        ),
    }
}

SUBPROF = {"n": "none", "s": "sign", "e": "encrypt"}


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


def flows_old(specific):
    """
    Return all flows that is defined for the specific profile

    :param specific: dictionary
    All dynamic => {"profile": "Basic", "discover": True, "register": True}
    All static => {"profile": "Basic", "discover": False, "register": False}
    :return:
    """
    _profile = specific["profile"]
    prelim = PROFILEMAP[_profile]["flows"]

    if specific["discover"]:
        prelim.extend(PROFILEMAP["Discover"]["flow"][_profile])

    if specific["register"]:
        prelim.extend(PROFILEMAP["Register"]["flows"])

    result = list(set(prelim))
    result.sort()
    return result


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


def flows(code, ordered_list, flows_=None):
    res = []
    p = code.split('.')

    if flows_ is None:
        flows_ = FLOWS

    for key in ordered_list:
        sp = flows_[key]["profile"].split('.')

        if map_prof(p, sp):
            res.append(key)

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


def get_sequence(flowid, spec, flows_=None):
    """
    Return a sequence of request/responses that together defined the test flow.

    :param flowid: Flow id
    :param spec: string or form <response_type><discovery><registration>...
    :return: list of request/responses and their arguments
    """

    _p = spec.split('.')
    seq = []

    if flows_ is None:
        flows_ = FLOWS

    _profile = _p[RESPONSE]
    for op in flows_[flowid]["sequence"]:
        if isinstance(op, tuple):
            _op, _args = op
        else:
            _op = op
            _args = {}

        if _op == "_discover_":
            if _p[DISCOVER] == "T":
                _op, arg = PROFILEMAP["Discover"]["*"]
                if arg:
                    carg = copy.deepcopy(arg)
                    _args = _update(_args, carg)
                seq.append((PHASES[_op], _args))
            continue

        if _op == "_register_":
            if _p[REGISTER] == "T":
                _op, arg = PROFILEMAP["Register"][_profile]
                if arg:
                    carg = copy.deepcopy(arg)
                    _args = _update(_args, carg)
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
            if b:
                cb = copy.deepcopy(b)
                _args = _update(_args, cb)

        seq.append((PHASES[_op], _args))

    return seq


def extras(flows_=None):
    if flows is None:
        all = FLOWS.keys()
    else:
        all = flows_.keys()

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

