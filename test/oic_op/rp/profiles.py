import copy
from tflow import FLOWS

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
        "flows": [
            'OP-A-01', 'OP-A-02',
            'OP-B-01s', 'OP-B-02', 'OP-B-03', 'OP-B-04', 'OP-B-05',
            'OP-C-01', 'OP-C-02', 'OP-C-03',
            'OP-D-01',
            'OP-E-01', 'OP-E-02', 'OP-E-03', 'OP-E-04', 'OP-E-05',
            'OP-F-01', 'OP-F-02',
            'OP-G-01', 'OP-G-02',
            'OP-H-01', 'OP-H-02', 'OP-H-03', 'OP-H-04', 'OP-H-05', 'OP-H-06',
            'OP-I-01', 'OP-I-02',
            'OP-J-01', 'OP-J-03',
            'OP-K-01s', 'OP-K-02s',
            'OP-O-01',
            'OP-P-01',
            'OP-Q-01'
        ],
        "sub": {
            "none": [],
            "sign": [],
            "sign_encr": []
        }
    },
    "I": {
        "_login_": ("oic-login",
                    {"request_args": {"response_type": ["id_token"]}}),
        "_accesstoken_": None,
        "flows": [
            'OP-A-02', 'OP-A-03', 'OP-A-04',
            'OP-B-01s', 'OP-B-02', 'OP-B-04', 'OP-B-07',
            'OP-C-01', 'OP-C-02', 'OP-C-03',
            'OP-D-02',
            'OP-E-01', 'OP-E-02', 'OP-E-03', 'OP-E-04', 'OP-E-05',
            'OP-F-01', 'OP-F-02',
            'OP-G-01', 'OP-G-02',
            'OP-H-01', 'OP-H-02', 'OP-H-03', 'OP-H-04', 'OP-H-05', 'OP-H-06',
            'OP-J-01', 'OP-J-03',
            'OP-O-01',
            'OP-P-01',
            'OP-Q-01'
        ]
    },
    "IT": {
        "_login_": ("oic-login",
                    {"request_args": {"response_type": ["id_token", "token"]}}),
        "_accesstoken_": None,
        "flows": [
            'OP-A-02', 'OP-A-03', 'OP-A-04',
            'OP-B-01s', 'OP-B-02', 'OP-B-04', 'OP-B-07',
            'OP-C-01', 'OP-C-02', 'OP-C-03',
            'OP-D-02',
            'OP-E-01', 'OP-E-02', 'OP-E-03', 'OP-E-04', 'OP-E-05',
            'OP-F-01', 'OP-F-02',
            'OP-G-01', 'OP-G-02',
            'OP-H-01', 'OP-H-02', 'OP-H-03', 'OP-H-04', 'OP-H-05', 'OP-H-06',
            'OP-J-01', 'OP-J-03',
            'OP-O-01',
            'OP-P-01',
            'OP-Q-01'
        ]
    },
    "CI": {
        "_login_": ("oic-login",
                    {"request_args": {"response_type": ["code", "id_token"]}}),
        "_accesstoken_": None,
        "flows": [
            'OP-A-02', 'OP-A-05', 'OP-A-06', 'OP-A-07',
            'OP-B-01s', 'OP-B-02', 'OP-B-04', 'OP-B-07', 'OP-B-08',
            'OP-C-01', 'OP-C-02', 'OP-C-03',
            'OP-D-02',
            'OP-E-01', 'OP-E-02', 'OP-E-03', 'OP-E-04', 'OP-E-05',
            'OP-F-01', 'OP-F-02',
            'OP-G-01', 'OP-G-02',
            'OP-H-01', 'OP-H-02', 'OP-H-03', 'OP-H-04', 'OP-H-05', 'OP-H-06',
            'OP-I-01', 'OP-I-02',
            'OP-J-01', 'OP-J-03',
            'OP-O-01',
            'OP-P-01',
            'OP-Q-01'
        ]
    },
    "CT": {
        "_login_": ("oic-login",
                    {"request_args": {"response_type": ["code", "token"]}}),
        "_accesstoken_": None,
        "flows": [
            'OP-A-02', 'OP-A-05', 'OP-A-06', 'OP-A-07',
            'OP-B-01s', 'OP-B-02', 'OP-B-04', 'OP-B-07',
            'OP-C-01', 'OP-C-02', 'OP-C-03',
            'OP-D-02',
            'OP-E-01', 'OP-E-02', 'OP-E-03', 'OP-E-04', 'OP-E-05',
            'OP-F-01', 'OP-F-02',
            'OP-G-01', 'OP-G-02',
            'OP-H-01', 'OP-H-02', 'OP-H-03', 'OP-H-04', 'OP-H-05', 'OP-H-06',
            'OP-I-01', 'OP-I-02',
            'OP-J-01', 'OP-J-03',
            'OP-O-01',
            'OP-P-01',
            'OP-Q-01'
        ]
    },
    "CIT": {
        "_login_": ("oic-login",
                    {"request_args": {
                        "response_type": ["code", "id_token", "token"]}}),
        "_accesstoken_": None,
        "flows": [
            'OP-A-02', 'OP-A-05', 'OP-A-06', 'OP-A-07',
            'OP-B-01s', 'OP-B-02', 'OP-B-04', 'OP-B-07', 'OP-B-08',
            'OP-C-01', 'OP-C-02', 'OP-C-03',
            'OP-D-02',
            'OP-E-01', 'OP-E-02', 'OP-E-03', 'OP-E-04', 'OP-E-05',
            'OP-F-01', 'OP-F-02',
            'OP-G-01', 'OP-G-02',
            'OP-H-01', 'OP-H-02', 'OP-H-03', 'OP-H-04', 'OP-H-05', 'OP-H-06',
            'OP-I-01', 'OP-I-02',
            'OP-J-01', 'OP-J-03',
            'OP-O-01',
            'OP-P-01',
            'OP-Q-01'
        ]
    },
    "Extra": {
        "flows": {
            "C": [
                'OP-A-08',
                'OP-L-04', 'OP-L-05',
                'OP-M-09',
                'OP-N-03',
                'OP-Q-02', 'OP-Q-03', 'OP-Q-04', 'OP-Q-05', 'OP-Q-06',
                'OP-Q-07', 'OP-Q-08', 'OP-Q-09', 'OP-Q-10', 'OP-Q-11',
                'OP-Q-12'
            ],
            "I": {},
            "IT": {},
            "CI": {},
            "CT": {},
            "CIT": {}
        }
    },
    "Discover": {
        "flow": {
            "C": [
                'OP-B-06',
                'OP-L-01', 'OP-L-02', 'OP-L-03',
                'OP-M-01', 'OP-M-06', 'OP-M-07', 'OP-M-08',
                'OP-N-01', 'OP-N-02',
                'OP-O-01', 'OP-O-02', 'OP-O-03'
            ],
            "I": [
                'OP-B-06',
                'OP-L-01', 'OP-L-02', 'OP-L-03',
                'OP-M-01', 'OP-M-08',
                'OP-N-01',
                'OP-O-01', 'OP-O-02', 'OP-O-03'
            ],
            "IT": [
                'OP-B-06',
                'OP-L-01', 'OP-L-02', 'OP-L-03',
                'OP-M-01', 'OP-M-08',
                'OP-N-01',
                'OP-O-01', 'OP-O-02', 'OP-O-03'
            ],
            "CI": [
                'OP-B-06',
                'OP-L-01', 'OP-L-02', 'OP-L-03',
                'OP-M-01', 'OP-M-06', 'OP-M-07', 'OP-M-08',
                'OP-N-01', 'OP-N-02',
                'OP-O-01', 'OP-O-02', 'OP-O-03'
            ],
            "CT": [
                'OP-B-06',
                'OP-L-01', 'OP-L-02', 'OP-L-03',
                'OP-M-01', 'OP-M-06', 'OP-M-07', 'OP-M-08',
                'OP-N-01', 'OP-N-02',
                'OP-O-01', 'OP-O-02', 'OP-O-03'
            ],
            "CIT": [
                'OP-B-06',
                'OP-L-01', 'OP-L-02', 'OP-L-03',
                'OP-M-01', 'OP-M-06', 'OP-M-07', 'OP-M-08',
                'OP-N-01', 'OP-N-02',
                'OP-O-01', 'OP-O-02', 'OP-O-03'
            ],
        },
        "flows": [
            'OP-B-06',
            'OP-L-01', 'OP-L-02', 'OP-L-03',
            'OP-M-01', 'OP-M-06', 'OP-M-07', 'OP-M-08',
            'OP-N-01', 'OP-N-02',
            'OP-O-01', 'OP-O-02', 'OP-O-03'
        ],
        "*": ("provider-discovery", {})
    },
    "Register": {
        "flows": [
            'OP-B-01d', 'OP-B-06',
            'OP-C-04',
            'OP-J-02', 'OP-J-04', 'OP-J-05', 'OP-J-06', 'OP-J-07',
            'OP-K-01d', 'OP-K-02d',
            'OP-L-01', 'OP-L-02', 'OP-L-03',
            'OP-M-03', 'OP-M-04', 'OP-M-05',
            'OP-N-01',
            'OP-P-02',
        ],
        "extras": {
            'OP-C-05', 'OP-C-06',
            'OP-K-03', 'OP-K-04',
            'OP-M-10', 'OP-M-11', 'OP-M-12',
            'OP-N-04',
            'OP-O-04', 'OP-O-05',
            'OP-P-03',
        },
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
        "I": (
            "oic-registration",
            {"request_args": {
                "response_types": ["id_token"],
                # don't register any
                "token_endpoint_auth_method": [],
                "userinfo_signed_response_alg": [],
                "id_token_signed_response_alg": [],
                "request_object_signing_alg": [],
                "grant_types": ["implicit"]
            }}
        ),
        "IT": (
            "oic-registration",
            {"request_args": {
                "response_types": ["id_token token"],
                # don't register any
                "token_endpoint_auth_method": [],
                "userinfo_signed_response_alg": [],
                "id_token_signed_response_alg": [],
                "request_object_signing_alg": [],
                "grant_types": ["implicit"]
            }}
        ),
        "CI": (
            "oic-registration",
            {"request_args": {
                "response_types": ["code id_token"],
                # don't register any
                "token_endpoint_auth_method": [],
                "userinfo_signed_response_alg": [],
                "id_token_signed_response_alg": [],
                "request_object_signing_alg": [],
                "grant_types": []
            }}
        ),
        "CT": (
            "oic-registration",
            {"request_args": {
                "response_types": ["code token"],
                # don't register any
                "token_endpoint_auth_method": [],
                "userinfo_signed_response_alg": [],
                "id_token_signed_response_alg": [],
                "request_object_signing_alg": [],
                "grant_types": []
            }}
        ),
        "CIT": (
            "oic-registration",
            {"request_args": {
                "response_types": ["code id_token token"],
                # don't register any
                "token_endpoint_auth_method": [],
                "userinfo_signed_response_alg": [],
                "id_token_signed_response_alg": [],
                "request_object_signing_alg": [],
                "grant_types": []
            }}
        ),
    }
}

SUBPROF = {"n": "none", "s": "sign", "b": "sign and encrypt"}


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


def flows(code):
    res = []
    p = code.split('.')

    for key, flow in FLOWS.items():
        sp = flow["profile"].split('.')

        # basic, implicit, hybrid
        if sp[0] != "":
            if p[0] not in sp[0].split(','):
                continue

        # dynamic discovery & registry
        f = True
        for n in [1, 2]:
            if sp[n] != "":
                if p[n] != sp[n]:
                    f = False
        if not f:
            continue

        if len(p) > 3:
            if len(sp) > 3:
                if sp[3] != '':
                    if set(p) != set(sp):
                        continue

        if len(sp) == 5:
            if len(p) == 5:
                if p[4] != sp[4]:
                    continue
            elif len(p) < 5:
                continue

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


def get_sequence(flowid, spec):
    """
    Return a sequence of request/responses that together defined the test flow.

    :param flowid: Flow id
    :param spec: string or form <response_type><discovery><registration>...
    :return: list of request/responses and their arguments
    """

    _p = spec.split('.')
    seq = []

    _profile = _p[RESPONSE]
    for op in FLOWS[flowid]["sequence"]:
        if isinstance(op, tuple):
            _op, _args = op
        else:
            _op = op
            _args = {}

        if _op == "_discover_":
            if _p[DISCOVER] == "T":
                _op, arg = PROFILEMAP["Discover"]["*"]
                _args = _update(_args, arg)
                seq.append((PHASES[_op], _args))
            continue

        if _op == "_register_":
            if _p[REGISTER] == "T":
                _op, arg = PROFILEMAP["Register"][_profile]
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


def extras():
    all = FLOWS.keys()
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


def test_1():
    for example in ["C.T.F", "C.T.T..+", "IT.T.F.n", "CIT.T.F.se.+"]:
        print example
        p = from_code(example)
        l1 = flows_old(p)
        l2 = flows(example)

        try:
            assert l1 == l2
        except AssertionError:
            ls1 = set(l1)
            ls2 = set(l2)
            a = list(ls1.difference(ls2))
            a.sort()
            print a
            b = list(ls2.difference(ls1))
            b.sort()
            print b


if __name__ == "__main__":

    print get_sequence("OP-A-01", "C.T.F")

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
