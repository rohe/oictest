import copy
from tflow import FLOWS

from testclass import PHASES

__author__ = 'roland'

PROFILEMAP = {
    "Basic": {
        "_login_": ("oic-login", {"request_args": {"response_type": ["code"]}}),
        "_accesstoken_": "access-token-request",
        "flows": [
            'OP-A-01', 'OP-A-02',
            'OP-B-01s', 'OP-B-02', 'OP-B-03', 'OP-B-04', 'OP-B-05', 'OP-B-06',
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
    "Implicit": {
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
    "Hybrid": {
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
    "Extra": {
        "flows": {
            "Basic": [
                'OP-A-08',
                'OP-L-04', 'OP-L-05',
                'OP-M-09',
                'OP-N-03',
                'OP-Q-02', 'OP-Q-03', 'OP-Q-04', 'OP-Q-05', 'OP-Q-06',
                'OP-Q-07', 'OP-Q-08', 'OP-Q-09', 'OP-Q-10', 'OP-Q-11',
                'OP-Q-12'
            ],
            "Implicit": {},
            "Hybrid": {}
        }
    },
    "Discover": {
        "flow": {
            "Basic": [
                'OP-B-06',
                'OP-L-01', 'OP-L-02', 'OP-L-03',
                'OP-M-01', 'OP-M-06', 'OP-M-07', 'OP-M-08',
                'OP-N-01', 'OP-N-02',
                'OP-O-01', 'OP-O-02', 'OP-O-03'
            ],
            "Implicit": [
                'OP-B-06',
                'OP-L-01', 'OP-L-02', 'OP-L-03',
                'OP-M-01', 'OP-M-08',
                'OP-N-01',
                'OP-O-01', 'OP-O-02', 'OP-O-03'
            ],
            "Hybrid": [
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
        "Basic": (
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
        "Implicit": (
            "oic-registration",
            {"request_args": {
                "response_types": ["id_token", "id_token token"],
                # don't register any
                "token_endpoint_auth_method": [],
                "userinfo_signed_response_alg": [],
                "id_token_signed_response_alg": [],
                "request_object_signing_alg": [],
                "grant_types": ["implicit"]
            }}
        ),
        "Hybrid": (
            "oic-registration",
            {"request_args": {
                "response_types": ["code id_token", "code token",
                                   "code id_token token"],
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


def flows(specific):
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


def get_sequence(flowid, spec):
    """
    Return a sequence of request/responses that together defined the test flow.

    :param flowid: Flow id
    :param spec: dictionary
    All dynamic => {"profile": "Basic", "discover": True, "register": True}
    All static => {"profile": "Basic", "discover": False, "register": False}
    :return: list of request/responses and their arguments
    """

    _profile = spec["profile"]
    seq = []

    for op in FLOWS[flowid]["sequence"]:
        if isinstance(op, tuple):
            _op, _args = op
        else:
            _op = op
            _args = {}

        if _op == "_discover_":
            if spec["discover"]:
                _op, arg = PROFILEMAP["Discover"]["*"]
                _args = _update(_args, arg)
                seq.append((PHASES[_op], _args))
            continue

        if _op == "_register_":
            if spec["register"]:
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


if __name__ == "__main__":
    print extras()
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
