import copy
from oictest.prof_util import RESPONSE, _update, REGISTER
from oictest.prof_util import DISCOVER

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
    "I": {
        "_login_": ("oic-login",
                    {"request_args": {"response_type": ["id_token"]}}),
        "_accesstoken_": None,
    },
    "IT": {
        "_login_": ("oic-login",
                    {"request_args": {"response_type": ["id_token", "token"]}}),
        "_accesstoken_": None,
    },
    "CI": {
        "_login_": ("oic-login",
                    {"request_args": {"response_type": ["code", "id_token"]}}),
        "_accesstoken_": "access-token-request",
    },
    "CT": {
        "_login_": ("oic-login",
                    {"request_args": {"response_type": ["code", "token"]}}),
        "_accesstoken_": "access-token-request",

    },
    "CIT": {
        "_login_": ("oic-login",
                    {"request_args": {
                        "response_type": ["code", "id_token", "token"]}}),
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
                "grant_types": ["authorization_code", "implicit"]
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
                "grant_types": ["authorization_code", "implicit"]
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
                "grant_types": ["authorization_code", "implicit"]
            }}
        ),
    }
}

SUBPROF = {"n": "none", "s": "sign", "e": "encrypt"}


def get_sequence(flowid, spec, flows_, profilemap, phases):
    """
    Return a sequence of request/responses that together defined the test flow.

    :param flowid: Flow id
    :param spec: string or form <response_type><discovery><registration>...
    :return: list of request/responses and their arguments
    """

    _p = spec.split('.')
    seq = []

    _profile = _p[RESPONSE]
    for op in flows_[flowid]["sequence"]:
        if isinstance(op, tuple):
            _op, _args = op
        else:
            _op = op
            _args = {}

        if _op == "_discover_":
            if _p[DISCOVER] == "T":
                _op, arg = profilemap["Discover"]["*"]
                if arg:
                    carg = copy.deepcopy(arg)
                    _args = _update(_args, carg)
                seq.append((phases[_op], _args))
            continue

        if _op == "_register_":
            if _p[REGISTER] == "T":
                _op, arg = profilemap["Register"][_profile]
                if arg:
                    carg = copy.deepcopy(arg)
                    _args = _update(_args, carg)
                seq.append((phases[_op], _args))
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
                op = profilemap[_profile][_op]
            except KeyError:
                break

        if _op is None:
            continue

        if _op == "oic-registration":  # default minimal registration info
            _, b = profilemap["Register"][_profile]
            if b:
                cb = copy.deepcopy(b)
                _args = _update(_args, cb)

        seq.append((phases[_op], _args))

    return seq
