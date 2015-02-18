import copy
from oictest.prof_util import DISCOVER
from oictest.prof_util import REGISTER
from oictest.prof_util import RESPONSE
from oictest.prof_util import _update

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
        "_discover_": "oic-discovery",
        "_uma_discover_": "uma-discovery",
        "*": {
            "oic-discovery": {},
            "uma-discovery": {}
        }
    },
    "Register": {
        "_register_": "oic-registration",
        "_oauth_register_": "oauth-registration",
        "C": {
            "oic-registration": {
                "request_args": {
                    "response_types": ["code"],
                    # don't register any
                    "token_endpoint_auth_method": [],
                    "userinfo_signed_response_alg": [],
                    "id_token_signed_response_alg": [],
                    "request_object_signing_alg": [],
                    "grant_types": ["authorization_code"]
                }},
            "oauth-registration": {
                "request_args": {
                    "token_endpoint_auth_method": ['client_secret_basic'],
                    "response_types": ["code"],
                    # don't register any
                    "grant_types": ["authorization_code"]
                }},
        },
        "T": {
            "oic-registration":
                {"request_args": {
                    "response_types": ["token"],
                    # don't register any
                    "token_endpoint_auth_method": [],
                    "userinfo_signed_response_alg": [],
                    "id_token_signed_response_alg": [],
                    "request_object_signing_alg": [],
                    "grant_types": ["implicit"]
                }},
            "oauth-registration": {
                "request_args": {
                    "token_endpoint_auth_method": ['client_secret_basic'],
                    "response_types": ["token"],
                    # don't register any
                    "grant_types": ["implicit"]
                }},
        }
    }
}

def get_sequence(flowid, spec, flowset, profilemap, phases):
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
                _op = profilemap["Discover"][_op]
                arg = profilemap["Discover"]["*"][_op]
                _args = _update(_args, arg)
                seq.append((phases[_op], _args))
            continue

        if _op in ["_register_", "_oauth_register_"]:
            if _p[REGISTER] == "T":
                _op = profilemap["Register"][_op]
                arg = profilemap["Register"][_profile][_op]
                _args = _update(_args, arg)
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

        if _op in ["oic-registration", "oauth-registration"]:
            # default minimal registration info
            _da = profilemap["Register"][_profile][_op]
            _args = _update(_args, _da)

        seq.append((phases[_op], _args))

    return seq