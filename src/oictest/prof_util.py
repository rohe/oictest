import copy

__author__ = 'roland'


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


def flows(code, ordered_list, flows_):
    res = []
    p = code.split('.')

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


def extras(flowset, profilemap):
    all = flowset.keys()
    for prof in ["Basic", "Implicit", "Hybrid"]:
        for _flow in profilemap[prof]["flows"]:
            if _flow in all:
                all.remove(_flow)

        for mode in ["Discover", "Register"]:
            for _flow in profilemap[mode]["flows"]:
                if _flow in all:
                    all.remove(_flow)
            try:
                for _flow in profilemap[mode]["flow"][prof]:
                    if _flow in all:
                        all.remove(_flow)
            except KeyError:
                pass

    all.sort()
    return all
