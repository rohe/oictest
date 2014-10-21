from oic.oic.provider import Provider

__author__ = 'roland'


def extract_mode(path):
    # path = <sign_alg>/<encrypt>/<errtype/<claims>/<endpoint>

    if path[0] == '/':
        path = path[1:]

    part = path.split("/", 4)

    mod = {}
    if len(part) < 4:  # might be no endpoint
        return None, path

    if part[0] != "_":
        mod["sign_alg"] = part[0]
    if part[3] != "_":
        mod["claims"] = part[3]

    if part[1] != "_":
        try:
            _enc_alg, _enc_enc = part[1].split(":")
        except ValueError:
            pass
        else:
            mod.update({"enc_alg": _enc_alg,"enc_enc": _enc_enc})

    if part[2] != "_":
        try:
            mod["err"] = part[2].split(",")
        except ValueError:
            pass

    if len(part) == 4:
        return mod, ""
    else:
        return mod, part[-1]


def mode2path(mode):
    # SHS512/A128CBC-HS256/_/normal
    noop = "_/"
    path = ""
    try:
        path += "%s/" % mode["sign_alg"]
    except KeyError:
        path += noop

    try:
        path += "%s:%s" % (mode["enc_alg"], mode["enc_enc"])
    except:
        path += noop

    try:
        path += "%s/" % ",".join(mode["err"])
    except KeyError:
        path += noop

    try:
        path += mode["claims"]
    except KeyError:
        path += "normal"

    return path


def setup_op(mode, com_args, op_arg):
    op = Provider(**com_args)

    for _authn in com_args["authn_broker"]:
        _authn.srv = op

    for key, val in op_arg.items():
        setattr(op, key, val)

    if op.baseurl.endswith("/"):
        div = ""
    else:
        div = "/"
    op.baseurl = "%s%s%s" % (op.baseurl, div, mode2path(mode))

    for _typ in ["sign_alg", "enc_alg", "enc_enc"]:
        try:
            _alg = mode[_typ]
        except KeyError:
            pass
        else:
            for obj in ["id_token", "request_object", "userinfo"]:
                op.jwx_def[_typ][obj] = _alg

    try:
        op.claims_type = mode["claims"]
    except KeyError:
        pass

    try:
        op.err_type = mode["err"]
    except KeyError:
        pass

    return op