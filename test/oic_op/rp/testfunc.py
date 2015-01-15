import json
from urllib import urlencode
from urlparse import urlparse
from oic.oic import message
from oictest.check import get_protocol_response

__author__ = 'roland'


def get_base(cconf=None):
    """
    Make sure a '/' terminated URL is returned
    """
    try:
        part = urlparse(cconf["_base_url"])
    except KeyError:
        part = urlparse(cconf["base_url"])
    # part = urlparse(cconf["redirect_uris"][0])

    if part.path:
        if not part.path.endswith("/"):
            _path = part.path[:] + "/"
        else:
            _path = part.path[:]
    else:
        _path = "/"

    return "%s://%s%s" % (part.scheme, part.netloc, _path, )


def id_token_hint(request_args, conv, kwargs):
    item = get_protocol_response(conv, message.AccessTokenResponse)
    instance, txt = item[0]

    _inst = json.loads(txt)
    request_args["id_token_hint"] = _inst["id_token"]
    return request_args


def ui_locales(request_args, conv, kwargs):
    try:
        uil = conv.client_config["ui_locales"]
    except KeyError:
        try:
            uil = conv.client_config["locales"]
        except KeyError:
            uil = ["se"]

    request_args["ui_locales"] = uil
    return request_args


def claims_locales(request_args, conv, kwargs):
    try:
        loc = conv.client_config["claims_locales"]
    except KeyError:
        try:
            loc = conv.client_config["locales"]
        except KeyError:
            loc = ["se"]

    request_args["claims_locales"] = loc
    return request_args


def acr_value(request_args, conv, kwargs):
    try:
        acr = conv.client_config["acr_value"]
    except KeyError:
        acr = ["1"]

    request_args["acr"] = acr
    return request_args


def mismatch_return_uri(request_args, conv, kwargs):
    request_args["redirect_uri"] = "https://foo.example.se/authz_cb"
    return request_args


def _get_redirect_uris(conv):
    try:
        return conv.client_config["client_info"]["redirect_uris"]
    except KeyError:
        return conv.client_config["client_register"]["redirect_uris"]


def multiple_return_uris(request_args, conv, kwargs):
    redirects = _get_redirect_uris(conv)
    redirects.append("%scb" % get_base(conv.client_config))
    request_args["redirect_uris"] = redirects
    return request_args


def redirect_uris_with_query_component(request_args, conv, kwargs):
    ru = _get_redirect_uris(conv)[0]
    ru += "?%s" % urlencode(kwargs) 
    request_args["redirect_uris"] = ru
    return request_args


def redirect_uris_with_fragment(request_args, conv, kwargs):
    ru = _get_redirect_uris(conv)[0]
    ru += "#" + ".".join(["%s%s" % (x, y) for x,y in kwargs.items()])
    request_args["redirect_uris"] = ru
    return request_args


def redirect_uri_with_query_component(request_args, conv, kwargs):
    ru = _get_redirect_uris(conv)[0]
    ru += "?%s" % urlencode(kwargs) 
    request_args["redirect_uri"] = ru
    return request_args


# Very hard (impossible ?) to defined
# def invalid_redirect_uris(request_args, conv, kwargs):
#     request_args["redirect_uris"] = ["smtp://example.com"]
#     return request_args


def policy_uri(request_args, conv, kwargs):
    ru = _get_redirect_uris(conv)[0]
    p = urlparse(ru)

    request_args["policy_uri"] = "%s://%s/%s" % (p.scheme, p.netloc,
                                                 "static/policy.html")

    return request_args


def logo_uri(request_args, conv, kwargs):
    ru = _get_redirect_uris(conv)[0]
    p = urlparse(ru)

    request_args["logo_uri"] = "%s://%s/%s" % (p.scheme, p.netloc,
                                               "static/logo.png")

    return request_args


def tos_uri(request_args, conv, kwargs):
    ru = _get_redirect_uris(conv)[0]
    p = urlparse(ru)

    request_args["tos_uri"] = "%s://%s/%s" % (p.scheme, p.netloc,
                                              "static/tos.html")

    return request_args


def static_jwk(request_args, conv, kwargs):
    _client = conv.client
    request_args["jwks_uri"] = None
    request_args["jwks"] = {"keys": _client.keyjar.dump_issuer_keys("")}
    return request_args


def store_sector_redirect_uris(request_args, conv, kwargs):
    _base = get_base(conv.client_config)

    sector_identifier_url = "%s%s%s" % (_base, "export/", "siu.json")
    f = open("%ssiu.json" % "export/", 'w')
    if all:
        f.write(json.dumps(request_args["redirect_uris"]))
    else:
        f.write(json.dumps(request_args["redirect_uris"][:-1]))
    f.close()

    try:
        request_args["redirect_uris"].append("%s%s" % (_base, kwargs["extra"]))
    except KeyError:
        pass

    request_args["sector_identifier_uri"] = sector_identifier_url
    return request_args


def request_in_file(args, conv, kwargs):
    args["base_path"] = get_base(conv.client_config) + "export/"
    return args


def sub_claims(request_args, conv, kwargs):
    inst, txt = get_protocol_response(conv, message.AccessTokenResponse)[0]
    idt = inst["id_token"]
    _sub = idt["sub"]
    request_args["claims"] = {"id_token": {"sub": {"value": _sub}}}

    return request_args


def specific_acr_claims(request_args, conv, kwargs):
    try:
        _acrs = conv.client_config["acr_values"]
    except KeyError:
        _acrs = ["2"]

    request_args["claims"] = {"id_token": {"acr": {"values": _acrs}}}
    return request_args


def login_hint(request_args, conv, kwargs):
    try:
        hint = conv.client_config["login_hint"]
    except KeyError:
        hint = "buffy"

    request_args["login_hint"] = hint
    return request_args
