#!/usr/bin/env python
from oic.oauth2 import rndstr
from oic.oic import Client
from oictest.mode import mode2path

__author__ = 'roland'


def do_flow(iss, cinfo, mode, flow, static=None):
    """

    :param iss:
    :param cinfo:
    :param mode:
    :param flow:
    :return:
    """

    cli = Client()
    for arg, val in cinfo.items():
        setattr(cli, arg, val)

    _path = mode2path(mode)
    if iss.endswith("/"):
        url = "%s%s" % (iss, _path)
    else:
        url = "%s/%s" % (iss, _path)

    pcr = {}

    for action, args in flow:
        if action == "discover":
            if args:
                issuer = cli.discover(args)
            else:
                issuer = cli.discover(url)
        elif action == "provider_info":
            if not issuer:
                issuer = url
            pcr = cli.provider_config(issuer)
        elif action == "registration":
            try:
                _endp = pcr["registration_endpoint"]
            except KeyError:
                _endp = static["registration_endpoint"]
            _ = cli.register(_endp)
        elif action == "authn_req":
            state = rndstr()
            resp = cli.do_authorization_request(
                state=state, request_args=args)
            print resp
        elif action == "token_req":
            pass
        elif action == "userinfo_req":
            pass

    return

if __name__ == "__main__":
    c_info = {
        "redirect_uris": ["https://localhost:8090/authz_cb"],
        "application_type": "web",
        "contact": ["foo@example.com"]
    }

    op = "https://localhost:8080"

    mode_ = {}

    # --------------------------------------------------------------
    # Uses WebFinger Discovery, principal as URL
    #flow = [("discover", None)]

    #do_flow(op, c_info, mode_, flow)

    # --------------------------------------------------------------
    # Uses WebFinger Discovery, principal as email
    # flow = [("discover", "acct:local@localhost:8080")]
    #
    # do_flow(op, c_info, mode_, flow)

    # --------------------------------------------------------------
    # Dynamic provider discovery
    # flow = [("discover", None), ("provider_info", None)]
    #
    # do_flow(op, c_info, mode_, flow)

    # --------------------------------------------------------------
    # Dynamic registration
    flow = [("discover", None), ("provider_info", None),
            ("registration", None)]

    do_flow(op, c_info, mode_, flow)

    # --------------------------------------------------------------
    # Can Make Request with 'code' Response Type
    flow = [("discover", None), ("provider_info", None),
            ("registration", None),
            ("authn_req", {"scope": "openid", "response_type": ["code"]})]

    do_flow(op, c_info, mode_, flow)

