#!/usr/bin/env python
from oic.oauth2 import PBase
from oic.oic import Client
from oic.utils.webfinger import WebFinger

__author__ = 'roland'


import argparse

parser = argparse.ArgumentParser()
parser.add_argument('-w', dest='webfinger')
parser.add_argument('-p', dest='providerinfo')
cargs = parser.parse_args()

issuer = ""

if cargs.webfinger:
    _httpd = PBase(verify_ssl=False)
    w = WebFinger(httpd=_httpd)
    issuer = w.discovery_query(cargs.webfinger)
    print issuer

if cargs.providerinfo:
    cli = Client(verify_ssl=False)
    if cargs.providerinfo != "-":
        issuer = cargs.providerinfo

    cli.provider_config(issuer)
    print cli.provider_info