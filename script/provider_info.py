#!/usr/bin/env python
__author__ = 'rohe0002'

import sys
from oic.oic.consumer import Consumer

principal = sys.argv[1]

if principal[0] in ["@", "=", "!"]:
    print "Not supported"
    sys.exit()

if "@" in principal:
    idtype = "mail"
else:
    idtype = "url"

client = Consumer(None, None)
issuer = client.discover(principal, idtype)

print "ISSUER: %s" % issuer

pcr = client.provider_config(issuer)
print pcr.to_dict()