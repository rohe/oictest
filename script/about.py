#!/usr/bin/env python
__author__ = 'rohe0002'

import sys
from oic.oic.consumer import Consumer

client = Consumer(None, None)

hosts = {"ebay":"https://openidconnect.ebay.com/",
         "edmund":"https://connect.openid4.us/",
         "gluu":"https://seed.gluu.org",
         "herokuapp":"https://alloallo.herokuapp.com/",
         "ibmau":"https://vhost0026.dc1.co.us.compute.ihost.com/",
         "kodtest":"https://www.kodtest.se:8088/",
         "orange":"http://pub-openid-int.orange.fr/",
         "ryo":"https://openidconnect.info/",
         "wenou":"https://wenou-test.wenoit.org/"}

attr = sys.argv[1]

for imp, host in hosts.items():
    try:
        pcr = client.provider_config(host)
    except Exception:
        print imp, "*failed*"
        continue

    try:
        print imp, pcr[attr]
    except KeyError:
        print imp, "-"
