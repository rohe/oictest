#!/usr/bin/env python

import json

__author__ = 'roland'

res = json.load(open("p1.json"))

PROF = [
    "code",
    "id_token", "id_token+token",
    "code+id_token", "code+token", "code+id_token+token"
]

OPCONF = ["config", "no-config"]
CLIREG = ["static", "dynamic"]

endres = {}
for iss, info in res.items():
    res = {}
    for pro, stat in info.items():
        if not stat:
            continue
        p = pro.split(".")
        red = ".".join(p[0:3])
        if red in res:
            for test, _res in stat.items():
                try:
                    _pr = res[red][test]
                except KeyError:
                    res[red][test] = _res
                else:
                    if _pr == " PASSED":
                        pass
                    elif _res == " PASSED":
                        res[red][test] = _res
                    elif _pr == " WARNING":
                        pass
                    elif _res == " WARNING":
                        res[red][test] = _res
        else:
            res[red] = stat
    endres[iss] = res

print json.dumps(endres)