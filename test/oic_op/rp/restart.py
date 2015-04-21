#!/usr/bin/env python

import importlib
import os
import sys
import psutil
import re
from subprocess import Popen, PIPE

__author__ = 'roland'


def run_command(command, working_directory=None):
    #print command
    try:
        _ = Popen(command, stderr=PIPE, stdout=PIPE).pid
    except Exception as err:
        print err


def run_module(module):
    test_conf = importlib.import_module(module)
    conf = test_conf.CLIENT
    profile = conf["behaviour"]["profile"]
    command = ["sudo", "./oprp2.py", "-p", profile, "-t", "tflow", module]
    run_command(command, ".")


def kill_instance(module):
    for proc in psutil.process_iter():
        try:
            _lines = proc.cmdline
        except psutil.AccessDenied:
            pass
        else:
            if module in _lines:
                #print _lines
                proc.kill()
    

p = re.compile("rp_conf_[0-9]+.py$")

if sys.argv > 2:
    files = sys.argv[1:]
else:
    files = [f for f in os.listdir('.') if os.path.isfile(f)]

for module in files:
    if p.match(module):
        module = module[:-3]
        print "restarting %s" % module
        kill_instance(module)
        run_module(module)
