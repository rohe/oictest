#!/usr/bin/env python
__author__ = 'rohe0002'

import os
import urlparse
import time
import sys
import json
from subprocess import Popen
from subprocess import PIPE

from oictest.check import STATUSCODE

OICC = "oicc.py"

class Node():
    def __init__(self, name="", desc=""):
        self.name = name
        self.desc = desc
        self.children = {}
        self.parent = []
        self.state = STATUSCODE[0]

def add_to_tree(root, parents, cnode):
    to_place = parents[:]
    for parent in parents:
        if parent in root:
            root[parent].children[cnode.name] = cnode
            cnode.parent.append(root[parent])
            to_place.remove(parent)

    if to_place:
        for branch in root.values():
            if branch == {}:
                continue
            to_place = add_to_tree(branch.children, to_place, cnode)
            if not to_place:
                break

    return to_place

def in_tree(root, item):
    if not item:
        return False
    elif item in root:
        return True
    else:
        for key, branch in root.items():
            if in_tree(branch.children, item):
                return True
    return False

def sort_flows_into_graph(flows, grp):
    result = {}
    if grp:
        remains = [k for k in flows.keys() if k.startswith(grp)]
    else:
        remains = flows.keys()
    while remains:
        for flow in remains:
            spec = flows[flow]
            if "depends" in spec:
                flag = False
                for dep in spec["depends"]:
                    if in_tree(result, dep):
                        flag = True
                    else:
                        flag = False
                        break

                if flag:
                    remains.remove(flow)
                    node = Node(flow, spec["name"])
                    add_to_tree(result, spec["depends"], node)
            else:
                remains.remove(flow)
                result[flow] = Node(flow, spec["name"])

    return result

def sorted_flows(flows):
    result = []
    remains = flows.keys()
    while remains:
        for flow in remains:
            spec = flows[flow]
            if "depends" in spec:
                flag = False
                for dep in spec["depends"]:
                    if dep in result:
                        flag = True
                    else:
                        flag = False
                        break

                if flag:
                    result.append(flow)
                    remains.remove(flow)
            else:
                result.append(flow)
                remains.remove(flow)

    return result

def print_graph(root, inx=""):
    next_inx = inx + "  "
    for key, branch in root.items():
        print "%s%s" % (inx, key)
        print_graph(branch.children, next_inx)

def test(node, who):
    global OICC

    #print ">> %s" % node.name

    p1 = Popen(["./%s.py" % who], stdout=PIPE)
    cmd2 = [OICC, "-J", "-", node.name]

    p2 = Popen(cmd2, stdin=p1.stdout, stdout=PIPE, stderr=PIPE)
    p1.stdout.close()
    (p_out, p_err) = p2.communicate()

    reason = ""
    if p_out:
        try:
            output = json.loads(p_out)
        except ValueError:
            print p_out
            raise
        node.trace = output
        if output["status"] > 1:
            for test in output["tests"]:
                if test["status"] > 1:
                    try:
                        reason = test["message"]
                    except KeyError:
                        print test
            node.err = p_err
        #print output["status"]
        _sc = STATUSCODE[output["status"]]
    else:
        _sc = STATUSCODE[1]
        node.err = p_err

    node.state = _sc
    if reason:
        print "* (%s)%s - %s (%s)" % (node.name, node.desc, _sc, reason)
    else:
        print "* (%s)%s - %s" % (node.name, node.desc, _sc)

    if node.name.endswith("*"):
        time.sleep(5)

def recursively_test(node, who):
    for parent in node.parent:
        if parent.state == STATUSCODE[0]: # untested, don't go further
            print "SKIP %s Parent untested: %s" % (node.name, parent.name)
            return

    test(node, who)

    #print "node.state: %s" % node.state

    if node.state == STATUSCODE[1]:
        test_all(node.children, who)

def test_all(graph, who):
    skeys = graph.keys()
    skeys.sort()
    for key in skeys:
        recursively_test(graph[key], who)

def run_script(_ke):
    part = urlparse.urlsplit(_ke["server"])

    try:
        (host, port) = part.netloc.split(":")
    except ValueError:
        host = part.netloc
        port = 80

    popen_args = [_ke["script"]]
    popen_args.extend([host, port])
    return Popen(popen_args, stdout=PIPE, stderr=PIPE)

if __name__ == "__main__":
    from oictest.oic_operations import FLOWS

    try:
        test_group = sys.argv[2]
    except IndexError:
        test_group = None

    who = sys.argv[1]

    p1 = Popen(["./%s.py" % who], stdout=PIPE)
    _cnf = json.loads(p1.stdout.read())
    if "key_export" in _cnf["features"]:
        _pop = run_script(_cnf["features"]["key_export"])
    else:
        _pop = None

    flow_graph = sort_flows_into_graph(FLOWS, test_group)
    #print_graph(flow_graph)
    #print
    test_all(flow_graph, who)

    if _pop:
        _pop.kill()

    os.wait()