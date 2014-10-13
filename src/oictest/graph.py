class Node():
    def __init__(self, name, desc, rmc=False, experr=False):
        self.name = name
        self.desc = desc
        self.children = {}
        self.parent = []
        self.state = 0
        self.rmc = rmc
        self.experr = experr


def node_cmp(n1, n2):
    return cmp(n1.name, n2.name)


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
    if item in root:
        return root[item]
    else:
        for key, branch in root.items():
            _node = in_tree(branch.children, item)
            if _node:
                return _node
    return None


def _depends(flows, flow, result, remains):
    spec = flows[flow]
    _node = Node(flow, spec["name"],
                 "rm_cookie" in spec["sequence"],
                 "expect_err" in spec["sequence"])
    if "depends" in spec:
        for dep in spec["depends"]:
            _parent = in_tree(result, dep)
            if _parent:
                pass
            else:
                _parent = _depends(flows, dep, result, remains)
            _parent.children[_node.name] = _node
    else:
        result[flow] = _node  # root test

    remains.remove(flow)
    return _node


def sort_flows_into_graph(flows, grp=""):
    result = {}
    if grp:
        remains = [k for k in flows.keys() if k.startswith(grp)]
    else:
        remains = flows.keys()
    while remains:
        flow = remains[0]
        _depends(flows, flow, result, remains)

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


def flatten(root):
    """

    :param root: dictionary
    :return:
    """
    _list = []
    for key, node in root.items():
        _list.append(node)
        _list.extend(flatten(node.children))
    return _list
