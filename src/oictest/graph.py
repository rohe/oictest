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
        for flow in remains[:]:
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


