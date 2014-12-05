
<%!

from rrtest.check import STATUSCODE

def test_output(out):
    """

    """
    element = ["<h3>Test output</h3>", "<pre><code>"]
    for item in out:
        if isinstance(item, tuple):
            element.append("__%s:%s__" % item)
        else:
            element.append("[%s]" % item["id"])
            element.append("\tstatus: %s" % STATUSCODE[item["status"]])
            try:
                element.append("\tdescription: %s" % (item["name"]))
            except KeyError:
                pass
            try:
                element.append("\tinfo: %s" % (item["message"]))
            except KeyError:
                pass
    element.append("</code></pre>")
    return "\n".join(element)
%>

<%!
def trace_output(trace):
    """

    """
    element = ["<h3>Trace output</h3>", "<pre><code>"]
    for item in trace:
        element.append("%s" % item)
    element.append("</code></pre>")
    return "\n".join(element)
%>

<%!
    def link(url, tag):
        return "<a href='%s'>%s</a>" % (url, tag)
%>
