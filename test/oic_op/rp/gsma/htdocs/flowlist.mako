<%!

def op_choice(base, nodes, test_info, headlines):
    """
    Creates a list of test flows
    """
    #colordict = {
    #    "OK":'<img src="static/green.png" alt="Green">',
    #    "WARNING":'<img src="static/yellow.png" alt="Yellow">',
    #    "ERROR":'<img src="static/red.png" alt="Red">',
    #    "CRITICAL":'<img src="static/red.png" alt="Red">'
    #}
    _grp = "_"
    color = ['<img src="static/black.png" alt="Black">',
             '<img src="static/green.png" alt="Green">',
             '<img src="static/yellow.png" alt="Yellow">',
             '<img src="static/red.png" alt="Red">',
             '<img src="static/greybutton" alt="Grey">',
             '<img src="static/qmark.jpg" alt="QuestionMark">']
    element = "<ul>"

    for node in nodes:
        p, grp, spec = node.name.split("-", 2)
        if not grp == _grp:
            _grp = grp
            element += "<hr size=2><h3 id='%s'>%s</h3>" % (_grp, headlines[_grp])
        element += "<li><a href='%s%s'>%s</a>%s (%s) " % (base,
            node.name, color[node.state], node.desc, node.name)

        if node.rmc:
            element += '<img src="static/delete-icon.png">'
        if node.experr:
            element += '<img src="static/beware.png">'
        if node.name in test_info:
            element += "<a href='%stest_info/%s'><img src='static/info32.png'></a>" % (
                    base, node.name)
        #if node.mti == "MUST":
        #    element += '<img src="static/must.jpeg">'

    element += "</select>"
    return element
%>

<%!

ICONS = [
    ('<img src="static/beware.png">',
    "The tests should fail with an error message from the OP."),
    ('<img src="static/delete-icon.png">', "Somewhere in that flow you will be "
    "asked to remove all the cookies you have received from the OP because the "
    "test might for instance want to see the difference between two login sessions."),
    ('<img src="static/info32.png">',
    "Signals the fact that there are trace information available for the test"),
    ('<img src="static/black.png" alt="Black">',"The test has not be run"),
    ('<img src="static/green.png" alt="Green">',"Success"),
    ('<img src="static/yellow.png" alt="Yellow">',
    "Warning, something was not as expected"),
    ('<img src="static/red.png" alt="Red">',"Failed"),
    ('<img src="static/greybutton" alt="Grey">', "Based on the provider info this test will probably fail"),
    ('<img src="static/qmark.jpg" alt="QuestionMark">',
    "The test flow wasn't completed. This may have been expected or not"),
    ('<img src="static/must.jpeg">', "Mandatory to implement")
    ]

def legends():
    element = "<table border='1' id='legends'>"
    for icon, txt in ICONS:
        element += "<tr><td>%s</td><td>%s</td></tr>" % (icon, txt)
    element += '</table>'
    return element
%>

<%
    PMAP = {
        "C": "Basic (code)", "I": "Implicit (id_token)",
        "IT": "Implicit (id_token+token)",
        "CI": "Hybrid (code+id_token)", "CT": "Hybrid (code+token)",
        "CIT": "Hybrid (code+id_token+token)"
    }

    L2I = {"discovery": 1, "registration": 2}
    CM = {"n": "none", "s": "sign", "e": "encrypt"}

    def display_profile(spec):
        el = ["<p><ul>"]
        p = spec.split('.')
        el.append("<li> %s" % PMAP[p[0]])
        for mode in ["discovery", "registration"]:
            if p[L2I[mode]] == "T":
                el.append("<li> Dynamic %s" % mode)
            else:
                el.append("<li> Static %s" % mode)
        if len(p) > 3:
            if p[3]:
                el.append("<li> crypto support %s" % [CM[x] for x in p[3]])
        if len(p) == 5:
            if p[4] == '+':
                el.append("<li> extra tests")
        el.append("</ul></p>")

        return "\n".join(el)
%>

<!DOCTYPE html>
<html>
  <head>
    <title>GSMA OP Test</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <!-- Bootstrap -->
    <link href="static/bootstrap/css/bootstrap.min.css" rel="stylesheet" media="screen">
      <link href="static/style.css" rel="stylesheet" media="all">

    <!-- HTML5 shim and Respond.js IE8 support of HTML5 elements and media queries -->
    <!--[if lt IE 9]>
      <script src="../../assets/js/html5shiv.js"></script>
      <script src="../../assets/js/respond.min.js"></script>
    <![endif]-->
  </head>
  <body>
    <div class="container">
     <!-- Main component for a primary marketing message or call to action -->
      <div class="jumbotron">
        <h1>GSMA OP Test</h1>
          <em>Explanations of legends at <a href="#legends">end of page</a></em>
          <h3>Chose the next test flow you want to run from this list: </h3>
          ${op_choice(base, flows, test_info, headlines)}
          <h3>Legends</h3>
          ${legends()}
      </div>

    </div> <!-- /container -->
    <!-- jQuery (necessary for Bootstrap's JavaScript plugins) -->
    <script src="/static/jquery.min.1.9.1.js"></script>
    <!-- Include all compiled plugins (below), or include individual files as needed -->
    <script src="/static/bootstrap/js/bootstrap.min.js"></script>

  </body>
</html>
