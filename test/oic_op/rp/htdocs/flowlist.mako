<%!

DESC = {
    "A": "Response Type & Response Mode",
    "B": "ID Token",
    "C": "Userinfo Endpoint",
    "D": "nonce Request Parameter",
    "E": "scope Request Parameter",
    "F": "display Request Parameter",
    "G": "prompt Request Parameter",
    "H": "Misc Request Parameters",
    "I": "OAuth behaviors",
    "J": "redirect_uri",
    "K": "Client Authentication",
    "L" : "Discovery",
    "M": "Dynamic Client Registration",
    "N": "Key Rollover",
    "O": "request_uri Request Parameter",
    "P": "request Request Parameter",
    "Q": "claims Request Parameter",
    "R": "Third Party initiated Login",
    "S": "Session Management"
    }

def op_choice(base, nodes, test_info):
    """
    Creates a list of test flows
    """
    #colordict = {
    #    "OK":'<img src="static/green.png" alt="Green">',
    #    "WARNING":'<img src="static/yellow.png" alt="Yellow">',
    #    "ERROR":'<img src="static/red.png" alt="Red">',
    #    "CRITICAL":'<img src="static/red.png" alt="Red">'
    #}
    _id = "_"
    color = ['<img src="static/black.png" alt="Black">',
             '<img src="static/green.png" alt="Green">',
             '<img src="static/yellow.png" alt="Yellow">',
             '<img src="static/red.png" alt="Red">',
             '<img src="static/greybutton" alt="Grey">',
             '<img src="static/qmark.jpg" alt="QuestionMark">']
    element = "<ul>"
    for node in nodes:
        if not node.name[3] == _id:
            _id = node.name[3]
            element += "<hr size=2><h3 id='%s'>%s</h3>" % (_id, DESC[_id])
        element += "<li><a href='%s%s'>%s</a>%s (%s) " % (base,
            node.name, color[node.state], node.desc, node.name)
        if node.profiles:
            element += "[%s]" % ",".join(node.profiles)
        if node.rmc:
            element += '<img src="static/delete-icon.png">'
        if node.experr:
            element += '<img src="static/beware.png">'
        if node.name in test_info:
            element += "<a href='%stest_info/%s'><img src='static/info32.png'></a>" % (
                base, node.name)
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
    "The test flow wasn't completed. This may have been expected or not")
    ]

def legends():
    element = "<table border='1'>"
    for icon, txt in ICONS:
        element += "<tr><td>%s</td><td>%s</td></tr>" % (icon, txt)
    element += '</table>'
    return element
%>

<!DOCTYPE html>
<html>
  <head>
    <title>pyoidc RP</title>
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
        <h1>OICTEST</h1>
          <em>Explanations of legends at end of page</em>
          <h3>Chose the next test flow you want to run from this list: </h3>
          ${op_choice(base, flows, test_info)}
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