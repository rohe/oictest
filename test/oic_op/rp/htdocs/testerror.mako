<%!
def test_output(list):
    """

    """
    element = ["<h3>Test output</h3>", "<pre><code>"]
    for item in list:
        element.append("%s" % item)
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
        <h2>${exception}</h2>
        <hr>
        ${test_output(output)}
        <hr>
        ${trace_output(trace)}
    </div> <!-- /container -->
    <!-- jQuery (necessary for Bootstrap's JavaScript plugins) -->
    <script src="/static/jquery.min.1.9.1.js"></script>
    <!-- Include all compiled plugins (below), or include individual files as needed -->
    <script src="/static/bootstrap/js/bootstrap.min.js"></script>
  </body>
</html>