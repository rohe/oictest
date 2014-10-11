<%!
def op_choice(base, nodes):
    """
    Creates a dropdown list of test flows
    """
    #colordict = {
    #    "OK":'<img src="static/green.png" alt="Green">',
    #    "WARNING":'<img src="static/yellow.png" alt="Yellow">',
    #    "ERROR":'<img src="static/red.png" alt="Red">',
    #    "CRITICAL":'<img src="static/red.png" alt="Red">'
    #}
    color = ['<img src="static/black.png" alt="Black">',
             '<img src="static/green.png" alt="Green">',
             '<img src="static/red.png" alt="Red">',
             '<img src="static/yellow.png" alt="Yellow">']
    element = "<ul>"
    for node in nodes:
        element += "<li>%s%s (%s) <a href='%s%s'><img src='static/run.png' alt='Start'></a>" % (
            color[node.state], node.desc, node.name, base, node.name)
    element += "</select>"
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

    <!-- Static navbar -->
    <div class="navbar navbar-default navbar-fixed-top">
        <div class="navbar-header">
          <a class="navbar-brand" href="#">oictest</a>
        </div>
    </div>

    <div class="container">
     <!-- Main component for a primary marketing message or call to action -->
      <div class="jumbotron">
        <h1>OICTEST</h1>
          <h3>Chose the next test flow you want to run from this list: </h3>
            ${op_choice(base, flows)}
      </div>

    </div> <!-- /container -->
    <!-- jQuery (necessary for Bootstrap's JavaScript plugins) -->
    <script src="/static/jquery.min.1.9.1.js"></script>
    <!-- Include all compiled plugins (below), or include individual files as needed -->
    <script src="/static/bootstrap/js/bootstrap.min.js"></script>

  </body>
</html>