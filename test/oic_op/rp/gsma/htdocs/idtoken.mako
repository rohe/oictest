<%!
    def link(url):
        return "<a href='%s'>link</a>" % url
%>

<!DOCTYPE html>

<html>
  <head>
    <title>OpenID Certification OP Test</title>
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
        <h1>IdToken</h1>
          <% alt = 0 %>
          <table border="1">
            <tr>
              <th>Claim</th><th>Value</th>
            </tr>
            % for key, val in table.items():
                <tr>
                   <% alt += 1 %>
                   <td>${key}</td>
                   <td>${val}</td>
                </tr>
            % endfor
          </table>
        <br>
        To go back click this ${link(back)}.
      </div>

    </div> <!-- /container -->
    <!-- jQuery (necessary for Bootstrap's JavaScript plugins) -->
    <script src="/static/jquery.min.1.9.1.js"></script>
    <!-- Include all compiled plugins (below), or include individual files as needed -->
    <script src="/static/bootstrap/js/bootstrap.min.js"></script>

  </body>
</html>