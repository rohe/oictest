<%
    def profile_form(present):
        el = ["<h3>Chose base profile</h3>",
              '<form name="profile" action="profile" method="POST">']
        for prof in ["Basic", "Implicit", "Hybrid"]:
            if prof in present["profile"]:
                el.append('<input type="radio" name="base" value="%s" checked>%s<br>' % (prof, prof))
            else:
                el.append('<input type="radio" name="base" value="%s">%s<br>' % (prof, prof))
        el.append("<br>")
        el.append("These you can't change here:")
        el.append("<ul>")
        for mode in ["discover", "register"]:
            if present[mode]:
                el.append("<li>Dynamic %s" % mode)
            else:
                el.append("<li>Static %s" % mode)
        el.append('</ul><br><input type="checkbox" name="extra">')
        el.append('<p>Check this if you want the extra tests')
        el.append('<input type="submit" value="Continue"></p>')
        el.append('</form>')
        return "\n".join(el)
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
          <h2>Here you change the profile you are testing</h2>
          ${profile_form(profile)}
      </div>

    </div> <!-- /container -->
    <!-- jQuery (necessary for Bootstrap's JavaScript plugins) -->
    <script src="/static/jquery.min.1.9.1.js"></script>
    <!-- Include all compiled plugins (below), or include individual files as needed -->
    <script src="/static/bootstrap/js/bootstrap.min.js"></script>

  </body>
</html>