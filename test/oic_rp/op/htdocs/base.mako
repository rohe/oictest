<html ng-app="main">
<head>
    <%block name="meta"/>
##    <script src="/_static/angular.js"></script>
    <script src="/_static/angular1.2.0.min.js"></script>
    <script src="/_static/angular-sanitize.min.js"></script>
    <script src="/_static/jquery.min.latest.js"></script>
    <script src="/_static/bootstrap/js/bootstrap.min.js"></script>
    <%block name="script"/>
    <link href="/_static/bootstrap/css/bootstrap.min.css" rel="stylesheet" media="screen">
    <link rel="stylesheet" type="text/css" href="/_static/basic.css">
    <%block name="css"/>
    <title> <%block name="title"/></title>
</head>
<body>

    <%block name="header">
        <toaster-container toaster-options="{'time-out': 6000}"></toaster-container>
        <div class="container">

        <%block name="headline"></%block>

        <div id="formContainer" class="jumbotron">
    </%block>

    ${self.body()}

    <%block name="footer">
        </div>
        </div>
        <script src="/_static/bootbox.min.js"></script>
    </%block>


</body>
</html>