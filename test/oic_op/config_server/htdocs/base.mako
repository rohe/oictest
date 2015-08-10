<html ng-app="main">
<head>
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <%block name="meta"/>
    <script type="text/javascript" src="https://ajax.googleapis.com/ajax/libs/angularjs/1.4.3/angular.min.js"></script>
    <script src="/_static/jquery.min.latest.js" type="text/javascript"></script>
    <script src="/_static/bootstrap/js/bootstrap.min.js" type="text/javascript"></script>
    <%block name="script"/>
    <link href="/_static/bootstrap/css/bootstrap.min.css" rel="stylesheet" media="screen">
    <link rel="stylesheet" type="text/css" href="/_static/basic.css">
    <link rel="stylesheet" type="text/css" href="/_static/toaster.css">
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

        <script src="/_static/toaster.js" type="text/javascript"></script>
        <script src="/_static/bootbox.min.js" type="text/javascript"></script>
    </%block>


</body>
</html>