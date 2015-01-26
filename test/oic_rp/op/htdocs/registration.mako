## index.html
<%inherit file="base.mako"/>

<%block name="script">
</%block>

<%block name="css">
    <!-- Add more css imports here! -->
    <link rel="stylesheet" type="text/css" href="/static/registration.css">
</%block>

<%block name="title">
    oictest application
</%block>

<%block name="header">
    ${parent.header()}
</%block>

<%block name="headline">
    <div ng-controller="IndexCtrl">
</%block>


<%block name="body">

    <h1>Registration</h1>
    Before running tests there are some information which should be registered.
    <hr>

    <h2>Log identifier registration</h2>
    <p>In order to get access to the logs created by the test tool you need to enter a unique identifier which should be
        added to the issuer path.</p>

    Log ID:
    <div class="row">
        <form class="col-sm-5">
                <input type="text" ng-model="log_id" ng-init="log_id=''" class="form-control col-sm-10">
        </form>
    </div>
    <button class="btn btn-default btn-sm"
            ng-click="register_rp_log_id(log_id)">
        Register log id
    </button>
    <hr>

    <h2>Generate static client credentials</h2>
    <p>If the RP in question does not support dynamic client registration please register it here in order to receive
        client_id and client_secret</p>

    <div class="row">
        <span class="col-sm-3">
            <br>
            Redirect URI's
        </span>

        <div class="col-sm-3">
            New element:
            <form>
                <div class="input-group">
                    <input type="text" ng-model="new_redirect_uri.value" class="form-control">
                    <span class="input-group-btn">
                        <button class="btn btn-default btn-sm"
                                ng-click="add_redirect_uri()">
                            Add
                        </button>
                    </span>
                </div>
            </form>
        </div>

        <div class="col-sm-3">
            Added elements:
            <form ng-repeat="uri in redirect_uris">
                <div class="input-group">
                    <input type="text" ng-model="uri.value" class="form-control">
                        <span class="input-group-btn">
                            <button class="btn btn-danger btn-sm"
                                    ng-click="remove_redirect_uri($index)">
                                X
                            </button>
                        </span>
                </div>
            </form>
        </div>

        <div class="col-sm-3">
        </div>
    </div>

    <button class="btn btn-default btn-sm"
            ng-click="generate_client_credentials()">
        Generate client credentials
    </button>

    <hr>

    <a class="btn btn-primary btn-sm" href="/test_list">
        Continue to test page
    </a>

</%block>

<%block name="footer">
    </div>

    <script type="text/javascript" src="/static/registration.js"></script>

    ${parent.footer()}
</%block>