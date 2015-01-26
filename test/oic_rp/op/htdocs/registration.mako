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

    <h1>Static client credentials</h1>
    <p>If the RP does not support dynamic client registration please generate static client credentials in order to receive
        a client ID and client secret. Enter at least one redirect URI where the OP will send a response after
        completing a authorization request.</p>

        <hr>
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