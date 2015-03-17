## index.html
<%inherit file="base.mako"/>

<%block name="script">
</%block>

<%block name="css">
    <!-- Add more css imports here! -->
    <link rel="stylesheet" type="text/css" href="/static/registration.css">
</%block>

<%block name="title">
    OpenID Certification OP Test Tool Configuration
</%block>

<%block name="header">
    ${parent.header()}
</%block>

<%block name="headline">
    <div ng-controller="IndexCtrl">
</%block>


<%block name="body">

    <h1>Static client credentials</h1>
    <p>If the RP does not support dynamic client registration please generate static client credentials in order to
        receive a client ID and client secret.</p>

    <hr>
    <div class="row">
        <span class="col-sm-3">
            <br>
            <span class="glyphicon glyphicon-info-sign infoIcon"
                  title="Enter at least one redirect URI where the OP will send a response after completing a authorization request."
                  data-toggle="tooltip"
                  data-placement="right"
                  directive-callback="{{$last}}">
            </span>
            Redirect URI's <span class="requiredText">**</span>

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

    <div class="row">
        <span class="col-sm-3">
            <span class="glyphicon glyphicon-info-sign infoIcon"
                  title="URL for the Client's JSON Web Key Set document. If the Client signs requests to the Server,
                  it contains the signing key(s) the Server uses to validate signatures from the Client. The JWK Set MAY also
                  contain the Client's encryption keys(s), which are used by the Server to encrypt responses to the Client.
                  When both signing and encryption keys are made available, a use (Key Use) parameter value is REQUIRED
                  for all keys in the referenced JWK Set to indicate each key's intended usage."
                  data-toggle="tooltip"
                  data-placement="right"
                  directive-callback="{{$last}}">
            </span>
            jwks uri

        </span>

        <div class="col-sm-3">
            <input type="text" ng-model="jwks_uri" class="form-control">
        </div>
    </div>

    <button class="btn btn-default btn-sm"
            ng-click="generate_client_credentials()">
        Generate static client credentials
    </button>

    <hr>

    <span class="requiredText">** Required in order to generate static client credentials</span>
    <br>

    <a class="btn btn-default btn-sm"
       href="/test_list">
        Continue to test page
    </a>

</%block>

<%block name="footer">
    </div>

    <script type="text/javascript" src="/static/registration.js"></script>

    ${parent.footer()}
</%block>