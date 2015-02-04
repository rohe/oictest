## index.html
<%inherit file="base.mako"/>

<%block name="script">
    <!-- Add more script imports here! -->
    <script src="/static/bootbox.min.js" xmlns="http://www.w3.org/1999/html"></script>
</%block>

<%block name="css">
    <!-- Add more css imports here! -->
    <link rel="stylesheet" type="text/css" href="/static/op_config.css">
</%block>

<%block name="title">
    oictest application
</%block>

<%block name="header">
    ${parent.header()}
</%block>

<%block name="headline">
    <div ng-controller="IndexCtrl" data-ng-init="loadExistingConfig()">
</%block>


<%block name="body">

    <div id="content">

    <h2>
        Test tool configuration
    </h2>

    <div class="row">
        <div class="col-sm-4">
            <button class="btn btn-primary btn-sm" ng-click="createNewConfigFile();">
                <span class="glyphicon glyphicon-file"></span>
                Create new configurations
            </button>
        </div>

        <div class="col-sm-4">
            <button class="btn btn-primary btn-sm" ng-click="showModalUploadConfigWindow();">
                <span class="glyphicon glyphicon-open"></span>
                Upload configurations
            </button>
        </div>

        <div class="col-sm-4">
            <button class="btn btn-primary btn-sm" ng-click="requestDownloadConfigFile();">
                <span class="glyphicon glyphicon-download-alt"></span>
                Download configurations
            </button>
        </div>
    </div>
    <br>

    <ul class="nav nav-tabs" ng-show="opConfig">
        <li role="presentation"
            ng-class="{'active': !contains_redirect_url}">

            <a ng-click="goToPrevious()">Provider configuration</a>
        </li>

        <li role="presentation"
            ng-class="{'active': contains_redirect_url}">

            <a ng-click="getRedirectUrl()">Client configuration</a>
        </li>
    </ul>

    <!-- HIDE EVERY THING UNDER THIS LINE UNTIL DATA IS STORED IN THE SESSION -->
    <!-- ################################################################################################# -->
    <div ng-show="opConfig" class="infoBlock">
    <div ng-show="!contains_redirect_url">
        <h3>
            Provider configuration:
        </h3>

        <span>
            {{opConfig.fetchInfoFromServerDropDown.name}}
        </span>

        <select ng-model="opConfig.fetchInfoFromServerDropDown.value"
                ng-options="v.type as v.name for v in opConfig.fetchInfoFromServerDropDown.values"
                ng-change="switchBetweenProviderConfigElement();">
        </select>

        <br>

        <div class="row" ng-show="opConfig.fetchDynamicInfoFromServer.showInputField == true">
        <span class="col-sm-2">
            {{opConfig.fetchDynamicInfoFromServer.inputField.label}}
        </span>

            <form class="col-sm-5">
                <input type="text" ng-model="opConfig.fetchDynamicInfoFromServer.inputField.value" class="form-control">
            </form>
        </div>


        <button class="btn btn-default btn-sm"
                ng-click="showModalWindowAddConfigFields();"
                ng-show="opConfig.fetchStaticProviderInfo.showInputFields"
                style="margin-bottom: 20px;">
            Add static provider metadata field
        </button>

        <div ng-show="opConfig.fetchStaticProviderInfo.showInputFields">

            <div ng-repeat="inputField in opConfig.fetchStaticProviderInfo.inputFields"
                 ng-show="inputField.show == true || inputField.required == true">
                <hr>
                <div class="row">

                    <div class="col-sm-5">
                        <br>
                        <span>{{inputField.label}}</span>
                    </div>

                    <div ng-show="inputField.isList">
                        <div class="col-sm-3">
                            New element:
                            <form>
                                <div class="input-group">
                                    <input type="text" class="form-control" id="input_{{inputField.id}}">
                                <span class="input-group-btn">
                                    <button class="btn btn-default btn-sm"
                                            ng-click="addStaticProviderInfoElement(inputField.id)">
                                        Add
                                    </button>
                                </span>
                                </div>
                            </form>
                        </div>

                        <div class="col-sm-4">
                            Added elements:
                            <form ng-repeat="element in inputField.values">
                                <div class="input-group">
                                    <input type="text" ng-model="element.value" class="form-control">
                                <span class="input-group-btn">
                                    <button class="btn btn-danger btn-sm"
                                            ng-click="removeStaticProviderInfoElement($index, inputField.id)">
                                        X
                                    </button>
                                </span>
                                </div>
                            </form>
                        </div>
                    </div>

                    <div class="col-sm-3" ng-show="!inputField.isList"></div>

                    <div class="col-sm-4" ng-show="!inputField.isList">
                        <input type="text" class="form-control" ng-model="inputField.values">
                    </div>
                </div>
            </div>
        </div>

        <span class="requiredText" ng-show="opConfig.fetchStaticProviderInfo.showInputFields ||
                                        opConfig.fetchDynamicInfoFromServer.showInputField">
            * Required fields
        </span>

        <br>
        <button class="btn btn-primary btn-sm" disabled="disabled">
            Previous
        </button>

        <button class="btn btn-primary btn-sm" ng-click="getRedirectUrl()">
            Next
        </button>
    </div>

    <!-- ################################################################################################# -->
    <div ng-show="contains_redirect_url">
    <h3>
        Client configuration:
    </h3>

    <div class="row">
        <div class="col-sm-12">
            <span>
                {{opConfig.dynamicClientRegistrationDropDown.label}}
            </span>

            <select ng-model="opConfig.dynamicClientRegistrationDropDown.value"
                    ng-options="v.type as v.name for v in opConfig.dynamicClientRegistrationDropDown.values">
            </select>
        </div>
    </div>

    <div ng-show="opConfig.dynamicClientRegistrationDropDown.value == 'no'">
        <div class="row" ng-repeat="textField in opConfig.supportsStaticClientRegistrationTextFields">
            <div class="col-sm-4">
                {{textField.label}}
            </div>

            <form class="col-sm-8">
                <input type="text" ng-model="textField.textFieldContent" ng-readonly="textField.disabled"
                       class="form-control">
            </form>
        </div>
        <span class="requiredText">* Required info</span>
    </div>

    <div class="row">
        <div class="col-sm-12">
            <span>
                {{opConfig.clientSubjectType.label}}
            </span>

            <select ng-model="opConfig.clientSubjectType.value"
                    ng-options="v.type as v.name for v in opConfig.clientSubjectType.values">
            </select>
        </div>
    </div>

    <h4>
        <span class="glyphicon glyphicon-info-sign infoIcon"
          title="The request parameters are used in specific tests. The ID of the test which uses a request parameter is specified after every parameter"
          data-toggle="tooltip"
          data-placement="right"
          directive-callback=""></span>

        Test specific request parameters:
    </h4>




##    <div class="row">
##        <div class="col-sm-3">
##            <span class="glyphicon glyphicon-info-sign infoIcon"
##                  title="Sets the identifier for the target End-User that is the subject of the discovery request. For example user in the webfinger request; user@localhost:8092"
##                  data-toggle="tooltip"
##                  data-placement="right"
##                  directive-callback=""></span>
##
##            <span>Webfinger subject</span>
##        </div>
##
##        <form class="col-sm-3">
##            <input type="text" ng-model="opConfig.webfingerSubject" class="form-control">
##        </form>
##
##        <div class="col-sm-6">
##        </div>
##    </div>
##
    <div class="row">
        <div class="col-sm-3">
            <span class="glyphicon glyphicon-info-sign infoIcon"
                  title="Hint to the Authorization Server about the login identifier the End-User might use to log in (if necessary). This hint can be used by an RP if it first asks the End-User for their e-mail address (or other identifier) and then wants to pass that value as a hint to the discovered authorization service. It is RECOMMENDED that the hint value match the value used for discovery. This value MAY also be a phone number in the format specified for the phone_number Claim. The use of this parameter is left to the OP's discretion"
                  data-toggle="tooltip"
                  data-placement="right"
                  directive-callback=""></span>

            <span>Login hint (OP-H-03)</span>
        </div>

        <form class="col-sm-3">
            <input type="text" ng-model="opConfig.loginHint" class="form-control">
        </form>

        <div class="col-sm-6">
        </div>
    </div>

    ##### UI locales ######

    <div class="row">
        <span class="col-sm-3">
            <br>
            <span class="glyphicon glyphicon-info-sign infoIcon"
                  title="End-User's preferred languages and scripts for the user interface, represented as a space-separated list of BCP47 [RFC5646] language tag values, ordered by preference. For instance, the value 'fr-CA fr en' represents a preference for French as spoken in Canada, then French (without a region designation), followed by English (without a region designation). An error SHOULD NOT result if some or all of the requested locales are not supported by the OpenID Provider."
                  data-toggle="tooltip"
                  data-placement="right"
                  directive-callback=""></span>

            UI locales (OP-H-04)
        </span>

        <div class="col-sm-3">
            New element:
            <form>
                <div class="input-group">
                    <input type="text" ng-model="uiLocale.value" class="form-control">
                    <span class="input-group-btn">
                        <button class="btn btn-default btn-sm"
                                ng-click="addUiLocale()">
                            Add
                        </button>
                    </span>
                </div>
            </form>
        </div>

        <div class="col-sm-3">
            Added elements:
            <form ng-repeat="locale in opConfig.uiLocales">
                <div class="input-group">
                    <input type="text" ng-model="locale.value" class="form-control">
                        <span class="input-group-btn">
                            <button class="btn btn-danger btn-sm"
                                    ng-click="removeUiLocale($index)">
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

        <div class="col-sm-3">
            <br>
            <span class="glyphicon glyphicon-info-sign infoIcon"
                  title="End-User's preferred languages and scripts for Claims being returned, represented as a space-separated list of BCP47 [RFC5646] language tag values, ordered by preference. An error SHOULD NOT result if some or all of the requested locales are not supported by the OpenID Provider."
                  data-toggle="tooltip"
                  data-placement="right"
                  directive-callback=""></span>

            Claims locales (OP-H-05)

        </div>

        <div class="col-sm-3">
            New element:
            <form>
                <div class="input-group">
                    <input type="text" ng-model="claimLocale.value" class="form-control">
                    <span class="input-group-btn">
                        <button class="btn btn-default btn-sm"
                                ng-click="addClaimLocale()">
                            Add
                        </button>
                    </span>
                </div>
            </form>
        </div>

        <div class="col-sm-3">
            Added elements:
            <form ng-repeat="locale in opConfig.claimsLocales">
                <div class="input-group">
                    <input type="text" ng-model="locale.value" class="form-control">
                        <span class="input-group-btn">
                            <button class="btn btn-danger btn-sm"
                                    ng-click="removeClaimLocale($index)">
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
        <div class="col-sm-3">
            <br>
            <span class="glyphicon glyphicon-info-sign infoIcon"
                  title="Requested Authentication Context Class Reference values. Space-separated string that specifies the acr values that the Authorization Server is being requested to use for processing this authentication request, with the values appearing in order of preference. The Authentication Context Class satisfied by the authentication performed is returned as the acr Claim Value, as specified in Section 2.1.2.1. The acr Claim is requested as a Voluntary Claim by this parameter."
                  data-toggle="tooltip"
                  data-placement="right"
                  directive-callback=""></span>

            Acr values (OP-Q-12 & (OP-H-06?))

        </div>

        <div class="col-sm-3">
            New element:
            <form>
                <div class="input-group">
                    <input type="text" ng-model="acrValue.value" class="form-control">
                    <span class="input-group-btn">
                        <button class="btn btn-default btn-sm"
                                ng-click="addAcrValues()">
                            Add
                        </button>
                    </span>
                </div>
            </form>
        </div>

        <div class="col-sm-3">
            Added elements:
            <form ng-repeat="locale in opConfig.acrValues">
                <div class="input-group">
                    <input type="text" ng-model="locale.value" class="form-control">
                        <span class="input-group-btn">
                            <button class="btn btn-danger btn-sm"
                                    ng-click="removeAcrValues($index)">
                                X
                            </button>
                        </span>
                </div>
            </form>
        </div>

        <div class="col-sm-3">
        </div>
    </div>

    <button class="btn btn-primary btn-sm" ng-click="goToPrevious()">
        Previous
    </button>

    <button class="btn btn-primary btn-sm" ng-click="saveConfigurations()">
        Submit
    </button>

    <!-- ################################################################################################# -->
    </div>
    </div>

    <div class="modal fade" id="modalWindowAddConfigFields" tabindex="-1" role="dialog" aria-labelledby="myModalLabel"
         aria-hidden="true">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <button type="button" class="close" data-dismiss="modal" aria-hidden="true">&times;</button>
                    <h4 class="modal-title">Static metadata fields</h4>
                </div>

                Mark the fields you want to show on the config page

                <div id="advancedFieldTable">
                    <table class="table table-striped">
                        <tr ng-repeat="inputField in opConfig.fetchStaticProviderInfo.inputFields">
                            <td><input type="checkbox" ng-model="inputField.show" ng-disabled="inputField.required"></td>
                            <td>{{inputField.label}}</td>
                        <tr>
                    </table>
                </div>
            </div>
        </div>
    </div>

    <div class="modal fade" id="modalWindowUploadConfigurationFile" tabindex="-1" role="dialog"
         aria-labelledby="myModalLabel" aria-hidden="true">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <button type="button" class="close" data-dismiss="modal" aria-hidden="true">&times;</button>
                    <h4 class="modal-title">Upload configuration</h4>
                </div>
                <div class="modal-body">
                    <input type="file" name="file" id="targetFile">
                    <button class="btn btn-primary btn-sm" ng-click="requestUploadConfigFile();">Upload configurations
                    </button>
                </div>
            </div>
        </div>
    </div>

    <!-- Modal window containg iframe-->
    <div class="modal fade" id="modalWindowInteraction" tabindex="-1" role="dialog" aria-labelledby="myModalLabel"
         aria-hidden="true">
        <div class="modal-dialog">
            <div class="modal-content" id="modalWindowHTMLContent">
                <div class="modal-header">
                    <button type="button" class="close" data-dismiss="modal" aria-hidden="true">&times;</button>
                    <h4 class="modal-title">Show html dialog</h4>
                </div>
            </div>
        </div>
    </div>

</%block>

<%block name="footer">
    </div>

    <script type="text/javascript" src="/static/op_config.js"></script>
    ${parent.footer()}
</%block>