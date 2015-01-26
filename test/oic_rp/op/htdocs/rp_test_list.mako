## index.html
<%inherit file="base.mako"/>

<%block name="script">
</%block>

<%block name="css">
    <!-- Add more css imports here! -->
    <link rel="stylesheet" type="text/css" href="/static/rp_test_list.css">
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

    <h1>RP test tool</h1>

    <!-- The code which generates the rows of the test table -->
    <div ng-repeat="(test_name, test_data) in guidlines" class="row test_row">

        <div class="col-sm-1" id="totalStatus{{data.status}}" ng-click="toggle_more_info_visibility(test_name);">
            <img src="static/pitures/arrowRight.png" ng-show="test_data.visible == false">
            <img src="static/pitures/arrowDown.png" ng-show="test_data.visible == true">

            <span><b>{{test_name}}</b></span>
        </div>

        <div class="col-sm-11" ng-click="toggle_more_info_visibility(test_name);">
            {{test_data.short_description}}
        </div>

        <br>

        <div class="resultFrame" ng-show="test_data.visible == true">
            <h3>Detailed description:</h3>
            <p ng-bind-html="test_data.detailed_description"></p>

            <b>NOTE:</b> If the RP doesn't support dynamic client registration you need to make some modifications to the tests
            <br>
            <span ng-click="toggle_static_client_registration_visibility();" class="more_info_button">
                Read more
                <img src="static/pitures/arrowRight.png" ng-show="!static_client_registration_info.visible">
                <img src="static/pitures/arrowDown.png" ng-show="static_client_registration_info.visible">
            </span>

            <p ng-bind-html="static_client_registration_info.text" ng-show="static_client_registration_info.visible" class="more_info_text"></p>

            <h3>Test setup:</h3>
            <div class="row test_setup" ng-repeat="setup_phase in test_data.test_setup">
                <p>
                    <b>{{setup_phase[0]}}</b>:
                    <ul ng-repeat="parameter in setup_phase[1]">
                        <li ng-bind-html="parameter"></li>
                    </ul>
                </p>
            </div>

            <h3>Expected result:</h3>
            <p ng-bind-html="test_data.expected_result"></p>
        </div>

    </div>

</%block>

<%block name="footer">
    </div>

    <script type="text/javascript" src="/static/rp_test_list.js"></script>

    ${parent.footer()}
</%block>