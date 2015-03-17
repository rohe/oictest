## index.html
<%inherit file="base.mako"/>

<%block name="script">
</%block>

<%block name="css">
    <!-- Add more css imports here! -->
    <link rel="stylesheet" type="text/css" href="/static/rp_test_list.css">
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

    <div class="header">
        <h1>RP test tool</h1>

        Before you start testing please read the "how to use the RPtest" guide,
        <a href="https://dirg.org.umu.se/static/oictest/how_to_use_rp_test.html"
           target="_blank">
            click here to access the guide
        </a>
    </div>

    <div ng-repeat="category_list in guidlines track by $index" class="row category_row">
        <span class="category_text">{{category_list[category_const]}}</span>
        <div ng-repeat="(test_name, test_data) in category_list[test_const]" class="row test_row">
            <div class="col-sm-11" ng-click="toggle_more_info_visibility($parent.$index, test_name);">
                <img src="static/pictures/arrowRight.png" ng-show="!test_data.visible">
                <img src="static/pictures/arrowDown.png" ng-show="test_data.visible">
                {{test_data.short_description}}
            </div>

            <br>

            <div class="resultFrame" ng-show="test_data.visible">

                <table class="table table-striped">
                    <tr>
                        <td>Identifier</td>
                        <td>{{test_name}}</td>
                    </tr>
                    <tr>
                        <td>Description</td>
                        <td>
                            <p ng-bind-html="test_data.detailed_description"></p>
                        </td>
                    </tr>
                    <tr>
                        <td>Expected result:</td>
                        <td>
                            <p ng-bind-html="test_data.expected_result"></p>
                        </td>
                    </tr>
                </table>
            </div>
        </div>
    </div>

</%block>

<%block name="footer">
    </div>

    <script type="text/javascript" src="/static/rp_test_list.js"></script>

    ${parent.footer()}
</%block>