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
    OpenID Certification OP Test Tool Configuration
</%block>

<%block name="header">
    ${parent.header()}
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <style>
        hr {border-color: #cfcfcf}
    </style>
</%block>

<%block name="headline">
    <div ng-controller="IndexCtrl">
</%block>

<%block name="body">

    <div id="content">

        <h2>OpenID Connect Provider Certification</h2>
        <br>

        <p>
            This is a tool used for testing the compliance of an OpenID Connect Provider with the
            OpenID Connect specifications. In order
            to start testing you need to configure a test instance. Enter the issuer URL to the OpenID
            Connect Provider you want to test.
        </p>
        <br>

        <form class="row"
              novalidate
              name="dynamic_disco_form">

            <span class="col-sm-3">
                Issuer URL (without .well-known):
            </span>

            <div class="col-sm-4">
                <input type="text" maxlength="200" class="form-control" ng-model="issuer" name="issuer" issuer />
            </div>

            <button class="btn btn-primary btn-sm col-sm-1"
                    ng-click="request_instance_ids(issuer)"
                    ng-disabled="dynamic_disco_form.$invalid">
                Next
            </button>

            <span ng-show="dynamic_disco_form.issuer.$error.issuer"
                  class="col-sm-3 requiredText">
                Issuer URL should not contain <i>.well-known/openid-configuration</i>
            </span>
        </form>

        <div ng-show="does_test_instances_exist()">
            <hr>
            <h2>Existing test instances</h2>

            <div class="row">
                <div class="col-sm-4">
                    <b>Instance ID</b>
                </div>

                <div class="col-sm-1">
                    <b>Port</b>
                </div>
            </div>

            <div ng-repeat="(instance_id, values) in test_instances" class="row">
                <div class="col-sm-4">
                    <input type="text" class="form-control" value="{{instance_id}}" disabled/>
                </div>

                <div class="col-sm-1">
                    <input type="text" class="form-control" value="{{values.port}}" disabled/>
                </div>

                <div class="col-sm-6">
                    <button class="btn btn-default btn-sm col-sm-3"
                            ng-click="reconfigure_test_instance(instance_id)">

                        <span class="glyphicon glyphicon-pencil"></span>
                        Reconfigure
                    </button>

                    <button class="btn btn-default btn-sm col-sm-3"
                            ng-click="request_download_config_file(instance_id)";
                            ng-disabled="!values.contains_config">

                        <span class="glyphicon glyphicon-download-alt"></span>
                        Download config
                    </button>

                   <button class="btn btn-default btn-sm col-sm-3"
                            ng-click="request_restart_test_instance(instance_id)";
                            ng-disabled="!values.contains_config">

                        <span class="glyphicon glyphicon-repeat"></span>
                        Restart
                    </button>

                    <a href={{values.url}} class="btn btn-default btn-sm col-sm-3" target="_blank">
                        Go to test instance
                        <span class="glyphicon glyphicon-arrow-right"></span>
                    </a>


                </div>
                    <span class="glyphicon glyphicon-warning-sign"
                      ng-show="!values.contains_config"
                      style="color: #d2322d"
                      title="No configuration exists for this test instance"></span>


            </div>
            <br>
        </div>


        <div ng-show="test_instances">
            <hr>
            <h3>New test instance</h3>

            <p>
                Enter a ID for the new test instance. When configured the test instance will
                appear in a list above which will contain all existing test instances. It will then
                be possible to continue using an existing test instance later on or reconfigure
                it if needed.
            </p>

            <div class="row">
                <div class="input-group col-sm-4">
                    <input type="text"
                           maxlength="200"
                           class="form-control"
                           ng-model="new_instance_id"
                           ng-disabled="reached_max_num_of_instances()">
                </div>

                <button class="btn btn-primary btn-sm col-sm-2"
                        ng-click="create_new_test_instance()"
                        ng-disabled="does_instance_id_exist(new_instance_id) ||
                                     reached_max_num_of_instances() ||
                                     new_instance_id == ''">

                    <span class="glyphicon glyphicon-file"></span>
                    Create new configurations
                </button>
            </div>

            <span class="requiredText"
                  ng-show="reached_max_num_of_instances()">
                You have reached the maximum number of test instances
            </span>

            <span class="requiredText"
                 ng-show="does_instance_id_exist(new_instance_id)">
                This instance id already exists
            </span>

        </div>
        <br>

        <div ng-show="test_instances">
            <hr>
            <h3>Upload configuration</h3>

            <div class="row">
                <span class="col-sm-4">Enter a instance ID for the new test instance</span>

                <div class="input-group col-sm-4">
                    <input type="text"
                           maxlength="200"
                           class="form-control"
                           ng-model="uploaded_instance_id"
                           ng-disabled="reached_max_num_of_instances()">
                </div>
            </div>

            <div class="row">
                <span class="col-sm-4">Select configuration file</span>
                <input type="file" name="file" id="targetFile" class="col-sm-4" onchange="angular.element(this).scope().fileNameChanged()">
            </div>

            <button class="btn btn-primary btn-sm col-sm-2"
                    ng-click="request_upload_config_file()"
                    ng-disabled="does_instance_id_exist(uploaded_instance_id) ||
                                 reached_max_num_of_instances() ||
                                 uploaded_instance_id == '' ||
                                 file_to_upload == ''">

                <span class="glyphicon glyphicon-file"></span>
                Upload configuration
            </button>


            <span class="requiredText"
                  ng-show="reached_max_num_of_instances()">
                You have reached the maximum number of test instances
            </span>

            <span class="requiredText"
                 ng-show="does_instance_id_exist(uploaded_instance_id)">
                This instance id already exists
            </span>
            <br>

            <span><b>
                NOTE: This feature only loads the uploaded configuration to the web form.
                The configuration will be stored on the server ONLY when the web form is
                submitted.
            </b></span>


        </div>

    </div>

</%block>

<%block name="footer">
    </div>

    <script type="text/javascript" src="/static/test_instance_list.js"></script>
    ${parent.footer()}
</%block>