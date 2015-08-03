var app = angular.module('main', ['toaster'])

app.factory('op_configuration_factory', function ($http) {
    return {
        get_op_config: function () {
            return $http.get("/get_op_config");
        },

        request_download_config_file: function (op_configurations) {
            return $http.post("/download_config_file", {"op_configurations": op_configurations});
        },

        request_upload_config_file: function (configFileContent) {
            return $http.post("/upload_config_file", {"configFileContent": configFileContent});
        },

        create_new_config_file: function () {
            return $http.get("/create_new_config_file");
        },

        does_config_file_exist: function () {
            return $http.get("/does_op_config_exist");
        },

        start_op_tester: function (op_configurations, oprp_instance_id) {
            return $http.post("/start_op_tester", {"op_configurations": op_configurations, "oprp_instance_id": oprp_instance_id});
        },

        get_redirect_url: function (issuer, oprp_instance_id) {
            return $http.post("/get_redirect_url", {"issuer": issuer, "oprp_instance_id": oprp_instance_id});
        },

        request_instance_ids: function (opConfigurations) {
            return $http.post("/request_instance_ids", {"opConfigurations": opConfigurations});
        }
    };
});

app.controller('IndexCtrl', function ($scope, toaster, op_configuration_factory) {
    $scope.opConfig;
    $scope.contains_redirect_url = false;

    var TEST_STATUS = {
        'INFORMATION': {value: 0, string: 'INFORMATION'},
        'OK': {value: 1, string: 'OK'},
        'WARNING': {value: 2, string: 'WARNING'},
        'ERROR': {value: 3, string: 'ERROR'},
        'CRITICAL': {value: 4, string: 'CRITICAL'},
        'INTERACTION': {value: 5, string: 'INTERACTION'},
        'EMPTY_STATUS': {value: 6, string: 'EMPTY_STATUS'}
    };

    $scope.NEW_INSTANCE_ID="new";
    $scope.EXISTING_INSTANCE_ID="existing";

    $scope.instance_type = {
        value: $scope.NEW_INSTANCE_ID
    };

    $('input').attr("autocomplete", "off");
    $('form').attr("autocomplete", "off");

    /**
     * Shows the appropriate input fields depending on which value which has been selected in the
     * "fetchInfoFromServerDropDown" drop down menu
     */
    $scope.switchBetweenProviderConfigElement = function () {

        if ($scope.opConfig.fetchInfoFromServerDropDown.value == "static") {
            $scope.opConfig.fetchStaticProviderInfo.showInputFields = true;
            $scope.opConfig.fetchDynamicInfoFromServer.showInputField = false;
        }
        if ($scope.opConfig.fetchInfoFromServerDropDown.value == "dynamic") {
            $scope.opConfig.fetchDynamicInfoFromServer.showInputField = true;
            $scope.opConfig.fetchStaticProviderInfo.showInputFields = false;
        }
    };

    /**
     * Sets the configuration returned from the server
     * @param data - The result returned from the server
     * @param status - The status on the response from the server
     * @param headers - The header on the response from the server
     * @param config - The configuration on the response from the server
     */
    function get_op_configuration_success_callback(data, status, headers, config) {
        $scope.opConfig = data;
    }


    /**
     * Confirms that the configuration successfully has been retried from the server. Then is downloaded to the
     * clients computer.
     * @param data - The result returned from the server
     * @param status - The status on the response from the server
     * @param headers - The header on the response from the server
     * @param config - The configuration on the response from the server
     */
    function downloadConfigFileSuccessCallback(data, status, headers, config) {
        configDict = JSON.stringify(data["configDict"])
        var a = document.createElement("a");
        a.download = "config.json";
        a.href = "data:text/plain;base64," + btoa(configDict);

        //Appending the element a to the body is only necessary for the download to work in firefox
        document.body.appendChild(a)
        a.click();
        document.body.removeChild(a)
    }

    /**
     * Requests latest config from the server.
     */
    function requestLatestConfigFileFromServer() {
        op_configuration_factory.get_op_config().success(get_op_configuration_success_callback).error(error_callback);
    }

    /**
     * Confirms that the configuration successfully has been uploaded on the server
     * @param data - The result returned from the server
     * @param status - The status on the response from the server
     * @param headers - The header on the response from the server
     * @param config - The configuration on the response from the server
     */
    function upload_config_file_success_callback(data, status, headers, config) {
        $("#modalWindowUploadConfigurationFile").modal('toggle');
        resetGui()
        requestLatestConfigFileFromServer();
    }

    /**
     * Confirms that a new configuration successfully has been stored on the server
     * @param data - The result returned from the server
     * @param status - The status on the response from the server
     * @param headers - The header on the response from the server
     * @param config - The configuration on the response from the server
     */
    function create_new_config_file_success_callback(data, status, headers, config) {
        requestLatestConfigFileFromServer();
    }

    /**
     * Show a "No configuration is available" error dialog
     */
    function showNoConfigAvailable() {
        bootbox.alert("No configurations available. Either the session may have timed out or no configuration has be created or uploaded to the server.");
    }

    /**
     * Confirms that a there exists a configuration file on the server
     * @param data - The result returned from the server
     * @param status - The status on the response from the server
     * @param headers - The header on the response from the server
     * @param config - The configuration on the response from the server
     */
    function does_config_file_exist_success_callback(data, status, headers, config) {
        if (data['does_config_file_exist']) {
            requestLatestConfigFileFromServer();
        }
    }

    function clear_tabs(){
        $scope.provider_tab_visible = false;
        $scope.test_instance_tab_visible = false;
        $scope.client_tab_visible = false;
    }

    $scope.provider_tab_visible = true;
    $scope.test_instance_tab_visible = false;
    $scope.client_tab_visible = false;

    $scope.show_provider_config = function () {
        clear_tabs();
        $scope.provider_tab_visible = true;
    };

    $scope.show_test_instance_config = function () {
        clear_tabs();
        $scope.test_instance_tab_visible = true;
    };

    function get_instance_id(){
        if ($scope.instance_type.value == $scope.NEW_INSTANCE_ID){
            return $scope.new_instance_id
        }
        else{
            return $scope.existing_instance_ids.value
        }
    }

    $scope.show_client_config = function () {
        var instance_id = get_instance_id();
        get_redirect_url(instance_id);
        clear_tabs();
        $scope.client_tab_visible = true;
    };

    $scope.existing_instance_ids = {};
    $scope.selected_issuer = ""

    function request_instance_ids_success_callback(data, status, headers, config) {
        $scope.existing_instance_ids = data['existing_instance_ids'];
        $scope.selected_issuer = data['issuer'];
        $scope.show_test_instance_config()
    }

    $scope.request_instance_ids = function(){
        op_configuration_factory.request_instance_ids($scope.opConfig).success(request_instance_ids_success_callback).error(error_callback);
    };

    function setRedirectUrl(redirectUrl) {
        var input_fields = $scope.opConfig.supportsStaticClientRegistrationTextFields

        for (var i = 0; i < input_fields.length; i++) {
            if (input_fields[i].id == "redirect_uris") {
                input_fields[i].textFieldContent = redirectUrl;
                $scope.contains_redirect_url = true;
                break;
            }
        }
    }

    function get_redirect_url_success_callback(data, status, headers, config) {
        setRedirectUrl(data['redirect_url'])
    }

    /**
     * Confirms that a there exists a configuration file on the server. If configuration file exist then it's downloaded
     * @param data - The result returned from the server
     * @param status - The status on the response from the server
     * @param headers - The header on the response from the server
     * @param config - The configuration on the response from the server
     */
    function config_file_exist_for_download_success_callback(data, status, headers, config) {
        if (data['does_config_file_exist']) {
            op_configuration_factory.request_download_config_file($scope.opConfig).success(downloadConfigFileSuccessCallback).error(error_callback);
        } else {
            showNoConfigAvailable();
        }
    }

    /**
     * Shows error message dialog
     * @param data - The result returned from the server
     * @param status - The status on the response from the server
     * @param headers - The header on the response from the server
     * @param config - The configuration on the response from the server
     */
    function error_callback(data, status, headers, config) {
        $('#myPleaseWait').modal('hide');
        bootbox.alert(data.ExceptionMessage);
    }

    /**
     * Shows a confirmation dialog for creating a new configuration
     */
    $scope.showModalWindowAddConfigFields = function () {
        $("#modalWindowAddConfigFields").modal('toggle');
    };

    /**
     * Shows a modal dialog for uploading new configuration.
     */
    $scope.showModalUploadConfigWindow = function () {
        $("#modalWindowUploadConfigurationFile").modal('toggle');
    };

    //TODO remove function (only used for test purposes)
    $scope.test = function () {
        alert("test");
    };

    /**
     * Add new list item to a static input field.
     * @param staticInputFieldIndex - Index of a static input field
     */
    $scope.addElementToList = function (staticInputFieldIndex) {
        var currentInputField = $scope.opConfig.fetchStaticProviderInfo.input_fields[staticInputFieldIndex];
        var newConfigTextField = {"index": currentInputField.values.length, "textFieldContent": ""};
        $scope.opConfig.fetchStaticProviderInfo.input_fields[staticInputFieldIndex].values.splice(currentInputField.values.length, 0, newConfigTextField);
    };


    /**
     * Removes list item from a static input field.
     * @param staticInputFieldIndex - Index of a static input field
     * @param valueListIndex - Index of list item to remove
     */
    $scope.removeElementFromList = function (staticProviderIndex, valueListIndex) {
        var valueList = $scope.opConfig.fetchStaticProviderInfo.input_fields[staticProviderIndex].values
        valueList.splice(valueListIndex, 1);
    };

    function makeCopy(newElement) {
        var copy = {};
        jQuery.extend(true, copy, newElement);
        return copy;
    }

    $scope.subClaim = {'value': ''};

    $scope.addSubClaim = function () {
        $scope.opConfig.subClaim.splice(0, 0, makeCopy($scope.subClaim));
        $scope.subClaim = {'value': ''}
    };

    $scope.removeSubClaim = function (index) {
        $scope.opConfig.subClaim.splice(index, 1);
    };


    $scope.new_instance_id = "";

    $scope.addStaticProviderInfoElement = function (input_field_id) {
        selected_input = $('#input_' + input_field_id);

        var new_element = selected_input.val();

        var allInputFields = $scope.opConfig.fetchStaticProviderInfo.input_fields;
        for (var i = 0; i < allInputFields.length; i++) {
            if (allInputFields[i].id == input_field_id) {
                allInputFields[i].values.splice(0, 0, makeCopy({'value': new_element}));
                selected_input.val("")
            }
        }
    };

    $scope.removeStaticProviderInfoElement = function (index, input_field_id) {
        var allInputFields = $scope.opConfig.fetchStaticProviderInfo.input_fields;
        for (var i = 0; i < allInputFields.length; i++) {
            if (allInputFields[i].id == input_field_id) {
                allInputFields[i].values.splice(index, 1);
            }
        }
    };
    /**
     * Checks if the user har entered the required client id and client secret
     * @returns {boolean} - Returns true if client id and client secret input fields are not empty else false
     */
    function hasEnteredClientIdAndClientSecret() {
        clientId = $scope.opConfig['supportsStaticClientRegistrationTextFields'][1]['textFieldContent']
        clientSecret = $scope.opConfig['supportsStaticClientRegistrationTextFields'][2]['textFieldContent']

        if (clientId == "")
            return false;

        else if (clientSecret == "")
            return false;

        return true
    }

    /**
     * Checks if the user has entered all the required information.
     * @returns {boolean} - Returns true if required input fields are not empty else false
     */
    $scope.containsRequiredClientInfo = function() {
        if ($scope.opConfig['dynamicClientRegistrationDropDown']['value'] == "no") {
            if (!hasEnteredClientIdAndClientSecret()) {
                return false
            }
        }
        return true;
    }

    /**
     * Sends the configuration file to the server
     */
    $scope.saveConfigurations = function () {
        if ($scope.contains_required_provider_info() && $scope.containsRequiredClientInfo()) {
            bootbox.dialog({
                message: "The configuration information will now be stored on the server. Do you want to continue?"+
                "<br><br> Note: If the configurations are stored and the test server starts correctly you wiil be redirected to the test server.",
                title: "Save configurations",
                buttons: {
                    danger: {
                        label: "No",
                        className: "btn-default"
                    },
                    success: {
                        label: "Yes",
                        className: "btn-primary",
                        callback: function () {
                            $('#myPleaseWait').modal('show');
                            op_configuration_factory.start_op_tester($scope.opConfig, get_instance_id()).success(start_op_tester_success_callback).error(error_callback);
                            $scope.$apply();
                        }
                    }
                }
            });
        }
    };

    function start_op_tester_success_callback(data, status, headers, config) {
        $('#myPleaseWait').modal('hide');
        var info_text = "Your test instance has been successfully launched, please take note of the URL you now will " +
            "be redirected to. The test instance will be around until you tell us to remove it. Therefor the next time " +
            "you want to test you can go directly to the test instance and continue testing. No need to create a " +
            "new test instance unless you want to change from static provider configuration discovery to dynamic or " +
            "static client registration to dynamic.";

        bootbox.confirm({
            message: info_text,
            title: "Test instance successfully started",
            callback: function (clicked_ok) {
                if (clicked_ok) {
                    window.location.href = data['oprp_url'];
                }
            }
        });
    }

    /**
     * Tries to download the configuration file from the server
     */
    $scope.request_download_config_file = function () {
        op_configuration_factory.does_config_file_exist().success(config_file_exist_for_download_success_callback).error(error_callback);
    };

    /**
     * Tries to upload the configuration file to the server.
     */
    $scope.request_upload_config_file = function () {
        var file = document.getElementById("targetFile").files[0];

        if (file) {
            var reader = new FileReader();
            reader.readAsText(file, "UTF-8");
            reader.onload = function (evt) {
                op_configuration_factory.request_upload_config_file(evt.target.result).success(upload_config_file_success_callback).error(error_callback);
                $scope.$apply();
            };
            reader.onerror = function (evt) {
                alert("error reading file");
            }
        }
    };

    function resetGui() {
        $scope.new_instance_id = "";
        $scope.contains_redirect_url = false;
        $scope.show_provider_config();
    }

    /**
     * Show a "confirm that you want to create a new configuration file" dialog
     */
    $scope.create_new_config_file = function () {
        bootbox.dialog({
            message: "All your existing configurations which is not downloaded will be overwritten. Are you sure you want to create a new configuration?",
            title: "Create new file",
            buttons: {
                danger: {
                    label: "No",
                    className: "btn-default"
                },
                success: {
                    label: "Yes",
                    className: "btn-primary",
                    callback: function () {
                        resetGui();
                        op_configuration_factory.create_new_config_file().success(create_new_config_file_success_callback).error(error_callback);
                        $scope.$apply();
                    }
                }
            }
        });
    };

    $("[data-toggle='tooltip']").tooltip();

    $scope.loadExistingConfig = function () {
        op_configuration_factory.does_config_file_exist().success(does_config_file_exist_success_callback).error(error_callback);
    };

    $scope.contains_required_provider_info = function() {
        var provider_discovery = $scope.opConfig.fetchInfoFromServerDropDown.value;

        if (!$scope.opConfig || !provider_discovery){
            return false
        }

        if (provider_discovery == "dynamic") {
            var issuerUrlInputField = $scope.opConfig.fetchDynamicInfoFromServer.input_field;

            if (issuerUrlInputField.value == "") {
                return false
            }
        }
        else if (provider_discovery == "static") {
            var input_fields = $scope.opConfig.fetchStaticProviderInfo.input_fields;
            for (var i = 0; i < input_fields.length; i++) {
                var input_field_data = input_fields[i].values;
                if ((input_field_data == [] || input_field_data == "") && input_fields[i].required) {
                    return false;
                }
            }
        }

        return true
    }

    function get_issuer() {
        var fetchingProviderConfig = $scope.opConfig.fetchInfoFromServerDropDown.value;
        var issuer = "";

        if (fetchingProviderConfig == "dynamic") {
            issuer = $scope.opConfig.fetchDynamicInfoFromServer.input_field.value;
        }
        else if (fetchingProviderConfig == "static") {
            var input_fields = $scope.opConfig.fetchStaticProviderInfo.input_fields;
            for (var i = 0; i < input_fields.length; i++) {
                if (input_fields[i].id == "issuer") {
                    issuer = input_fields[i].values;
                    break;
                }
            }
        }

        return issuer
    }

    function get_redirect_url(instance_id) {
        op_configuration_factory.get_redirect_url(get_issuer(), instance_id).success(get_redirect_url_success_callback).error(error_callback);
    }

});

var ISSUER_REGEXP = /^((?!.well-known).)*$/;

app.directive('issuer', function () {
    return {
        require: 'ngModel',
        link: function (scope, elm, attrs, ctrl) {
            ctrl.$parsers.unshift(function (viewValue) {
                if (ISSUER_REGEXP.test(viewValue)) {
                    ctrl.$setValidity('issuer', true);
                    return viewValue;
                } else {
                    ctrl.$setValidity('issuer', false);
                    return undefined;
                }
            });
        }
    };
});