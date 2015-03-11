var app = angular.module('main', ['toaster'])

app.factory('opConfigurationFactory', function ($http) {
    return {
        getOpConfig: function () {
            return $http.get("/get_op_config");
        },

        requestDownloadConfigFile: function () {
            return $http.get("/download_config_file");
        },

        requestUploadConfigFile: function (configFileContent) {
            return $http.post("/upload_config_file", {"configFileContent": configFileContent});
        },

        createNewConfigFile: function () {
            return $http.get("/create_new_config_file");
        },

        doesConfigFileExist: function () {
            return $http.get("/does_op_config_exist");
        },

        startOpTester: function (op_configurations) {
            return $http.post("/start_op_tester", {"op_configurations": op_configurations});
        },

        getRedirectUrl: function (issuer) {
            return $http.post("/get_redirect_url", {"issuer": issuer});
        }
    };
});

app.controller('IndexCtrl', function ($scope, toaster, opConfigurationFactory) {
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
    function getOpConfigurationSuccessCallback(data, status, headers, config) {
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
        opConfigurationFactory.getOpConfig().success(getOpConfigurationSuccessCallback).error(errorCallback);
    }

    /**
     * Confirms that the configuration successfully has been uploaded on the server
     * @param data - The result returned from the server
     * @param status - The status on the response from the server
     * @param headers - The header on the response from the server
     * @param config - The configuration on the response from the server
     */
    function uploadConfigFileSuccessCallback(data, status, headers, config) {
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
    function createNewConfigFileSuccessCallback(data, status, headers, config) {
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
    function doesConfigFileExistSuccessCallback(data, status, headers, config) {
        if (data['doesConfigFileExist']) {
            requestLatestConfigFileFromServer();
        }
    }

    $scope.goToPrevious = function () {
        $scope.contains_redirect_url = false;
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

    function getRedirectUrlSuccessCallback(data, status, headers, config) {
        setRedirectUrl(data['redirect_url'])
    }

    /**
     * Confirms that a there exists a configuration file on the server. If configuration file exist then it's downloaded
     * @param data - The result returned from the server
     * @param status - The status on the response from the server
     * @param headers - The header on the response from the server
     * @param config - The configuration on the response from the server
     */
    function configFileExistForDownloadSuccessCallback(data, status, headers, config) {
        if (data['doesConfigFileExist']) {
            opConfigurationFactory.requestDownloadConfigFile().success(downloadConfigFileSuccessCallback).error(errorCallback);
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
    function errorCallback(data, status, headers, config) {
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

    $scope.staticProviderInfoElement = {'value': ''};

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
    function containsRequiredClientInfo() {
        if ($scope.opConfig['dynamicClientRegistrationDropDown']['value'] == "no") {
            if (!hasEnteredClientIdAndClientSecret()) {
                showMissingRequiredInfoError("client")
                return false
            }
        }
        return true;
    }

    /**
     * Sends the configuration file to the server
     */
    $scope.saveConfigurations = function () {
        if ($scope.contains_required_provider_info() && containsRequiredClientInfo()) {
            bootbox.dialog({
                message: "Do you want to start testing your OP?" +
                " <br><br> Note: If a test server successfully starts you will be redirected to the test server. Do you want to continue?",
                title: "Start test server",
                buttons: {
                    danger: {
                        label: "No",
                        className: "btn-default"
                    },
                    success: {
                        label: "Yes",
                        className: "btn-primary",
                        callback: function () {
                            opConfigurationFactory.startOpTester($scope.opConfig).success(startOpTesterSuccessCallback).error(errorCallback);
                            $scope.$apply();
                        }
                    }
                }
            });
        }
    };

    function startOpTesterSuccessCallback(data, status, headers, config) {
        window.location.href = data['oprp_url'];
    }

    /**
     * Tries to download the configuration file from the server
     */
    $scope.requestDownloadConfigFile = function () {
        opConfigurationFactory.doesConfigFileExist().success(configFileExistForDownloadSuccessCallback).error(errorCallback);
    };

    /**
     * Tries to upload the configuration file to the server.
     */
    $scope.requestUploadConfigFile = function () {
        var file = document.getElementById("targetFile").files[0];

        if (file) {
            var reader = new FileReader();
            reader.readAsText(file, "UTF-8");
            reader.onload = function (evt) {
                opConfigurationFactory.requestUploadConfigFile(evt.target.result).success(uploadConfigFileSuccessCallback).error(errorCallback);
                $scope.$apply();
            };
            reader.onerror = function (evt) {
                alert("error reading file");
            }
        }
    };

    function resetGui() {
        $scope.contains_redirect_url = false;
    }

    /**
     * Show a "confirm that you want to create a new configuration file" dialog
     */
    $scope.createNewConfigFile = function () {
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
                        opConfigurationFactory.createNewConfigFile().success(createNewConfigFileSuccessCallback).error(errorCallback);
                        $scope.$apply();
                    }
                }
            }
        });
    };

    $("[data-toggle='tooltip']").tooltip();

    $scope.loadExistingConfig = function () {
        opConfigurationFactory.doesConfigFileExist().success(doesConfigFileExistSuccessCallback).error(errorCallback);
    };

    function showMissingRequiredInfoError(infoType, emptyRequiredInfoFields) {
        var errorText = "<p>In order to go to continue you need to enter all the required " + infoType + " information.</p>";

        if (typeof emptyRequiredInfoFields !== "undefined" && emptyRequiredInfoFields.length > 0) {
            errorText += "<p> Missing required fields: </p>";

            for (var i = 0; i < emptyRequiredInfoFields.length; i++) {
                errorText += "<li>" + emptyRequiredInfoFields[i] + "</li>"
            }
        }
        bootbox.alert(errorText);
    }

    $scope.is_invalid = function () {
        return true;
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

    $scope.getRedirectUrl = function () {
        opConfigurationFactory.getRedirectUrl(get_issuer()).success(getRedirectUrlSuccessCallback).error(errorCallback);
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