var app = angular.module('main', ['toaster'])

String.prototype.endsWith = function(suffix) {
    return this.indexOf(suffix, this.length - suffix.length) !== -1;
};

function append_current_path(path){
    var current_path = window.location.pathname;

    if (current_path.endsWith("/") == false) {
        current_path += "/"
    }

    return current_path + path
}

app.factory('op_configuration_factory', function ($http) {
    return {
        request_instance_ids: function (issuer) {
            return $http.post(append_current_path("request_instance_ids"), {"issuer": issuer});
        },
        create_new_config_file: function (instance_id, issuer) {
            return $http.post(append_current_path("create_new_config_file"), {
                "instance_id": instance_id,
                "issuer": issuer});
        },
        load_existing_config: function (instance_id, issuer) {
            return $http.post(append_current_path("load_existing_config"), {
                "instance_id": instance_id,
                "issuer": issuer});
        },
        request_upload_config_file: function (configFileContent, instance_id, issuer) {
            return $http.post(append_current_path("upload_config_file"), {
                "configFileContent": configFileContent,
                "instance_id": instance_id,
                "issuer": issuer
            });
        },
        download_config_file: function (issuer, instance_id) {
            return $http.post("/download_config_file", {"issuer": issuer, "instance_id": instance_id});
        },

        restart_test_instance: function (issuer, instance_id) {
            return $http.post("/restart_test_instance", {"issuer": issuer, "instance_id": instance_id});
        }
    };
});

app.controller('IndexCtrl', function ($scope, $window, $location, toaster, op_configuration_factory) {

    $scope.new_instance_id = "";
    $scope.uploaded_instance_id = "";
    $scope.issuer = "";
    $scope.file_to_upload = "";

    $('input').attr("autocomplete", "off");
    $('form').attr("autocomplete", "off");

    function download_config_file_success_callback(data, status, headers, config) {
        configDict = JSON.stringify(data["configDict"])
        var a = document.createElement("a");
        a.download = "config.json";
        a.href = "data:text/plain;base64," + btoa(configDict);

        //Appending the element a to the body is only necessary for the download to work in firefox
        document.body.appendChild(a)
        a.click();
        document.body.removeChild(a)
    }

    function restart_test_instance_success_callback(data, status, headers, config) {
        bootbox.alert("The test instance restarted successfully")
    }

    $scope.request_download_config_file = function (instance_id)  {
        op_configuration_factory.download_config_file($scope.issuer, instance_id).success(download_config_file_success_callback).error(error_callback);
    }

    $scope.request_restart_test_instance = function (instance_id)  {
        op_configuration_factory.restart_test_instance($scope.issuer, instance_id).success(restart_test_instance_success_callback).error(error_callback);
    }

    $scope.fileNameChanged = function() {
        $scope.file_to_upload = document.getElementById("targetFile").files[0];
        $scope.$apply();
    }

    $scope.request_upload_config_file = function () {
        if ($scope.file_to_upload) {

            var reader = new FileReader();
            reader.readAsText($scope.file_to_upload, "UTF-8");
            reader.onload = function (evt) {
                op_configuration_factory.request_upload_config_file(evt.target.result, $scope.uploaded_instance_id, $scope.issuer).success(go_to_config_page).error(error_callback);
                $scope.$apply();
            };
            reader.onerror = function (evt) {
                alert("error reading file");
            }
        }
        else{
            alert("Failed to upload file because no file where selected.")
        }
    };

    $scope.reconfigure_test_instance = function(instance_id){
        op_configuration_factory.load_existing_config(instance_id, $scope.issuer).
            success(go_to_config_page).
            error(error_callback);
    };

    function request_instance_ids_success_callback(data, status, headers, config) {
        $scope.test_instances = data;
    }

    $scope.request_instance_ids = function(issuer){
        op_configuration_factory.request_instance_ids(issuer).
            success(request_instance_ids_success_callback).
            error(error_callback);
    };

    $scope.does_instance_id_exist = function(instance_id){
        if ($scope.test_instances){
            return instance_id in $scope.test_instances
        }
        return false;
    };

    $scope.does_test_instances_exist = function(){
        if ($scope.test_instances){
            return Object.keys($scope.test_instances).length > 0
        }
        return false
    };

    $scope.reached_max_num_of_instances = function(){
        if ($scope.test_instances){
            return Object.keys($scope.test_instances).length >= 5
        }
        return false
    };

    $scope.create_new_test_instance = function(){
        op_configuration_factory.create_new_config_file($scope.new_instance_id, $scope.issuer).
            success(go_to_config_page).
            error(error_callback);
    };

    function go_to_config_page(data, status, headers, config) {
        $window.location.href = append_current_path('config_page');
    }

    function error_callback(data, status, headers, config) {
        bootbox.alert(data.ExceptionMessage);
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