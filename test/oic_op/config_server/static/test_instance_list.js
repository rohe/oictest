var app = angular.module('main', ['toaster'])

app.factory('op_configuration_factory', function ($http) {
    return {
        request_instance_ids: function (issuer) {
            return $http.post("/request_instance_ids", {"issuer": issuer});
        },
        create_new_config_file: function (instance_id, issuer) {
            return $http.post("/create_new_config_file", {
                "instance_id": instance_id,
                "issuer": issuer});
        },
        load_existing_config: function (instance_id, issuer) {
            return $http.post("/load_existing_config", {
                "instance_id": instance_id,
                "issuer": issuer});
        }
    };
});

app.controller('IndexCtrl', function ($scope, $window, toaster, op_configuration_factory) {

    $scope.new_instance_id = "";
    $scope.issuer = "";

    $('input').attr("autocomplete", "off");
    $('form').attr("autocomplete", "off");

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
        $window.location.href = '/config_page';
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