var app = angular.module('main', ['ngSanitize']);

app.controller('IndexCtrl', function ($scope, $sce) {

    $scope.toggle_static_client_registration_visibility = function () {
        var visible = $scope.static_client_registration_info.visible;

        if (visible) {
            $scope.static_client_registration_info.visible= false;
            return
        }
        else {
            $scope.static_client_registration_info.visible = true;
            return
        }
    };

    $scope.toggle_more_info_visibility = function (test_name) {
        var test = $scope.guidlines[test_name];

        if (test.visible == false) {
            test.visible = true;
            return
        }
        else if (test.visible == true) {
            test.visible = false;
            return
        }
    };

    var OPENID_DOCS = "OpenId connect documentation";

    var HOSTPORT = "oictest.umdc.umu.se:7000";
    var ISSUER = convertToLink("https://" + HOSTPORT);
    var ISSUER_FULL_PATH = convertToLink("https://" + HOSTPORT + "/_/_/_/normal");
    var ISSUER_FULL_PATH_SIGN = convertToLink("https://" + HOSTPORT + "/RS256/_/_/normal");
    var ISSUER_FULL_PATH_ENC = convertToLink("https://" + HOSTPORT + "/_/RSA1_5/_/normal");
    var OP_CONFIGURATION_PAGE = convertToLink("https://" + HOSTPORT + "/.well-known/openid-configuration", "here.");
    var INVALID_ID_TOKEN_SIGN_ISSUER_URL = convertToLink("https://" + HOSTPORT + "/_/_/idts/normal")
    var INVALID_ACCESS_TOKEN_ISSUER_URL = convertToLink("https://" + HOSTPORT + "/_/_/ath/normal")
    var DISCOVERY_DOC = convertToLink("http://openid.net/specs/openid-connect-discovery-1_0.html#IssuerDiscovery", OPENID_DOCS)
    var PROVIDER_CONF_DOC = convertToLink("http://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig", OPENID_DOCS)
    var REGISTRATION = convertToLink("http://openid.net/specs/openid-connect-registration-1_0-27.html", OPENID_DOCS)
    var CODE_FLOW = convertToLink("http://openid.net/specs/openid-connect-core-1_0-17.html#CodeFlowAuth", OPENID_DOCS)
    var IMPLICIT_FLOW = convertToLink("http://openid.net/specs/openid-connect-core-1_0-17.html#ImplicitFlowSteps", OPENID_DOCS)
    var CLIENT_AUTHENTICATION = convertToLink("http://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication", OPENID_DOCS);
    var CLIENT_SECRET_BASIC = convertToLink("http://tools.ietf.org/html/rfc6749#section-2.3.1", "The OAuth 2.0 Authorization Framework")

    var OP_CONF_TEXT = "Can be found dynamically using the Issuer URL: " + ISSUER + " or if dynamic discovery isn't " +
        "supported then the configuration could be found " + OP_CONFIGURATION_PAGE;

    $scope.static_client_registration_info = {"visible": false, "text" : "If you application doesn't support dynamic client "+
    " registration you will need to modify some tests. That is all tests including "+
    " signing or encryption, like RP-12 for example. If you want the test tool to use a" +
    " specific signing algorithm you need to modify the issuer path. Normally" +
    " the issuer published by the test tool looks like this " + ISSUER_FULL_PATH +
    " when using static client registration you need to change to issuer path. For example " +
    + ISSUER_FULL_PATH_SIGN + "tells the test tool to use the RS256 signing" +
    " algorithm for signing the id_token. If you want the test tool to use RSA1_5 encryption algorithm" +
    " the path would look like this " + ISSUER_FULL_PATH_ENC + ". If the RP supports dynamic client registration it's " +
    "highly recommended to add the required signing/encruption algorithms in the registration request as mentioned " +
    "in the tests"};

    function convertToLink(url, text) {
        if (text) {
            return '<a href=' + url + ' target="_blank">' + text + '</a>';
        }
        return '<a href=' + url + ' target="_blank">' + url + '</a>';
    }

    $scope.guidlines = {
        "RP-01": {
            "short_description": "Can Discover Identifiers using URL Syntax",
            "detailed_description": $sce.trustAsHtml("Tests if an entity can use WebFinger as described by" +
            "RFC 7033 and the " + DISCOVERY_DOC + " to determine the location of the OpenID Provider" +
            "using a URL as user identifier"),
            "test_setup": [
                ["Webfinger", ["The identifier to use is: <br> https://" + HOSTPORT + "/diana"]]
            ],
            "expected_result": "The issuer URL recovered MUST be: " + ISSUER,
            "Information to be added to the certification request": ""

        },
        "RP-02": {
            "short_description": "Can Discover Identifiers using acct Syntax",
            "detailed_description": ("Tests if an entity can use WebFinger as described by" +
            "RFC 7033 and the " + DISCOVERY_DOC + " to determine the location of the OpenID Provider" +
            "using an email address as user identifier"),
            "test_setup": [
                ["Webfinger", ["The identifier to use is: <br> acct:diana@" + HOSTPORT]]
            ],
            "expected_result": "The issuer URL recovered MUST be: " + ISSUER,
            "Information to be added to the certification request": ""
        },
        "RP-03": {
            "short_description": "Can use openid-configuration Discovery Information",
            "detailed_description": "Tests if an entity can obtain the OpenID Provider " +
            "Configuration Information as described in the " + PROVIDER_CONF_DOC,
            "test_setup": [
                ["OP Configuration Information", ["Issuer URL to use is: <br> " + ISSUER]]
            ],
            "expected_result": "A JSON file with the OpenID Provider Configuration Information",
            "Information to be added to the certification request": ""
        },
        "RP-04": {
            "short_description": "Can Uses Dynamic Registration",
            "detailed_description": ("Tests if an entity can dynamically register as a OpenID Relaying" +
            "Party as described in the " + REGISTRATION),
            "test_setup": [
                ["OP Configuration Information",
                    [OP_CONF_TEXT]
                ]
            ],
            "expected_result": "A JSON file with the Client registration information",
            "Information to be added to the certification request": ""
        },
        "RP-05": {
            "short_description": "Can Make Request with 'code' Response Type",
            "detailed_description": "Tests if an entity can make a authentication request by using code" +
            "flow as descripbed in the " + CODE_FLOW,
            "test_setup": [
                ["OP Configuration Information",
                    [OP_CONF_TEXT]],
                ["Authentication request",
                    ["The parameter 'response_type' must be set to 'code'"]]
            ],
            "expected_result": "A authorization response containing an Authorization Code",
            "Information to be added to the certification request": ""
        },
        "RP-06": {
            "short_description": "Can Make Request with 'id_token' Response Type",
            "detailed_description": "Tests if an entity can make a authentication request by using implicit" +
            "flow (id_token) as descripbed in the " + IMPLICIT_FLOW,
            "test_setup": [
                ["OP Configuration Information",
                    [OP_CONF_TEXT]
                ],
                ["Authentication request", [
                    "The parameter 'response_type' must be set to 'id_token'"
                ]]
            ],
            "expected_result": "A authorization response containing an id_token",
            "Information to be added to the certification request": ""
        },
        "RP-07": {
            "short_description": "Can Make Request with 'id_token token' Response Type",
            "detailed_detailed_description": "Tests if an entity can make a authentication request by using implicit" +
            "flow (id_token token) as descripbed in the " + IMPLICIT_FLOW,
            "test_setup": [
                ["OP Configuration Information",
                    [OP_CONF_TEXT]],

                ["Authentication request",
                    ["The parameter 'response_type' must be set to 'id_token token'"]]

            ],
            "expected_result": "A authorization response containing an id_token and an access token",
            "Information to be added to the certification request": ""
        },
        "RP-08": {
            "short_description": "Can Make Access Token Request with 'client_secret_basic' Authentication",
            "detailed_description": "Tests if a client can authenticate to the Authentication server " +
            "when using the token endpoint. In order to authenticate" +
            "the client should be using 'client_secret_basic' as descripbed" +
            " in the " + CLIENT_AUTHENTICATION,
            "test_setup": [
                ["OP Configuration Information",
                    [OP_CONF_TEXT]],

                ["Client registration request", [
                    "The parameter 'token_endpoint_auth_method' could be set to 'client_secret_basic'" +
                    "By default to OP should select client_secret_basic if no other algorithm are selected"
                ]],
                ["Authentication request", [
                    "The parameter 'response_type' must be set to 'code'"
                ]],
                ["Token request:", [
                    "The Authorization field in the request header should contain The keyword Basic and the client" +
                    "credentials. The client credentials consists of the client_id concatinated with client_secret " +
                    "seperated by : and encoded using 'application/x-www-form-urlencoded." +
                    "For more information go to the " + CLIENT_SECRET_BASIC

                ]],
            ],
            "expected_result": "A token response should be returned containing an ID token",
            "Information to be added to the certification request": ""
        },
        "RP-09": {
            "short_description": "Can Make Access Token Request with 'client_secret_jwt' Authentication",
            "detailed_description": "Tests if a client can authenticate to the Authentication server " +
            "when using the token endpoint. In order to authenticate" +
            "the client should be using 'client_secret_jwt' as descripbed" +
            " in the" + CLIENT_AUTHENTICATION,
            "test_setup": [
                ["OP Configuration Information",
                    [OP_CONF_TEXT]],
                ["Client registration request",
                    ["The parameter 'token_endpoint_auth_method' must be set to 'client_secret_jwt'"]],
                ["Authentication request", [
                    "The parameter 'response_type' must be set to 'code'"
                ]],
                ["Token request:", [
                    "The parameter 'client_assertion' must be a JWT based on client_secret, " +
                    "for more info on required claims go to " + CLIENT_AUTHENTICATION,
                    " The parameter 'client_assertion_type' must be set to" +
                    "'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'"
                ]]
            ],
            "expected_result": "A token response should be returned containing an ID token",
            "Information to be added to the certification request": ""
        },
        "RP-10": {
            "short_description": "Can Make Access Token Request with 'client_secret_post' Authentication",
            "detailed_description": "Tests if a client can authenticate to the Authentication server " +
            "when using the token endpoint. In order to authenticate" +
            "the client should be using 'client_secret_post' as descripbed" +
            " in the " + CLIENT_AUTHENTICATION,
            "test_setup": [
                ["OP Configuration Information", [
                    OP_CONF_TEXT
                ]],
                ["Client registration request", [
                    "The parameter 'token_endpoint_auth_method' must be set to 'client_secret_post'"
                ]],
                ["Authentication request", [
                    "The parameter 'response_type' must be set to 'code'"
                ]],
                ["Token request:", [
                    "The request needs to contain the parameters 'client_secret' and 'client_id'"
                ]],

            ],
            "expected_result": "A token response should be returned containing an ID token",

            "Information to be added to the certification request": ""
        },
        "RP-11": {
            "short_description": "Can Make Access Token Request with 'private_key_jwt' Authentication",
            "detailed_description": "Tests if a client can authenticate to the Authentication server " +
            "when using the token endpoint. In order to authenticate" +
            "the client should be using 'private_key_jwt' as descripbed" +
            " in the " + CLIENT_AUTHENTICATION,
            "test_setup": [
                ["OP Configuration Information", [OP_CONF_TEXT]],

                ["Client registration request", ["The parameter 'token_endpoint_auth_method' must be set to 'private_key_jwt'"]],

                ["Authentication request", ["The parameter 'response_type' must be set to 'code'"]],

                ["Token request:",
                    ["The parameter 'client_assertion' must be a JWT based on client_secret" +
                    "and signed using a public key which in turn should be published" +
                    "at JWKS_URI provided at the client registration, for more info on required claims go to the " + CLIENT_AUTHENTICATION,
                        "The parameter 'client_assertion_type' must be set to 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'"]
                ]
            ],
            "expected_result": "A token response should be returned containing an ID token",
            "Information to be added to the certification request": ""
        }
        ,
        "RP-12": {
            "short_description": "Can accept valid Asymmetric ID Token Signature",
            "detailed_description": "Tests if the client accepts an ID Token with an " +
            "valid signature singed by a asymetric signing algorithm",
            "test_setup": [
                ["OP Configuration Information", [
                    OP_CONF_TEXT]],

                ["Registration", [
                    "The parameter 'id_token_signed_response_alg' could be set to 'RS256'" +
                    " or other asymmetric signing algorithm"
                ]],
                ["Authentication request", [
                    "The parameter 'response_type' must be set to 'id_token'"
                ]],
            ],
            "expected_result": "A authorization response containing an id_token",
            "Information to be added to the certification request": ""
        }
        ,
        "RP-13": {
            "short_description": "Accept Valid Symmetric ID Token Signature",
            "detailed_description": "Tests if the client accepts an ID Token with an " +
            "valid signature singed by a symetric signing algorithm",
            "test_setup": [
                ["OP Configuration Information", [
                    OP_CONF_TEXT]],

                ["Registration", [
                    "The parameter 'id_token_signed_response_alg' could be set to 'HS256' or other symmetric signing algorithm"]],

                ["Authentication request", [
                    "The parameter 'response_type' must be set to 'id_token'"]]

            ],
            "expected_result": "A authorization response containing an id_token",
            "Information to be added to the certification request": ""
        }
        ,
        "RP-14": {
            "short_description": "Reject Invalid Asymmetric ID Token Signature",
            "detailed_description": "Tests if the client rejects an ID Token with an " +
            "invalid signature singed by a asymetric signing algorithm",
            "test_setup": [
                ["OP Configuration Information", [
                    OP_CONF_TEXT,
                    "The parameter 'issuer' must be set to '" + INVALID_ID_TOKEN_SIGN_ISSUER_URL + "'"
                ]],
                ["Registration", [
                    "The parameter 'id_token_signed_response_alg' could be set to 'RS256'" +
                    " or other asymmetric signing algorithm"
                ]],
                ["Authentication request", [
                    "The parameter 'response_type' must be set to 'id_token'"
                ]],
            ],
            "expected_result": "A authorization response containing an id_token",
            "Information to be added to the certification request": ""
        }
        ,
        "RP-15": {
            "short_description": "Reject Invalid Symmetric ID Token Signature",
            "detailed_description": "Tests if the client rejects an ID Token with an " +
            "invalid signature singed by a symetric signing algorithm",
            "test_setup": [
                ["OP Configuration Information", [
                    OP_CONF_TEXT,
                    "The parameter 'issuer' must be set to '" + INVALID_ID_TOKEN_SIGN_ISSUER_URL + "'"
                ]],
                ["Registration", [
                    "The parameter 'id_token_signed_response_alg' could be set to 'HS256'" +
                    " or other symmetric signing algorithm"
                ]],
                ["Authentication request", [
                    "The parameter 'response_type' must be set to 'id_token'"
                ]],
            ],
            "expected_result": "A authorization response containing an id_token",
            "Information to be added to the certification request": ""
        }
        ,
        "RP-16": {
            "short_description": "Tests if the client can request and use an signed and encrypted ID Token",
            "detailed_description": "Tests if the client can request and use an signed and encrypted ID Token",
            "test_setup": [
                ["OP Configuration Information",
                    [OP_CONF_TEXT]],

                ["Registration",
                    ["The parameter 'id_token_signed_response_alg' could be set to 'HS256'",
                        "The parameter 'id_token_encrypted_response_alg' could be set to 'RSA1_5'",
                        "The parameter 'id_token_encrypted_response_enc' could be set to 'A128CBC-HS256'"]],

                ["Authentication request", ["The parameter 'response_type' must be set to 'id_token'"]]

            ],
            "expected_result": "Retrieve an ID Token from the authorization response, verify the signature and decrypt the ID token",
            "Information to be added to the certification request": ""
        }
        ,
        "RP-17": {
            "short_description": "Can Request and Use Unsigned ID Token Response",
            "detailed_description": "Tests if the client can request and use an unsigned ID Token",
            "test_setup": [
                ["OP Configuration Information", [
                    OP_CONF_TEXT
                ]],
                ["Registration", [
                    "The parameter 'id_token_signed_response_alg' could be set to 'none'"
                ]],
                ["Authentication request", [
                    "The parameter 'response_type' must be set to 'code'"
                ]],
            ],
            "expected_result": "Retrieve an unsigned ID Token from the authorization response",
            "Information to be added to the certification request": ""
        }
        ,
        "RP-18": {
            "short_description": "Can Use Elliptic Curve ID Token Signatures",
            "detailed_description": "Tests if the client can request and use an ID Token which is signed using Elliptic Curves",
            "test_setup": [[
                "OP Configuration Information", [
                    OP_CONF_TEXT
                ]],
                ["Registration", [
                    "The parameter 'id_token_signed_response_alg' could be set to 'ES256'"
                ]],
                ["Authentication request", [
                    "The parameter 'response_type' must be set to 'id_token'"
                ]]
            ],
            "expected_result": "Retrieve an ID Token from the authorization response, verify the signature which" +
            " where signed using Elliptic Curves",
            "Information to be added to the certification request": ""
        }
        ,
        "RP-19": {
            "short_description": "Rejects incorrect at_hash from an ID token presented as json",
            "detailed_description": "Tests if the client extract an at_hash from an ID token presented as json. It should be used " +
            "to validate an Access Token. In this test the Access Token is incorrect",
            "test_setup": [[
                "OP Configuration Information", [
                    OP_CONF_TEXT,
                    "The parameter 'issuer' must be set to '" + INVALID_ACCESS_TOKEN_ISSUER_URL + "'"
                ]],
                ["Authentication request", [
                    "The parameter 'response_type' must be set to 'code'"
                ]]
            ],
            "expected_result": "The RP should be able to detect that the Access Token i invalid",
            "Information to be added to the certification request": ""
        }
        ,
        "RP-20": {
            "short_description": "Rejects incorrect at_hash from an signed ID token",
            "detailed_description": "Tests if the client extract an at_hash from an ID token which " +
            "has been signed using the HS256 algorithm. It should be used " +
            "to validate an Access Token. In this test the Access Token is incorrect",
            "test_setup": [
                ["OP Configuration Information", [
                    OP_CONF_TEXT,
                    "The parameter 'issuer' must be set to '" + INVALID_ACCESS_TOKEN_ISSUER_URL + "'"
                ]],
                ["Registration request:", [
                    "The parameter 'userinfo_signed_response_alg' must be set to 'HS256'"
                ]],
                ["Authentication request", [
                    "The parameter 'response_type' must be set to 'code'"
                ]],
            ],
            "expected_result": "The RP should be able to detect that the Access Token i invalid",
            "Information to be added to the certification request": ""
        }
        ,
        "RP-21": {
            "short_description": "Rejects incorrect at_hash from an ecrypted ID token",
            "detailed_description": "Tests if the client extract an at_hash from an ID token which " +
            "has been encypted using the RSA1_5 algorithm. It should be used " +
            "to validate an Access Token. In this test the Access Token is incorrect",
            "test_setup": [[
                "OP Configuration Information", [
                    OP_CONF_TEXT,
                    "The parameter 'issuer' must be set to '" + INVALID_ACCESS_TOKEN_ISSUER_URL + "'"
                ]],
                ["Registration request:", [
                    "The parameter 'userinfo_encrypted_response_alg' must be set to 'RSA1_5'",
                    "The parameter 'userinfo_encrypted_response_enc' must be set to 'A128CBC-HS256'"
                ]],
                ["Authentication request", [
                    "The parameter 'response_type' must be set to 'code'"
                ]],
            ],
            "expected_result": "The RP should be able to detect that the Access Token i invalid",
            "Information to be added to the certification request": ""
        }
        ,
        "RP-22": {
            "short_description": "Rejects incorrect at_hash from an signed and ecrypted ID token",
            "detailed_description": "Tests if the client extract an at_hash from an ID token which " +
            "has been singed and encrypted. It should be used " +
            "to validate an Access Token. In this test the Access Token is incorrect",
            "test_setup": [[
                "OP Configuration Information", [
                    OP_CONF_TEXT,
                    "The parameter 'issuer' must be set to '" + INVALID_ACCESS_TOKEN_ISSUER_URL + "'"
                ]],
                ["Registration request:", [
                    "The parameter 'userinfo_signed_response_alg' must be set to 'HS256'",
                    "The parameter 'userinfo_encrypted_response_alg' must be set to 'RSA1_5'",
                    "The parameter 'userinfo_encrypted_response_enc' must be set to 'A128CBC-HS256'"
                ]],
                ["Authentication request", [
                    "The parameter 'response_type' must be set to 'code'"
                ]]
            ],
            "expected_result": "The RP should be able to detect that the Access Token i invalid",
            "Information to be added to the certification request": ""
        }
    };

    function set_default_test_visibility() {
        var keys = Object.keys($scope.guidlines);

        for (var i = 0; i < keys.length; i++) {
            var key = keys[i];
            $scope.guidlines[key]['visible'] = false;
        }
    }

    set_default_test_visibility();

})
;
