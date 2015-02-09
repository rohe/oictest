var app = angular.module('main', ['ngSanitize']);

app.controller('IndexCtrl', function ($scope, $sce) {

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
    var INVALID_ID_TOKEN_SIGN_ISSUER_URL = convertToLink("https://" + HOSTPORT + "/_/_/idts/normal");
    var INVALID_ATHASH_URL = convertToLink("https://" + HOSTPORT + "/_/_/ath/normal");
    var INVALID_CHASH_URL = convertToLink("https://" + HOSTPORT + "/_/_/ch/normal");
    var DISCOVERY_DOC = convertToLink("http://openid.net/specs/openid-connect-discovery-1_0.html#IssuerDiscovery", OPENID_DOCS);
    var PROVIDER_CONF_DOC = convertToLink("http://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig", OPENID_DOCS);
    var REGISTRATION = convertToLink("http://openid.net/specs/openid-connect-registration-1_0-27.html", OPENID_DOCS);
    var CODE_FLOW = convertToLink("http://openid.net/specs/openid-connect-core-1_0-17.html#CodeFlowAuth", OPENID_DOCS);
    var IMPLICIT_FLOW = convertToLink("http://openid.net/specs/openid-connect-core-1_0-17.html#ImplicitFlowSteps", OPENID_DOCS);
    var CLIENT_AUTHENTICATION = convertToLink("http://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication", OPENID_DOCS);
    var CLIENT_SECRET_BASIC = convertToLink("http://tools.ietf.org/html/rfc6749#section-2.3.1", "The OAuth 2.0 Authorization Framework");

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
        "RP-A-01": {
            "short_description": "Can Discover Identifiers using URL Syntax",
            "detailed_description": $sce.trustAsHtml("Tests if an entity can use WebFinger as described by " +
            "RFC 7033 and the " + DISCOVERY_DOC + " to determine the location of the OpenID Provider " +
            "using a URL as user identifier"),
            "test_setup": [
                ["Webfinger", ["The identifier to use is: <br> https://" + HOSTPORT + "/diana"]]
            ],
            "expected_result": "The issuer URL recovered MUST be: " + ISSUER,
            "Information to be added to the certification request": ""

        },
        "RP-A-02": {
            "short_description": "Can Discover Identifiers using acct Syntax",
            "detailed_description": ("Tests if an entity can use WebFinger as described by " +
            "RFC 7033 and the " + DISCOVERY_DOC + " to determine the location of the OpenID Provider " +
            "using an email address as user identifier"),
            "test_setup": [
                ["Webfinger", ["The identifier to use is: <br> acct:diana@" + HOSTPORT]]
            ],
            "expected_result": "The issuer URL recovered MUST be: " + ISSUER,
            "Information to be added to the certification request": ""
        },
        "RP-B-01": {
            "short_description": "Can use openid-configuration Discovery Information",
            "detailed_description": "Tests if an entity can obtain the OpenID Provider " +
            "Configuration Information as described in the " + PROVIDER_CONF_DOC,
            "test_setup": [
                ["OP Configuration Information", ["Issuer URL to use is: <br> " + ISSUER]]
            ],
            "expected_result": "A JSON file with the OpenID Provider Configuration Information",
            "Information to be added to the certification request": ""
        },
        "RP-C-01": {
            "short_description": "Can use Dynamic Registration",
            "detailed_description": ("Tests if an entity can dynamically register as a OpenID Relaying " +
            "Party as described in " + REGISTRATION),
            "test_setup": [
                ["OP Configuration Information",
                    [OP_CONF_TEXT]
                ]
            ],
            "expected_result": "A JSON file with the Clients registration information",
            "Information to be added to the certification request": ""
        },
        "RP-D-01": {
            "short_description": "Can Make Request with 'code' Response Type",
            "detailed_description": "Tests if an entity can make a authentication request by using code " +
            "flow as descripbed in " + CODE_FLOW,
            "test_setup": [
                ["OP Configuration Information",
                    [OP_CONF_TEXT]],
                ["Authentication request",
                    ["The parameter 'response_type' must be set to 'code'"]]
            ],
            "expected_result": "A authorization response containing an Authorization Code",
            "Information to be added to the certification request": ""
        },
        "RP-D-02": {
            "short_description": "Can Make Request with 'id_token' Response Type",
            "detailed_description": "Tests if an entity can make a authentication request by using implicit " +
            "flow (id_token) as descripbed in " + IMPLICIT_FLOW,
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
        "RP-D-03": {
            "short_description": "Can Make Request with 'id_token token' Response Type",
            "detailed_detailed_description": "Tests if an entity can make a authentication request by using implicit " +
            "flow (id_token token) as described in " + IMPLICIT_FLOW,
            "test_setup": [
                ["OP Configuration Information",
                    [OP_CONF_TEXT]],

                ["Authentication request",
                    ["The parameter 'response_type' must be set to 'id_token token'"]]

            ],
            "expected_result": "A authorization response containing an id_token and an access token",
            "Information to be added to the certification request": ""
        },
        "RP-E-01": {
            "short_description": "Can Make Access Token Request with 'client_secret_basic' Authentication",
            "detailed_description": "Tests if a client can authenticate to the Authentication server " +
            "when using the token endpoint. In order to authenticate " +
            "the client should be using 'client_secret_basic' as described " +
            "in " + CLIENT_AUTHENTICATION,
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
                    "The Authorization field in the request header should contain The keyword Basic and the client " +
                    "credentials. The client credentials consists of the client_id concatenated with client_secret " +
                    "separated by a ':' and encoded using 'application/x-www-form-urlencoded. " +
                    "For more information go to " + CLIENT_SECRET_BASIC
                ]]
            ],
            "expected_result": "A token response should be returned containing an ID token",
            "Information to be added to the certification request": ""
        },
        "RP-E-02": {
            "short_description": "Can Make Access Token Request with 'client_secret_jwt' Authentication",
            "detailed_description": "Tests if a client can authenticate to the Authentication server " +
            "when using the token endpoint. In order to authenticate " +
            "the client should be using 'client_secret_jwt' as described " +
            "in " + CLIENT_AUTHENTICATION,
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
                    " The parameter 'client_assertion_type' must be set to " +
                    "'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'"
                ]]
            ],
            "expected_result": "A token response should be returned containing an ID token",
            "Information to be added to the certification request": ""
        },
        "RP-E-03": {
            "short_description": "Can Make Access Token Request with 'client_secret_post' Authentication",
            "detailed_description": "Tests if a client can authenticate to the Authentication server " +
            "when using the token endpoint. In order to authenticate " +
            "the client should be using 'client_secret_post' as described " +
            "in " + CLIENT_AUTHENTICATION,
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
                ]]
            ],
            "expected_result": "A token response should be returned containing an ID token",

            "Information to be added to the certification request": ""
        },
        "RP-E-04": {
            "short_description": "Can Make Access Token Request with 'private_key_jwt' Authentication",
            "detailed_description": "Tests if a client can authenticate to the Authentication server " +
            "when using the token endpoint. In order to authenticate " +
            "the client should be using 'private_key_jwt' as described " +
            "in " + CLIENT_AUTHENTICATION,
            "test_setup": [
                ["OP Configuration Information", [OP_CONF_TEXT]],

                ["Client registration request", ["The parameter 'token_endpoint_auth_method' must be set to 'private_key_jwt'"]],

                ["Authentication request", ["The parameter 'response_type' must be set to 'code'"]],

                ["Token request:",
                    ["The parameter 'client_assertion' must be a JWT based on client_secret " +
                    "and signed using a public key which in turn should be published " +
                    "at JWKS_URI provided at the client registration, for more info on required claims go to " + CLIENT_AUTHENTICATION,
                        "The parameter 'client_assertion_type' must be set to 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'"]
                ]
            ],
            "expected_result": "A token response should be returned containing an ID token",
            "Information to be added to the certification request": ""
        }
        ,
        "RP-F-01": {
            "short_description": "Can accept valid Asymmetric ID Token Signature",
            "detailed_description": "Tests if the client accepts an ID Token with an " +
            "valid signature singed by a asymetric signing algorithm",
            "test_setup": [
                ["OP Configuration Information", [
                    OP_CONF_TEXT]],

                ["Registration", [
                    "The parameter 'id_token_signed_response_alg' could be set to 'RS256' " +
                    "or another asymmetric signing algorithm that is supported by the Provider"
                ]],
                ["Authentication request", [
                    "The parameter 'response_type' must be set to 'id_token'"
                ]]
            ],
            "expected_result": "A authorization response containing an id_token",
            "Information to be added to the certification request": ""
        }
        ,
        "RP-F-02": {
            "short_description": "Accept Valid Symmetric ID Token Signature",
            "detailed_description": "Tests if the client accepts an ID Token with an " +
            "valid signature singed by a symmetric signing algorithm",
            "test_setup": [
                ["OP Configuration Information", [
                    OP_CONF_TEXT]],

                ["Registration", [
                    "The parameter 'id_token_signed_response_alg' could be set to 'HS256' or another symmetric signing algorithm"]],

                ["Authentication request", [
                    "The parameter 'response_type' must be set to 'id_token'"]]
            ],
            "expected_result": "A authorization response containing an id_token",
            "Information to be added to the certification request": ""
        }
        ,
        "RP-G-01": {
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
                    " or another asymmetric signing algorithm"
                ]],
                ["Authentication request", [
                    "The parameter 'response_type' must be set to 'id_token'"
                ]]
            ],
            "expected_result": "A authorization response containing an id_token",
            "Information to be added to the certification request": ""
        }
        ,
        "RP-G-02": {
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
                ]]
            ],
            "expected_result": "A authorization response containing an id_token",
            "Information to be added to the certification request": ""
        }
        ,
        "RP-H-01": {
            "short_description": "Can request and use an signed and encrypted ID Token",
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
        "RP-H-02": {
            "short_description": "Can Request and Use Unsigned ID Token Response",
            "detailed_description": "Tests if the client can request and use an unsigned ID Token",
            "test_setup": [
                ["OP Configuration Information", [
                    OP_CONF_TEXT
                ]],
                ["Registration", [
                    "The parameter 'id_token_signed_response_alg' must be set to 'none'"
                ]],
                ["Authentication request", [
                    "The parameter 'response_type' must be set to 'code'"
                ]]
            ],
            "expected_result": "Retrieve an unsigned ID Token from the authorization response",
            "Information to be added to the certification request": ""
        }
        ,
        "RP-I-01": {
            "short_description": "Rejects incorrect c_hash from an ID token presented as json",
            "detailed_description": "Tests if the client extract an c_hash from an ID token presented as json. It should be used " +
            "to validate a code. In this test the c_hash is incorrect",
            "test_setup": [[
                "OP Configuration Information", [
                    OP_CONF_TEXT,
                    "The parameter 'issuer' must be set to '" + INVALID_CHASH_URL + "'"
                ]],
                ["Authentication request", [
                    "The parameter 'response_type' must be set to 'code id_token'"
                ]]
            ],
            "expected_result": "The RP should be able to detect that the c_hash i invalid",
            "Information to be added to the certification request": ""
        }
        ,
        "RP-I-02": {
            "short_description": "Verifies correct c_hash when Code Flow is Used",
            "detailed_description": "Tests if the client extract an c_hash from an ID token which " +
            "has been signed using the HS256 algorithm. It should be used " +
            "to validate a code. In this test the at_hash is correct",
            "test_setup": [
                ["OP Configuration Information", [
                    OP_CONF_TEXT
                ]],
                ["Authentication request", [
                    "The parameter 'response_type' must be set to 'code id_token'"
                ]],
            ],
            "expected_result": "The RP should be able to detect that the c_hash is correct",
            "Information to be added to the certification request": ""
        }
        ,
        "RP-J-01": {
            "short_description": "Rejects incorrect at_hash when Implicit Flow is Used",
            "detailed_description": "Tests if the client cab extract an at_hash from an ID token " +
            "and validate its correctness. In this test the at_hash is incorrect",
            "test_setup": [[
                "OP Configuration Information", [
                    OP_CONF_TEXT,
                    "The parameter 'issuer' must be set to '" + INVALID_ATHASH_URL + "'"
                ]],
                ["Authentication request", [
                    "The parameter 'response_type' must be set to 'id_token token'"
                ]]
            ],
            "expected_result": "The RP should be able to detect that the at_hash is incorrect",
            "Information to be added to the certification request": ""
        }
        ,
        "RP-J-02": {
            "short_description": "Verifies correct at_hash when Implicit Flow is Used",
            "detailed_description": "Tests if the client cab extract an at_hash from an ID token " +
            "and validate its correctness. In this test the at_hash is correct",
            "test_setup": [
                ["OP Configuration Information", [
                    OP_CONF_TEXT
                ]],
                ["Authentication request", [
                    "The parameter 'response_type' must be set to 'code id_token'"
                ]]
            ],
            "expected_result": "The RP should be able to detect that the at_hash is correct",
            "Information to be added to the certification request": ""
        },
        "RP-K-01": {
            "short_description": "Can Use Elliptic Curve ID Token Signatures",
            "detailed_description": "Tests if the client can request and use an ID Token which is signed using Elliptic Curves",
            "test_setup": [[
                "OP Configuration Information", [
                    OP_CONF_TEXT
                ]],
                ["Registration", [
                    "The parameter 'id_token_signed_response_alg' should be set to 'ES256'"
                ]],
                ["Authentication request", [
                    "The parameter 'response_type' must be set to 'id_token'"
                ]]
            ],
            "expected_result": "Retrieve an ID Token from the authorization response, verify the signature which" +
            " where signed using Elliptic Curve cryptography",
            "Information to be added to the certification request": ""
        },
        "RP-L-01": {
            "short_description": "Can Request and Use Claims in id_token using the 'claims' request parameter",
            "detailed_description": "Tests if the client can ask for a specific claim to be returned in the id_token",
            "test_setup": [[
                "OP Configuration Information", [
                    OP_CONF_TEXT
                ]],
                ["Authentication request", [
                    "The parameter 'response_type' must be set to 'code'",
                    "The parameter 'claims' should be set to '{'idtoken': {'name': null}'"
                ]]
            ],
            "expected_result": "The claim 'name' should appear in the returned id_token",
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
