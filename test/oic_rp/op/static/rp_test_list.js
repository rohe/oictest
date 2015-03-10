var app = angular.module('main', ['ngSanitize']);

app.controller('IndexCtrl', function ($scope, $sce) {

    var OPENID_DOCS = "OpenId connect documentation";
    var DISCOVERY_DOC = convert_to_link("http://openid.net/specs/openid-connect-discovery-1_0.html#IssuerDiscovery", OPENID_DOCS);
    var PROVIDER_CONF_DOC = convert_to_link("http://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig", OPENID_DOCS);
    var REGISTRATION = convert_to_link("http://openid.net/specs/openid-connect-registration-1_0-27.html", OPENID_DOCS);
    var CODE_FLOW = convert_to_link("http://openid.net/specs/openid-connect-core-1_0-17.html#CodeFlowAuth", OPENID_DOCS);
    var IMPLICIT_FLOW = convert_to_link("http://openid.net/specs/openid-connect-core-1_0-17.html#ImplicitFlowSteps", OPENID_DOCS);
    var CLIENT_AUTHENTICATION = convert_to_link("http://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication", OPENID_DOCS);
    var BEARER_HEADER = convert_to_link("http://tools.ietf.org/html/rfc6750#section-2.1", "http://tools.ietf.org");
    var FORM_ENCODED_BODY = convert_to_link("http://tools.ietf.org/html/rfc6750#section-2.2", "http://tools.ietf.org");

    $scope.guidlines = [
        ["Discovery", {
            "rp-ids-url": {
                "short_description": "Can Discover Identifiers using URL Syntax",
                "detailed_description": $sce.trustAsHtml("Tests if an entity can use WebFinger as described by " +
                "RFC 7033 and the " + DISCOVERY_DOC + " to determine the location of the OpenID Provider " +
                "using a URL as user identifier"),
                "expected_result": "An issuer should be returned"

            },
            "rp-ids-email": {
                "short_description": "Can Discover Identifiers using acct Syntax",
                "detailed_description": ("Tests if an entity can use WebFinger as described by " +
                "RFC 7033 and the " + DISCOVERY_DOC + " to determine the location of the OpenID Provider " +
                "using an email address as user identifier"),
                "expected_result": "An issuer should be returned"
            },
            "rp-config": {
                "short_description": "Can use openid-configuration Discovery Information",
                "detailed_description": "Tests if an entity can obtain the OpenID Provider " +
                "Configuration Information as described in the " + PROVIDER_CONF_DOC,
                "expected_result": "A JSON file with the OpenID Provider Configuration Information"
            }
        }],
        ["Dynamic Client Registration", {
            "rp-registration": {
                "short_description": "Uses Dynamic Registration",
                "detailed_description": "Tests if an entity can dynamically register as a OpenID Relaying " +
                "Party as described in " + REGISTRATION,
                "expected_result": "A JSON file with the Clients registration information"
            }
        }],
        ["Response type and response mode", {
            "rp-rtyp-code": {
                "short_description": "Can Make Request with 'code' Response Type",
                "detailed_description": "Tests if an entity can make a authentication request by using code " +
                "flow as descripbed in " + CODE_FLOW,
                "expected_result": "A authorization response containing an Authorization Code"
            },
            "rp-rtyp-idt": {
                "short_description": "Can Make Request with 'id_token' Response Type",
                "detailed_description": "Tests if an entity can make a authentication request by using implicit " +
                "flow (id_token) as descripbed in " + IMPLICIT_FLOW,
                "expected_result": "A authorization response containing an id_token"
            },
            "rp-rtyp-idttoken": {
                "short_description": "Can Make Request with 'id_token token' Response Type",
                "detailed_description": "Tests if an entity can make a authentication request by using implicit " +
                "flow (id_token token) as descripbed in " + IMPLICIT_FLOW,
                "expected_result": "A authorization response containing an id_token and an access token"
            }
        }],
        ["Client Authentication", {
            "rp-tok-csbasic": {
                "short_description": "Can Make Access Token Request with 'client_secret_basic' Authentication",
                "detailed_description": "Tests if a client can authenticate to the Authentication server " +
                "when using the token endpoint. In order to authenticate " +
                "the client should be using 'client_secret_basic' as described " +
                "in " + CLIENT_AUTHENTICATION,
                "expected_result": "A token response should be returned containing an ID token"
            },
            "rp-tok-csjwt": {
                "short_description": "Can Make Access Token Request with 'client_secret_jwt' Authentication",
                "detailed_description": "Tests if a client can authenticate to the Authentication server " +
                "when using the token endpoint. In order to authenticate " +
                "the client should be using 'client_secret_jwt' as described " +
                "in " + CLIENT_AUTHENTICATION,
                "expected_result": "A token response should be returned containing an ID token"
            },
            "rp-tok-cspost": {
                "short_description": "Can Make Access Token Request with 'client_secret_post' Authentication",
                "detailed_description": "Tests if a client can authenticate to the Authentication server " +
                "when using the token endpoint. In order to authenticate " +
                "the client should be using 'client_secret_post' as described " +
                "in " + CLIENT_AUTHENTICATION,
                "expected_result": "A token response should be returned containing an ID token"
            },
            "rp-tok-pkjwt": {
                "short_description": "Can Make Access Token Request with 'private_key_jwt' Authentication",
                "detailed_description": "Tests if a client can authenticate to the Authentication server " +
                "when using the token endpoint. In order to authenticate " +
                "the client should be using 'private_key_jwt' as described " +
                "in " + CLIENT_AUTHENTICATION,
                "expected_result": "A token response should be returned containing an ID token"
            }
        }],
        ["ID Token", {
            "RP-IdToken-Asym-Sig": {
                "short_description": "Accept valid asymmetric ID token signature",
                "detailed_description": "Tests if the client accepts an ID Token with an " +
                "valid signature singed by a asymmetric signing algorithm, for example RS256",
                "expected_result": "Get valid ID token"
            },
            "RP-IdToken-Sym-Sig": {
                "short_description": "Accept valid symmetric ID token signature",
                "detailed_description": "Tests if the client accepts an ID Token with an " +
                "valid signature singed by a symmetric signing algorithm, for example HS256",
                "expected_result": "Get valid ID token"
            },
            "rp-alg-rs256": {
                "short_description": "Reject invalid asymmetric ID Token signature",
                "detailed_description": "Tests if the client rejects an ID Token with an " +
                "invalid signature singed by a asymmetric signing algorithm, for example RS256",
                "expected_result": "Identify invalid ID token"
            },
            "rp-alg-hs256": {
                "short_description": "Reject invalid symmetric ID Token signature with HS256",
                "detailed_description": "Tests if the client rejects an ID Token with an " +
                "invalid signature singed by a symmetric signing algorithm, for example HS256",
                "expected_result": "Identify invalid ID token"
            },
            "rp-idt-signenc": {
                "short_description": "Can request and use signed and encrypted ID Token response",
                "detailed_description": "Tests if the client can request and use an signed and encrypted ID Token",
                "expected_result": "Retrieve an ID Token from the authorization response, verify the signature and decrypt the ID token"
            },
            "rp-alg-none": {
                "short_description": "Can Request and Use Unsigned ID Token Response",
                "detailed_description": "Register for, request, and use unsigned ID Token responses using the code flow and 'alg':'none'",
                "expected_result": "Retrieve an unsigned ID Token from the authorization response"
            },
            "rp-idt-c_hash": {
                "short_description": "Rejects incorrect c_hash from an ID token when code flow it used",
                "detailed_description": "Tests if the client extract an c_hash from an ID token presented as json. It should be used " +
                "to validate the correctness of the authorization code.",
                "expected_result": "The RP should be able to detect that the c_hash i invalid"
            },
            "RP-CHash-correct": {
                "short_description": "Verifies correct c_hash when response type equals 'code id_token'",
                "detailed_description": "Tests if the client extract an c_hash from an ID token which " +
                "has been signed using the HS256 algorithm. It should be used " +
                "to validate the correctness of the authorization code.",
                "expected_result": "The RP should be able to detect that the c_hash is valid"
            },
            "rp-idt-at_hash": {
                "short_description": "Rejects incorrect at_hash when response type equals 'id_token token'",
                "detailed_description": "Tests if the client can extract an at_hash from an ID token " +
                "and validate its correctness. When response type equals  id_token token",
                "expected_result": "The RP should be able to detect that the at_hash is invalid"
            },
            "RP-AtHash-correct": {
                "short_description": "Verifies correct at_hash when response type equals 'id_token token'",
                "detailed_description": "Tests if the client can extract an at_hash from an ID token " +
                "and validate its correctness. When response type equals  id_token token",
                "expected_result": "The RP should be able to detect that the at_hash is valid"
            },
            "RP-IdToken-Elliptic-Sig": {
                "short_description": "Can Use Elliptic Curve ID Token Signatures",
                "detailed_description": "Tests if the client can request and use an ID Token which is signed using Elliptic Curves",
                "expected_result": "Retrieve an ID Token and verify signature"
            }

        }],
        ["UserInfo Endpoint", {
            "rp-ui-hdr": {
                "short_description": "Accesses UserInfo Endpoint with Header Method",
                "detailed_description": "Using the 'Bearer' authentication scheme to transmit the access token from UserInfo Endpoint. Read more at " + BEARER_HEADER,
                "expected_result": "Receiving user info response"
            },
            "rp-ui-body": {
                "short_description": "Accesses UserInfo Endpoint with form-encoded body method",
                "detailed_description": "Using form-encoded body method to transmit the access token from UserInfo Endpoint. Read more at " + FORM_ENCODED_BODY,
                "expected_result": "Receiving user info response"
            },
            "RP-userinfo-json": {
                "short_description": "Can Request and Use JSON UserInfo Response",
                "detailed_description": "Can Request and Use UserInfo Response which is neither signed nor encrypted",
                "expected_result": "Receiving user info response"
            }
        }],
        ["Claims Request Parameter", {
            "rp-clm-idt": {
                "short_description": "Can Request and use claims in id_token using the 'claims' request parameter",
                "detailed_description": "Tests if the client can ask for a specific claim to be returned in the id_token",
                "expected_result": "The claim 'name' should appear in the returned id_token"
            }
        }]
    ];

    $scope.category_const = 0
    $scope.test_const = 1

    $scope.toggle_more_info_visibility = function (category_index, test_name) {
        var test = $scope.guidlines[category_index][$scope.test_const][test_name];

        if (test.visible == false) {
            test.visible = true;
        }
        else if (test.visible == true) {
            test.visible = false;
        }
    };

    function set_default_test_visibility() {
        for (var j = 0; j < $scope.guidlines.length; j++) {
            var category = $scope.guidlines[j][$scope.test_const]
            var tests = Object.keys(category);
            for (var i = 0; i < tests.length; i++) {
                category[tests[i]]['visible'] = false;
            }
        }
    }

    set_default_test_visibility();

    function convert_to_link(url, text) {
        if (text) {
            return '<a href=' + url + ' target="_blank">' + text + '</a>';
        }
        return '<a href=' + url + ' target="_blank">' + url + '</a>';
    }

})
;
