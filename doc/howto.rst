.. _howto:

********************************
How to test an OpenID Connect OP
********************************

This is the simple how-to description. For those that just wants to test
there OpenId provider (OP) using a pre-defined set of test flows.

There will eventually be more documentation for those that wants to build
their own test flows.

The configuration for the test script is a JSON-document. Myself I
prefer to write a small Python script that when run produces as output the
JSON-document, but that is me. The configuration examples given in this
document are all taken from such python scripts.

Configuration
*************

Dealing with user interaction when no user is present
=====================================================

The communication between an Relying party (RP) and an OpenId provider (OP) basically consists of a sequence of
requests and responses. Some of these are defined in the standard some are not.
The once that are not in the standard are those where the user are involved.
Like authentication and choosing which user information to be share
with a service.

To be able to *fake* the user the test tool has some extra features.

Basically the user interaction boils down to two things; either entering
information in a form and then submitting the form or clicking on a link.

The tool has to be taught how to do this and what is used is something
called interactions.
This is part of the configuration of the tool and this is an example::

    "interaction": [
        {
            "matches": {
                "url": "https://xenosmilus2.umdc.umu.se:8091/authorization"
            },
            "page-type": "login",
            "control": {
                "type": "form",
                "set": {"login":"diana","password": "krall"}
            }
        }
    ]

What this means is that when the tool gets to the page with the URL above,
what is on the page is among other things a form. Two things should be added
to the form. An input field with the id=login should be given the value "diana"
and another input field (id=password) should have the value "krall".
After that the form will be submitted.
The 'page-type' parameter is used by the test tool to keep tracks on what
type of interactions that are happening between the user and the service.

Another example::

    "interaction":[
        {
            "matches" : {
                "url": "https://openidconnect.info/account/login"
            },
            "page-type": "login",
            "control": {
                "type": "link",
                "path": "/account/fake"
            }
        },
        {
            "matches" : {
                "url": "https://openidconnect.info/account/consent"
            },
            "page-type": "user-consent",
            "control": {
                "type": "form"
            }
        }
    ]

Here there are two pages where user action are expected. On the first one
(the login page) the user should click on a link with the path "/account/fake".
The second is again a user consent form, but this form is pre-filled with
the necessary information so a submit is all that is needed.

The third example deals with the case where one page contains more than one
form, so the tools has to chose which one to deal with::

    "interaction":[
        {
            "matches" : {
                "url": "https://connect-op.heroku.com/authorizations/new"
            },
            "page-type": "user-consent",
            "control": {
                "type": "form",
                "pick": {
                    "form": {"action": "/authorizations", "class": "approve"}
                }
            }
        },
        {
            "matches" : {
                "url": "https://connect-op.heroku.com/"
            },
            "page-type": "login",
            "control": {
                "type": "form",
                "pick":{"form": {"action": "/connect/fake"}}
            }
        }
    ]

On the first page the form is pick solely on the action defined for the form.::

    <form accept-charset="UTF-8" action="/connect/fake" method="post">

On the second page the action is not enough to distinguish between the forms so
another attribute is used, in this case the 'class'.

The relevant part of the HTML::

    <form accept-charset="UTF-8" action="/authorizations" class="approve"
    method="post">

And a last example::

    "interaction": [
            {
            "matches" : {
                "title": "connect.openid4.us OP"
            },
            "control": {
                "type": "form"
            },
            "page-type": "login"
        },
        {
            "matches" : {
                "title": "connect.openid4.us AX Confirm"
            },
            "control": {
                "type": "form",
                "pick": {
                    "control": {"id":"persona", "value":"Default"}
                }
            },
            "page-type":"user-consent"
        }
    ]

Here one problem was that the url was not unique, dependent on where in the
process a user might be the URL was the same but the page returned was
different. So I had to use something else that was unique for the page.
The *title* of the page turned out to be useful.

Once that was done the handling of the login page is straightforward
while the consent page was a bit more complicated.

In this case there are more then one form on the page and arguments on
the <form> tag are not enough to distinguish between the forms.
So I have had to resort to use information within the form. ::

  <form method="POST" action="/abop/op.php/confirm_userinfo">
  <input type="hidden" name="mode" value="ax_confirm">
  <input type="hidden" name="persona" value="Default">

It turn out that there was a hidden control which could be used to distinguish
between the forms.

If you want to test someone else's OP this part has to be done by trial and
error.

Server information
==================
The first part of the configuration is just information about which
specifications that are supported::

    "version": { "oauth": "2.0", "openid": "3.0"},

How much information that has to be added to the configuration depends on
whether the OP supports dynamic discovery and client registration or not.
The second part of the configuration deals with this::

    "features": {
        "registration": True,
        "discovery": True,
        "session_management": False,
        "key_export": True,
    },

If the OP supports discovery, then you don't have to add so much
information about the OP, something similar to this is should be enough::

    "provider": {
        "dynamic": "https://xenosmilus2.umdc.umu.se:8091/",
        },

The *dynamic* parameter specifies where you expect to find the provider
information.

If it doesn't, you have to enter all the information by hand.
The format for this is the same as in
http://openid.net/specs/openid-connect-discovery-1_0-07.html
with one exception and that is that all the endpoints are collected in
a dictionary, like this::

    "provider": {
        "version": "3.0",
        "issuer": "https://server.example.com",
        "authorization_endpoint": "https://server.example.com/connect/authorize",
        "token_endpoint": "https://server.example.com/connect/token",
        "userinfo_endpoint": "https://server.example.com/connect/userinfo",
        "registration_endpoint": "https://connect-op.heroku.com/connect/client",
        "scopes_supported": ["openid", "profile", "email", "address", "phone",
                             "offline_access"],
        "response_types_supported": ["code", "code id_token", "id_token",
                                     "token id_token"],
        "subject_types_supported": ["public", "pairwise"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "jwks_uri": "https://server.example.com/jwks.json"
    },

Client information
==================

If you are using dynamic client registration then you have add some
information used in the Client Registration Request::

    "client": {
        "redirect_uris": ["https://%s/authz_cb"],
        "contact": ["roland.hedberg@example.com"],
        "application_type": "web",
        "application_name": "OIC test tool",
        "keys": {
            "RSA": {
                "key": "keys/pyoidc",
                "use": ["enc", "sig"]
            }
        },
        "preferences":{
            "subject_type": ["pairwise", "public"],
            "request_object_signing_alg": ["RS256", "RS384", "RS512",
                                           "HS512", "HS384", "HS256"],
            "token_endpoint_auth_methods_supported": ["client_secret_basic",
                                                      "client_secret_post",
                                                      "client_secret_jwt",
                                                      "private_key_jwt"],
            "id_token_signed_response_alg": ["RS256", "RS384", "RS512",
                                              "HS512", "HS384", "HS256"],
            "default_max_age": 3600,
            "require_auth_time": True,
            "default_acr_values":["2", "1"]
        }
    },

Note the '%s' in the redirect_uris, that notation will be obvious when we
look at the '-H' argument you can use when running the script.

Running tests
*************

There are two ways to run tests

* All tests in a sequence
* One test at the time

I have found that I alternate between this two variants.
Starting of with getting the simplest test working, this involves getting
all the interactions correctly.
Then I run the complete set of tests to see which ones work and which that
fails. If I find some that fails I then run that test over and over until
while fiddling with the server until it behaves as it should.

Running one test is done by doing (provided you have the configuration in a
python script)::

    ./nov.py | oicc.py -J - -H <FQDN> -i 'mj-00'

Those of the tests defined by Mike Jones that I have implemented are named
mj-XX (00 <= XX <= 60 and increasing).

FQDN is of course the fully qualified domain name of the host you are running
the script from.

If you have the configuration as a JSON file running the tests becomes::

    oicc.py -J nov.json -H <FQDN> 'mj-00'

To run all Mike's test you can do::

    oic_flow_tests.py -H <FQDN> nov

This depends on there being a nov.py file.
If you are exporting key material which you most probable are then you have 
to run another script before starting oic_flow_tests.py and that is 
scripts/static_provider.py.

Assuming that you plan to run the tests from the test/oic_op directory do::

    $ cd test/oic_op
    $ ../../script/static_provider.py <FQDN> 8090
    
and now you can run oic_flow_tests.py . The reason for this is that 
the oic_flow_tests.py script would otherwise have to spawn of a webserver
just for servering it's key material. For better or for worse I chose to do it
this way.

This is the documentation of the scripts arguments::

    usage: oicc.py [-h] [-d] [-v] [-C CA_CERTS] [-J JSON_CONFIG_FILE]
                   [-I INTERACTIONS] [-l] [-H HOST] [-i] [-e]
                   [flow]

    positional arguments:
      flow                 Which test flow to run

    optional arguments:
      -h, --help           show this help message and exit
      -d                   Print debug information
      -v                   Print runtime information
      -C CA_CERTS          CA certs to use to verify HTTPS server certificates, if
                           HTTPS is used and no server CA certs are defined then
                           no cert verification is done
      -J JSON_CONFIG_FILE  Script configuration
      -I INTERACTIONS      Extra interactions not defined in the script
                           configuration file
      -l                   List all the test flows as a JSON object
      -H HOST              Which host the script is running on, used to construct
                           the key export URL
      -i                   Whether or not an internal web server to handle key
                           export should be forked
      -e                   A external web server are used to handle key export

Interpreting the test output
============================

**oicc.py** will always print a summary of the test to stdout.
This regardless of whether the test succeeds or not.
If the test failed a trace log will be printed to stderr.

Test summary
------------

The format of the test summary is::


    {
        "status":1,
        "id": "mj-01"
        "tests":[
        {
            "status":0,
            "message":{
                "registration_endpoint":"https://connect-op.heroku.com/connect/client",
                "userinfo_endpoint":"https://connect-op.heroku.com/user_info",
                "user_id_types_supported":["public", "pairwise"],
                "scopes_supported":["openid", "profile", "email", "address", "PPID"],
                "token_endpoint":"https://connect-op.heroku.com/access_tokens",
                "version":"3.0",
                "response_types_supported":["code", "token", "id_token", "code token",
                                            "code id_token", "id_token token"],
                "authorization_endpoint":"https://connect-op.heroku.com/authorizations/new",
                "check_id_endpoint":"https://connect-op.heroku.com/id_token",
                "x509_url":"https://connect-op.heroku.com/cert.pem",
                "issuer":"https://connect-op.heroku.com"
            },
            "id":"check",
            "name":"Provider Configuration Response"
        },
        {
            "status":1,
            "url":"https://connect-op.heroku.com/",
            "id":"check-http-response",
            "name":"Checks that the HTTP response status is within the 200 or 300 range"
        }
        ],
    }

* status: The overall result of the flow test, the possible outcomes are:

    1. OK
    2. WARNING - something was not as I had expected, but it's not against the
        standard
    3. ERROR - something was not correct according to the standard but the
        error was not worse than I could work around it.
    4. CRITICAL - Something happend that prevented the script from continuing.

* id: An identifier of a flow
* tests: A collection of tests done during the flow. Apart from the status
  codes 1-4 described above, an extra '0' is used to indicate something which
  are of informational status.

Trace log
---------

When a test failed a trace log is provide to help you with the debugging.

All the parts of the trace log follows the same pattern::

    ======================================================================
    --> URL: https://openidconnect.info/connect/register
    --> BODY: application_type=web&type=client_associate&
                redirect_uris=https%3A%2F%2Fsmultron.catalogix.se%2Fauthz_cb&
                application_name=OIC+test+tool
    --> HEADERS: {'content-type': 'application/x-www-form-urlencoded'}
    <-- RESPONSE: {'status': '400', 'content-length': '27', 'server': 'Apache',
                    'connection': 'close',
                    'date': 'Mon, 20 Feb 2012 10:04:45 GMT',
                    'content-type': 'application/json'}
    <-- CONTENT: {"error":"invalid_request"}

(Added some linebreaks to make it more readable)

Everything prefaced with **-->** is sent from the script (the RP in this case).

The lines prefaced with **<--** is what is received from the OP.

Complete example
================

Let's take my OP as the server to test.

First the configuration of the script as a Python script::

    #!/usr/bin/env python

    import json

    info = {
        "client": {
            "redirect_uris": ["https://%s/authz_cb"],
            "contact": ["roland.hedberg@adm.umu.se"],
            "application_type": "web",
            "application_name": "OIC test tool",
            "register":True,
            },
        "provider": {
            "version": { "oauth": "2.0", "openid": "3.0"},
            "dynamic": "https://xenosmilus2.umdc.umu.se:8091/",
            },

        "interaction": {
            "https://xenosmilus2.umdc.umu.se:8091/authorization": ["select_form",
                                {"login":"diana", "password": "krall"}]
        }
    }

    print json.dumps(info)

This is placed in a file named *xenosmilus2.py*

Now I can run the whole test suit::

    $ oic_flow_tests.py senosmilus2
    * (mj-00)Client registration Request - OK
    * (mj-01)Request with response_type=code - OK
    * (mj-02)Request with response_type=token - OK
    * (mj-03)Request with response_type=id_token - OK
    * (mj-04)Request with response_type=code token - OK
    * (mj-05)Request with response_type=code id_token - OK
    * (mj-06)Request with response_type=id_token token - OK
    * (mj-07)Request with response_type=code id_token token - OK
    * (mj-08)Check ID Endpoint Access with GET and bearer_header - OK
    * (mj-09)Check ID Endpoint Access with POST and bearer_header - OK
    * (mj-10)Check ID Endpoint Access with POST and bearer_body - OK
    * (mj-11)UserInfo Endpoint Access with GET and bearer_header - OK
    * (mj-12)UserInfo Endpoint Access with POST and bearer_header - OK
    * (mj-13)UserInfo Endpoint Access with POST and bearer_body - OK
    * (mj-14)Scope Requesting profile Claims - OK
    * (mj-15)Scope Requesting email Claims - OK
    * (mj-16)Scope Requesting address Claims - OK
    * (mj-17)Scope Requesting phone Claims - OK
    * (mj-18)Scope Requesting all Claims - OK
    * (mj-19)OpenID Request Object with Required name Claim - OK
    * (mj-20)OpenID Request Object with Optional email and picture Claim - OK
    * (mj-21)OpenID Request Object with Required name and Optional email and picture Claim - OK
    * (mj-22)Requesting ID Token with auth_time Claim - OK
    * (mj-23)Requesting ID Token with Required acr Claim - OK
    * (mj-24)Requesting ID Token with Optional acr Claim - OK
    * (mj-25a)Requesting ID Token with max_age=1 seconds Restriction - OK
    * (mj-25b)Requesting ID Token with max_age=10 seconds Restriction - OK
    * (mj-26)Request with display=page - OK
    * (mj-27)Request with display=popup - OK
    * (mj-28)Request with prompt=none - OK
    * (mj-29)Request with prompt=login - OK

Hey, what did you expect I have made both the test tool and the OP :-) :-)

Now, I still might want to see more specifically what happened in a flow::

    $ ./xenosmilus2.py | oicc.py -J - -d 'mj-01' 2> mj-01.out > /dev/null
    $ head mj-01.out
    SERVER CONFIGURATION: {'version': {u'oauth': u'2.0', u'openid': u'3.0'}}
    ======================================================================
    <-- FUNCTION: discover
    <-- ARGS: {'location': '',
                '_trace_': <oictest.base.Trace object at 0x101829550>,
                'issuer': u'https://xenosmilus2.umdc.umu.se:8091/'}
    ======================================================================
    --> URL: https://xenosmilus2.umdc.umu.se:8091/registration
    --> BODY: application_type=web&type=client_associate&redirect_uris=https%3A%2F%2Fsmultron.catalogix.se%2Fauthz_cb&application_name=OIC+test+tool
    --> HEADERS: {'content-type': 'application/x-www-form-urlencoded'}
    <-- RESPONSE: {'status': '200', 'transfer-encoding': 'chunked',
                    'server': 'xenosmilus2.umdc.umu.se', 'cache-control':
                    'no-store', 'date': 'Mon, 20 Feb 2012 10:21:51 GMT',
                    'content-type': 'application/json'}
    <-- CONTENT: {"client_secret": "f22d86e878a0afa7d8663e099e8e44977e338aa3ec7f14e41dfd2cf6",
                    "client_id": "OXPlZt2Ll3zP", "expires_at": 0}

Create New tests:
*****************

In order to add a test case to this project begin by extending the file [..]/oictest/src/oictest/oic_operations.py

The file oic_operations.py consists of three essential parts:
* Flows dictionary
* Phases dictionary
* Request or Response classes

Flows and test cases
====================

Flows is a dictionary containing all test cases which has been defined. An example of Flow dictionary is presented below::

    $ FLOWS = {
        'oic-verify': {
            "name": 'Special flow used to find necessary user interactions',
            "descr": 'Request with response_type=code',
            "sequence": ["verify"],
            "endpoints": ["authorization_endpoint"],
            "block": ["key_export"]
        },

        'err-01': {
            "name": "Authorization request containing a random 'response_type' parameter",
            "sequence": ["oic-random_response_type"],
            "endpoints": ["authorization_endpoint"],
            "tests": [("verify-error", {"error": ["invalid_request",
                                                  "unsupported_response_type"]})],
            "depends": ['mj-01'],
        }
    }

In this example two test cases, oic-verify and oic-discovery has been defined. Note that the keys i the Flow dictionary corresponds to the name of the test case.

Every test is a dictionary which can contain a given number of attributes.

=========  =========
name       Name of the test
descr      A description of the test
sequence   A sequence is a list of strings in which every element should be defined as a key in a dictionary called Phases. Every element in the sequence list should correspond to a key
           in the Phases dictionary. Every key in the Phases dictionary corresponds to a request and response pair.
endpoints  A list of strings which contains all endpoints which will be used in the test. The endpoint should correspond to the endpoints in the configurations file.
           The order of the endpoints in th list does not matter. The purpose of the endpoints should be seen as documentation and doesn't have any other purpose.
depends    A list with strings where every element in the list corresponds to another test case in the Flows dictionary. When a test case is executed the depending test cases will be
           executed before the current test case. Which means that if a depending test case fails the current test case doesn't have to be executed.
tests      A list of tests which will be executed after the current test case has been executed. Note that the tests will be executed in the order in which they have been
           assigned to the list. There are multiple ways to define a test, for more information read "How to connect a test to a test case or an request/response"
=========  =========

Phases and sequences
====================
A sequence is a list of strings in which every element should be defined as a key in a dictionary called Phases. Every element in the sequence list should correspond to a key in the
Phases dictionary. Every key in the Phases dictionary corresponds to a request and response pair.

Here is an example of Phases::

    PHASES = {
        "login": (AuthorizationRequestCode, AuthorizationResponse),
        "access-token-request": (AccessTokenRequest, AccessTokenResponse)
    }

In the example above two Phases, login and access-token-request, has been defined. Every Phase (key/value pair the the Phases dictionary) consists of a Name (key) and a request/response
tuple (value). The first value in the tuple are always a class corresponding to a request. While the second value equals a class responsible for handling the response.

The simples way to handle request and responses are to use the implementations located in:

[..]/oictest/src/rrtest/request.py

Note that both the request and response classes are located in the file named request.py.

If necessary it's possible to write new implementations or extends existing implementations, which is fairly common while writing new test cases.

Create new request class
========================
A class which handles request should inherit from either GetRequest or PostRequest, depending on whether a get or post call should be executed. The two classes
in return inherits from the Request class. Implementations of GetRequest or PostRequest are located in:

[..]/oictest/src/rrtest/request.py

While extending the Request class four parameters could be overridden:

1. request:
    Could be a text string with the name of one of classed defined in the dictionary MSG which is located in:
    [..]/pyoidc/src/oic/oic/message.py.
    Note that the text string must match one of the key i the MSG dictionary exactly. Use only the classes where the name end with request.
    It's strongly recommended to use one of the pre defined classes since the one writing the new tests won't need to know how the underlining code works.
    If a no class contains all the functionally necessary to create a request, we strongly recommend to extend an existing class, extend a class in message
    or implement a new class. The last alternative is considered advanced programming and aren't recommended since it's easy to make mistakes which could
    result in misleading results. It's also possible to leave this parameter blank but then the endpoint has to added into the _kw_arg parameter

2. _request_args:
    A dictionary which should containing the parameters that should be added to the request, in excess of the parameters added by the request parameter above.
    This parameter could be empty.

3. tests:
    This parameter should be a dictionary which must follow the format {"pre": [], "post": []}. The key named "pre" should contain tests which should be executed before
    the requests has been sent. While the key named "post" should contain tests which should be executed after the requests has been sent. More info about possible test
    notations read "How to connect a test to a test case or an request/response"

4. _kw_arg:
    Extra parameters which will be added to a local dictionary self.kw_args while initializing the class. _kw_arg contains two pre defined parameters/keys;
    authn_method and endpoint. Use endpoint to specify which URL the request should invoke if no endpoint where defined in the Request parameter. The second
    pre defined parameter in _kw_arg is authn_method which hold the values:

    * client_secret_basic
    * client_secret_post
    * client_secret_jwt
    * private_key_jwt
    * bearer_header
    * bearer_body

    The different values explains how to send the access_tolken to the client. The names of the different values are considered self explanatory

In order to make an more advanced request class it's possible to override the __init__ and __call__ methods. It would then be possible to initialize the parameters
request, _request_args, tests and _kw_arg in either method.::

    class MyRequest(PostRequest):
        request = "AuthorizationRequest"
        _request_args = {}
        tests = {"pre": [], "post": [CheckHTTPResponse]}

        def __init__(self, conv):
            PostRequest.__init__(self, conv)
            #Extra initializations

        def __call__(self, location, response, content, features):
            #Extra logic could be added here.
            return PostRequest.__call__(self, location, response,
                                        content, features)

Create new response class
=========================
A class responsible for handling responses should inherit from either UrlResponse or BodyResponse. Both implementations inherits from the Respons class. UrlResponse,
BodyResponse and Respons are all located in:
[..]/oictest/src/rrtest/request.py

While extending the Response class two parameters could be overridden:

1. response:
    Could be a text string with the name of one of classed defined in the dictionary MSG which is located in:
    [..]/pyoidc/src/oic/oic/message.py.
    Note that the text string must match one of the key i the MSG dictionary exactly. Use only the classes where the name end with Response.
    It's strongly recommended to use one of the pre defined classes since the one writing the new tests won't need to know how the underlining code works.
    If a no class contains all the functionally necessary to create a request, we strongly recommend to extend an existing class, extend a class in message
    or implement a new class. The last alternative is considered advanced programming and aren't recommended since it's easy to make mistakes which could
    result in misleading results.

2. tests:
    This parameter should be a dictionary which must follow the format {"post": []}. The key named "post" should contain tests which should be executed after
    the requests has been sent. More info about possible test notations read "How to connect a test to a test case or an request/response"

In order to make an more advanced response class it's possible to override the __init__ and __call__ methods.

How to connect a test to a test case or an request/response
===========================================================
As mentioned above it's possible to add tests at different levels, either by adding it in a test case or in a request/response class.

A test could be defied by either a tuple or a single value. A single value could be either a class which is responsible for handling the test or a unique string (cid)
which could

The first value in a tuple should correspond to