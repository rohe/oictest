.. _howto:

********************************
How to test an OpenID Connect OP
********************************

This is the simple how-to description. For those that just wants to test
there OP using a pre-defined set of test flows.

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

The communication between an RP and an OP basically consists of a sequence of
requests and responses. Some of these are defined in the standard some are not.
The once that are not in the standard are those where the user are involved.
Like authentication and choosing which user information to be share
with a service.

To be able to *fake* the user the test tool has some extra features.

Basically the user interaction boils down to two things; either entering
information on a form and then submitting the form or clicking on a link.

The tool has to be taught how to do this and what is used is something
called interactions.
This is part of the configuration of the tool and this is an example::

    "interaction": [
        {
            "matches": {
                "url": "https://www.kodtest.se:8088/authorization"
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

How much information that has to be added to the configuration depends on
whether the OP supports dynamic discovery and client registration or not.
The first part of the configuration deals with this::

    "features": {
        "registration": True,
        "discovery": True,
        "sessionmangement": False
    },

If the OP supports discovery, then you don't have to add so much
information about the OP, something similar to this is should be enough::

    "provider": {
        "version": { "oauth": "2.0", "openid": "3.0"},
        "dynamic": "https://www.kodtest.se:8088/",
        },

The *dynamic* parameter specifies where you expect to find the provider
information.

If it doesn't, you have enter all the information by hand.
The format is the same as in
http://openid.net/specs/openid-connect-discovery-1_0-07.html
with one exception and that is that all the endpoints are collected in
a dictionary, like this::

    "provider": {
        "version": "3.0",
        "issuer": "https://connect-op.heroku.com",
        "authorization_endpoint": "https://connect-op.heroku.com/authorizations/new",
        "token_endpoint": "https://connect-op.heroku.com/access_tokens",
        "userinfo_endpoint": "https://connect-op.heroku.com/user_info",
        "check_id_endpoint": "https://connect-op.heroku.com/id_token",
        "registration_endpoint": "https://connect-op.heroku.com/connect/client",
        "scopes_supported": ["openid", "profile", "email", "address", "phone"],
        "response_types_supported": ["code", "token", "id_token", "code token",
                                    "code id_token", "id_token token",
                                    "code id_token token"],
        "user_id_types_supported": ["public", "pairwise"],
        "id_token_algs_supported": ["RS256"],
        "x509_url": "https://connect-op.heroku.com/cert.pem"
    },

Client information
==================

If you are using dynamic client registration then you have add some
information used in the Client Registration Request::

    "client": {
        "redirect_uris": ["https://smultron.catalogix.se/authz_cb"],
        "contact": ["roland.hedberg@adm.umu.se"],
        "application_type": "web",
        "application_name": "OIC test tool",
        "register":True,
    },

The *register* parameter specifies whether dynamic registration should be
used or not.
If not you should only have to specify *client_id*, *client_secret* and
*redirect_uris*.


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

    ./nov.py | oicc.py -J - 'mj-00'

Those of the tests defined by Mike Jones that I have implemented are named
mj-XX (00 <= XX <= 29).

If you have the configuration as a JSON file running the tests becomes::

    oicc.py -J nov.json 'mj-00'

To run all Mike's test you can do::

    oic_flow_tests.py nov mj

This depends on there being a nov.py file.

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
            "redirect_uris": ["https://smultron.catalogix.se/authz_cb"],
            "contact": ["roland.hedberg@adm.umu.se"],
            "application_type": "web",
            "application_name": "OIC test tool",
            "register":True,
            },
        "provider": {
            "version": { "oauth": "2.0", "openid": "3.0"},
            "dynamic": "https://www.kodtest.se:8088/",
            },

        "interaction": {
            "https://www.kodtest.se:8088/authorization": ["select_form",
                                {"login":"diana", "password": "krall"}]
        }
    }

    print json.dumps(info)

This is placed in a file named *kodtest.py*

Now I can run the whole test suit::

    $ oic_flow_tests.py kodtest mj
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

    $ ./kodtest.py | oicc.py -J - -d 'mj-01' 2> mj-01.out > /dev/null
    $ head mj-01.out
    SERVER CONFIGURATION: {'version': {u'oauth': u'2.0', u'openid': u'3.0'}}
    ======================================================================
    <-- FUNCTION: discover
    <-- ARGS: {'location': '',
                '_trace_': <oictest.base.Trace object at 0x101829550>,
                'issuer': u'https://www.kodtest.se:8088/'}
    ======================================================================
    --> URL: https://www.kodtest.se:8088/registration
    --> BODY: application_type=web&type=client_associate&redirect_uris=https%3A%2F%2Fsmultron.catalogix.se%2Fauthz_cb&application_name=OIC+test+tool
    --> HEADERS: {'content-type': 'application/x-www-form-urlencoded'}
    <-- RESPONSE: {'status': '200', 'transfer-encoding': 'chunked',
                    'server': 'xenosmilus2.umdc.umu.se', 'cache-control':
                    'no-store', 'date': 'Mon, 20 Feb 2012 10:21:51 GMT',
                    'content-type': 'application/json'}
    <-- CONTENT: {"client_secret": "f22d86e878a0afa7d8663e099e8e44977e338aa3ec7f14e41dfd2cf6",
                    "client_id": "OXPlZt2Ll3zP", "expires_at": 0}

