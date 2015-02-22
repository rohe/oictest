Use RPtest
==========

The RP test tool is designed to test OpenID Connect RP libraries. It is not for
testing websites that uses OpenID Connect for authentication and access control
purposes.

That does not mean that it completely impossible to test a website, but that
has not been the target for this tool.

It is all in the URL
--------------------
We had the choice to either run a number of OpenID Connect providers (OPs) each
with a different configuration or just run one but then have some way of
telling it what is expected from it. We chose the later.
For the RP to be able to tell the OP what to do it uses a specially crafted url
path.

The basic format of the path is:

/<`id`_>/<`signalg`_>/<`encalg`_>/<`errtype`_>/<`claims`_>/<`endpoint`_>

The absence of a specification is marked with a underscore ('_'). The id MUST
be present!!

URL parts:
__________

In this section the different parts of the URL is explained

id
....
The ID should be selected by the one testing the RP. This identifier will the be used to access the logs of a specific test run.

In order to access the logs use the path::

    /log/<RP IP-address>/<id>

===============   =======================================
RP IP-address     The IP-address on which the RP is running
id                ID selected by the one testing the RP
===============   =======================================

signalg
.......
Specifies which algorithm that the OP should use for signing JWTs, this algorithm is use
for all signing. So it will for instance be used both for id_token and user
info signing. A typical value would be RSA256.

If possible this information should be specifies while doing the dynamic client registration.
But if the RP only supports static client registration you need to modify the URL path.

encalg
......

The encryption algorithms used, this is actually a tuple. The encryption alg
and the encryption enc algorithms. The tuple are joined by a ':' so a typical
value could be RSA1_5:A128CBC-HS256.

If possible this information should be specifies while doing the dynamic client registration.
But if the RP only supports static client registration you need to modify the URL path.

errtype
.......

This is about getting the OP to make 'errors', presently these are defined:

======  ==========================
ath     the at_hash is incorrect
aud     ID Token with invalid aud
ch      the c_hash is incorrect
iat     ID Token without iat claim
idts    the id_token signature is invalid
issi    the id_token iss value is not the same as the provider info issuer
isso    the provider info issuer is not the same as the discovery url
itsub   ID Token without sub claim
kmm     signing/encryption with a key the RP doesn't have access to
nonce   the nonce value returned is not the same as the received
state   the state value returned is not the same as the received
======  ==========================

claims
......

The three possible claims types are:

* normal
* aggregated
* distributed

endpoint
........

The provider endpoint to which the different request are made.

URL example 1
_____________
::

    rp-01/_/_/_/normal/authorization_endpoint

#. The log file will be named 'log/<remote_address>/**rp-01**
#. No signing of any item
#. No encryption of any item
#. No intentional errors
#. **Normal** userinfo claims
#. Making a request to **authorization_endpoint**

URL example 2
_____________
::

    rp-01/RS256/_/isso/normal/token_endpoint

#. The log file will be named 'log/<remote_address>/**rp-01**
#. IdToken will be signed using the **RS256** algorithm
#. No encryption of any item
#. The **isso** value will not be the same as the provider info issuer previously returned
#. **Normal** userinfo claims
#. Making a request to **token_endpoint**

Before you start testing
-----------------------
* If the RP doesn't support dynamic discovery all the endpoints end other necessary OP configurations could be found here: https://oictest.umdc.umu.se:7000/.well-known/openid-configuration
* If the application doesn't support dynamic client registrations the path needs to be modified in order to request different signing and encryption algorithms, see `signalg`_ and `encalg`_
* Some tests assumes that incorrect data is returned by the OP, see `errtype`_




