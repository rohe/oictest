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

behavior
........

This is about getting the OP to behave in different ways, presently these are
defined:

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
uisub   invalid subject
rotsig  Rotate signing keys
rotenc  Rotate encryption keys
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
* If the RP doesn't support dynamic discovery all the endpoints end other necessary OP configurations could be found below
* If the application doesn't support dynamic client registrations the path needs to be modified in order to request different signing and encryption algorithms, see `signalg`_ and `encalg`_
* Some tests assumes that incorrect data is returned by the OP, see `errtype`_


OP configurations:
__________________

The configuration for the RP certification service.

====================================================    ========================================================================================================
acr_values_supported                                    PASSWORD

subject_types_supported                                 * public
                                                        * pairwise

request_parameter_supported                             true

userinfo_signing_alg_values_supported                   * ES512
                                                        * PS521
                                                        * ES512
                                                        * PS521
                                                        * RS512
                                                        * HS512
                                                        * PS384
                                                        * RS256
                                                        * ES384
                                                        * HS256
                                                        * HS384
                                                        * PS256
                                                        * none
                                                        * ES256
                                                        * RS384

claims_supported                                        * profile
                                                        * family_name
                                                        * phone_number
                                                        * email_verified
                                                        * middle_name
                                                        * name
                                                        * phone_number_verified
                                                        * picture
                                                        * locale
                                                        * gender
                                                        * zoneinfo
                                                        * preferred_username
                                                        * updated_at
                                                        * birthdate
                                                        * website
                                                        * given_name
                                                        * address
                                                        * nickname
                                                        * email
                                                        * sub

issuer                                                  https://rp.certification.openid.net:8080/id/_/_/_/normal/

endsession_endpoint                                     https://rp.certification.openid.net:8080/id/_/_/_/normal/endsession

id_token_encryption_enc_values_supported                * A128CBC-HS256
                                                        * A192CBC-HS384
                                                        * A256CBC-HS512
                                                        * A128GCM
                                                        * A192GCM
                                                        * A256GCM

require_request_uri_registration                        true


grant_types_supported                                   * authorization_code
                                                        * implicit
                                                        * urn:ietf:params:oauth:grant-type:jwt-bearer

token_endpoint                                          https://rp.certification.openid.net:8080/id/_/_/_/normal/token

request_uri_parameter_supported                         true

version                                                 3.0

registration_endpoint                                   https://rp.certification.openid.net:8080/id/_/_/_/normal/registration

response_modes_supported                                * query
                                                        * fragment
                                                        * form_post

jwks_uri                                                https://rp.certification.openid.net:8080/static/jwk.json

userinfo_encryption_alg_values_supported                * RSA1_5
                                                        * RSA-OAEP
                                                        * A128KW
                                                        * A192KW
                                                        * A256KW
                                                        * ECDH-ES
                                                        * ECDH-ES+A128KW
                                                        * ECDH-ES+A192KW
                                                        * ECDH-ES+A256KW

scopes_supported                                        * profile
                                                        * openid
                                                        * offline_access
                                                        * phone
                                                        * address
                                                        * email
                                                        * openid

token_endpoint_auth_methods_supported                   * client_secret_post
                                                        * client_secret_basic
                                                        * client_secret_jwt
                                                        * private_key_jwt

userinfo_encryption_enc_values_supported                * A128CBC-HS256
                                                        * A192CBC-HS384
                                                        * A256CBC-HS512
                                                        * A128GCM
                                                        * A192GCM
                                                        * A256GCM

id_token_signing_alg_values_supported                   * ES512
                                                        * PS521
                                                        * RS512
                                                        * HS512
                                                        * PS384
                                                        * RS256
                                                        * ES384
                                                        * HS256
                                                        * HS384
                                                        * PS256
                                                        * none
                                                        * ES256
                                                        * RS384


request_object_encryption_enc_values_supported          * A128CBC-HS256
                                                        * A192CBC-HS384
                                                        * A256CBC-HS512
                                                        * A128GCM
                                                        * A192GCM
                                                        * A256GCM

claims_parameter_supported                              true

token_endpoint_auth_signing_alg_values_supported
                                                        * ES512
                                                        * PS521
                                                        * RS512
                                                        * HS512
                                                        * PS384
                                                        * RS256
                                                        * ES384
                                                        * HS256
                                                        * HS384
                                                        * PS256
                                                        * ES256
                                                        * RS384

userinfo_endpoint                                       https://rp.certification.openid.net:8080/id/_/_/_/normal/userinfo

request_object_signing_alg_values_supported             * ES512
                                                        * PS521
                                                        * RS512
                                                        * HS512
                                                        * PS384
                                                        * RS256
                                                        * ES384
                                                        * HS256
                                                        * HS384
                                                        * PS256
                                                        * none
                                                        * ES256
                                                        * RS384

request_object_encryption_alg_values_supported          * RSA1_5
                                                        * RSA-OAEP
                                                        * A128KW
                                                        * A192KW
                                                        * A256KW
                                                        * ECDH-ES
                                                        * ECDH-ES+A128KW
                                                        * ECDH-ES+A192KW
                                                        * ECDH-ES+A256KW

response_types_supported                                * code
                                                        * token
                                                        * id_token
                                                        * code token
                                                        * code id_token
                                                        * id_token token
                                                        * code token id_token

id_token_encryption_alg_values_supported                * RSA1_5
                                                        * RSA-OAEP
                                                        * A128KW
                                                        * A192KW
                                                        * A256KW
                                                        * ECDH-ES
                                                        * ECDH-ES+A128KW
                                                        * ECDH-ES+A192KW
                                                        * ECDH-ES+A256KW

authorization_endpoint                                  https://rp.certification.openid.net:8080/id/_/_/_/normal/authorization

claim_types_supported                                   * normal
                                                        * aggregated
                                                        * distributed
====================================================    ========================================================================================================
