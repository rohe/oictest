Setup OPRP
**********

This application consists of two parts; config_server and OPRP.

**config_server**
The config_server is responsible for collecting all the necessary information needed to start aOPRP instance.
After collecting all the information it starts a new web server on which OPRP is running. The OPRP
runs as sub process to the config_server.

**OPRP**
OPRP is a web server which runs the tests. It could be configured and started using the config_server or
this could be made manually.

Quick Setup config_server
================================
* Go to <YOUR PATH>/oictest/test/oic_op/rp
* Rename the file named **sslconf.py.example** it could be renamed **sslconf.py**
* In **sslconf.py** you could add SSL cert for the OPRP

* Go to <YOUR PATH>/oictest/test/oic_op/config_server
* Rename the file named **config.py.example** it could be renamed **config.py**
* Edit **config.py** the most important attributes are:
    * HOST - Hostname for the config_server
    * OPRP_PATH - Full path to the OPRP script. The path could not contain ~. The OPRP script is placed in <YOUR PATH>/oictest/test/oic_op/rp/oprp2.py


Configure the config_server
===========================

========= ============================================================================
HOST      Hostname for the config_server
PORT      The port which should be using when starting the config_server
HTTPS     Should the SSL be used or not
OPRP_PATH Full path to the OPRP script. The path could not contain Tilde (~). The OPRP script is placed in <YOUR PATH>/oictest/test/oic_op/rp/oprp2.py
========= ============================================================================

NOTE: Static ports are used when the OpenID provider only supports static client registration. Since an URL containing a port
needs to be stored in OpenID provider it is stored in a database and should not be removed as often as the dynamic ports.
Currently port and processes are not removed while started.

==========================  ============================================================================
STATIC_PORT_RANGE_MIN       The lowest port number which could be assigned to a newly started OPRP instance
STATIC_PORT_RANGE_MAX       The highest port number which could be assigned to a newly started OPRP instance
DYNAMIC_PORT_RANGE_MIN      The lowest port number which could be assigned to a newly started OPRP instance
DYNAMIC_PORT_RANGE_MAX      The highest port number which could be assigned to a newly started OPRP instance
SERVER_CERT                 SSL certificate
SERVER_KEY                  SSL private key
CA_BUNDLE                   SSL CA bundle
STATIC_PORTS_DATABASE_FILE  Path of the database file which will be created in order to store static ports.
OPRP_DIR_PATH               Path to the folder containing to OPRP script
OPRP_SSL_MODULE             module containing the OPRP's SSL configuration
OPRP_TEST_FLOW              Specifies which test flow OPRP should use.
==========================  ============================================================================

Run config_server
=================
* Go to <YOUR PATH>/oictest/test/oic_op/config_server
* Run the config_server::

    python config_server.py config


Configure OPRP manually
=======================
The OPRP config module consists of

=====================   ===================
from sslconf import *   Imports the SSL information from shared configuration file
PORT                    Port which the OPRP should use
BASE                    The complete URL where the OPRP will be running
CLIENT                  Information about the OPRP
=====================   ===================

Client
------
The client attribute is a dictionary which can contain the following keys:

======================     ================================================================
CLIENT keys                Description
======================     ================================================================
`client_info`_             If the OpenID provider supports dynamic client registration then you have add some information used in the Client Registration Request
`preferences`_             Information about what to OPRP can do
`keys`_                    The which should be used while signing and encryption
`key_export_url`_          The URL where the keys will be exported. The %s will be replaced with the PORT attribute
`base_url`_                The complete URL where the OPRP will be running
`behaviour`_               Specifies which values Scope should have
`srv_discovery_url`_       Issuer URL used when the OpenID provider supports dynamic discovery
`client_registration`_     If static client registration is used the registered information should be stored here.
`provider_info`_           If the OpenID provider does not support dynamic client registration all the required info should be enter in the dictionary. For more information about the metadata values visit `openid.net <http://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata>`_.
`allow`_                   If the OpenID provider doesn't follow the OpenID Connect standard some implementation errors could be specified and will then ignored by the OPRP.
`ui_locales`_              End-User's preferred languages and scripts for the user interface. A list where the items are separated by commas (,)
`claims_locales`_          End-User's preferred languages and scripts for Claims being returned. A list where the items are separated by commas (,)
`acr_values`_              Requested Authentication Context Class Reference values. A list where the items are separated by commas (,)
`login_hint`_              Hint to the Authorization Server about the login identifier the End-User might use to log in. This hint can be used by an RP if it first asks the End-User for their e-mail address (or other identifier) and then wants to pass that value as a hint to the discovered authorization service. It is RECOMMENDED that the hint value match the value used for discovery. This value MAY also be a phone number in the format specified for the phone_number Claim. The use of this parameter is left to the OP's discretion.
======================     ================================================================

client_info
^^^^^^^^^^^
::

   'client_info':{
      'application_name':'OIC test tool',
      'application_type':'web',
      'redirect_uris':['https://localhost:8005/authz_cb'],
      'post_logout_redirect_uris':['https://localhost:8005/logout']
   },


preferences
^^^^^^^^^^^
::

   'preferences':{
      'token_endpoint_auth_method':['client_secret_basic','client_secret_post','client_secret_jwt','private_key_jwt'],
      'subject_type':'public',
      'grant_types':['authorization_code','implicit','refresh_token','urn:ietf:params:oauth:grant-type:jwt-bearer:'],
      'userinfo_signed_response_alg':['RS256','RS384','RS512','HS512','HS384','HS256'],
      'id_token_signed_response_alg':['RS256','RS384','RS512','HS512','HS384','HS256'],
      'response_types':['code','token','id_token','token id_token','code id_token','code token','code token id_token'],
      'require_auth_time':True,
      'request_object_signing_alg':['RS256','RS384','RS512','HS512','HS384','HS256'],
      'default_max_age':3600
   },

keys
^^^^
::

    'keys': [
        {'use': ['enc'], 'type': 'RSA', 'key': '../keys/second_enc.key'},
        {'use': ['sig'], 'type': 'RSA', 'key': '../keys/second_sig.key'},
        {'type': 'EC', 'use': ['sig'], 'crv': 'P-256'},
        {'type': 'EC', 'use': ['enc'], 'crv': 'P-256'}
    ],

key_export_url
^^^^^^^^^^^^^^
::

   'key_export_url':'https://localhost:8005/export/jwk_%s.json',

base_url
^^^^^^^^
::

   'base_url': 'https://localhost:8008/',

behaviour
^^^^^^^^^
::

   'behaviour':{
      'scope':['openid','profile','email','address','phone']
   },

srv_discovery_url
^^^^^^^^^^^^^^^^^
::

    'srv_discovery_url':'https://localhost:8092/'

client_registration
^^^^^^
::

    'client_registration':{
        'client_secret': 'dsadas',
        'redirect_uris': ['https://localhost:8507/authn_cb'],
        'client_id': 'asdsad'
    },

provider_info
^^^^^^
::

    'provider_info': {
        'jwks_uri': 'https://localhost:8092/static/jwks.json',
        'subject_types_supported': ['pairwise', 'public'],
        'id_token_signing_alg_values_supported': ['A128KW', 'RSA-OAEP', 'RSA1_5'],
        'response_types_supported': ['id_token token', 'code id_token', 'code token', 'token', 'token', 'code'],
        'authorization_endpoint': 'https://localhost:8092/authorization',
        'issuer': 'https://localhost:8092/'
    }

allow
^^^^^
::

    "allow": {
        "issuer_mismatch": True,
        "no_https_issuer": True
    },

ui_locales
^^^^^^^^^^
::

    'ui_locales': ['se', 'en', 'fr'],

claims_locale
^^^^^^^^^^^^^
::

    'ui_locales': ['se', 'en', 'fr'],

acr_values
^^^^^^^^^^
::

    'acr_values': ['password', 'yubikey']

login_hint
^^^^^^^^^^
::

    'login_hint': 'test@exampel.com'


Run OPRP manually
=================

* Go to <YOUR PATH>/oictest/test/oic_op/rp
* Run the OPRP::

    python oprp2.py <configuration file>


Optional scripts arguments:
--------------------------

-p PROFILE
^^^^^^^^^^

The profile makes it possible to only show tests compatible with a certain OpenID provider.

To achieve this you need specify 5 arguments separated by dots.

Example::

    -p C.T.T.ns.  (Default if -p is not specified)

    -p <Response type>.<Dynamic discovery>.<Dynamic client registration>.<Crypto features supported>.<Extra tests>

**Response type**

Possible values:

* C = code
* I = id_token
* T = token (Not valid by itself)
* CI = "code id_token"
* CT = ”code token"
* IT = ”id_token token"
* CIT = ”code id_token token"

**Dynamic discovery**

Possible values:

* T = True
* F = False

**Dynamic client registration**

Possible values:

* T = True
* F = False

**Crypto features supported**

Possible values:

* n = Supports JWT + Signing algorithm equals None
* s = Supports JWT + Signing algorithm other then None
* e = Supports JWT + encryption
* ns = Supports all signing algorithms
* ne = Signing algorithm equals None + encryption
* nse = Supports all signing algorithms + encryption
* se = Signing algorithm other then None+ encryption
* Nothing = Does note support JWT

**Extra tests**

Possible values:

* \+ = Extra tests are listed which does not test required OpenID connect functionality
* Nothing

-t TESTFLOWS
^^^^^^^^^^^^

Specifies a file containing all the test flows which should be listed. Default is tflow which is placed in the folder:

<Your path>/oictest/test/oic_op/rp/tflow.py

Example::

    -t tflow

Note: Remove .py from the test flow file name while running -t
