#!/usr/bin/env python
__author__ = 'roland'

from oic.utils.keyio import create_and_store_rsa_key_pair
create_and_store_rsa_key_pair('pyoidc_enc', size=2048)
create_and_store_rsa_key_pair('pyoidc_sig', size=2048)
