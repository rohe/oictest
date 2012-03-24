#!/usr/bin/env python

__author__ = 'rohe0002'

from oictest import OAuth2
from oictest import oauth2_operations
from oic.oauth2 import Client

cli = OAuth2(oauth2_operations, Client)

cli.run()