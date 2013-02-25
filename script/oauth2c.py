#!/usr/bin/env python

__author__ = 'rohe0002'

from oic.oauth2 import Client
from oic.oauth2 import factory
from oauth2test import OAuth2
from oauth2test import oauth2_operations

from oauth2test.base import Conversation
from oauth2test.check import factory as chk_factory

cli = OAuth2(oauth2_operations, Client, factory, chk_factory, Conversation)

cli.run()