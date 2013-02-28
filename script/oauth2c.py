#!/usr/bin/env python

__author__ = 'rohe0002'

from oic.oauth2 import Client
from oic.oauth2 import factory as message_factory
from oauth2test import OAuth2
from oauth2test import operations

from oauth2test.base import Conversation
from oauth2test.check import factory as check_factory

cli = OAuth2(operations, Client, message_factory, check_factory, Conversation)

cli.run()
