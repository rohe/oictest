#!/usr/bin/env python

__author__ = 'rohe0002'

from oictest import OIC
from oictest import oic_operations
from oictest.base import Conversation
from oictest.check import factory as check_factory

from oic.oic import Client
from oic.oic.consumer import Consumer
from oic.oic.message import factory as message_factory

cli = OIC(oic_operations, Client, Consumer, message_factory, check_factory,
          Conversation)

cli.run()
