#!/usr/bin/env python

__author__ = 'roland'

from uma import UMARS
from uma import operations_rp
from oauth2test.base import Conversation
from oauth2test.check import factory as check_factory

from uma.resourcesrv import ResourceServer1C
from uma.message import factory as message_factory

cli = UMAAS(operations_rp, ResourceServer1C, message_factory, check_factory,
            Conversation)

cli.run()
