#!/usr/bin/env python

__author__ = 'rohe0002'

from oictest import OIC
from oictest import oic_operations

from oic.oic import Client
from oic.oic import message

from oic.oic.consumer import Consumer

cli = OIC(oic_operations, message, Client, Consumer)

cli.run()