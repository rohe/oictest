#!/usr/bin/env python

__author__ = 'rohe0002'

from oictest import OIC
from oictest import oic_operations

from oic.oic import Client
from oic.oic.consumer import Consumer
from oic.oic.message import factory

cli = OIC(oic_operations, Client, Consumer, factory)

cli.run()