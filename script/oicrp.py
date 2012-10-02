#!/usr/bin/env python

__author__ = 'rohe0002'

from oictest import OIC
from rptest import rp_operations

from oic.oic import Client
from oic.oic.consumer import Consumer
from oic.oic.message import factory

cli = OIC(rp_operations, Client, Consumer, factory)

cli.run()