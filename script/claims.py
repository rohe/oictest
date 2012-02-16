#!/usr/bin/env python

__author__ = 'rohe0002'

from oictest import OIC
from oictest import claims_operations

from oic.oic.claims_provider import ClaimsClient
import oic.oic.claims_provider as message

from oic.oic.consumer import Consumer

cli = OIC(claims_operations, message, ClaimsClient, Consumer)

cli.run()