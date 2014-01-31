from oauth2test import OAuth2
from umatest import UMA

__author__ = 'roland'


class UMACAS(UMA):
    def __init__(self, operations_mod, client_class, msgfactory, chk_factory,
                 conversation_cls):
        OAuth2.__init__(self, operations_mod, client_class, msgfactory,
                        chk_factory, conversation_cls)

        self._parser.add_argument(
            '-a', dest="authsrv", help="The authsrv URL")

    def provider_info(self):
        return {}