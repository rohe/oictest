from oic.oic.message import RegistrationResponse
from oictest.base import Conversation
from rrtest import Trace
from oictest.oidcrp import do_response, Client
from oic.oic.message import factory as message_factory
from oictest.check import factory as check_factory

__author__ = 'roland'

_cli = Client()
CONV = Conversation(_cli, {}, Trace(), None,
                    message_factory, check_factory=check_factory)

class Response(object):
    pass


def test_do_response_400_empty():
    response = Response()
    response.status_code = 400
    response.text = ""
    response.content = ""

    url = "https://exaample.com/registration"
    client = Client()
    response_type = RegistrationResponse
    trace = Trace()
    state = ""
    kwargs = {}

    resp = do_response(response, CONV, url, trace, client, "json",
                       response_type, state, **kwargs)

    assert resp is None

if __name__ == "__main__":
    test_do_response_400_empty()