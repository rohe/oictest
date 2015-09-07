from rrtest import Trace
from oictest.oprp import not_supported
from oictest.base import Conversation
from oictest.check import factory as check_factory
from oictest.oidcrp import Client
from oic.oic.message import factory as message_factory

__author__ = 'roland'

_cli = Client()
CONV = Conversation(_cli, {}, Trace(), None,
                    message_factory, check_factory=check_factory)


def test_not_support():
    assert not_supported("abc", "abc") is None
    assert not_supported("bac", "abc") == ["bac"]
    assert not_supported("abc", ["abc", "def"]) is None
    assert not_supported("bac", ["abc", "def"]) == ["bac"]
    assert not_supported(["abc", "def"], ["abc", "def"]) is None
    assert not_supported(["bac", "def"], ["abc", "def"]) == ["bac"]
    assert not_supported(["abc", "def", "ghi"], ["abc", "def"]) == ["ghi"]

# TODO pi.google does not exist
# def test_support():
#     pi = json.loads(open("pi.google").read())
#     CONV.client.provider_info = ProviderConfigurationResponse(**pi)
#
#     stat = support(CONV, {'warning': {
#         'scopes_supported': ['profile', 'email', 'address', 'phone']}})
#
#     print CONV.test_output[-1]
#     assert stat is WARNING
#     _output = CONV.test_output[-1]
#     assert _output["status"] == WARNING
#     assert _output["message"] == ("OP is not supporting ['address', 'phone'] "
#                                   "according to 'scopes_supported' in the "
#                                   "provider configuration")

if __name__ == "__main__":
    # test_support()
    pass
