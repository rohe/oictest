import logging
import traceback
import sys
from oic.utils.http_util import Response
from oic.utils.authn.client import CLIENT_AUTHN_METHOD
from oic import oic
from oic.oauth2 import rndstr, PBase
from oic.oauth2.message import ErrorResponse

from oic.oic.message import AuthorizationResponse
from oic.oic.message import AuthorizationRequest
from oic.oic.message import AccessTokenResponse
from oic.utils.webfinger import WebFinger


__author__ = 'rolandh'

logger = logging.getLogger(__name__)


def token_secret_key(sid):
    return "token_secret_%s" % sid


SERVICE_NAME = "OIC"
FLOW_TYPE = "code"  # or "token"

CLIENT_CONFIG = {}


class OpenIDConnect(object):
    def __init__(self, attribute_map=None, authenticating_authority=None,
                 name="", registration_info=None, **kwargs):
        self.attribute_map = attribute_map
        self.authenticating_authority = authenticating_authority
        self.name = name

        for param in ["client_id", "client_secret"]:
            try:
                setattr(self, param, kwargs[param])
                del kwargs[param]
            except KeyError:
                setattr(self, param, "")

        self.extra = kwargs
        try:
            self.srv_discovery_url = kwargs["srv_discovery_url"]
        except KeyError:
            self.srv_discovery_url = None
        self.flow_type = FLOW_TYPE
        self.access_token_response = AccessTokenResponse
        self.client_cls = oic.Client
        self.authn_method = None
        self.registration_info = registration_info

    def find_srv_discovery_url(self, resource):
        """
        Use Webfinger to find the OP, The input is a unique identifier
        of the user. Allowed forms are the acct, mail, http and https
        urls. If no protocol specification is given like if only an
        email like identifier is given. It will be translated if possible to
        one of the allowed formats.

        :param resource: unique identifier of the user.
        :return:
        """

        wf = WebFinger(httpd=PBase(ca_certs=self.extra["ca_bundle"]))
        return wf.discovery_query(resource)