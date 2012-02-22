__author__ = 'rohe0002'

from oictest.oic_operations import PostRequest
from oictest.oic_operations import RegistrationRequest
from oictest.oic_operations import RegistrationResponse
from oictest.oic_operations import Discover
from oictest.oic_operations import ProviderConfigurationResponse
from oictest.oic_operations import BodyResponse

class UserClaimsRequest(PostRequest):
    request = "UserClaimsRequest"
    request_args = {"user_id": ["diana"], "claims_names": ["address",
                                                           "gender"]}

class UserClaimsResponse(BodyResponse):
    response = "UserClaimsResponse"


PHASES= {
    "claims_request": (UserClaimsRequest, UserClaimsResponse),
    "oic-registration": (RegistrationRequest, RegistrationResponse),
    "provider-discovery": (Discover, ProviderConfigurationResponse)
    }


FLOWS = {
    'x-1': {
        "name": 'First claims provider test',
        "sequence": ["claims_request"],
        "endpoints": ["userclaims_endpoint"]
    },
}