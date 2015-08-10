from oic.oauth2 import message
from oic.oauth2 import MissingRequiredAttribute
from oic.oauth2 import MissingRequiredValue
from oic.oauth2 import REQUIRED_LIST_OF_STRINGS
from oic.oauth2 import VerificationError
from oic.oauth2 import REQUIRED_LIST_OF_SP_SEP_STRINGS
from oic.oauth2 import SINGLE_REQUIRED_STRING
from oic.oauth2 import SINGLE_OPTIONAL_STRING
from oic.oauth2 import OPTIONAL_LIST_OF_STRINGS
from oic.oauth2 import SINGLE_OPTIONAL_INT
from oic.oauth2 import OPTIONAL_LIST_OF_SP_SEP_STRINGS

from oic.exception import InvalidRequest
from oic.exception import NotForMe

from oic import oic
from oic.oic import OpenIDSchema
from oic.oic.message import SINGLE_REQUIRED_INT

__author__ = 'roland'


class AuthorizationRequest(message.AuthorizationRequest):
    c_param = message.AuthorizationRequest.c_param.copy()
    c_param.update(
        {
            "scope": REQUIRED_LIST_OF_SP_SEP_STRINGS,
            "state": SINGLE_REQUIRED_STRING,
            "redirect_uri": SINGLE_REQUIRED_STRING,
            "nonce": SINGLE_REQUIRED_STRING,
            "display": SINGLE_OPTIONAL_STRING,
            "prompt": OPTIONAL_LIST_OF_STRINGS,
            "max_age": SINGLE_OPTIONAL_INT,
            "ui_locales": OPTIONAL_LIST_OF_SP_SEP_STRINGS,
            "claims_locales": OPTIONAL_LIST_OF_SP_SEP_STRINGS,
            "id_token_hint": SINGLE_OPTIONAL_STRING,
            "login_hint": SINGLE_OPTIONAL_STRING,
            "acr_values": REQUIRED_LIST_OF_SP_SEP_STRINGS,
        }
    )
    c_allowed_values = message.AuthorizationRequest.c_allowed_values.copy()
    c_allowed_values.update({
        "display": ["page", "popup", "touch", "wap"],
        "prompt": ["none", "login", "consent", "select_account"]
    })

    def verify(self, **kwargs):
        """Authorization Request parameters that are OPTIONAL in the OAuth 2.0
        specification MAY be included in the OpenID Request Object without also
        passing them as OAuth 2.0 Authorization Request parameters, with one
        exception: The scope parameter MUST always be present in OAuth 2.0
        Authorization Request parameters.
        All parameter values that are present both in the OAuth 2.0
        Authorization Request and in the OpenID Request Object MUST exactly
        match."""
        args = {}
        for arg in ["key", "keyjar"]:
            try:
                args[arg] = kwargs[arg]
            except KeyError:
                pass

        if "id_token_hint" in self:
            if isinstance(self["id_token_hint"], basestring):
                idt = IdToken().from_jwt(str(self["id_token_hint"]), **args)
                self["id_token_hint"] = idt

        if "response_type" not in self:
            raise MissingRequiredAttribute("response_type missing", self)

        try:
            assert "openid" in self["scope"]
        except AssertionError:
            raise MissingRequiredValue("openid in scope", self)

        if "offline_access" in self["scope"]:
            try:
                assert "consent" in self["prompt"]
            except AssertionError:
                raise MissingRequiredValue("consent in prompt", self)

        if "prompt" in self:
            if "none" in self["prompt"] and len(self["prompt"]) > 1:
                raise InvalidRequest("prompt none combined with other value",
                                     self)

        return super(AuthorizationRequest, self).verify(**kwargs)


class IdToken(OpenIDSchema):
    c_param = OpenIDSchema.c_param.copy()
    c_param.update({
        "iss": SINGLE_REQUIRED_STRING,
        "sub": SINGLE_REQUIRED_STRING,
        "aud": REQUIRED_LIST_OF_STRINGS,  # Array of strings or string
        "exp": SINGLE_REQUIRED_INT,
        "iat": SINGLE_REQUIRED_INT,
        "auth_time": SINGLE_REQUIRED_INT,
        "nonce": SINGLE_REQUIRED_STRING,
        "at_hash": SINGLE_OPTIONAL_STRING,
        "acr": SINGLE_REQUIRED_STRING,
        "amr": REQUIRED_LIST_OF_STRINGS,
        "azp": OPTIONAL_LIST_OF_STRINGS,  # Array of strings or string
    })

    def verify(self, **kwargs):
        if "aud" in self:
            if "client_id" in kwargs:
                # check that I'm among the recipients
                if kwargs["client_id"] not in self["aud"]:
                    raise NotForMe("", self)

            if len(self["aud"]) > 1:
                # Then azp has to be present and be one of the aud values
                try:
                    assert "azp" in self
                except AssertionError:
                    raise VerificationError("azp missing", self)
                else:
                    try:
                        assert self["azp"] in self["aud"]
                    except AssertionError:
                        raise VerificationError(
                            "Mismatch between azp and aud claims", self)

        if "azp" in self:
            if "client_id" in kwargs:
                if kwargs["client_id"] != self["azp"]:
                    raise NotForMe("", self)

        return super(IdToken, self).verify(**kwargs)


MSG = {
    "AuthorizationRequest": AuthorizationRequest,
    "IdToken": IdToken,
}


def factory(msgtype):
    try:
        return MSG[msgtype]
    except KeyError:
        return oic.message.factory(msgtype)
