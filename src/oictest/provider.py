from oic import oic
from oic.oauth2 import Message, rndstr
from oic.oic import provider, ProviderConfigurationResponse

__author__ = 'roland'


def sort_string(string):
    _l = list(string)
    _l.sort()
    return "".join(_l)


class Server(oic.Server):
    def __init__(self, keyjar=None, ca_certs=None, verify_ssl=True):
        oic.Server.__init__(self, keyjar, ca_certs, verify_ssl)

        self.behavior_type = {}

    def make_id_token(self, session, loa="2", issuer="",
                      alg="RS256", code=None, access_token=None,
                      user_info=None, auth_time=0, exp=None, extra_claims=None):
        idt = oic.Server.make_id_token(self, session, loa, issuer, alg, code,
                                       access_token, user_info, auth_time, exp,
                                       extra_claims)

        if "ath" in self.behavior_type:  # modify the at_hash if available
            try:
                idt["at_hash"] = sort_string(idt["at_hash"])
            except KeyError:
                pass

        if "ch" in self.behavior_type:  # modify the c_hash if available
            try:
                idt["c_hash"] = sort_string(idt["c_hash"])
            except KeyError:
                pass

        if "issi" in self.behavior_type:  # mess with the iss value
            idt["iss"] = "https://example.org/"

        if "itsub" in self.behavior_type:  # missing sub claim
            try:
                del idt["itsub"]
            except KeyError:
                pass

        if "aud" in self.behavior_type:  # invalid aud claim
            try:
                idt["aud"] = "https://example.com/"
            except KeyError:
                pass

        if "iat" in self.behavior_type:  # missing iat claim
            try:
                del idt["iat"]
            except KeyError:
                pass

        if "nonce" in self.behavior_type:  # invalid nonce if present
            try:
                idt["nonce"] = "012345678"
            except KeyError:
                pass

        return idt


class Provider(provider.Provider):
    def __init__(self, name, sdb, cdb, authn_broker, userinfo, authz,
                 client_authn, symkey, urlmap=None, ca_certs="", keyjar=None,
                 hostname="", template_lookup=None, template=None,
                 verify_ssl=True, capabilities=None):

        provider.Provider.__init__(
            self, name, sdb, cdb, authn_broker, userinfo, authz, client_authn,
            symkey, urlmap, ca_certs, keyjar, hostname, template_lookup,
            template, verify_ssl, capabilities)

        self.claims_type = ["normal"]
        self.behavior_type = []
        self.server = Server(ca_certs=ca_certs, verify_ssl=verify_ssl)
        self.server.behavior_type = self.behavior_type
        self.claim_access_token = {}

    def id_token_as_signed_jwt(self, session, loa="2", alg="", code=None,
                               access_token=None, user_info=None, auth_time=0,
                               exp=None, extra_claims=None):
        _jws = provider.Provider.id_token_as_signed_jwt(
            self, session, loa=loa, alg=alg, code=code,
            access_token=access_token, user_info=user_info, auth_time=auth_time,
            exp=exp, extra_claims=extra_claims)

        if "idts" in self.behavior_type:  # mess with the signature
            #
            p = _jws.split(".")
            p[2] = sort_string(p[2])
            _jws = ".".join(p)

        return _jws

    def _collect_user_info(self, session, userinfo_claims=None):
        ava = provider.Provider._collect_user_info(self, session,
                                                   userinfo_claims)

        if "aggregated" in self.claims_type:  # add some aggregated claims
            extra = Message(eye_color="blue", shoe_size=8)
            _jwt = extra.to_jwt(algorithm="none")
            ava["_claim_names"] = Message(eye_color="src1", shoe_size="src1")
            ava["_claim_sources"] = Message(src1={"JWT": _jwt})

        if "distributed" in self.claims_type:
            urlbase = self.name
            _tok = rndstr()
            self.claim_access_token[_tok] = {"age": 30}
            ava["_claim_names"] = Message(age="src1")
            ava["_claim_sources"] = Message(
                src1={"endpoint": urlbase + "claim", "access_token": _tok})

        if "sub" in self.behavior_type:
            ava["uisub"] = "foobar"

        return ava

    def create_providerinfo(self, pcr_class=ProviderConfigurationResponse,
                            setup=None):
        _response = provider.Provider.create_providerinfo(self, pcr_class,
                                                          setup)

        if "isso" in self.behavior_type:
            _response["issuer"] = "https://example.com"

        return _response