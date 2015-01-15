from oic import oic
from oic.oic import provider

__author__ = 'roland'


def sort_string(string):
    _l = list(string)
    _l.sort()
    return "".join(_l)


class Server(oic.Server):
    def __init__(self, keyjar=None, ca_certs=None, verify_ssl=True):
        oic.Server.__init__(self, keyjar, ca_certs, verify_ssl)

        self.err_type = {}

    def make_id_token(self, session, loa="2", issuer="",
                      alg="RS256", code=None, access_token=None,
                      user_info=None, auth_time=0, exp=None, extra_claims=None):
        idt = oic.Server.make_id_token(self, session, loa, issuer, alg, code,
                                       access_token, user_info, auth_time, exp,
                                       extra_claims)

        if "ath" in self.err_type:  # modify the at_hash if available
            try:
                idt["at_hash"] = sort_string(idt["at_hash"])
            except KeyError:
                pass

        if "ch" in self.err_type:  # modify the c_hash if available
            try:
                idt["c_hash"] = sort_string(idt["c_hash"])
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
        self.err_type = []
        self.server = Server(ca_certs=ca_certs, verify_ssl=verify_ssl)
        self.server.err_type = self.err_type

    def id_token_as_signed_jwt(self, session, loa="2", alg="", code=None,
                               access_token=None, user_info=None, auth_time=0,
                               exp=None, extra_claims=None):
        _jws = provider.Provider.id_token_as_signed_jwt(
            self, session, loa=loa, alg=alg, code=code,
            access_token=access_token, user_info=user_info, auth_time=auth_time,
            exp=exp, extra_claims=extra_claims)

        if "idts" in self.err_type:  # mess with the signature
            #
            p = _jws.split(".")
            p[2] = sort_string(p[2])
            _jws = ".".join(p)

        return _jws