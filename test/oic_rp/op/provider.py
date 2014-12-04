from oic import oic
from oic.oic import provider

__author__ = 'roland'


class Server(oic.Server):
    def __init__(self, keyjar=None, ca_certs=None, verify_ssl=True):
        oic.Server.__init__(self, keyjar, ca_certs, verify_ssl)

        self.err_type = {}

    def make_id_token(self, session, loa="2", issuer="", alg="RS256", code=None,
                      access_token=None, user_info=None, auth_time=0, **kwargs):
        idt = oic.Server.make_id_token(self, session, loa, issuer, alg, code,
                                       access_token, user_info, auth_time)

        if "ath" in self.err_type:  # modify the at_hash if available
            try:
                idt["at_hash"].sort()
            except KeyError:
                pass

        if "ch" in self.err_type:  # modify the c_hash if available
            try:
                idt["c_hash"].sort()
            except KeyError:
                pass


class Provider(provider.Provider):
    def __init__(self, name, sdb, cdb, authn_broker, userinfo, authz,
                 client_authn, symkey, urlmap=None, ca_certs="", keyjar=None,
                 hostname="", template_lookup=None, template=None,
                 verify_ssl=True, capabilities=None):

        provider.Provider.__init__(
            self, name, sdb, cdb, authn_broker, userinfo, authz, client_authn,
            symkey, urlmap, ca_certs, keyjar, hostname, template_lookup,
            template, verify_ssl, capabilities)

        self.claims_type = "normal"
        self.err_type = []
        self.server = Server(ca_certs=ca_certs, verify_ssl=verify_ssl)
        self.server.err_type = self.err_type

    def providerinfo_endpoint(self, handle="", **kwargs):
        resp = provider.Provider.providerinfo_endpoint(self, handle, **kwargs)
        return resp

    def authorization_endpoint(self, request="", cookie=None, **kwargs):
        resp = provider.Provider.authorization_endpoint(self, request, cookie,
                                                        **kwargs)
        return resp

    def token_endpoint(self, request="", authn=None, **kwargs):
        resp = provider.Provider.token_endpoint(self, request, authn, **kwargs)
        return resp

    def userinfo_endpoint(self, request="", **kwargs):
        resp = provider.Provider.userinfo_endpoint(self, request, **kwargs)
        return resp

    def register_endpoint(self, request="", **kwargs):
        resp = provider.Provider.register_endpoint(self, request, **kwargs)
        return resp

    def verify_endpoint(self, request="", cookie=None, **kwargs):
        resp = provider.Provider.register_endpoint(self, request, cookie,
                                                   **kwargs)
        return resp

