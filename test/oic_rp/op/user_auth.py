__author__ = 'roland'

from oic.utils.authn.user import UsernamePasswordMako
from oic.utils.authn.user import create_return_url


class UsernamePasswordMakoMod(UsernamePasswordMako):
    def generate_return_url(self, return_to, uid, path=""):
        return create_return_url(return_to, uid, **{self.query_param: "true"})
