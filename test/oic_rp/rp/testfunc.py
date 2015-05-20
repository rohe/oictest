from urlparse import urlparse

__author__ = 'roland'

def resource(oper, args):
    _p = urlparse(oper.conv.conf.ISSUER)
    oper.op_args["resource"] = args["pattern"].format(oper.conv.test_id, _p.netloc)


def expect_exception(oper, args):
    oper.expect_exception = args


def set_request_args(oper, args):
    oper.req_args.update(args)


def set_jwks_uri(oper, args):
    oper.req_args["jwks_uri"] = oper.conv.client.jwks_uri


def set_op_args(oper, args):
    oper.op_args.update(args)