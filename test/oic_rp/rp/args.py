import copy
from oictest import NotSupported
from rrtest.check import ERROR
from rrtest.check import WARNING

__author__ = 'roland'

def add_test_result(conv, status, message, tid="-"):
    conv.test_output.append({"id": str(tid),
                             "status": status,
                             "message": message})





def endpoint_support(client, endpoint):
    if endpoint in client.provider_info:
        return True
    else:
        return False




def not_supported(val, given):
    if isinstance(val, basestring):
        if isinstance(given, basestring):
            try:
                assert val == given
            except AssertionError:
                return [val]
        else:
            try:
                assert val in given
            except AssertionError:
                return [val]
    elif isinstance(val, list):
        if isinstance(given, basestring):
            _missing = [v for v in val if v != given]
        else:
            _missing = []
            for _val in val:
                try:
                    assert _val in given
                except AssertionError:
                    _missing.append(_val)
        if _missing:
            return _missing
    else:
        try:
            assert val == given
        except AssertionError:
            return [val]

    return None


def support(conv, args):
    pi = conv.client.provider_info
    stat = 0
    for ser in ["warning", "error"]:
        if ser not in args:
            continue
        if ser == "warning":
            err = WARNING
        else:
            err = ERROR
        for key, val in args[ser].items():
            try:
                _ns = not_supported(val, pi[key])
            except KeyError:  # Not defined
                conv.trace.info(
                    "'%s' not defined in provider configuration" % key)
            else:
                if _ns:
                    add_test_result(
                        conv, err,
                        "OP is not supporting %s according to '%s' in the provider configuration" % (val, key))
                    stat = err

    return stat

# def function(self, spec, req_args):
#     if isinstance(spec, tuple):
#         func, args = spec
#     else:
#         func = spec
#         args = {}
#
#     try:
#         req_args = func(req_args, self.conv, args)
#     except KeyError as err:
#         self.conv.trace.error("function: %s failed" % func)
#         self.conv.trace.error(str(err))
#         raise NotSupported
#     except ConfigurationError:
#         raise
#     else:
#         return req_args

def setup(kwa, conv):
    kwargs = copy.deepcopy(kwa)  # decouple

    # evaluate possible functions
    try:
        spec = kwargs["function"]
    except KeyError:
        pass
    else:
        try:
            kwargs["request_args"] = run_func(spec, conv,
                                              kwargs["request_args"])
        except KeyError:
            kwargs["request_args"] = run_func(spec, conv, {})

        del kwargs["function"]

    try:
        spec = kwargs["kwarg_func"]
    except KeyError:
        pass
    else:
        kwargs = run_func(spec, conv, kwargs)
        del kwargs["kwarg_func"]

    try:
        res = support(conv, kwargs["support"])
        if res >= ERROR:
            raise NotSupported()

        del kwargs["support"]
    except KeyError:
        pass

    return kwargs
