__author__ = 'roland'


def rm(args, conv, kwargs):
    for arg in kwargs["args"]:
        try:
            del args[arg]
        except KeyError:
            pass
        
    return args