__author__ = 'roland'


class VerifyError(object):
    def __init__(self):
        pass

    def __call__(self, response):
        pass


class VerifyAtHashError(VerifyError):
    def __init__(self):
        VerifyError.__init__(self)

    def __call__(self, response):
        pass
