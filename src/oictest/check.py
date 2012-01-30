__author__ = 'rohe0002'

from oic.oic.message import IdToken

class Test():
    """ General test
    """
    id = "test"

    def __init__(self, **kwargs):
        self._status = 1
        self._significance = -1
        self.content = None
        self.url = None
        self._arg = kwargs

    def _func(self):
        pass

    def __call__(self):
        self._func()
        res = {
            "id": self.id,
            "name": self.__doc__,
            "status": self._status,
        }

        if self._significance >= 0:
            res["significance"] = self._significance

        if self.content:
            res["content"] = self.content
        if self.url:
            res["url"] = self.url

        return res

class CmpIdtoken(Test):
    """
    Compares the JSON received as a CheckID response with my own
    interpretation of the IdToken.
    """
    id = "compare-idoken-received-with-check_id-response"

    def __init__(self, client, item):
        """
        :param client: A Client instance
        :param item: A list of responses collected during a flow
        """
        Test.__init__(self, client=client, item=item)

    def _func(self):
        idt = IdToken.from_jwt(self._arg["item"][0].id_token,
                               key=self._arg["client"].client_secret)
        if idt.dictionary() == self._arg["item"][-1].dictionary():
            return
        else:
            self._status = 0
            self._significance = 3

class HTTPResponse(Test):
    """
    Checks that the HTTP response status is within the 200 or 300 range
    """
    id = "check-http-response"

    def __init__(self, url, response, content):
        Test.__init__(self, url=url, response=response, content=content)

    def _func(self):
        if self._arg["response"].status >= 400 :
            self._status = 0
            self._significance = 3
            self.content = self._arg["content"]
            self.url = self._arg["url"]
            self.http_status = self._arg["response"].status
        else:
            self.status = 1