import json
from oic.utils.http_util import Response, ServiceError

class ResponseEncoder:
    def __init__(self, environ=None, start_response=None):
        self.environ = environ
        self.start_response = start_response

    def return_json(self, text):
        """
        :return A response with the content type json
        """
        resp = Response(text, headers=[('Content-Type', "application/json")])
        return resp(self.environ, self.start_response)

    def service_error(self, message, html=None):
        """
        :return A error response which is used to show error messages in the client
        """
        message = {"ExceptionMessage": message, "HTML": html}
        resp = ServiceError(json.dumps(message))
        return resp(self.environ, self.start_response)