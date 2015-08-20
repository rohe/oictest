import json
from oic.utils.http_util import Response, ServiceError, BadRequest


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

    def service_error(self, message, event_id=None, html=None):
        """
        :return A error response which is used to show error messages in the client
        """
        if event_id:
            message += " Please reference to this event by: " + event_id

        response_message = {"ExceptionMessage": message + "", "HTML": html}
        resp = ServiceError(json.dumps(response_message))
        return resp(self.environ, self.start_response)

    def bad_request(self):
        message = "Invalid request"
        resp = BadRequest(json.dumps(message))
        return resp(self.environ, self.start_response)