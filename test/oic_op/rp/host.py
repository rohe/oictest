HOST = "localhost"
PORT = 8088
BASE = "https://%s:%d/" % (HOST, PORT)

# If default port
#BASE = "https://%s/" % HOST

# If BASE is https these has to be specified
SERVER_CERT = "certs/server.crt"
SERVER_KEY = "certs/server.key"
CA_BUNDLE = None
VERIFY_SSL = False
