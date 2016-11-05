
class Keycloak:
    def __init__(self, server='localhost', http_port=8080, https_port=8443, realm='master', ssl_required=False):
        self._server = server
        self._http_port = http_port
        self._https_port = https_port
        self._realm = realm
        self._ssl_required = ssl_required
        self._root = '/auth'

    def realm(self): return self._realm

    def root(self): return self._root

    def ssl_required(self, required):
        self._ssl_required = bool(required)

    def _server_root_url(self):
        protocol = 'http'
        port = self._http_port

        if self._ssl_required:
            protocol = 'https'
            port = self._https_port

        return '{0}://{1}:{2}'.format(protocol, self._server, port)
