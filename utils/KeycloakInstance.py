from .Keycloak import Keycloak
from .OpenIDConnectMetadata import OpenIDConnectMetadata


class KeycloakInstance(Keycloak):
    '''Represents an instance of Keycloak with OIDC metadata. The type would not
    have been needed have python could handle cyclic module dependencies.
    '''
    def __init__(self, server='localhost', http_port=8080, https_port=8443, realm='master', ssl_required=False):
        super(KeycloakInstance,self).__init__(server,http_port,https_port,realm,ssl_required)
        self._metadata = OpenIDConnectMetadata()

    def get_metadata(self):
        return self._metadata.get_metadata(self)
