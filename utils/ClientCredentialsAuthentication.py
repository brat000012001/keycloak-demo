from .ApiRequest import ApiRequest
from .headers import ConfidentialClientAuthorizationHeader
from .headers import HTTPHeader
from .Keycloak import Keycloak
from .AbstractAuthentication import AbstractAuthentication


class ClientCredentialsApi(AbstractAuthentication):

    def __init__(self,client_id,client_secret):
        super(ClientCredentialsApi, self).__init__('client_credentials')
        self.add_header(ConfidentialClientAuthorizationHeader(client_id,client_secret))
        self.add_parameter('grant_type','client_credentials')
        self.add_header(HTTPHeader('Content-type','application/x-www-form-urlencoded'))

    def execute(self, kc: Keycloak):
        return self.post(kc,'realms/{0}/protocol/openid-connect/token'.format(kc.realm()))