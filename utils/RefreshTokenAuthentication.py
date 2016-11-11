from .ApiRequest import ApiRequest
from .AbstractAuthentication import AbstractAuthentication
from .headers import HTTPHeader
from .headers import ConfidentialClientAuthorizationHeader
from utils.Keycloak import Keycloak
from utils.TokenResponse import TokenResponse


class RefreshTokenAuthentication(ApiRequest):

    def __init__(self,refresh_token:str,client_id:str, client_secret:str):
        super(RefreshTokenAuthentication, self).__init__('password')
        self.add_parameter('refresh_token',refresh_token)
        self.add_parameter('grant_type', 'refresh_token')
        self.add_header(ConfidentialClientAuthorizationHeader(client_id,client_secret))
        self.add_header(HTTPHeader('Content-type', 'application/x-www-form-urlencoded'))

    def execute(self, kc):
        '''Request access token
        '''
        return self.post(kc,'realms/{0}/protocol/openid-connect/token'.format(kc.realm()))

    def refresh(self,kc:Keycloak):
        response = self.execute(kc)
        if response.status() / 100 != 2:
            raise RuntimeError('Invalid response {0}'.format(response))
        return TokenResponse(response.data())
