from utils.ApiRequest import ApiRequest
from utils.Keycloak import Keycloak
from utils.JwtToken import JwtToken
from utils.headers.BearerTokenAuthorizationHeader import BearerTokenAuthorizationHeader
from utils.ApiResponse import ApiResponse
import json


class ProtectionEndpoint(ApiRequest):
    ''' Represents the Protection API endpoint. Requires uma_protection scope
    '''
    def __init__(self, access_token: JwtToken):
        super(ProtectionEndpoint,self).__init__('Protection API Endpoint')
        self.add_header(BearerTokenAuthorizationHeader(access_token.token()))

    def execute(self, kc:Keycloak):
        return self.get(kc, 'realms/{}/authz/protection/resource_set'.format(kc.realm()))

    def get_resource_list(self, kc:Keycloak):
        response = self.execute(kc) # type: utils.ApiResponse
        if response.status() / 100 != 2:
            raise RuntimeError('Invalid response {0}'.format(response))
        return json.loads(response.data())

    def get_resource_description(self, kc: Keycloak, id: str):
        return self.get(kc, 'realms/{0}/authz/protection/resource_set/{1}'.format(kc.realm(), id))
