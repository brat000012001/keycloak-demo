from utils.ApiRequest import ApiRequest
from utils.ApiResponse import ApiResponse
from utils.JwtToken import JwtToken
from utils.Keycloak import Keycloak
from utils.headers.BearerTokenAuthorizationHeader import BearerTokenAuthorizationHeader
import json


class EntitlementEndpoint(ApiRequest):
    ''' Enables client applications to query the server for user permissions.
    Entitlement API is a lightweight version of Authorization API for obtaining
    authorization data. Entitlement is not UMA compliant and does not require
    permission tickets.
    '''
    def __init__(self, token: JwtToken):
        super(EntitlementEndpoint,self).__init__('Entitlement API Endpoint')
        self.add_header(BearerTokenAuthorizationHeader(token.token()))

    def execute(self, kc:Keycloak):
        return self.get(kc, 'realms/{0}/authz/entitlement/'.format(kc.realm()))

    def get_entitlements(self, kc:Keycloak, resource_server_id:str) -> JwtToken:
        response = self.get(kc, 'realms/{0}/authz/entitlement/{1}'.format(kc.realm(), resource_server_id))
        if response.status() / 100 != 2:
            raise RuntimeError('Invalid response {0}'.format(response))

        parsed = json.loads(response.data())
        return JwtToken(parsed['rpt'])
