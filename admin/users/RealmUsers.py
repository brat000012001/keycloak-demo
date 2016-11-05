from utils.ApiRequest import ApiRequest
from utils.Keycloak import Keycloak
from utils.JwtToken import JwtToken
from utils.headers.BearerTokenAuthorizationHeader import BearerTokenAuthorizationHeader
import json

class RealmUsers(ApiRequest):
    '''Returns a list of realm users.
    Required role(s): master-realm:view-user
    To configure the roles, use the Client's "Scope" tab
    '''
    def __init__(self, access_token: JwtToken):
        super(RealmUsers,self).__init__('get realm users')
        self.add_header(BearerTokenAuthorizationHeader(access_token.token()))

    def execute(self, kc: Keycloak):
        return self.get(kc, 'admin/realms/{}/users'.format(kc.realm()))

    def get_users(self, kc:Keycloak):
        response = self.execute(kc)
        if response.status() / 100 != 2:
            raise RuntimeError('Invalid response {0}'.format(response))

        return json.loads(response.data())

    def get_users_summary(self,kc:Keycloak):
        response = self.get_users(kc)
        return [{'username':u['username'], 'e-mail': u['email'] if 'email' in u else None, 'id': u['id']} for u in response]
