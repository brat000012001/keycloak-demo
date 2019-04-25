from utils.ApiRequest import ApiRequest
from utils.Keycloak import Keycloak
from utils.JwtToken import JwtToken
from utils.headers.BearerTokenAuthorizationHeader import BearerTokenAuthorizationHeader
import json
import urllib.parse


class RealmUsers(ApiRequest):
    '''Returns a list of realm users.
    Required role(s): master-realm:view-user
    To configure the roles, use the Client's "Scope" tab
    '''
    def __init__(self, access_token: JwtToken):
        super(RealmUsers,self).__init__('get realm users')
        self.add_header(BearerTokenAuthorizationHeader(access_token.token()))
        self._max = 100000

    def execute(self, kc: Keycloak):
        return self.get(kc, 'admin/realms/{}/users?max={}'.format(kc.realm(), self._max))

    def get_users(self, kc:Keycloak):
        self.clear_parameters()
        response = self.execute(kc)
        if int(response.status() / 100) != 2:
            raise RuntimeError('Invalid response {0}'.format(response))

        return json.loads(response.data())

    def find_user_by_username_or_email(self, username_or_email: str, kc: Keycloak):
        response = self.get(kc, 'admin/realms/{}/users?{}&max={}'.format(kc.realm(), urllib.parse.urlencode({'username':username_or_email}), self._max))
        if int(response.status() / 100) != 2:
            raise RuntimeError('Invalid response {}'.format(response))
        return json.loads(response.data())

    def get_user_federated_identities(self, userid: str, kc: Keycloak):
        response = self.get(kc, 'admin/realms/{}/users/{}/federated-identity'.format(kc.realm(), userid))
        if int(response.status() / 100) != 2:
            raise RuntimeError('Invalid response {}'.format(response))
        return json.loads(response.data())

    def remove_user_federated_identity(self,userid:str, provider: str, kc:Keycloak):
        """Delete the user's federated identity
        """
        response = self.delete(kc, "admin/realms/{}/users/{}/federated-identity/{}".format(kc.realm(), userid, provider))
        if int(response.status() / 100) != 2:
            raise RuntimeError('Invalid response {0}'.format(response))

    def delete_user(self, userid:str, kc:Keycloak):
        """Delete a user by username
        """
        response = self.delete(kc, "admin/realms/{}/users/{}".format(kc.realm(), userid))
        if int(response.status() / 100) != 2:
            raise RuntimeError('Invalid response {0}'.format(response))

    def get_users_summary(self,kc:Keycloak):
        response = self.get_users(kc)
        return [{'username':u['username'], 'e-mail': u['email'] if 'email' in u else None, 'id': u['id']} for u in response]
