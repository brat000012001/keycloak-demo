from utils.ApiRequest import ApiRequest
from utils.Keycloak import Keycloak
from utils.JwtToken import JwtToken
from utils.headers import HTTPHeader
from utils.headers.BearerTokenAuthorizationHeader import BearerTokenAuthorizationHeader
import json
from admin.clients import RealmClientModel


class RealmUserRoleMappings(ApiRequest):
    """Client level role mappings for a user
    """
    def __init__(self, userid: str, access_token: JwtToken):
        super(RealmUserRoleMappings,self).__init__('realm client role mappings for user')
        self._userid = userid
        self._access_token = access_token
        self.add_header(BearerTokenAuthorizationHeader(access_token.token()))
        self.add_header(HTTPHeader('Content-Type','application/json'))

    def execute(self, kc: Keycloak): pass # return self.get(kc, 'admin/realms/{}/clients/{}'.format(kc.realm(), self._client_id))

    def add_role_mappings(self, realm_client: RealmClientModel, roles: list, kc: Keycloak):
        """ Adds client level role mappings to a user
        :param roles: an array of RealmClientRole objects
        :param realm_client: RealmClient
        :param kc: a keycloak instance that includes the target realm
        :return: None
        """
        body = json.dumps(roles)
        response = self._connect_(kc=kc, body=body, headers=self._build_headers(), method='POST',
                                  relative_path='admin/realms/{}/users/{}/role-mappings/clients/{}'.format(
                                                    kc.realm(), self._userid, realm_client['id']))
        if int(response.status() / 100) != 2:
            raise RuntimeError('Invalid response {0}'.format(response))

    def get_role_mappings(self, realm_client: RealmClientModel, kc: Keycloak):
        """ Get client level role mappings for a user
        :param realm_client: RealmClient
        :param kc: a keycloak instance that includes the target realm
        :return: an array og client level role mappings for specified user
        """
        response = self.get(kc=kc, relative_path='admin/realms/{}/users/{}/role-mappings/clients/{}'.format(
                                                    kc.realm(), self._userid, realm_client['id']))
        if int(response.status() / 100) != 2:
            raise RuntimeError('Invalid response {0}'.format(response))

        return json.load(response.data())