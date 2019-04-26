from utils.ApiRequest import ApiRequest
from utils.Keycloak import Keycloak
from utils.JwtToken import JwtToken
from utils.headers.BearerTokenAuthorizationHeader import BearerTokenAuthorizationHeader
import json
from ..roles import RealmClientRole


class RealmClient(ApiRequest):
    """Represents a Keycloak client
    """
    def __init__(self, client_id: str, access_token: JwtToken):
        super(RealmClient,self).__init__('realm client')
        self._client_id = client_id
        self._access_token = access_token
        self.add_header(BearerTokenAuthorizationHeader(access_token.token()))

    def execute(self, kc: Keycloak):
        return self.get(kc, 'admin/realms/{}/clients/{}'.format(kc.realm(), self._client_id))

    def get_roles(self, kc: Keycloak):
        """ Returns a a list of client roles
        :param kc: a keycloak instance that includes the target realm
        :return: a list of client roles
        """
        response = self.get(kc, 'admin/realms/{}/clients/{}/roles'.format(kc.realm(), self._client_id))
        if int(response.status() / 100) != 2:
            raise RuntimeError('Invalid response {0}'.format(response))

        response = json.loads(response.data())
        result = dict()
        for roleRep in response:
            result[roleRep['name']] = RealmClientRole(self._client_id, roleRep, self._access_token)

        return result

    @property
    def client_id(self):
        return self._client_id
