from utils.ApiRequest import ApiRequest
from utils.Keycloak import Keycloak
from utils.JwtToken import JwtToken
from utils.headers.BearerTokenAuthorizationHeader import BearerTokenAuthorizationHeader
import json
from ..users import RealmUserModel


class RealmClientRole(ApiRequest):
    """Represents a Keycloak client role
    """
    def __init__(self, client_id: str, role_rep, access_token: JwtToken):
        super(RealmClientRole,self).__init__('realm client role')
        self._client_id = client_id
        self._role_rep = role_rep
        self._max = 100000
        self.add_header(BearerTokenAuthorizationHeader(access_token.token()))

    def execute(self, kc: Keycloak): pass #return self.get(kc, 'admin/realms/{}/clients/{}'.format(kc.realm(), self._client_id))

    def get_users(self, kc: Keycloak):
        """ Returns a a list of users with specified role
        :param kc: a keycloak instance that includes the target realm
        :return: a list of users with specified role
        """
        response = self.get(kc, 'admin/realms/{}/clients/{}/roles/{}/users?max={}'.format(kc.realm(),
                                                                                   self._client_id,
                                                                                   self._role_rep['name'],
                                                                                          self._max))
        if int(response.status() / 100) != 2:
            raise RuntimeError('Invalid response {0}'.format(response))

        result = dict()
        for rep in json.loads(response.data()):
            result[rep['username']] = RealmUserModel(rep)

        return result

    def __getitem__(self, item):
        return self._role_rep[item]

    def __str__(self):
        return str(self._role_rep)
