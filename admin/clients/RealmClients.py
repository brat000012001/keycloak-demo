from utils.ApiRequest import ApiRequest
from utils.Keycloak import Keycloak
from utils.JwtToken import JwtToken
from utils.headers.BearerTokenAuthorizationHeader import BearerTokenAuthorizationHeader
import json
from .RealmClientModel import RealmClientModel
from .RealmClient import RealmClient


class RealmClients(ApiRequest):
    """Returns a list of realm clients.
    """
    def __init__(self, access_token: JwtToken):
        super(RealmClients,self).__init__('get realm clients')
        self._access_token = access_token
        self.add_header(BearerTokenAuthorizationHeader(access_token.token()))
        self._max = 100000

    def execute(self, kc: Keycloak):
        return self.get(kc, 'admin/realms/{}/clients'.format(kc.realm()))

    def client(self, id):
        """ Returns realm client

        :param id: a client id (not clientId)
        :return: an instance of RealmClient
        """
        return RealmClient(id, self._access_token)

    def get_clients(self, kc: Keycloak):
        """ Returns a set of clients in the specified realm.

        :param kc:
        :return: An key/value container where key is the client's id
        """
        response = self.execute(kc)
        if int(response.status() / 100) != 2:
            raise RuntimeError('Invalid response {0}'.format(response))

        client_map = dict()
        for rep in json.loads(response.data()):
            client_map[rep['clientId']] = RealmClientModel(rep)
        return client_map
