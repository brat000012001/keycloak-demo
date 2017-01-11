from utils.ApiRequest import ApiRequest
from utils.Keycloak import Keycloak
from utils.JwtToken import JwtToken
from utils.headers.BearerTokenAuthorizationHeader import BearerTokenAuthorizationHeader
import json


class Groups(ApiRequest):
    '''Allows to get a list of groups
    Required roles: master-realm:view-realm
    To test, go to 'Groups' and create a new group. Optionally, create a subgroup
    within the newly created group
    '''
    def __init__(self, access_token: JwtToken):
        super(Groups,self).__init__('get groups')
        self.add_header(BearerTokenAuthorizationHeader(access_token.token()))


    def execute(self, kc: Keycloak):
        return self.get(kc, 'admin/realms/{}/groups'.format(kc.realm()))


    def get_groups(self, kc: Keycloak):
        response = self.execute(kc)
        if response.status() / 100 != 2:
            raise RuntimeError('Invalid response {0}'.format(response))

        return json.loads(response.data())
