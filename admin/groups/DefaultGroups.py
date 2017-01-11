from utils.ApiRequest import ApiRequest
from utils.Keycloak import Keycloak
from utils.JwtToken import JwtToken
from utils.headers.BearerTokenAuthorizationHeader import BearerTokenAuthorizationHeader
import json


class DefaultGroups(ApiRequest):
    '''Allows to get a list of default groups
    Required roles: master-realm:view-realm
    To test, go to 'Groups', create a new group, switch to 'Default Groups'
    and add the group to the 'Default Groups' list
    '''
    def __init__(self, access_token: JwtToken):
        super(DefaultGroups,self).__init__('get default groups')
        self.add_header(BearerTokenAuthorizationHeader(access_token.token()))


    def execute(self, kc: Keycloak):
        return self.get(kc, 'admin/realms/{}/default-groups'.format(kc.realm()))


    def get_default_groups(self, kc: Keycloak):
        response = self.execute(kc)
        if response.status() / 100 != 2:
            raise RuntimeError('Invalid response {0}'.format(response))

        return json.loads(response.data())
