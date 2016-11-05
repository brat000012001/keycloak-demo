from utils.ApiRequest import ApiRequest
from utils.Keycloak import Keycloak
from utils.JwtToken import JwtToken
from utils.headers.BearerTokenAuthorizationHeader import BearerTokenAuthorizationHeader
import json


class AdminEvents(ApiRequest):
    '''Returns all admin events
    Required role(s): master-realm:view-events
    To configure the roles, use the Client's "Scope" tab
    '''
    def __init__(self, access_token: JwtToken):
        super(AdminEvents,self).__init__('get admin events')
        self.add_header(BearerTokenAuthorizationHeader(access_token.token()))

    def execute(self, kc: Keycloak):
        return self.get(kc, 'admin/realms/{}/admin-events'.format(kc.realm()))

    def get_admin_events(self, kc: Keycloak):
        response = self.execute(kc)
        if response.status() / 100 != 2:
            raise RuntimeError('Invalid response {0}'.format(response))

        return json.loads(response.data())
