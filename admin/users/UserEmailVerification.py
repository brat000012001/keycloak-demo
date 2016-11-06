from utils.ApiRequest import  ApiRequest
from utils.Keycloak import Keycloak
from utils.JwtToken import JwtToken
from utils.headers.BearerTokenAuthorizationHeader import BearerTokenAuthorizationHeader


class UserEmailVerification(ApiRequest):
    '''Sends an e-mail verification to a specified user
    Required roles: master-realm:manage-users
    To configure the roles, use the Client's "Scope" tab to include
    desired scopes into the access token
    Use the service account roles to add master-realm:manage-users to scope mappings
    '''
    def __init__(self, userid: str, access_token: JwtToken, redirect_uri: str = None):
        super(UserEmailVerification,self).__init__('user e-mail verification')
        self.add_header(BearerTokenAuthorizationHeader(access_token.token()))
        self._userid = userid
        if not redirect_uri is None: self.add_parameter('redirect_uri', redirect_uri)

    def execute(self, kc: Keycloak):
        return self.put(kc, 'admin/realms/{0}/users/{1}/send-verify-email'.format(kc.realm(), self._userid))

    def send_email_verification(self, kc: Keycloak):
        return self.execute(kc)