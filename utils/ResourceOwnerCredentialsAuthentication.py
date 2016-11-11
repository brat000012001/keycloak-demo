from .ApiRequest import ApiRequest
from .AbstractAuthentication import AbstractAuthentication
from .headers import HTTPHeader
from .headers import ConfidentialClientAuthorizationHeader


class ResourceOwnerCredentialsAuthentication(AbstractAuthentication):

    def __init__(self,username:str,password:str,client_id:str, client_secret:str):
        super(ResourceOwnerCredentialsAuthentication, self).__init__('password')
        self.add_parameter('username',username)
        self.add_parameter('password',password)
        self.add_parameter('grant_type', 'password')
        self.add_header(ConfidentialClientAuthorizationHeader(client_id,client_secret))
        self.add_header(HTTPHeader('Content-type', 'application/x-www-form-urlencoded'))

    def set_offline_access(self, request: bool):
        ''' Whether to request the offline_access token '''
        if request:
            self.add_parameter('scope', 'offline_access')
        else:
            scope = self.find_parameter('scope')
            if not scope is None:
                if 'offline_access' in scope:
                    scope = scope.replace('offline_access','').strip()
                    self.update_parameter('scope', scope)

    def execute(self, kc):
        '''Authenticates with Keycloak using Resource Owner Credentials Flow
        '''
        return self.post(kc,'realms/{0}/protocol/openid-connect/token'.format(kc.realm()))
