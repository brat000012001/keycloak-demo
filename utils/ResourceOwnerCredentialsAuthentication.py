from .ApiRequest import ApiRequest
from .AbstractAuthentication import AbstractAuthentication
from .headers import HTTPHeader


class ResourceOwnerCredentialsAuthentication(AbstractAuthentication):

    def __init__(self,username:str,password:str,client_id:str):
        super(ResourceOwnerCredentialsAuthentication, self).__init__('password')
        self.add_parameter('username',username)
        self.add_parameter('password',password)
        self.add_parameter('grant_type', 'password')
        self.add_parameter('client_id',client_id)
        self.add_header(HTTPHeader('Content-type', 'application/x-www-form-urlencoded'))

    def execute(self, kc):
        '''Authenticates with Keycloak using Resource Owner Credentials Flow
        '''
        return self.post(kc,'realms/{0}/protocol/openid-connect/token'.format(kc.realm()))
