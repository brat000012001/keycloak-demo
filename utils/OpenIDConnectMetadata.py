from .Keycloak import Keycloak
from .ApiRequest import ApiRequest


class OpenIDConnectMetadata(ApiRequest):
    def __init__(self):
        super(OpenIDConnectMetadata,self).__init__('well-known-openid-configuration')

    def get_metadata(self,kc:Keycloak):
        return self.execute(kc)

    def execute(self, kc:Keycloak):
        return self.get(kc, 'realms/{}/.well-known/openid-configuration'.format(kc.realm()))