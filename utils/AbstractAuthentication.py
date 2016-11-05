from .ApiResponse import ApiResponse
from .ApiRequest import ApiRequest
from .Keycloak import Keycloak
from .TokenResponse import TokenResponse


class AbstractAuthentication(ApiRequest):
    def __init_(self,name=None):
        super(AbstractAuthentication,self).__init__(name)

    def authenticate(self,kc:Keycloak) -> TokenResponse:
        response = self.execute(kc) # type: ApiResponse
        if response.status() / 100 != 2:
            raise RuntimeError('Invalid response {0}'.format(response))

        return TokenResponse(response.data())