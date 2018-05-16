from .ApiResponse import ApiResponse
from .ApiRequest import ApiRequest
from .Keycloak import Keycloak
from .TokenResponse import TokenResponse


class AbstractAuthentication(ApiRequest):
    def __init_(self,name=None):
        super(AbstractAuthentication,self).__init__(name)

    def add_offline_access_scope(self):
        self._add_offline_access_scope('offline_access', True)

    def remove_offline_access_scope(self):
        self._add_offline_access_scope('offline_access', False)

    def _add_offline_access_scope(self, scope, request: bool):
        ''' Whether to request the offline_access token '''
        if request:
            self.add_parameter('scope', scope)
        else:
            scope = self.find_parameter('scope')
            if not scope is None:
                if scope in scope:
                    scope = scope.replace(scope,'').strip()
                    self.update_parameter('scope', scope)

    def authenticate(self,kc:Keycloak) -> TokenResponse:
        response = self.execute(kc) # type: ApiResponse
        if response.status() / 100 != 2:
            raise RuntimeError('Invalid response {0}'.format(response))

        return TokenResponse(response.data())