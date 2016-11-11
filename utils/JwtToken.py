import jwt
import json


class JwtToken:
    '''A JWT token
    '''
    def __init__(self, token):
        self._token = token
        self._decoded = None

    def token(self):
        return self._token

    def __str__(self):
        return json.dumps(self.token_decoded(), indent=4, sort_keys=True)

    def token_decoded(self):
        if self._decoded is None:
            self._decoded = jwt.decode(self._token, verify=False)
        return self._decoded
