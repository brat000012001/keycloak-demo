import jwt
import json


class JwtToken:
    '''A JWT token
    '''
    def __init__(self, token):
        self._token = token

    def token(self):
        return self._token

    def token_decoded(self):
        decoded = jwt.decode(self._token, verify=False)
        #print(decoded)
        return json.dumps(decoded,indent=4,sort_keys=True)