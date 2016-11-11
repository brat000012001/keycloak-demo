import json


class TokenResponse:

    def __init__(self,raw_response):
        self._parsed = json.loads(raw_response)

    def id_token(self) -> str:
        return self._parsed['id_token']

    def access_token(self) -> str:
        return self._parsed['access_token']

    def session_state(self):
        return self._parsed['session_state']

    def refresh_token(self) -> str:
        return self._parsed['refresh_token']

    def expires_in(self):
        return self._parsed['expires_in']

    def refresh_expires_in(self):
        return self._parsed['refresh_expires_in']

    def token_type(self):
        return self._parsed['token_type']

    def not_before_policy(self):
        return self._parsed['not-before-policy']

    def __str__(self):
        return json.dumps(self._parsed,indent=4,sort_keys=True)