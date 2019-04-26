from utils.TokenResponse import TokenResponse


class ActionBase:
    def __init__(self, kc_server: str, kc_port: int):
        self._kc_server = kc_server
        self._kc_port = kc_port

    def evaluate(self, response: TokenResponse, args, interactive_mode):
        raise RuntimeError('Derived classes must implement the method')
