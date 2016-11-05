from .HTTPHeader import HTTPHeader


class BearerTokenAuthorizationHeader(HTTPHeader):
    def __init__(self,bearer_token):
        super(BearerTokenAuthorizationHeader,self).__init__('Authorization', 'Bearer {0}'.format(bearer_token))