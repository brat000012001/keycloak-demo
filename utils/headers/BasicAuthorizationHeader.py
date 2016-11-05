from utils.headers.HTTPHeader import HTTPHeader


class BasicAuthorizationHeader(HTTPHeader):

    def __init__(self,token):
        super(BasicAuthorizationHeader,self).__init__('Authorization', 'Basic {0}'.format(token))

