from .BasicAuthorizationHeader import BasicAuthorizationHeader
from base64 import urlsafe_b64encode


class ConfidentialClientAuthorizationHeader(BasicAuthorizationHeader):
    def __init__(self, client_id, client_secret):
        token = urlsafe_b64encode(bytes('{0}:{1}'.format(client_id,client_secret),'utf-8')).decode('utf-8')
        super(ConfidentialClientAuthorizationHeader,self).__init__(token)
