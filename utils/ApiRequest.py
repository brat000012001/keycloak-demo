import http.client
import urllib.parse
import ssl

from .ApiResponse import ApiResponse
from utils.headers.HTTPHeader import HTTPHeader
from .Keycloak import Keycloak


class ApiRequest:
    def __init__(self, name=None):
        self._name = name
        self._headers = []
        self._params = []

    def add_parameter(self,name,value):
        self._params.append((name,value))

    def clear_parameters(self):
        self._params = []

    def find_parameter(self,name:str):
        selection = [p for p in self._params if p[0] == name]
        if len(selection) != 1:
            return None
        else:
            selection[0][1]

    def update_parameter(self,name:str,value:str):
        for idx,item in enumerate(self._params):
            if item[1] == name:
                self._params[idx]=(name,value)
                break

    def add_header(self, header:HTTPHeader):
        if not isinstance(header,HTTPHeader): raise RuntimeError('header must be of HTTPHeader type')
        self._headers.append(header)
        return self

    def execute(self, kc:Keycloak): raise NotImplementedError()

    def _build_headers(self):
        return {header.name():header.value() for header in self._headers}

    def _build_params(self):
        return {t[0]:t[1] for t in self._params}

    def post(self, kc:Keycloak, relative_path:str):
        method = 'POST'
        return self._connect(kc,self._build_params(),self._build_headers(),method,relative_path)

    def get(self, kc:Keycloak, relative_path:str):
        method = 'GET'
        return self._connect(kc,self._build_params(),self._build_headers(),method,relative_path)

    def delete(self, kc:Keycloak, relative_path:str):
        method = 'DELETE'
        return self._connect(kc,self._build_params(),self._build_headers(),method,relative_path)

    def put(self, kc:Keycloak, relative_path:str):
        method = 'PUT'
        return self._connect(kc,self._build_params(),self._build_headers(),method,relative_path)

    def _connect(self, kc: Keycloak, params: dict, headers: dict,method:str,relative_path:str):
        if not isinstance(kc, Keycloak):
            raise RuntimeError('Must specify an instance of Keycloak type')
        ''' Establishes a connection to a running instance of Keycloak using
		specified parameters and the headers
		'''
        _params = urllib.parse.urlencode(params)
        return self._connect_(kc, _params, headers, method, relative_path)

    def _connect_(self, kc: Keycloak, body: str, headers: dict, method: str, relative_path: str):
        #print(_params)
        #print(headers)

        url = urllib.parse.urlparse(kc._server_root_url()) # type: urllib.parse.ParseResult

        try:
            if url.scheme == 'http':
                conn = http.client.HTTPSConnection(url.hostname,url.port)
            elif url.scheme == 'https':
                context = ssl.create_default_context()
                # check_hostname must be turned off before setting changing the verify mode
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                conn = http.client.HTTPSConnection(url.hostname,url.port,context=context)

            path = '{0}/{1}'.format(kc.root(),relative_path)
            # print(path)

            #print('scheme:{0}\nhost:{1}\nport:{2}\npath:{3}'.format(url.scheme,url.hostname,url.port,path))
            conn.request(method=method, url=path, body=body, headers=headers)

            response = conn.getresponse()

            status = response.status
            reason = response.reason
            data = response.read()
        finally:
            conn.close()

        return ApiResponse(status, reason, data)