from utils import KeycloakInstance
from utils import ResourceOwnerCredentialsAuthentication
from utils import TokenResponse
from utils import RefreshTokenAuthentication


class LoginAction:
    @staticmethod
    def login(kc_server: str,
                kc_port: int,
                username: str,
                password: str,
                realm: str,
                client_id: str,
                client_secret: str) -> TokenResponse:
            """
            Obtains an access token using user credentials
            :param realm: admin realm (typically, master)
            :param password:  admin password
            :param username: admin username
            :param kc_port: IdP port #
            :param kc_server: IdP DNS or IP Address
            :param client_id: OAuth2 client_id
            :param client_secret: OAuth2 client_secret
            :return: Returns OAuth2 response that includes a refresh and access tokens
            """

            admin_kc = KeycloakInstance(server=kc_server,
                                        https_port=kc_port,
                                        realm=realm,
                                        ssl_required=True)
            authentication_method = ResourceOwnerCredentialsAuthentication(username,
                                                                           password,
                                                                           client_id,
                                                                           client_secret)
            # authentication_method.add_offline_access_scope()
            response = authentication_method.authenticate(admin_kc)
            return response

    @staticmethod
    def refresh(self, kc_server: str,
                          kc_port: int,
                          opaque_refresh_token,
                          realm: str,
                          client_id: str,
                          client_secret: str) -> TokenResponse:
            """
            Obtains an access token using user credentials
            :param client_id: OAuth2 client_id
            :param client_secret: OAuth2 client_secret
            :param realm: admin realm (typically, master)
            :param opaque_refresh_token:
            :param kc_port: IdP port #
            :param kc_server: IdP DNS or IP Address
            :return: TokenResponse
            """

            admin_kc = KeycloakInstance(server=kc_server,
                                        https_port=kc_port,
                                        realm=realm,
                                        ssl_required=True)
            authentication_method = RefreshTokenAuthentication(opaque_refresh_token, client_id, client_secret)
            response = authentication_method.refresh(admin_kc)
            return response
