from utils import KeycloakInstance
from utils import ResourceOwnerCredentialsAuthentication
from utils import RefreshTokenAuthentication
from utils import ClientCredentialsApi
from utils import JwtToken
from admin.users import RealmUsers
from admin.events import AdminEvents
from admin.users import UserEmailVerification
from admin.authorization import ProtectionEndpoint
from admin.authorization import EntitlementEndpoint
from utils import TokenResponse
from datetime import datetime


def display_login_response(response: TokenResponse):
    # print the response
    print(response)

    print('==========Current Time in UTC ============')
    print(datetime.utcnow().isoformat())

    # Pretty-print the access token
    print('==========Access Token============')
    access_token = JwtToken(response.access_token())
    print(access_token)
    print(datetime.utcfromtimestamp(int(access_token.token_decoded()["iat"])).isoformat())
    print(datetime.utcfromtimestamp(int(access_token.token_decoded()["exp"])).isoformat())

    # Pretty-print the ID token
    print('==========ID Token============')
    id_token = JwtToken(response.id_token())
    print(id_token)
    print(datetime.utcfromtimestamp(int(id_token.token_decoded()["iat"])).isoformat())
    print(datetime.utcfromtimestamp(int(id_token.token_decoded()["exp"])).isoformat())

    # Pretty-print the refresh token
    print('==========Refresh Token============')
    refresh_token = JwtToken(response.refresh_token())
    print(refresh_token)
    print(datetime.utcfromtimestamp(int(refresh_token.token_decoded()["iat"])).isoformat())
    print(datetime.utcfromtimestamp(int(refresh_token.token_decoded()["exp"])).isoformat())


def login_with_client_credentials(kc:KeycloakInstance) -> TokenResponse:
    '''
    Obtains an access token using client credentials.
    :param kc: an instance of Keycloak
    :return: None
    '''

    authentication_method = ClientCredentialsApi(
        client_id='service-account-client',client_secret='9e853caa-9956-4505-9299-4dd83bd0069b')

    response = authentication_method.authenticate(kc)

    display_login_response(response)

    return response


def login_with_refresh_token(kc:KeycloakInstance, refresh_token: str) -> TokenResponse:
    refresh_token_auth = RefreshTokenAuthentication(refresh_token,
                                                    client_id='loopback-client',
                                                    client_secret='5f9a4922-ff5a-427c-a046-b854fb51a29c')
    response = refresh_token_auth.refresh(kc)
    display_login_response(response)
    return response


def login_with_user_credentials(kc:KeycloakInstance) -> TokenResponse:
    '''
    Obtains an access token using user credentials
    :param kc: an instance of Keycloak
    :return: None
    '''

    authentication_method = ResourceOwnerCredentialsAuthentication('pnalyvayko@agi.com.com',
    'intrepid','loopback-client', '5f9a4922-ff5a-427c-a046-b854fb51a29c')
    authentication_method.set_offline_access(True)

    response = authentication_method.authenticate(kc)

    display_login_response(response)

    return response


def demo_protection_api(kc:KeycloakInstance, response: TokenResponse):
    # Demo the protection API
    print('\nRequesting protected resources using the Protection API')
    protection = ProtectionEndpoint(JwtToken(response.access_token()))
    try:
        print (protection.get_resource_list(kc))
        for resource_id in protection.get_resource_list(kc):
            print (protection.get_resource_description(kc, resource_id))
    except RuntimeError as e:
        print(e)


def demo_entitlement_api(kc:KeycloakInstance, response: TokenResponse):
    print('\nRequesting entitlements using Entitlement API')
    entitlement = EntitlementEndpoint(JwtToken(response.access_token()))
    print(entitlement.get_entitlements(kc, 'service-account-client'))


def demo_get_list_of_users_api(kc: KeycloakInstance, response: TokenResponse):
    '''Get a list of realm users.
    Requires master-realm:view-user role
    To verify, check the JWT access token and look for:
    "resource_access": {
        "master-realm": {
             "roles": [
                  "view-users"
             ]
        }
     }
    '''
    users = RealmUsers(JwtToken(response.access_token()))

    # Get a list of users and display a short summary for each user
    list_of_users = users.get_users_summary(kc)
    print('\n'.join([str(d) for d in list_of_users]))

    # Iterate over the users and send e-mail verification
    for u in list_of_users:
        if not u['e-mail'] is None:
            verify = UserEmailVerification(u['id'], JwtToken(response.access_token()))
            sent = verify.send_email_verification(kc)
            print(sent)


def demo_admin_events_api(kc: KeycloakInstance, response: TokenResponse):
    # Get all admin events
    admin_events = AdminEvents(JwtToken(response.access_token()))
    try:
        list_of_admin_events = admin_events.get_admin_events(kc)
        print('\n'.join([str(d) for d in list_of_admin_events]))
    except RuntimeError as e:
        print(e)

if __name__ == "__main__":
    kc = KeycloakInstance(server='online.stk.com',ssl_required=True)

    # Get OIDC endpoints
    print (kc.get_metadata())

    # Get access token, id token and refresh token
    response = login_with_user_credentials(kc)

    # Demo the Protection API
    demo_protection_api(kc, response)

    # Demo the entitlement API
    demo_entitlement_api(kc, response)

    # Demo admin API
    demo_get_list_of_users_api(kc, response)

    # Get all admin events
    demo_admin_events_api(kc, response)

    response = login_with_refresh_token(kc, response.refresh_token())

    # Request a list of users again, but this time the client
    # will pass the access token returned by the authorization server
    # in response to the refresh token request
    demo_get_list_of_users_api(kc, response)
