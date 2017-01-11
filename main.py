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
from admin.groups import DefaultGroups
from admin.groups import Groups


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


def login_with_client_credentials(kc: KeycloakInstance) -> TokenResponse:
    '''
    Obtains an access token using client credentials.
    :param kc: an instance of Keycloak
    :return: None
    '''

    authentication_method = ClientCredentialsApi(
        client_id='service-account-client', client_secret='9aa57c07-6d26-4385-ac95-8075303cc825')

    response = authentication_method.authenticate(kc)

    display_login_response(response)

    return response


def login_with_refresh_token(kc: KeycloakInstance, refresh_token: str) -> TokenResponse:
    refresh_token_auth = RefreshTokenAuthentication(refresh_token,
                                                    client_id='service-account-client',
                                                    client_secret='9aa57c07-6d26-4385-ac95-8075303cc825')
    response = refresh_token_auth.refresh(kc)
    display_login_response(response)
    return response


def login_with_user_credentials(kc: KeycloakInstance) -> TokenResponse:
    '''
    Obtains an access token using user credentials
    :param kc: an instance of Keycloak
    :return: None
    '''

    authentication_method = ResourceOwnerCredentialsAuthentication('owner email',
                                                                   'owner password', 'service-account-client',
                                                                   '9aa57c07-6d26-4385-ac95-8075303cc825')
    authentication_method.set_offline_access(True)

    response = authentication_method.authenticate(kc)

    display_login_response(response)

    return response


def demo_protection_api(kc: KeycloakInstance, response: TokenResponse):
    # Demo the protection API
    print('\nRequesting protected resources using the Protection API')
    protection = ProtectionEndpoint(JwtToken(response.access_token()))
    try:
        print(protection.get_resource_list(kc))
        for resource_id in protection.get_resource_list(kc):
            print(protection.get_resource_description(kc, resource_id))
    except RuntimeError as e:
        print(e)


def demo_entitlement_api(kc: KeycloakInstance, response: TokenResponse):
    try:
        print('\nRequesting entitlements using Entitlement API')
        entitlement = EntitlementEndpoint(JwtToken(response.access_token()))
        print(entitlement.get_entitlements(kc, 'service-account-client'))
    except RuntimeError as e:
        print(e)


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
    list_of_users = users.get_users(kc)
    print('\n'.join([str(d) for d in list_of_users]))

    # Iterate over the users and send e-mail verification
    for u in list_of_users:
        if 'email' in u and not u['email'] is None:
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


def demo_groups(kc: KeycloakInstance, response: TokenResponse):
    print('============= Default Groups ============')
    # Get a list of default groups
    action = DefaultGroups(JwtToken(response.access_token()))
    default_groups = action.get_default_groups(kc)
    print('\n'.join([str(d) for d in default_groups]))

    print('============= Groups ============')
    # Get a list of default groups
    action = Groups(JwtToken(response.access_token()))
    groups = action.get_groups(kc)
    print('\n'.join([str(d) for d in groups]))


if __name__ == "__main__":
    kc = KeycloakInstance(server='online.stk.com', ssl_required=True)

    # Get OIDC endpoints
    print(kc.get_metadata())

    # Get access token, id token and refresh token
    # response = login_with_client_credentials(kc)
    response = login_with_user_credentials(kc)

    # Demo the Protection API
    demo_protection_api(kc, response)

    # Demo the entitlement API
    demo_entitlement_api(kc, response)

    # Demo admin API
    demo_get_list_of_users_api(kc, response)

    # Get all admin events
    demo_admin_events_api(kc, response)

    # offline_token = 'eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJSN2lraGZ1cVFWZ2N1U1JEdURBVGVjcy1TOWcxZTVxNFQ5SXRad29vaWJ3In0.eyJqdGkiOiIyNWI1NDcwMi0yMzRmLTRlNjMtYjE0YS1jNDNlMTE0ZDU1MzciLCJleHAiOjAsIm5iZiI6MCwiaWF0IjoxNDc5MTA2MTc3LCJpc3MiOiJodHRwczovL29ubGluZS5zdGsuY29tOjg0NDMvYXV0aC9yZWFsbXMvbWFzdGVyIiwiYXVkIjoibG9vcGJhY2stY2xpZW50Iiwic3ViIjoiNWU5YTM4N2YtOTg4ZS00MDkxLTg2ZmEtYWIzMjE4MjYyMTYxIiwidHlwIjoiT2ZmbGluZSIsImF6cCI6Imxvb3BiYWNrLWNsaWVudCIsImF1dGhfdGltZSI6MCwic2Vzc2lvbl9zdGF0ZSI6ImQ4NTk2OGM5LTdlYzctNDMxOS1hNDUwLTNkYjg1ODMwOTAwNSIsImNsaWVudF9zZXNzaW9uIjoiNzg2MjcyMjctYmIyNC00M2ExLTg1YjktYWUzYTY3YWZkYTZmIiwicmVhbG1fYWNjZXNzIjp7InJvbGVzIjpbIm9mZmxpbmVfYWNjZXNzIiwidW1hX2F1dGhvcml6YXRpb24iXX0sInJlc291cmNlX2FjY2VzcyI6eyJtYXN0ZXItcmVhbG0iOnsicm9sZXMiOlsidmlldy1ldmVudHMiLCJ2aWV3LXVzZXJzIl19fX0.bSSOpLhEuwPXgQk_kZ7v3a7MnMx-dU-jToXJvr25ACFnEWJ5vtKVgqIeK29V54jHyL2MCZz4I5qHS2lOX7_EgKsKRFjHq-XDcLTbvmPZaORaw4j0Sh_IZ3WTl1YGAcndvLcwJk5suwZiE8Piwu4eXV8So0ZH5B0c4QIe9zKe70wV5GgoK-1tA-ATMiNYwRPRTR1mNyvf6yhAHe1u6Kjf_vvQFxyZjsVvOW0nhV6G9YsWheOIYRoNX4rL2Etva6b3oSecM_7XI1365MASnEo7YtHwtgAbl0enuYXzRqJg9eOCCm4vsLC8R9rTrRnaGAp0D1BG_q3wd6S1vOu0Rw0HFw'
    # response = login_with_refresh_token(kc, offline_token)
    response = login_with_refresh_token(kc, response.refresh_token())

    # Request a list of users again, but this time the client
    # will pass the access token returned by the authorization server
    # in response to the refresh token request
    demo_get_list_of_users_api(kc, response)

    # Demo of groups API
    demo_groups(kc, response)
