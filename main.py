from utils import KeycloakInstance
from utils import ResourceOwnerCredentialsAuthentication
from utils import ClientCredentialsApi
from utils import JwtToken
from admin.users import RealmUsers
from admin.events import AdminEvents
from admin.users import UserEmailVerification

if __name__ == "__main__":
    kc = KeycloakInstance(server='online.stk.com',ssl_required=True)

    # Get OIDC endpoints
    print (kc.get_metadata())

    authentication_method = ClientCredentialsApi(
        client_id='service-account-client',client_secret='9e853caa-9956-4505-9299-4dd83bd0069b')

    # authentication_method = ResourceOwnerCredentialsAuthentication('<username | email>',
    # '<user password>','loopback-client')

    response = authentication_method.authenticate(kc)

    # Pretty-print the access token
    print(JwtToken(response.access_token()).token_decoded())

    # Get a list of realm users.
    # Requires master-realm:view-user role
    # To verify, check the JWT access token and look for:
    # "resource_access": {
    #     "master-realm": {
    #          "roles": [
    #               "view-users"
    #          ]
    #     }
    #  }
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

    # Get all admin events
    admin_events = AdminEvents(JwtToken(response.access_token()))
    list_of_admin_events = admin_events.get_admin_events(kc)
    print('\n'.join([str(d) for d in list_of_admin_events]))
