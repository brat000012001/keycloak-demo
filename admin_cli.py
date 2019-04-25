import argparse
import sys
import datetime
from utils import KeycloakInstance
from utils import ResourceOwnerCredentialsAuthentication
from utils import RefreshTokenAuthentication
from utils import JwtToken
from admin.users import RealmUsers
from utils import TokenResponse

class ActionResult:
    def __init__(self):
        self._processed = 0
        self._total = 0
        self._failed = 0
        self._skipped = 0

    def on_processed(self):
        self._processed += 1
        self._total += 1

    def on_skipped(self):
        self._skipped += 1
        self._total += 1

    def on_failed(self):
        self._failed += 1
        self._total += 1

    def processed(self): return self._processed
    def failed(self): return self._failed
    def total(self): return self._total
    def skipped(self): return self._skipped

def login_with_user_credentials(KC_SERVER:str,
                                KC_PORT:int,
                                username: str,
                                password: str,
                                realm: str,
                                client_id: str,
                                client_secret: str) -> TokenResponse:
    """
    Obtains an access token using user credentials
    :param kc: an instance of Keycloak
    :return: Returns OAuth2 response that includes a refresh and access tokens
    """

    admin_kc = KeycloakInstance(server=KC_SERVER,
                                https_port=KC_PORT,
                                realm=realm,
                                ssl_required=True)
    authentication_method = ResourceOwnerCredentialsAuthentication(username,
                                                                   password,
                                                                   client_id,
                                                                   client_secret)
    # authentication_method.add_offline_access_scope()
    response = authentication_method.authenticate(admin_kc)
    return response


def refresh_token(KC_SERVER, KC_PORT, refresh_token, realm, client_id, client_secret) -> TokenResponse:
    """
    Obtains an access token using user credentials
    :param kc: an instance of Keycloak
    :return: TokenResponse
    """

    admin_kc = KeycloakInstance(server=KC_SERVER,
                                https_port=KC_PORT,
                                realm=realm,
                                ssl_required=True)
    authentication_method = RefreshTokenAuthentication(refresh_token, client_id, client_secret)
    response = authentication_method.refresh(admin_kc)
    return response


def query_yes_no(question, default="yes"):
    """Ask a yes/no question via raw_input() and return their answer.

    "question" is a string that is presented to the user.
    "default" is the presumed answer if the user just hits <Enter>.
        It must be "yes" (the default), "no" or None (meaning
        an answer is required of the user).

    The "answer" return value is True for "yes" or False for "no".
    """
    valid = {"yes": True, "y": True, "ye": True,
             "no": False, "n": False}
    if default is None:
        prompt = " [y/n] "
    elif default == "yes":
        prompt = " [Y/n] "
    elif default == "no":
        prompt = " [y/N] "
    else:
        raise ValueError("invalid default answer: '%s'" % default)

    while True:
        sys.stdout.write(question + prompt)
        choice = input().lower()
        if default is not None and choice == '':
            return valid[default]
        elif choice in valid:
            return valid[choice]
        else:
            sys.stdout.write("Please respond with 'yes' or 'no' "
                             "(or 'y' or 'n').\n")


def delete_users(KC_HOST, KC_PORT, response: TokenResponse, args, interactive_mode):
    """ Delete realm users.

    :param KC_HOST: A DNS name or an IP address of a keycloak instance
    :param KC_PORT: an SSL port the keycloak instance is listening on for incoming connections
    :param response: OAuth2 response that includes an access token
    :param args: command line arguments returned by argparse
    :param interactive_mode: if True, prompt to confirm before deleting a realm user
    :return: ActionResult
    """
    pattern = args.pattern
    realm = args.realm

    kc = KeycloakInstance(server=KC_HOST, https_port=KC_PORT, realm=realm, ssl_required=True)

    print('Searching for {}'.format(pattern))
    users = RealmUsers(JwtToken(response.access_token()))
    user_rep = users.find_user_by_username_or_email('{}'.format(pattern), kc)
    expires_in = datetime.datetime.now() + datetime.timedelta(seconds=response.expires_in() - 20)
    if interactive_mode: print('Total number of users: {}'.format(len(user_rep)))

    result = ActionResult()

    for user in user_rep:
        # Check if the access token is about to expire and refresh it 
        if datetime.datetime.now() > expires_in:
            response = refresh_token(kc._server, kc._port, response.refresh_token(), 'master', 'admin-cli', '')
            expires_in = datetime.datetime.now() + datetime.timedelta(seconds=response.expires_in() - 20)
            users = RealmUsers(JwtToken(response.access_token()))

        print ('id={}, username={}'.format(user['id'], user['username']))
        if 'service-account-' not in user['username'] and '@' in user['username'] and (not interactive_mode or query_yes_no('Do you want to delete {}?'.format(user['username']))):
            print (users.delete_user(user['id'], kc))
            result.on_processed()
        else:
            print('Skipped the user {}'.format(user['username']))
            result.on_skipped()
    return result

def delete_user_federated_identities(KC_HOST, KC_PORT, response: TokenResponse, args, interactive_mode):
    """ For all users in a specified realm, delete their federated identities

    :param KC_HOST: A DNS name or an IP address of a keycloak instance
    :param KC_PORT: an SSL port the keycloak instance is listening on for incoming connections
    :param response: OAuth2 response that includes access_token
    :param args: command line arguments
    :param interactive_mode: whether to prompt for confirmation before updating the user's federated identities
    :return: ActionResult
    """
    pattern = args.pattern
    realm = args.realm

    kc = KeycloakInstance(server=KC_HOST, https_port=KC_PORT, realm=realm, ssl_required=True)

    print('Searching for \'{}\''.format(pattern))
    users = RealmUsers(JwtToken(response.access_token()))
    user_rep = users.find_user_by_username_or_email('{}'.format(pattern), kc)
    expires_in = datetime.datetime.now() + datetime.timedelta(seconds=response.expires_in() - 20)

    result = ActionResult()

    for user in user_rep:
        # Check if the access token is about to expire and refresh it 
        if datetime.datetime.now() > expires_in:
            response = refresh_token(kc._server, kc._port, response.refresh_token(), 'master', 'admin-cli', '')
            expires_in = datetime.datetime.now() + datetime.timedelta(seconds=response.expires_in() - 20)
            users = RealmUsers(JwtToken(response.access_token()))

        sys.stdout.write ('id={}, username={}...'.format(user['id'], user['username']))
        identities = users.get_user_federated_identities(user['id'], kc)
        if 'service-account-' not in user['username'] and '@' in user['username'] and len(identities) > 0 and (not interactive_mode or query_yes_no('Delete federated identities?')):
            for fi in identities:
                users.remove_user_federated_identity(user['id'], fi['identityProvider'], kc)
                sys.stdout.write("\nDeleted {}".format(fi['identityProvider']))
                result.on_processed()
        else:
            if len(identities) > 0: sys.stdout.write('Skipped')
            result.on_skipped()
        sys.stdout.write('\n')
    return result

def add_read_token_permission(KC_HOST, KC_PORT, response: TokenResponse, args, interactive_mode):
    """ For all users in a specified realm, delete their federated identities

    :param KC_HOST: A DNS name or an IP address of a keycloak instance
    :param KC_PORT: an SSL port the keycloak instance is listening on for incoming connections
    :param response: OAuth2 response that includes access_token
    :param args: command line arguments
    :param interactive_mode: whether to prompt for confirmation before updating the user's federated identities
    :return: ActionResult
    """
    pattern = args.pattern
    realm = args.realm
    client = args.client

    kc = KeycloakInstance(server=KC_HOST, https_port=KC_PORT, realm=realm, ssl_required=True)

    print('Searching for \'{}\''.format(pattern))
    users = RealmUsers(JwtToken(response.access_token()))
    user_rep = users.find_user_by_username_or_email('{}'.format(pattern), kc)
    expires_in = datetime.datetime.now() + datetime.timedelta(seconds=response.expires_in() - 20)

    result = ActionResult()

    for user in user_rep:
        # Check if the access token is about to expire and refresh it
        if datetime.datetime.now() > expires_in:
            response = refresh_token(kc._server, kc._port, response.refresh_token(), 'master', 'admin-cli', '')
            expires_in = datetime.datetime.now() + datetime.timedelta(seconds=response.expires_in() - 20)
            users = RealmUsers(JwtToken(response.access_token()))

        sys.stdout.write('id={}, username={}...'.format(user['id'], user['username']))
        if 'service-account-' not in user['username'] and '@' in user['username'] and \
                (not interactive_mode or query_yes_no('Delete federated identities?')):
            #
            # TODO: add read-token permission
            #
            #sys.stdout.write("\nDeleted {}".format(fi['identityProvider']))
            result.on_processed()
        else:
            sys.stdout.write('Skipped')
            result.on_skipped()
        sys.stdout.write('\n')
    return result


def dump_users(KC_HOST, KC_PORT, response: TokenResponse, args, interactive_mode):
    """ Dumps the users to an standard output

    :param KC_HOST: A DNS name or an IP address of a keycloak instance
    :param KC_PORT: an SSL port the keycloak instance is listening on for incoming connections
    :param response: OAuth2 response that includes access_token
    :param args: command line arguments
    :param interactive_mode: whether to prompt for confirmation before updating the user's federated identities
    :return: ActionResult
    """
    pattern = args.pattern
    realm = args.realm

    kc = KeycloakInstance(server=KC_HOST, https_port=KC_PORT, realm=realm, ssl_required=True)

    print('Searching for \'{}\''.format(pattern))
    users = RealmUsers(JwtToken(response.access_token()))
    user_rep = users.find_user_by_username_or_email('{}'.format(pattern), kc)
    expires_in = datetime.datetime.now() + datetime.timedelta(seconds=response.expires_in() - 20)

    result = ActionResult()

    for user in user_rep:
        # Check if the access token is about to expire and refresh it
        if datetime.datetime.now() > expires_in:
            response = refresh_token(kc._server, kc._port, response.refresh_token(), 'master', 'admin-cli', '')
            expires_in = datetime.datetime.now() + datetime.timedelta(seconds=response.expires_in() - 20)
            users = RealmUsers(JwtToken(response.access_token()))
        print('{}'.format(user))
        result.on_processed()

    return result


if __name__ == "__main__":

    commands = {
        'delete-users':              delete_users,
        'delete-federated-identity': delete_user_federated_identities,
        'add-read-token-permission': add_read_token_permission,
        'dump-users':                dump_users
    }

    parser = argparse.ArgumentParser()
    parser.add_argument('--host', required=True)
    parser.add_argument('--port', required=True)
    parser.add_argument('--admin', required=True)
    parser.add_argument('--adminsecret', required=True)
    parser.add_argument('--noprompt', required=False, action='store_true')
    sub_parsers = parser.add_subparsers(help='Sub-commands', dest='command')

    # delete-user command
    parser_delete_user = sub_parsers.add_parser('delete-users')
    parser_delete_user.add_argument('--realm', required=True)
    parser_delete_user.add_argument('--pattern')

    # delete-federated-identity command
    parser_delete_user_federated_identity = sub_parsers.add_parser('delete-federated-identity')
    parser_delete_user_federated_identity.add_argument('--realm', required=True)
    parser_delete_user_federated_identity.add_argument('--pattern')

    # add-read-token permission command
    parser_add_read_token_permission = sub_parsers.add_parser('add-read-token-permission')
    parser_add_read_token_permission.add_argument('--realm', required=True)
    parser_add_read_token_permission.add_argument('--pattern')
    parser_add_read_token_permission.add_argument('--client', required=True, default='broker')

    # dump-users command
    parser_dump_users = sub_parsers.add_parser('dump-users')
    parser_dump_users.add_argument('--realm', required=True)
    parser_dump_users.add_argument('--pattern')

    args = parser.parse_args()

    KC_REALM = args.realm
    KC_HOST = args.host
    KC_HOST_HTTPS_PORT = int(args.port)
    ADMIN = args.admin
    ADMIN_SECRET = args.adminsecret
    INTERACTIVE_MODE = False if args.noprompt else True

    token_response = login_with_user_credentials(KC_HOST, KC_HOST_HTTPS_PORT, ADMIN, ADMIN_SECRET, 'master', 'admin-cli', None)

    command = args.command
    if command in commands:
        print('Selected command: {}'.format(command))
        result = commands[command](KC_HOST, KC_HOST_HTTPS_PORT, token_response, args, INTERACTIVE_MODE)

        print('-------')
        print('Summary')
        print('-------')
        print('Total:     {}'.format(result.total()))
        print('Processed: {}'.format(result.processed()))
        print('Skipped:   {}'.format(result.skipped()))
        print('Failed:    {}'.format(result.failed()))
    else:
        print('Command {} is not supported'.format(command))
        sys.exit(1)
