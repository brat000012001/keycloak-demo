import datetime
import logging
from utils.TokenResponse import TokenResponse
from .ActionBase import ActionBase
from .ActionResult import ActionResult
from .LoginAction import LoginAction
from utils.KeycloakInstance import KeycloakInstance
from utils.Prompt import Prompt
from admin.users import RealmUsers
from utils.JwtToken import JwtToken


class DeleteUserFederatedIdentitiesAction(ActionBase):

    @staticmethod
    def add_sub_parser(sub_parser_group):
        parser_delete_user_federated_identity = sub_parser_group.add_parser(DeleteUserFederatedIdentitiesAction.name())
        parser_delete_user_federated_identity.add_argument('--realm', required=True)
        parser_delete_user_federated_identity.add_argument('--pattern')

    @staticmethod
    def name():
        return 'delete-federated-identity'

    def evaluate(self, response: TokenResponse, args, interactive_mode):
        """ For all users in a specified realm, delete their federated identities

        :param kc_host: A DNS name or an IP address of a keycloak instance
        :param kc_port: an SSL port the keycloak instance is listening on for incoming connections
        :param response: OAuth2 response that includes access_token
        :param args: command line arguments
        :param interactive_mode: whether to prompt for confirmation before updating the user's federated identities
        :return: ActionResult
        """
        pattern = args.pattern
        realm = args.realm

        kc = KeycloakInstance(server=self._kc_server, https_port=self._kc_port, realm=realm, ssl_required=True)

        logging.info('Searching for \'{}\''.format(pattern))
        users = RealmUsers(JwtToken(response.access_token()))
        user_rep = users.find_user_by_username_or_email('{}'.format(pattern), kc)
        expires_in = datetime.datetime.now() + datetime.timedelta(seconds=response.expires_in() - 20)

        action_result = ActionResult()

        for user in user_rep:
            # Check if the access token is about to expire and refresh it
            if datetime.datetime.now() > expires_in:
                response = LoginAction.refresh(kc.server, kc.https_port, response.refresh_token(), 'master',
                                               'admin-cli', '')
                expires_in = datetime.datetime.now() + datetime.timedelta(seconds=response.expires_in() - 20)
                users = RealmUsers(JwtToken(response.access_token()))

            logging.info('id={}, username={}...'.format(user['id'], user['username']))
            identities = users.get_user_federated_identities(user['id'], kc)
            if 'service-account-' not in user['username'] and '@' in user['username'] and len(identities) > 0 and (
                        not interactive_mode or Prompt.query_yes_no('Delete federated identities?')):
                for fi in identities:
                    users.remove_user_federated_identity(user['id'], fi['identityProvider'], kc)
                    logging.info("    :Deleted {}".format(fi['identityProvider']))
                    action_result.on_processed()
            else:
                if len(identities) > 0:
                    logging.info('    :Skipped')
                action_result.on_skipped()

        return action_result

