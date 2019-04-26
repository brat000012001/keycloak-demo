import logging
from utils.TokenResponse import TokenResponse
from .ActionBase import ActionBase
from .ActionResult import ActionResult
from utils.KeycloakInstance import KeycloakInstance
from admin.users import RealmUsers
from utils.JwtToken import JwtToken


class DumpUsersAction(ActionBase):

    @staticmethod
    def add_sub_parser(sub_parser_group):
        parser_dump_users = sub_parser_group.add_parser(DumpUsersAction.name())
        parser_dump_users.add_argument('--realm', required=True)
        parser_dump_users.add_argument('--pattern')

    @staticmethod
    def name():
        return 'dump-users'

    def evaluate(self, response: TokenResponse, args, interactive_mode):
        """ Dumps the users to an standard output

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

        action_result = ActionResult()

        for user in user_rep:
            logging.info('{}'.format(user))
            action_result.on_processed()

        return action_result
