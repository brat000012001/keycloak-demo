import datetime
import logging
from utils.TokenResponse import TokenResponse
from .ActionBase import ActionBase
from .ActionResult import ActionResult
from .LoginAction import LoginAction
from utils.KeycloakInstance import KeycloakInstance
from utils.Prompt import Prompt
from admin.clients import RealmClients
from admin.users import RealmUsers
from admin.rolemappings import RealmUserRoleMappings
from utils.JwtToken import JwtToken


class AddReadTokenPermissionAction(ActionBase):

    @staticmethod
    def add_sub_parser(sub_parser_group):
        parser_add_read_token_permission = sub_parser_group.add_parser(AddReadTokenPermissionAction.name())
        parser_add_read_token_permission.add_argument('--realm', required=True)
        parser_add_read_token_permission.add_argument('--pattern')
        parser_add_read_token_permission.add_argument('--clientid', default='broker')
        parser_add_read_token_permission.add_argument('--role', default='read-token')

    @staticmethod
    def name():
        return "add-read-token-permission"

    def evaluate(self, response: TokenResponse, args, interactive_mode):
        """ Add a client permission to all users
        :param response: OAuth2 response that includes access_token
        :param args: command line arguments
        :param interactive_mode: whether to prompt for confirmation before updating the user's client permissions
        :return: ActionResult
        """
        pattern = args.pattern
        realm = args.realm
        client_id = args.clientid
        client_role = args.role

        kc = KeycloakInstance(server=self._kc_server, https_port=self._kc_port, realm=realm, ssl_required=True)

        logging.info('Searching for \'{}\''.format(pattern))
        users = RealmUsers(JwtToken(response.access_token()))
        user_rep = users.find_user_by_username_or_email('{}'.format(pattern), kc)

        clients = RealmClients(JwtToken(response.access_token()))
        list_of_clients = clients.get_clients(kc)

        target_client_model = None
        client_role_model = None
        users_already_with_role = dict()
        # Verify that the specified client exists
        if client_id in list_of_clients:
            target_client_model = list_of_clients[client_id]
            # Verify that the specified client includes the specified role
            target_client = clients.client(target_client_model['id'])
            available_roles_mapping = target_client.get_roles(kc=kc)
            if client_role in available_roles_mapping:
                client_role_model = available_roles_mapping[client_role]._role_rep
                users_already_with_role = available_roles_mapping[client_role].get_users(kc=kc)
            else:
                raise RuntimeError('The client \'{}\' does not have \'{}\' role.'.format(client_id, client_role))
        else:
            raise RuntimeError('The realm {} does not have \'{}\' client.'.format(kc.realm(), client_id))

        expires_in = datetime.datetime.now() + datetime.timedelta(seconds=response.expires_in() - 20)

        action_result = ActionResult()
        for user in user_rep:
            # Check if the access token is about to expire and refresh it
            if datetime.datetime.now() > expires_in:
                response = LoginAction.refresh(kc.server, kc.https_port, response.refresh_token(), 'master',
                                               'admin-cli', '')
                expires_in = datetime.datetime.now() + datetime.timedelta(seconds=response.expires_in() - 20)

            logging.info('id={}, username={}...'.format(user['id'], user['username']))
            if user['username'] not in users_already_with_role:
                if 'service-account-' not in user['username'] and \
                                '@' in user['username'] and \
                        (not interactive_mode or Prompt.query_yes_no(
                            'Add {}:{} permission?'.format(client_id, client_role_model['name']))):
                    #
                    # add [client_id]:read-token permission
                    #
                    role_mappings = RealmUserRoleMappings(userid=user['id'],
                                                          access_token=JwtToken(response.access_token()))
                    role_mappings.add_role_mappings(realm_client=target_client_model, roles=[client_role_model], kc=kc)
                    logging.info('     :Added')
                    action_result.on_processed()
                else:
                    logging.info('         Skipped')
                    action_result.on_skipped()
            else:
                logging.info('         :Skipped, the permission \'{}\' has already been assigned'. \
                                 format(client_role_model['name']))
                action_result.on_skipped()

        return action_result
