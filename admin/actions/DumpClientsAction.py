import logging
from utils.TokenResponse import TokenResponse
from .ActionBase import ActionBase
from .ActionResult import ActionResult
from utils.KeycloakInstance import KeycloakInstance
from utils.JwtToken import JwtToken
from admin.clients import RealmClients


class DumpClientsAction(ActionBase):

    @staticmethod
    def add_sub_parser(sub_parser_group):
        parser_dump_clients = sub_parser_group.add_parser(DumpClientsAction.name())
        parser_dump_clients.add_argument('--realm', required=True)

    @staticmethod
    def name():
        return 'dump-clients'

    def evaluate(self, response: TokenResponse, args, interactive_mode):
        """ Dumps the realm clients

        :param kc_host: A DNS name or an IP address of a keycloak instance
        :param kc_port: an SSL port the keycloak instance is listening on for incoming connections
        :param response: OAuth2 response that includes access_token
        :param args: command line arguments
        :param interactive_mode: whether to prompt for confirmation before updating the user's federated identities
        :return: ActionResult
        """
        realm = args.realm

        kc = KeycloakInstance(server=self._kc_server, https_port=self._kc_port, realm=realm, ssl_required=True)

        clients = RealmClients(JwtToken(response.access_token()))
        list_of_clients = clients.get_clients(kc)

        if 'broker' in list_of_clients:
            logging.info('---------- broker ------------ ')
            logging.info(list_of_clients['broker'])

            client = clients.client(list_of_clients['broker']['id'])

            for role in client.get_roles(kc).items():
                logging.info(role)
                for u in role[1].get_users(kc):
                    logging.info(u)

        action_result = ActionResult()

        for client in list_of_clients.items():
            logging.info('{}'.format(client))
            action_result.on_processed()

        return action_result
