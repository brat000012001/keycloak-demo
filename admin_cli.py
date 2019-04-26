import argparse
import sys
import logging
from admin.actions import LoginAction
from admin.actions import AddReadTokenPermissionAction
from admin.actions import DeleteUsersAction
from admin.actions import DeleteUserFederatedIdentitiesAction
from admin.actions import DumpUsersAction
from admin.actions import DumpClientsAction


def display_disclaimer():
    logging.info('=================================================================================================')
    logging.info('=                                                                                               =')
    logging.info('=                                      DISCLAIMER                                               =')
    logging.info('=                                                                                               =')
    logging.info('= THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT     =')
    logging.info('= NOT  LIMITED TO,  THE IMPLIED  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR     =')
    logging.info('= PURPOSE ARE  DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS  BE LIABLE FOR ANY     =')
    logging.info('= DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES(INCLUDING, BUT     =')
    logging.info('= NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS    =')
    logging.info('= OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, =')
    logging.info('= STRICT LIABILITY, OR TORT(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE    =')
    logging.info('= USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.                      =')
    logging.info('=                                                                                               =')
    logging.info('=                                                                                               =')
    logging.info('=================================================================================================')


if __name__ == "__main__":
    logging.basicConfig(format='%(levelname)s:%(message)s', level=logging.DEBUG)

    parser = argparse.ArgumentParser()
    parser.add_argument('--host', required=True)
    parser.add_argument('--port', required=True)
    parser.add_argument('--admin', required=True)
    parser.add_argument('--adminsecret', required=True)
    parser.add_argument('--noprompt', required=False, action='store_true')
    sub_parsers = parser.add_subparsers(help='Sub-actions', dest='action')

    DeleteUsersAction.add_sub_parser(sub_parser_group=sub_parsers)
    DeleteUserFederatedIdentitiesAction.add_sub_parser(sub_parser_group=sub_parsers)
    AddReadTokenPermissionAction.add_sub_parser(sub_parser_group=sub_parsers)
    DumpUsersAction.add_sub_parser(sub_parser_group=sub_parsers)
    DumpClientsAction.add_sub_parser(sub_parser_group=sub_parsers)

    args = parser.parse_args()

    KC_REALM = args.realm
    KC_HOST = args.host
    KC_HOST_HTTPS_PORT = int(args.port)
    ADMIN = args.admin
    ADMIN_SECRET = args.adminsecret
    INTERACTIVE_MODE = False if args.noprompt else True

    actions = dict()
    actions[DeleteUsersAction.name()] = DeleteUsersAction(kc_server=KC_HOST, kc_port=KC_HOST_HTTPS_PORT)
    actions[DeleteUserFederatedIdentitiesAction.name()] = \
        DeleteUserFederatedIdentitiesAction(kc_server=KC_HOST, kc_port=KC_HOST_HTTPS_PORT)
    actions[AddReadTokenPermissionAction.name()] = \
        AddReadTokenPermissionAction(kc_server=KC_HOST, kc_port=KC_HOST_HTTPS_PORT)
    actions[DumpUsersAction.name()] = DumpUsersAction(kc_server=KC_HOST, kc_port=KC_HOST_HTTPS_PORT)
    actions[DumpClientsAction.name()] = DumpClientsAction(kc_server=KC_HOST, kc_port=KC_HOST_HTTPS_PORT)

    # noinspection PyTypeChecker
    logging.info('Authenticating...')
    token_response = LoginAction.login(KC_HOST,
                                       KC_HOST_HTTPS_PORT,
                                       ADMIN,
                                       ADMIN_SECRET,
                                       'master',
                                       'admin-cli',
                                       None)
    logging.info('Successfully authenticated...')

    display_disclaimer()

    action_name = args.action
    if action_name in actions:
        logging.info('Selected action: {}'.format(action_name))
        action_handler = actions[action_name]
        result = action_handler.evaluate(token_response, args, INTERACTIVE_MODE)

        logging.info('-------')
        logging.info('Summary')
        logging.info('-------')
        logging.info('Total:     {}'.format(result.total()))
        logging.info('Processed: {}'.format(result.processed()))
        logging.info('Skipped:   {}'.format(result.skipped()))
        logging.info('Failed:    {}'.format(result.failed()))
    else:
        logging.error('Action {} is not supported'.format(action_name))
        sys.exit(1)
