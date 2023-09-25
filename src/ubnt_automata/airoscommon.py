'''Base class for common functions for all Ubnt AirOS devices.
'''


# System imports
import abc
import logging

# Local imports
from . import exceptions
from . import utils


logger = logging.getLogger(__name__)


class AirOSCommonDevice:
    '''Base class for all AirOS device.
    '''

    # Default values
    _default_user = 'ubnt'
    _default_timeout = 30

    def __init__(self, management_ip: str, timeout: int = None):
        '''Constructor
        '''
        self._mgmt_ip = management_ip
        if timeout is None:
            self._timeout = timeout
        else:
            self._timeout = self._default_timeout

        self._curr_username = None
        self._curr_password = None  # Once we login successfully will contain the current password
        self._is_ssl = None

    def login(self, passwords: list[str], username: str = None, auto_apply: bool = False):
        '''Login to the device.
        '''
        if username is None:
            self._curr_username = self._default_user
        else:
            self._curr_username = username

        try:
            primary_pw = passwords[0]
            self.login_http(
                curr_pw=primary_pw,
                curr_user=self._curr_username,
            )
        except exceptions.WrongPassword as exc:
            logger.debug(f"Primary password '{primary_pw}' failed")
            alternate_pws = passwords[1:]
            pw_found = False
            for curr_pw in alternate_pws:
                try:
                    logger.debug(f"Trying: {curr_pw}")
                    self.login_http(
                        curr_pw=curr_pw,
                        curr_user=self._curr_username,
                    )
                    self.change_password(primary_pw)
                    if auto_apply:
                        self.apply_changes()
                    pw_found = True
                    break
                except exceptions.WrongPassword:
                    pass

            if pw_found is False:
                raise exceptions.WrongPassword(
                    f"Device {self._mgmt_ip} does not have a known password".format()
                ) from exc

    def _determine_ssl(self,) -> bool:
        '''Determine if the management interface has SSL enforced.
        '''
        return utils.determine_ssl(self._mgmt_ip)

    def _parse_version_string(self, version_string):
        '''Parse the version string.
        '''
        return utils.parse_ubnt_version_string(version_string=version_string)

    @abc.abstractmethod
    def login_http(self, curr_pw:str, curr_user:str = None):
        '''Login to device via HTTP.
        '''

    @abc.abstractmethod
    def change_password(self, new_password):
        '''Change password on device.
        '''

    @abc.abstractmethod
    def apply_changes(self, test_mode = False):
        '''Apply changes to device.
        '''
