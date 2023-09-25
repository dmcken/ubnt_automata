'''Base class for common functions for all Ubnt AirOS devices.
'''


# System imports
import abc
import logging

# Local imports
from . import exceptions


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

    def login(self, passwords: list[str], auto_apply: bool = False):
        '''Login to the device.
        '''
        try:
            primary_pw = passwords[0]
            self.login_http(primary_pw)
        except exceptions.WrongPassword as exc:
            logger.debug(f"Primary password '{primary_pw}' failed")
            alternate_pws = passwords[1:]
            pw_found = False
            for curr_pw in alternate_pws:
                try:
                    logger.debug(f"Trying: {curr_pw}")
                    self.login_http(curr_pw)
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

    @abc.abstractmethod
    def login_http(self, curr_pw, curr_user = None):
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
