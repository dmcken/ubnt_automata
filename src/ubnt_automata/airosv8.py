'''Ubnt v8 handler.
'''

# System imports
import http.client
import json
import logging
import pprint
import sys
import traceback

# External imports
import requests
import urllib3

# Local imports
from . import airoscommon
from . import exceptions


logger = logging.getLogger(__name__)

# Disable the self signed certificate warnings.
urllib3.disable_warnings()


class AirOSv8(airoscommon.AirOSCommonDevice):
    '''Ubnt version 8 equipment handler.


    To implement:
    - /test_mode.cgi
    - /airviewdata.cgi
    - /chanlist_active.cfg
    - /survey.json.cgi?iface=ath0&update=last - Site survey
    - /amdata.cgi


    To implement:
    loginSSH
    changePassword
    applyChanges
    discardChanges
    reboot
    fetchState
    fetchConfig
    fetchConfigHTTP
    fetchConfigSSH
    fetchSiteSurvey
    changeParameterHTTP
    changeParameterSSH
    upgradeDevice
    '''

    def __init__(self, management_ip: str, timeout: int = None) -> None:
        '''Constructor'''
        super().__init__(
            management_ip=management_ip,
            timeout=timeout,
        )
        self._req_session = requests.Session()
        # self._mgmt_ip = mgmt_ip
        # self._username = username
        # self._password = password
        # self._is_ssl = True
        self._dev_info = None
        self._csrf_id = None

    def _build_url(self, path: str):
        '''Build the final URL to pass to request library.

        Args:
            - path: the path
        '''
        if self._is_ssl is None:
            self._determine_ssl()

        final_url = f"{'https' if self._is_ssl else 'http'}://"
        final_url += f"{self._mgmt_ip}/{path}"
        return final_url

    def login_http(self, curr_pw: str, curr_user:str = None) -> None:
        """Login to device via HTTP(s).

        Args:
            curr_pw (str): Password to use for login.
            curr_user (str, optional): Username to use for login. Defaults to None.

        Raises:
            exceptions.WrongPassword: Thrown if the login fails for authentication reasons.
            exceptions.DeviceUnavailable: Thrown if the login fails for connectivity reasons.
        """
        try:
            # Default to 'ubnt'
            if curr_user is None:
                curr_user = self._default_user

            auth_data = {
                'username': curr_user,
                'password': curr_pw,
            }

            # Get connection cookies
            self._req_session.get(
                self._build_url(''),
                verify=self._verify_ssl,
            )

            # Login
            rez = self._req_session.post(
                self._build_url("api/auth"),
                data=auth_data,
                verify=self._verify_ssl,
            )

            if rez.status_code != 200:
                logger.debug(f"Error logging in: {rez.json()['error']}")
                raise exceptions.WrongPassword()


            # Successful login - save the parameters
            self._curr_username = curr_user
            self._curr_password = curr_pw
            self._dev_info = rez.json()['boardinfo']
            self._csrf_id = rez.headers['X-CSRF-ID']
        except exceptions.WrongPassword:
            raise
        except (requests.exceptions.ConnectionError, 
                requests.exceptions.ConnectTimeout,
                requests.exceptions.JSONDecodeError # Likely not a Ubnt device
                ) as exc:
            raise exceptions.DeviceUnavailable from exc
        except Exception as exc:
            logger.debug(
                f"An exception occurred 'login_http' - {self._mgmt_ip}: " +
                f"{exc.__class__} -> {exc}"
            )
            exc_type, exc_value, exc_traceback = sys.exc_info()
            logger.debug(repr(
                traceback.format_exception(exc_type, exc_value, exc_traceback)
            ))
            raise

    def change_password(self, new_password: str) -> None:
        '''Change current user password.
        '''

        old_password = self._curr_password

        pw_data = {
            'change': 'yes',
            'ro': '0',
            'pwd': new_password,
            'oldPwd': old_password,
        }
        rez = self._req_session.post(
            self._build_url("pwd.cgi"),
            data=pw_data,
            verify=self._verify_ssl,
            headers = {
                'Accept': 'application/json, text/javascript, */*; q=0.01',
                'X-CSRF-ID': self._csrf_id,
            }
        )

        try:
            change_result = rez.json()

            if change_result['success'] is True:
                return

            logger.error(f"Error changing password: {change_result}")
        except json.decoder.JSONDecodeError:
            logger.error(
                f"Error decoding json in change password: {rez.content}"
            )

    def discard_changes(self):
        '''
        POST to /discard.cgi with "d=0&testmode=yes"

        Response is JSON of:
        {"ok":true,"fast_restart":true,"code":0}
        '''

    def apply_changes(self, test_mode = False):
        '''Apply changes to device.

        # Save Changes
        GET to test_mode.cgi

        Response of:
        {"countdown_started":0,"time_left":0,"active":0}

        # Actual test mode needs to be set in the writecfg

        Response of:
        {"countdown_started":0,"time_left":240,"active":1}
        '''
        rez = self._req_session.get(
            self._build_url("test_mode.cgi"),
            verify=False,
            headers = {
                'X-CSRF-ID': self._csrf_id,
            }
        )

        try:
            apply_result = rez.json()

            if apply_result['active'] in [0,1]:
                return

            logger.error(f"Error apply changes: {apply_result}")
        except json.decoder.JSONDecodeError:
            logger.error(
                f"Error decoding json in apply changes: {rez.content}"
            )

    def getcfg(self):
        '''Get the device configuration.


        '''
        rez = self._req_session.get(
            self._build_url("getcfg.cgi"),
            verify=self._verify_ssl,
            headers = {
                'X-CSRF-ID': self._csrf_id,
            }
        )

        full_cfg = rez.text

        cfg_data = {}
        for curr_line in full_cfg.split('\n'):
            try:
                key,val = curr_line.strip().split('=',1)
                cfg_data[key] = val
            except ValueError:
                logger.error(f"Unable to parse line: {curr_line}")

        return cfg_data

    def writecfg(self, cfgdata):
        '''Write config to device.

        testmode: "yes" is to be set here.

        Response is JSON:
        {"ok":true,"fast_restart":true,"code":0}
        '''
        lines = []
        for k,val in cfgdata.items():
            lines.append(f"{k}={val}")

        logger.debug(f"Writecfg lines: {pprint.pformat(lines)}")

        cfg_output = "\r\n".join(lines)

        logger.debug(f"cfgoutput: \n{cfg_output}")

        cfg_data = {
            'cfgData': cfg_output,
            #'testmode': "yes"
        }
        rez = self._req_session.post(
            self._build_url("writecfg.cgi"),
            data=cfg_data,
            verify=self._verify_ssl,
            headers = {
                'X-CSRF-ID': self._csrf_id,
            }
        )

        res_data = rez.json()
        if res_data['ok'] is True:
            # Change was successful
            return

        logger.error(f"Error changing config: {res_data}")

    def getstatus(self):
        '''Get the device status.


        '''
        res = self._req_session.get(
            self._build_url("status.cgi"),
            verify=self._verify_ssl,
            headers = {
                'X-CSRF-ID': self._csrf_id,
            }
        )

        if res.status_code == 200:
            return res.json()

        # Something went wrong.
        raise RuntimeError(f"Error fetching status: {res.text}")

    def enable_debug(self) -> None:
        '''Enable debugging'''
        http.client.HTTPConnection.debuglevel = 1
        requests_log = logging.getLogger("requests.packages.urllib3")
        requests_log.setLevel(logging.DEBUG)
        requests_log.propagate = True

    def disable_debug(self) -> None:
        '''Disable debugging'''
        http.client.HTTPConnection.debuglevel = 0
        requests_log = logging.getLogger("requests.packages.urllib3")
        requests_log.setLevel(logging.WARNING)
        requests_log.propagate = False
