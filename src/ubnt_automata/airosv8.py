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
from . import exceptions

logger = logging.getLogger(__name__)

# Disable the self signed certificate warnings.
urllib3.disable_warnings()


class AirOSv8:
    '''Ubnt version 8 equipment handler.


    To implement:
    - /test_mode.cgi
    - /airviewdata.cgi
    - /chanlist_active.cfg
    - /survey.json.cgi?iface=ath0&update=last - Site survey
    - /amdata.cgi
    '''

    def __init__(self, host: str, password: str, username: str='ubnt',
                 autologin:bool=False) -> None:
        '''Constructor'''
        self._req_session = requests.Session()
        self._host = host
        self._username = username
        self._password = password
        self._is_ssl = True

        if autologin:
            self.login_http(self._password)

    def _build_url(self, path: str):
        '''Build the final URL to pass to request library.

        Args:
            - path: the path
        '''
        final_url = f"{'https' if self._is_ssl else 'http'}://"
        final_url += f"{self._host}/{path}"
        return final_url

    def login_http(self, password: str, username: str='ubnt') -> None:
        '''Login to device via HTTP(s).

        '''
        try:
            auth_data = {
                'username': username,
                'password': password,
            }

            # Get cookies
            self._req_session.get(
                self._build_url(''),
                verify=False,
            )

            # Login
            rez = self._req_session.post(
                self._build_url("api/auth"),
                data=auth_data,
                verify=False,
            )

            if rez.status_code != 200:
                logger.debug(f"Error logging in: {rez.json()['error']}")
                raise exceptions.WrongPassword()

            # Successful login
            self._curr_password = password
            self._dev_info = rez.json()['boardinfo']
            self._csrf_id = rez.headers['X-CSRF-ID']
        except exceptions.WrongPassword:
            raise
        except (requests.exceptions.ConnectionError, requests.exceptions.ConnectTimeout) as exc:
            raise exceptions.DeviceUnavailable from exc
        except Exception as exc:
            logger.debug(
                f"An exception occurred 'login_http' - {self._host}: " +
                f"{exc.__class__} -> {exc}"
            )
            exc_type, exc_value, exc_traceback = sys.exc_info()
            logger.debug(repr(
                traceback.format_exception(exc_type, exc_value, exc_traceback)
            ))
            raise

    def change_password(self, new_pw: str, old_pw: str=None) -> None:
        '''Change current user password.
        '''

        if old_pw is None:
            old_password = self._curr_password
        else:
            old_password = old_pw

        pw_data = {
            'change': 'yes',
            'ro': '0',
            'pwd': new_pw,
            'oldPwd': old_password,
        }
        rez = self._req_session.post(
            self._build_url("pwd.cgi"),
            data=pw_data,
            verify=False,
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


    def getcfg(self):
        '''Get the device configuration.


        '''
        rez = self._req_session.get(
            self._build_url("getcfg.cgi"),
            verify=False,
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
        '''
        lines = []
        for k,val in cfgdata.items():
            lines.append(f"{k}={val}")

        logger.debug(f"Writecfg lines: {pprint.pformat(lines)}")

        cfg_output = "\r\n".join(lines)

        logger.debug(f"cfgoutput: \n{cfg_output}")

        cfg_data = {
            'cfgData': cfg_output,
        }
        rez = self._req_session.post(
            self._build_url("writecfg.cgi"),
            data=cfg_data,
            verify=False,
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
            verify=False,
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
