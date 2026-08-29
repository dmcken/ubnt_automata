'''Ubnt v8 handler.
'''
from __future__ import annotations

# System imports
import http.client
import json
import logging
import pprint

# External imports
import requests
import urllib3

# Local imports
from . import airoscommon, exceptions, utils

logger = logging.getLogger(__name__)

# Disable the self signed certificate warnings.
urllib3.disable_warnings()


class AirOSv8(airoscommon.AirOSCommonDevice):
    '''Ubnt version 8 equipment handler.

    Confirmed live against a real Rocket Prism 5AC (fw v8.7.x):
    - getdiscovery()/getsurvey() added - same discovery.cgi mechanism
      as AirFiber, and survey.json.cgi (fetch-only, never triggers a
      new scan - see getsurvey()'s docstring).
    - getairview() was already working correctly as-is on this device -
      no query params (cmd=get_data/fastmode=yes) turned out to be
      required, a plain GET returns the same data either way. The web
      UI also opens a /ws/airview WebSocket (cookie-authenticated, a
      different auth mechanism to the X-CSRF-ID header everything else
      here uses) whose messages weren't captured in the HAR, so its
      exact role is unconfirmed - possibly what actually keeps a scan
      running in the background. Not implemented, since the plain HTTP
      endpoint already returns real data without it.

    To implement:
    - /chanlist_active.cfg
    - /amdata.cgi


    To implement:
    loginSSH
    reboot
    changeParameterHTTP
    changeParameterSSH
    upgradeDevice
    '''

    def __init__(self, management_ip: str, timeout: int | None = None) -> None:
        '''Constructor'''
        super().__init__(
            management_ip=management_ip,
            timeout=timeout,
        )
        self._req_session = requests.Session()
        self._dev_info   = None
        self._csrf_id    = None

    def _get(
        self, path: str, params: dict | None = None, extra_headers: dict | None = None,
    ) -> requests.Response:
        '''Authenticated GET against a data endpoint.'''
        return self._req_session.get(
            self._build_url(path),
            params=params,
            verify=self._verify_ssl,
            timeout=self._timeout,
            headers={'X-CSRF-ID': self._csrf_id, **(extra_headers or {})},
        )

    def _post(
        self, path: str, data=None, extra_headers: dict | None = None,
    ) -> requests.Response:
        '''Authenticated POST against a data endpoint.'''
        return self._req_session.post(
            self._build_url(path),
            data=data,
            verify=self._verify_ssl,
            timeout=self._timeout,
            headers={'X-CSRF-ID': self._csrf_id, **(extra_headers or {})},
        )

    def login_http(self, curr_pw: str, curr_user:str | None = None) -> None:
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
        except Exception:
            logger.debug(f"An exception occurred in login_http - {self._mgmt_ip}", exc_info=True)
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
        rez = self._post(
            "pwd.cgi",
            data=pw_data,
            extra_headers={'Accept': 'application/json, text/javascript, */*; q=0.01'},
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
        rez = self._get("test_mode.cgi")

        try:
            apply_result = rez.json()

            if apply_result['active'] in [0,1]:
                return

            logger.error(f"Error apply changes: {apply_result}")
        except json.decoder.JSONDecodeError:
            logger.error(
                f"Error decoding json in apply changes: {rez.content}"
            )

    def getcfg(self) -> dict[str,str]:
        '''Get the device configuration.


        '''
        rez = self._get("getcfg.cgi")

        return utils.parse_flat_kv_config(rez.text)

    def writecfg(self, cfgdata: dict[str,str]) -> None:
        """Write config to device.

        Args:
            cfgdata (dict[str,str]): Config to set on device.

        testmode: "yes" is to be set here.

        Response is JSON:
        {"ok":true,"fast_restart":true,"code":0}
        """
        lines = []
        for k,val in cfgdata.items():
            lines.append(f"{k}={val}")

        logger.debug(f"Writecfg lines: {pprint.pformat(lines)}")

        cfg_output = "\r\n".join(lines)

        logger.debug(f"Cfgoutput: \n{cfg_output}")

        cfg_data = {
            'cfgData': cfg_output,
            #'testmode': "yes"
        }
        rez = self._post("writecfg.cgi", data=cfg_data)

        res_data = rez.json()
        if res_data['ok'] is True:
            # Change was successful
            return

        logger.error(f"Error changing config: {res_data}")

    def getstatus(self) -> dict:
        """Get the device status.

        Raises:
            RuntimeError: Raised if the data can't be parsed.

        Returns:
            dict: Status data.
        """
        res = self._get("status.cgi")

        if res.status_code == 200:
            return res.json()

        # Something went wrong.
        raise RuntimeError(f"Error fetching status: {res.text}")

    def getairview(self) -> dict:
        """Get Air View data.

        Raises:
            RuntimeError: Raised if the data can't be parsed.

        Returns:
            dict: Air View data.
        """
        res = self._get("airviewdata.cgi")

        if res.status_code == 200:
            return res.json()

        # Something went wrong.
        raise RuntimeError(f"Error fetching airview data: {res.text}")

    def getdiscovery(self) -> list[dict]:
        '''Broadcast-discover nearby Ubiquiti devices (discovery.cgi).

        Confirmed via a captured HAR of a real session - same
        discovery.cgi mechanism as AirFiber (POST discover=y&duration=500).

        Raises:
            RuntimeError: Raised if the data can't be parsed.

        Returns:
            list[dict]: One entry per discovered device (hwaddr, ipv4,
                hostname, product, uptime, wmode, fwversion, addresses).
        '''
        res = self._post("discovery.cgi", data={'discover': 'y', 'duration': 500})

        if res.status_code == 200:
            return res.json().get('devices', [])

        raise RuntimeError(f"Error fetching discovery data: {res.text}")

    def getsurvey(self, iface: str = 'ath0') -> dict:
        '''Get the latest wireless site survey results (survey.json.cgi).

        Only ever fetches the latest already-known results/status
        (update=last) - deliberately never triggers a new scan (that's
        the same request with an empty `update` param instead, observed
        in a captured HAR - starting one changes the radio's channel-
        hopping behaviour, out of scope for fetch-only).

        Args:
            iface (str, optional): Wireless interface to survey.
                Defaults to 'ath0' (this device's only radio).

        Raises:
            RuntimeError: Raised if the data can't be parsed.

        Returns:
            dict: {"scan_status": ..., "scan_data": [...]} - scan_data
                is a list of nearby BSSes (cell/mac/mode/frequency/
                channel/quality/signal_level/noise_level/encryption/
                essid/...), empty if no scan has completed yet.
        '''
        res = self._get("survey.json.cgi", params={'iface': iface, 'update': 'last'})

        if res.status_code == 200:
            return res.json()

        raise RuntimeError(f"Error fetching site survey data: {res.text}")

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
