'''AirFiber implementation.

Shares the same auth/session mechanism as AirOSv8 (/api/auth, X-CSRF-ID
header). Verified live against a real airFiber 60 HD (AF60HD, fw
v1.2.4) - the API surface is expected to be shared across the AirFiber
family, but only AF60 HD has actually been confirmed so far.

Auth endpoint:
- /api/auth

Data endpoints confirmed against a live AF60 HD:
- status.cgi          - Rich JSON: host/uptime/fw, wireless link stats
                         (rssi/snr/capacity/distance/mcs), remote-end
                         stats, per-interface counters, GPS.
- getcfg.cgi           - Full device config as newline-separated
                         key=value text (same format as AirOSv8).
- hist-stats.cgi       - JSON historical link-score/stat samples.
- ipscan.cgi           - Newline-separated list of IPs seen on the
                         management segment.
- api/warnings         - JSON device warnings (default password set,
                         crash report pending, etc).
- airviewdata.cgi      - Exists (200) but returned an empty body on
                         idle hardware; may need AirView actively
                         running to populate.

Confirmed NOT present on AF60 HD (404) - do not call these for this
model, kept here only as breadcrumbs for other AirFiber hardware:
- antlist.cgi
- btstatus.cgi
- api/fw/update-check

Needs different auth (401 with the standard session) - not implemented:
- api/v1.0/tools/unms
'''

# System imports
import logging

# External imports
import requests
import urllib3

# Local imports
from . import airoscommon
from . import exceptions

logger = logging.getLogger(__name__)

# Disable the self signed certificate warnings.
urllib3.disable_warnings()


class AirFiber(airoscommon.AirOSCommonDevice):
    '''AirFiber device handler.

    Read-only for now: change_password()/apply_changes() are
    deliberately no-ops here, never touching the device.
    '''

    def __init__(self, management_ip: str, timeout: int = None) -> None:
        '''Constructor'''
        super().__init__(
            management_ip=management_ip,
            timeout=timeout,
        )
        self._req_session = requests.Session()
        self._dev_info = None
        self._csrf_id = None

    def _build_url(self, path: str):
        '''Build the final URL to pass to the request library.

        Args:
            - path: the path
        '''
        if self._is_ssl is None:
            self._determine_ssl()

        final_url = f"{'https' if self._is_ssl else 'http'}://"
        final_url += f"{self._mgmt_ip}/{path}"
        return final_url

    def _get(self, path: str) -> requests.Response:
        '''Authenticated GET against a data endpoint.'''
        return self._req_session.get(
            self._build_url(path),
            verify=self._verify_ssl,
            timeout=self._timeout,
            headers={
                'X-CSRF-ID': self._csrf_id,
            },
        )

    def login_http(self, curr_pw: str, curr_user: str = None) -> None:
        """Login to device via HTTP(s).

        Args:
            curr_pw (str): Password to use for login.
            curr_user (str, optional): Username to use for login. Defaults to None.

        Raises:
            exceptions.WrongPassword: Thrown if the login fails for authentication reasons.
            exceptions.DeviceUnavailable: Thrown if the login fails for connectivity reasons.
        """
        if curr_user is None:
            curr_user = self._default_user

        auth_data = {
            'username': curr_user,
            'password': curr_pw,
        }

        try:
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
        except (requests.exceptions.ConnectionError,
                requests.exceptions.ConnectTimeout) as exc:
            raise exceptions.DeviceUnavailable from exc

        if rez.status_code != 200:
            logger.debug(f"Error logging in to {self._mgmt_ip}: {rez.status_code}")
            raise exceptions.WrongPassword()

        # Successful login - save the parameters
        self._curr_username = curr_user
        self._curr_password = curr_pw
        self._dev_info = rez.json().get('boardinfo')
        self._csrf_id = rez.headers['X-CSRF-ID']

    def change_password(self, new_password: str) -> None:
        '''No-op for now - fetch-only, never modifies the device.'''
        logger.debug(
            f"change_password() called on {self._mgmt_ip} but is a no-op - not implemented yet"
        )

    def apply_changes(self, test_mode=False) -> None:
        '''No-op for now - fetch-only, never modifies the device.'''
        logger.debug(
            f"apply_changes() called on {self._mgmt_ip} but is a no-op - not implemented yet"
        )

    def getstatus(self) -> dict:
        """Get the device status (status.cgi).

        The richest endpoint - host/firmware info, wireless link stats
        for both the local and remote end of the backhaul, per-interface
        counters, and GPS.

        Raises:
            RuntimeError: Raised if the data can't be parsed.

        Returns:
            dict: Status data.
        """
        res = self._get("status.cgi")

        if res.status_code == 200:
            return res.json()

        raise RuntimeError(f"Error fetching status: {res.status_code} {res.text}")

    def getcfg(self) -> dict[str, str]:
        '''Get the device configuration (getcfg.cgi).

        Returns:
            dict[str,str]: Flat key=value config, same format as AirOSv8.
        '''
        rez = self._get("getcfg.cgi")

        cfg_data = {}
        for curr_line in rez.text.split('\n'):
            curr_line = curr_line.strip()
            if not curr_line:
                continue
            try:
                key, val = curr_line.split('=', 1)
                cfg_data[key] = val
            except ValueError:
                logger.error(f"Unable to parse line: {curr_line}")

        return cfg_data

    def gethiststats(self) -> dict:
        """Get historical link stats (hist-stats.cgi).

        Raises:
            RuntimeError: Raised if the data can't be parsed.

        Returns:
            dict: Historical stat samples.
        """
        res = self._get("hist-stats.cgi")

        if res.status_code == 200:
            return res.json()

        raise RuntimeError(f"Error fetching hist-stats: {res.status_code} {res.text}")

    def getipscan(self) -> list[str]:
        '''Get the list of IPs seen on the management segment (ipscan.cgi).

        Returns:
            list[str]: IP addresses, one per line as reported by the device.
        '''
        rez = self._get("ipscan.cgi")

        return [line.strip() for line in rez.text.splitlines() if line.strip()]

    def getwarnings(self) -> dict:
        """Get device warnings (api/warnings) - e.g. default password set,
        pending crash report.

        Raises:
            RuntimeError: Raised if the data can't be parsed.

        Returns:
            dict: Warnings data.
        """
        res = self._get("api/warnings")

        if res.status_code == 200:
            return res.json()

        raise RuntimeError(f"Error fetching warnings: {res.status_code} {res.text}")

    def getairview(self) -> dict | None:
        """Get Air View data (airviewdata.cgi).

        Observed to return an empty body on hardware that isn't actively
        running an AirView scan - returns None in that case rather than
        raising, since an empty response isn't necessarily an error here.

        Raises:
            RuntimeError: Raised on a non-200 response.

        Returns:
            dict | None: Air View data, or None if the device returned nothing.
        """
        res = self._get("airviewdata.cgi")

        if res.status_code != 200:
            raise RuntimeError(f"Error fetching airview data: {res.status_code} {res.text}")

        if not res.content:
            return None

        return res.json()
