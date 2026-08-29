'''Classic EdgeMAX/EdgeOS web UI implementation (EdgeRouter, etc).

A third, distinct API family from both AirOS/AirFiber and the modern
UISP-firmware family (uisp.py) - this is the older PHP/beaker-session
based EdgeMAX web UI, confirmed live against a real EdgeRouter ER-6P
(sw_ver "EdgeRouter.ER-e50.v2.0.9-hotfix.7..."). Despite similar
EdgePoint-branded hardware, an EdgePoint S16 switch was confirmed
running the newer UISP firmware (uisp.py's UispDevice) instead - these
two are NOT interchangeable. Check which API a given device actually
speaks (e.g. via get_public_device()-style pre-auth probing, or just
trying the login endpoints) before picking a class.

This is the same vyatta/EdgeOS CLI family that netbox_device_sync's
SSH-based drivers/edgeos.py already targets, but that's a completely
separate HTTP surface - the "show configuration" text-over-SSH there
has no code relationship to get_config() here.

Auth:
- POST / (root), form-urlencoded body {username, password}. No
  pre-fetch/CSRF-token dance needed for login itself - response is a
  303 redirect with Set-Cookie: PHPSESSID/beaker.session.id (the
  actual session) and X-CSRF-TOKEN (presumably only needed for state-
  changing POSTs, not used here since this is fetch-only).
  requests.Session() handles the cookies transparently for the GET-only
  endpoints below - no headers need to be replayed manually.
  Failure-mode detection (checking for a non-303 response) is inferred
  from the common redirect-on-success/re-render-on-failure pattern,
  NOT empirically confirmed against a real wrong password - deliberately
  avoided testing that live, given a sibling device (EdgePoint S16)
  triggered a brute-force lockout from a single bad attempt.

Confirmed endpoints:
- api/edge/data.json?data=sys_info       - Firmware version, UNMS
                                            status, available update.
- api/edge/data.json?data=routes         - Routing table snapshot.
- api/edge/data.json?data=default_config - {"is_default": "0"/"1"}.
- api/edge/get.json                      - Full running config as
                                            structured JSON (interfaces/
                                            vlans/NAT/services/SNMP/SSH/
                                            UNMS/...) - the HTTP
                                            equivalent of the SSH
                                            driver's 'show
                                            configuration', just JSON
                                            instead of flat text.
- api/edge/heartbeat.json                - Trivial session keepalive
                                            check ({"SESSION":true,
                                            "PING":true}).

Confirmed via HAR but NOT implemented:
- ws/stats (WebSocket)   - Presumably live interface/traffic stats. No
                            message content was captured in the HAR
                            (same limitation hit with AirOS's ws/airview
                            and the Wave-family websockets elsewhere in
                            this package), and the plain data.json/
                            get.json calls already cover useful data,
                            so not chased further.
- logout                 - Not needed for a fetch-only client.

Sensitive data warning: get_config() can return device secrets in
plain text - confirmed live: services.snmp.community (an SNMP
community string) and services.unms.connection (embeds the same UISP
auth-token pattern seen elsewhere in this package, e.g. uisp.py's
services.unms.key). Callers must not log/print the full get_config()
dict.
'''
from __future__ import annotations

# System imports
import logging

# External imports
import requests
import urllib3

# Local imports
from . import airoscommon, exceptions

logger = logging.getLogger(__name__)

# Disable the self signed certificate warnings.
urllib3.disable_warnings()


class EdgeRouter(airoscommon.AirOSCommonDevice):
    '''Classic EdgeMAX/EdgeOS web UI device handler (EdgeRouter, etc).

    Read-only for now: change_password()/apply_changes() are
    deliberately no-ops here, never touching the device.
    '''

    def __init__(self, management_ip: str, timeout: int | None = None) -> None:
        '''Constructor'''
        super().__init__(
            management_ip=management_ip,
            timeout=timeout,
        )
        self._req_session = requests.Session()

    def _build_url(self, path: str) -> str:
        '''Build the final URL to pass to the request library.

        Args:
            - path: the path, relative to the site root.
        '''
        if self._is_ssl is None:
            self._determine_ssl()

        final_url = f"{'https' if self._is_ssl else 'http'}://"
        final_url += f"{self._mgmt_ip}/{path}"
        return final_url

    def _get(self, path: str, params: dict | None = None) -> requests.Response:
        '''Authenticated GET against a data endpoint.'''
        return self._req_session.get(
            self._build_url(path),
            params=params,
            verify=self._verify_ssl,
            timeout=self._timeout,
        )

    def login_http(self, curr_pw: str, curr_user: str | None = None) -> None:
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

        try:
            rez = self._req_session.post(
                self._build_url(""),
                data={'username': curr_user, 'password': curr_pw},
                verify=self._verify_ssl,
                timeout=self._timeout,
                allow_redirects=False,
            )
        except (requests.exceptions.ConnectionError,
                requests.exceptions.ConnectTimeout) as exc:
            raise exceptions.DeviceUnavailable from exc

        # Confirmed live: success is a 303 redirect with a fresh
        # PHPSESSID. Failure-mode status has NOT been confirmed live
        # (see module docstring) - treating anything else as a failure.
        if rez.status_code != 303 or 'PHPSESSID' not in self._req_session.cookies:
            logger.debug(f"Error logging in to {self._mgmt_ip}: {rez.status_code}")
            raise exceptions.WrongPassword()

        # Successful login - save the parameters
        self._curr_username = curr_user
        self._curr_password = curr_pw

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

    def _get_data(self, data_type: str):
        '''Fetch one api/edge/data.json?data=<data_type> value.

        Args:
            data_type (str): e.g. 'sys_info', 'routes', 'default_config'.

        Raises:
            RuntimeError: Raised if the request or device-reported
                result isn't successful.

        Returns:
            The parsed 'output' value - shape depends on data_type.
        '''
        res = self._get("api/edge/data.json", params={'data': data_type})

        if res.status_code != 200:
            raise RuntimeError(
                f"Error fetching data.json?data={data_type}: {res.status_code} {res.text}"
            )

        body = res.json()
        if body.get('success') != '1':
            raise RuntimeError(f"data.json?data={data_type} reported failure: {body}")

        return body.get('output')

    def get_sys_info(self) -> dict:
        '''Firmware version, UNMS status, and available update info
        (data.json?data=sys_info).

        Raises:
            RuntimeError: Raised if the data can't be parsed.

        Returns:
            dict: {"sw_ver", "unms": {...}, "fw-latest": {...}}.
        '''
        return self._get_data('sys_info')

    def get_routes(self) -> list[dict]:
        '''Routing table snapshot (data.json?data=routes).

        Raises:
            RuntimeError: Raised if the data can't be parsed.

        Returns:
            list[dict]: One entry per route - {"pfx", "nh": [{"t",
                "metric", "via", "intf"}, ...]}.
        '''
        return self._get_data('routes')

    def is_default_config(self) -> bool:
        '''Whether the device is still at its factory-default config
        (data.json?data=default_config).

        Raises:
            RuntimeError: Raised if the data can't be parsed.

        Returns:
            bool: True if still at factory defaults.
        '''
        return self._get_data('default_config').get('is_default') == '1'

    def get_config(self) -> dict:
        '''Full running config (api/edge/get.json).

        The HTTP equivalent of the SSH driver's 'show configuration' -
        structured JSON instead of flat vyatta text.

        Contains secrets in plain text - see module docstring. Callers
        must not log/print the full returned dict.

        Raises:
            RuntimeError: Raised if the data can't be parsed.

        Returns:
            dict: The device's running configuration tree.
        '''
        res = self._get("api/edge/get.json")

        if res.status_code == 200:
            return res.json().get('GET', {})

        raise RuntimeError(f"Error fetching config: {res.status_code} {res.text}")

    def heartbeat(self) -> bool:
        '''Trivial session keepalive check (api/edge/heartbeat.json).

        Raises:
            RuntimeError: Raised if the data can't be parsed.

        Returns:
            bool: True if the session is alive and the device responded.
        '''
        res = self._get("api/edge/heartbeat.json")

        if res.status_code == 200:
            data = res.json()
            return bool(data.get('SESSION')) and bool(data.get('PING'))

        raise RuntimeError(f"Error fetching heartbeat: {res.status_code} {res.text}")
