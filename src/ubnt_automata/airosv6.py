'''Ubnt AirOS v6 (classic, pre-v8) device handler.'''
from __future__ import annotations

# System imports
import logging
from urllib.parse import urlparse

# External imports
import requests
import urllib3

# Local imports
from . import airoscommon, exceptions, utils

logger = logging.getLogger(__name__)

# Disable the self signed certificate warnings.
urllib3.disable_warnings()


class AirOSv6(airoscommon.AirOSCommonDevice):
    '''AirOS v6 (classic/pre-v8) equipment handler - the lighttpd-served,
    HTML-form/cookie-based web UI still running on older-generation
    gear (e.g. an AirFiber 11FX on fw v4.1.0), distinct from AirOSv8's
    JSON API (api/auth, X-CSRF-ID header).

    Confirmed live against a real AirFiber 11FX (fw v4.1.0, licensed
    11GHz PtP backhaul radio):
    - login_http() posts to login.cgi as a plain HTML form (uri/
      username/password/login fields, matching the real login form's
      field names). A wrong password redirects right back to
      /login.cgi; success lands on /index.html. (An earlier, never
      live-tested version of this method checked for a landing path of
      /index.cgi on success -- that never actually happens on this
      firmware, so even a correct login fell through to an unhandled
      RuntimeError.)
    - getcfg()/get_boardinfo() are the exact same flat key=value text
      format as AirOSv8's getcfg.cgi (reuses utils.parse_flat_kv_config()
      unchanged), just served from getcfg.sh/getboardinfo.sh instead.
    - getstatus()/get_discovery() return the same JSON shape as
      AirOSv8's status.cgi/discovery.cgi (confirmed via a captured
      HAR) -- get_discovery() differs only in HTTP mechanics (a GET
      with query params, not AirOSv8's POST with a body).
    - get_gps()/get_wireless() reuse the same status.cgi parsing
      helpers as AirOSv8/AirFiber, since the `gps`/`wireless` blocks
      match that shape too.

    Deliberately NOT implemented: AirFiber's get_link_status() -- this
    hardware's status.cgi carries link/peer data in a top-level
    `airfiber` block (remote_mac, remote_ip, rxpower0/1, ...), not the
    `wireless.sta[]` shape get_link_status() parses (built for AirMax/
    PRS hardware) -- that's a real, different shape needing its own
    parsing, not something safe to guess at without a second confirmed
    device to check the field names against.

    change_password()/apply_changes() are deliberately no-ops -- every
    class here except AirOSv8 treats these as read-only (see
    AirOSCommonDevice.login()'s own docstring on why that matters: a
    successful login on a non-primary password would otherwise try to
    write the primary password back to the device).
    '''

    def __init__(self, management_ip: str, timeout: int | None = None) -> None:
        '''Constructor'''
        super().__init__(
            management_ip=management_ip,
            timeout=timeout,
        )
        self._req_session = requests.Session()

    def _get(self, path: str, params: dict | None = None) -> requests.Response:
        '''GET against a data endpoint -- no CSRF header, unlike
        AirOSv8/AirFiber's _get(): this login flow never issues one.
        '''
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
        try:
            if curr_user is None:
                curr_user = self._default_user

            # Get connection cookies -- some sessions hop through an
            # intermediate /cookiechecker page first (apparently only
            # when no "browser accepts cookies" cookie is already
            # set); requests follows either chain automatically.
            self._req_session.get(
                self._build_url(''),
                verify=self._verify_ssl,
                timeout=self._timeout,
            )

            response = self._req_session.post(
                self._build_url('login.cgi'),
                data={
                    'uri': '/',
                    'username': curr_user,
                    'password': curr_pw,
                    'login': 'Login',
                },
                verify=self._verify_ssl,
                timeout=self._timeout,
            )

            if urlparse(response.url).path == '/login.cgi':
                raise exceptions.WrongPassword(
                    f"Password doesn't work on '{self._mgmt_ip}'"
                )

            self._curr_username = curr_user
            self._curr_password = curr_pw
        except exceptions.WrongPassword:
            raise
        except (requests.exceptions.ConnectionError,
                requests.exceptions.ConnectTimeout) as exc:
            raise exceptions.DeviceUnavailable from exc

    def change_password(self, new_password: str) -> None:
        '''No-op for now - fetch-only, never modifies the device.'''
        logger.debug(
            f"change_password() called on {self._mgmt_ip} but is a no-op - not implemented yet"
        )

    def apply_changes(self, test_mode: bool = False) -> None:
        '''No-op for now - fetch-only, never modifies the device.'''
        logger.debug(
            f"apply_changes() called on {self._mgmt_ip} but is a no-op - not implemented yet"
        )

    def getcfg(self) -> dict[str, str]:
        '''Get the device configuration (getcfg.sh).

        Returns:
            dict[str,str]: Flat key=value config, same format as AirOSv8.
        '''
        res = self._get('getcfg.sh?.')
        return utils.parse_flat_kv_config(res.text)

    def get_boardinfo(self) -> dict[str, str]:
        '''Get static hardware/board info (getboardinfo.sh) -- this is
        where the short model code lives (board.name=airFiber 11FX,
        board.shortname=AF11FX, board.hwaddr=...) -- status.cgi/
        getcfg() only expose the long form via `devmodel`.

        Returns:
            dict[str,str]: Board info key=value pairs.
        '''
        res = self._get('getboardinfo.sh')
        return utils.parse_flat_kv_config(res.text)

    def getstatus(self) -> dict:
        """Get the device status (status.cgi) -- same JSON shape as
        AirOSv8's.

        Raises:
            RuntimeError: Raised if the data can't be parsed.

        Returns:
            dict: Status data.
        """
        res = self._get('status.cgi')

        if res.status_code == 200:
            return res.json()

        raise RuntimeError(f"Error fetching status: {res.text}")

    def get_discovery(self, duration_ms: int = 500) -> list[dict]:
        '''Broadcast-discover nearby Ubiquiti devices (discovery.cgi) --
        same response shape as AirOSv8's/AirFiber's, but a GET with
        query params rather than a POST body.

        Args:
            duration_ms (int, optional): How long the device should scan
                for, in milliseconds. Defaults to 500 (matching the UI).

        Raises:
            RuntimeError: Raised if the data can't be parsed.

        Returns:
            list[dict]: One entry per discovered device (hwaddr, ipv4,
                hostname, product, uptime, wmode, fwversion, addresses).
        '''
        res = self._get('discovery.cgi', params={'discover': 'y', 'duration': duration_ms})

        if res.status_code == 200:
            return res.json().get('devices', [])

        raise RuntimeError(f"Error fetching discovery data: {res.text}")

    def get_gps(self) -> airoscommon.GPSFix | None:
        '''This device's own GPS location (status.cgi's top-level `gps`
        block) -- same shape as AirOSv8's.

        Returns:
            airoscommon.GPSFix | None: This device's GPS location.
        '''
        return airoscommon.parse_gps_fix(self.getstatus().get('gps'))

    def get_wireless(self) -> list[airoscommon.WirelessRadio]:
        '''This device's own operating frequency/channel width
        (status.cgi's top-level `wireless` block) -- mostly the same
        shape as AirOSv8's, with one confirmed difference: `frequency`
        arrives as a human-formatted string ("11155 MHz"), not a bare
        number, so it's normalized before handing the block to the
        shared parser (built against AirOSv8's plain-numeric field).
        Always a single-element list, matching AirOSv8's/AirFiber's
        multi-radio-shaped return type.

        Returns:
            list[airoscommon.WirelessRadio]: This device's one radio.
        '''
        wireless = dict(self.getstatus().get('wireless', {}))
        frequency = wireless.get('frequency')
        if isinstance(frequency, str):
            wireless['frequency'] = frequency.split()[0] if frequency.split() else 0
        return [airoscommon.parse_status_wireless_radio('main', wireless)]
