'''Ubnt v8 handler.
'''
from __future__ import annotations

# System imports
import dataclasses
import http.client
import json
import logging
import pprint
import time

# External imports
import requests
import urllib3

# Local imports
from . import airoscommon, exceptions, utils

logger = logging.getLogger(__name__)

# Disable the self signed certificate warnings.
urllib3.disable_warnings()


@dataclasses.dataclass
class AirOSv8UpgradeStatus:
    '''Progress of an in-flight (or just-finished) firmware upgrade
    (the /api/v1.0/system/upgrade GET response) - a different shape
    from UispDevice's UpgradeStatus (no metadata.version, no warnings
    list; has remaining_time and a failure_reason string instead).
    Confirmed live: "finished" means the image has been downloaded and
    staged, NOT that it's been applied - see commit_upgrade().
    '''
    status: str | None
    progress_percent: int
    remaining_time: int
    failure_reason: str


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
    - get_gps() added - status.cgi's top-level `gps` block, same shape
      as AirFiber's (used for the tower/site GPS a device with built-in
      GPS can report, not to be confused with per-peer GPS on a link).

    Confirmed live against a real GigaBeam LR (fw v1.4.0): the firmware-
    upgrade trio (start_upgrade()/get_upgrade_status()/commit_upgrade(),
    or upgrade_and_wait() for a blocking wrapper) - see each method's
    docstring. This device turns out to be a genuine hybrid: every
    other method on this class goes through the X-CSRF-ID/.cgi surface
    (_get()/_post()), but upgrading additionally needs the SAME modern
    /api/v1.0/ JSON REST surface UispDevice uses (a DIFFERENT credential
    though - its own x-auth-token, called `utoken` in the api/auth
    response, not the X-CSRF-ID header value - both come back from the
    exact same login call, captured by login_http() into separate
    attributes). The two-stage shape itself is also new: system/upgrade
    only downloads+stages the image (confirmed live: progressPercent
    stayed 0 throughout, same as UISP-firmware, then jumped to 100/
    "finished" - no restart happened at that point), and a SEPARATE
    legacy fwflash.cgi call (do_update=1, X-CSRF-ID auth like every
    other .cgi endpoint here) is what actually commits it to flash and
    reboots - confirmed live the real web UI waits ~12s after "finished"
    before sending it. Device went unreachable for ~168s after that,
    closely matching the api/auth response's own boardinfo
    (board.upgrade=180) - upgrade_and_wait() does not itself wait for
    the device to come back online, matching UispDevice.reboot()'s
    fire-and-forget behaviour; confirming the device actually
    recovered is left to the caller, the same as every real upgrade
    run against UispDevice this was built alongside.

    UNCONFIRMED whether this upgrade surface exists on anything but a
    GigaBeam LR - the Rocket Prism 5AC these other methods were
    confirmed against was never tested against it, and may simply 404
    (start_upgrade() surfaces that as a plain RuntimeError, not a
    crash, either way).

    To implement:
    - /chanlist_active.cfg
    - /amdata.cgi


    To implement:
    loginSSH
    changeParameterHTTP
    changeParameterSSH
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
        self._auth_token = None

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

    def _get_v1(self, path: str) -> requests.Response:
        '''Authenticated GET against the newer /api/v1.0/ surface this
        device ALSO exposes (confirmed live, GigaBeam LR) alongside the
        X-CSRF-ID/.cgi one every other method here uses - keyed by
        _auth_token (the api/auth response's `utoken`), not _csrf_id.
        '''
        return self._req_session.get(
            self._build_url(f"api/v1.0/{path}"),
            verify=self._verify_ssl,
            timeout=self._timeout,
            headers={'x-auth-token': self._auth_token},
        )

    def _post_v1(self, path: str, json_body: dict | None = None) -> requests.Response:
        '''POST counterpart to _get_v1() - see its docstring.'''
        return self._req_session.post(
            self._build_url(f"api/v1.0/{path}"),
            json=json_body,
            verify=self._verify_ssl,
            timeout=self._timeout,
            headers={'x-auth-token': self._auth_token},
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
            # A SEPARATE credential from _csrf_id (confirmed live the
            # two values differ) - only used by the /api/v1.0/ surface,
            # see start_upgrade()/get_upgrade_status(). Not every
            # AirOSv8 device's api/auth response has been confirmed to
            # include this key, so default to None rather than KeyError.
            self._auth_token = rez.json().get('utoken')
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

    def get_gps(self) -> airoscommon.GPSFix | None:
        '''This device's own GPS location (status.cgi's top-level `gps`
        block) - confirmed live on a real Rocket Prism 5AC Gen2. None if
        the device has no GPS fix (or no GPS hardware at all).

        Raises:
            RuntimeError: Raised if the data can't be parsed.

        Returns:
            airoscommon.GPSFix | None: This device's GPS location.
        '''
        return airoscommon.parse_gps_fix(self.getstatus().get('gps'))

    def get_wireless(self) -> list[airoscommon.WirelessRadio]:
        '''This device's own operating frequency/channel width
        (status.cgi's top-level `wireless` block) - confirmed live on a
        real Rocket Prism 5AC Gen2 (essid, frequency, center1_freq,
        chanbw all populated). Always a single-element list - an AirOS
        v8 unit has exactly one radio - so the return type matches
        AirFiber's/UISP's multi-radio shape at the call site.

        Raises:
            RuntimeError: Raised if the data can't be parsed.

        Returns:
            list[airoscommon.WirelessRadio]: This device's one radio.
        '''
        wireless = self.getstatus().get('wireless', {})
        return [airoscommon.parse_status_wireless_radio('main', wireless)]

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

    def start_upgrade(self, url: str, secure: bool = False) -> None:
        '''Start a firmware upgrade (/api/v1.0/system/upgrade, POST).

        Confirmed live (GigaBeam LR): same url-based mechanism as
        UispDevice.start_upgrade() - the device fetches and stages the
        firmware itself from `url`, so this doesn't have to be one of
        Ubiquiti's own servers (see ubnt_automata.firmware_catalog for
        querying that catalog directly). Confirmed DIFFERENT from
        UispDevice in two ways: no `timeout` key in the real request
        body (only url/secure), and this only downloads+stages the
        image - it does NOT apply it. Call commit_upgrade() (or use
        upgrade_and_wait()) once get_upgrade_status() reports
        "finished" to actually flash and reboot.

        IMPORTANT: this writes to the device - there is no dry-run/
        undo once commit_upgrade() is called.

        Args:
            url: Firmware image URL, reachable BY THE DEVICE - see
                UispDevice.start_upgrade()'s docstring, same reasoning.
            secure: Whether the device should verify the URL's TLS
                certificate. Confirmed live the real web UI sends
                `false` even for an https:// Ubiquiti CDN URL.

        Raises:
            RuntimeError: Raised if the device rejects the request
                itself - NOT raised for an upgrade that fails after
                starting; poll get_upgrade_status() for that.
        '''
        res = self._post_v1("system/upgrade", json_body={'url': url, 'secure': secure})
        if res.status_code != 200:
            raise RuntimeError(f"Error starting upgrade: {res.status_code} {res.text}")

    def get_upgrade_status(self) -> AirOSv8UpgradeStatus:
        '''Current firmware upgrade progress (/api/v1.0/system/upgrade,
        GET).

        Confirmed live (GigaBeam LR): progressPercent stayed at 0 for
        the entire download (no granular progress, same as
        UispDevice), then jumped straight to 100/"finished" - at which
        point the image is only staged, not yet applied (see
        commit_upgrade()). No failure case has been observed live -
        failure_reason is passed through as-is (empty string normally;
        a non-empty value is treated as a hard failure by
        upgrade_and_wait() regardless of `status`, since its meaning
        isn't ambiguous the way an unrecognized status string would be).

        Raises:
            RuntimeError: Raised if the data can't be parsed.

        Returns:
            AirOSv8UpgradeStatus: Current upgrade progress.
        '''
        res = self._get_v1("system/upgrade")
        if res.status_code != 200:
            raise RuntimeError(f"Error fetching upgrade status: {res.status_code} {res.text}")

        data = res.json()
        return AirOSv8UpgradeStatus(
            status=data.get('status'),
            progress_percent=data.get('progressPercent', 0),
            remaining_time=data.get('remainingTime', 0),
            failure_reason=data.get('failureReason', ''),
        )

    def commit_upgrade(self) -> None:
        '''Apply a staged upgrade and reboot (fwflash.cgi, POST
        do_update=1).

        Confirmed live (GigaBeam LR): this is the step that actually
        flashes the image get_upgrade_status() already reported
        "finished" (staged) - the device went unreachable for ~168s
        right after this call, then came back running the new
        firmware. Uses the SAME X-CSRF-ID auth as every other .cgi
        method on this class (unlike start_upgrade()/
        get_upgrade_status(), which need the separate _auth_token) -
        reuses _post() unchanged.

        Calling this with nothing staged, or before get_upgrade_status()
        reports "finished", has not been tested - do_update=1 is
        assumed to be meaningless/safe in that case, not confirmed.

        Raises:
            RuntimeError: Raised if the device rejects the request
                itself. The device going unreachable immediately after
                a successful call is the expected/confirmed behaviour,
                not a failure of this call.
        '''
        res = self._post("fwflash.cgi", data={'do_update': '1'})
        if res.status_code != 200:
            raise RuntimeError(f"Error committing upgrade: {res.status_code} {res.text}")

    def upgrade_and_wait(
        self, url: str, secure: bool = False,
        poll_interval: float = 1.0, max_wait: float = 300.0,
    ) -> AirOSv8UpgradeStatus:
        '''Start a firmware upgrade, block until it's staged, then
        commit it (flash + reboot).

        See start_upgrade() for what `url` can be. Unlike
        UispDevice.upgrade_and_wait(), this does NOT itself wait for
        the device to come back online afterwards - commit_upgrade()
        is fire-and-forget, the same as UispDevice.reboot(). Confirming
        the device actually recovered (it took ~168s live, against a
        real GigaBeam LR) is left to the caller.

        IMPORTANT: this writes to the device and can brick it if
        interrupted or given a bad image - there is no dry-run/undo.

        Args:
            url: Firmware image URL - see start_upgrade().
            secure: See start_upgrade().
            poll_interval: Seconds between get_upgrade_status() calls.
            max_wait: Give up and raise if staging hasn't reached
                "finished" within this many seconds.

        Raises:
            exceptions.UpgradeFailed: Raised if the device reports a
                non-empty failure_reason, an unrecognized status, or
                if max_wait elapses first.

        Returns:
            AirOSv8UpgradeStatus: The "finished" (staged) status, just
                before commit_upgrade() was called.
        '''
        self.start_upgrade(url, secure=secure)

        elapsed = 0.0
        while elapsed < max_wait:
            status = self.get_upgrade_status()
            if status.failure_reason:
                raise exceptions.UpgradeFailed(
                    f"Device {self._mgmt_ip} reported a failed upgrade: {status.failure_reason!r}"
                )
            if status.status == 'finished':
                self.commit_upgrade()
                return status
            if status.status not in (None, 'in_progress'):
                raise exceptions.UpgradeFailed(
                    f"Device {self._mgmt_ip} reported upgrade status {status.status!r}"
                )
            time.sleep(poll_interval)
            elapsed += poll_interval

        raise exceptions.UpgradeFailed(
            f"Device {self._mgmt_ip} did not finish staging the upgrade within {max_wait}s"
        )

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
