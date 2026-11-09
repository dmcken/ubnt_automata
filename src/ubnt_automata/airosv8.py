'''Ubnt v8 handler.
'''
from __future__ import annotations

# System imports
import dataclasses
import hashlib
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


@dataclasses.dataclass
class FirmwareDownloadProgress:
    '''Progress of an in-flight firmware download (api/fw/download,
    POST action=progress) - the LTU-family counterpart to
    AirOSv8UpgradeStatus/UpgradeStatus, confirmed live on an LTU-Lite.
    A completely different shape again: status is an int (0 every time
    observed, meaning in-progress/ok - no failure case confirmed
    live), and percent climbs smoothly rather than jumping straight
    from 0 to 100.
    '''
    status: int
    percent: int
    bytes_downloaded: int


@dataclasses.dataclass
class FirmwareUpdateInfo:
    '''What a device's own api/fw/update-check reports is available -
    confirmed live on a real NanoStation 5AC loco (classic airMAX AC, a
    FOURTH distinct upgrade mechanism on this one class - see
    upload_and_upgrade()'s docstring for why this family needs its own
    client-side-fetch-then-upload flow rather than reusing either of
    the other two). update_available=False with every other field
    blank/zero is the confirmed-live shape once nothing is outstanding
    (checked by re-querying right after a real successful upgrade).

    IMPORTANT: download_url/checksum here are NOT the same object
    firmware_catalog's CATALOG_IDENTITY-based lookup would give you
    for the same version number - confirmed live the MD5 each reports
    for the identical "v8.7.25" differs entirely. Only the file THIS
    method points at has been confirmed to upload and flash correctly
    on real hardware; treat the two as different files that happen to
    share a version label, not interchangeable.
    '''
    update_available: bool
    version: str | None
    download_url: str | None
    checksum: str | None
    changelog_url: str | None


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
    crash, either way). CONFIRMED NOT the mechanism a real LTU-Lite's
    own web UI actually uses, despite get_upgrade_status() responding
    cleanly against one too (an idle "status": None, the same shape
    GigaBeam reports) - that response alone doesn't mean start_upgrade()
    is the right call for a given device; see download_and_upgrade()
    below for what LTU-Lite's own web UI actually does instead.

    Confirmed live against a real LTU-Lite (fw v2.3.2, upgrading to a
    real v2.4.2): a THIRD, unrelated firmware-upgrade mechanism -
    start_firmware_download()/get_firmware_download_progress(), or
    download_and_upgrade() for a blocking wrapper - see each method's
    docstring. Reuses commit_upgrade() unchanged for the actual flash +
    reboot (confirmed live, same fwflash.cgi call, same ~2-3 minute
    downtime). Everything else differs from GigaBeam's flow: plain
    X-CSRF-ID auth throughout (no separate _auth_token needed), a
    different pair of endpoints (api/fw/download, not api/v1.0/system/
    upgrade), form-encoded rather than JSON bodies, and a progress poll
    that's itself a POST, not a GET. CONFIRMED LIVE HAZARD: a device
    with some prior stuck operation rejects a new download attempt
    with {"status": 0, "error": "connection failed", "error_details":
    "Operation already in progress"} (still an HTTP 200, so callers
    checking only status_code won't notice) - a plain reboot cleared
    this live.

    Confirmed live against a real LTU-Rocket (same AFLTU image,
    download_and_upgrade() itself worked fine): commit_upgrade() can
    ALSO get a 200 with a body reporting failure - "Firmware image
    check failed. Error code: 99" - rather than the device actually
    being wrong for this family, this means LTU-Rocket needs its own,
    still-unknown catalog identity (see firmware_catalog's module
    docstring) - firmware_catalog.CATALOG_IDENTITY deliberately does
    NOT list LTU-Rocket/Pro/XR/Instant despite sharing a changelog with
    LTU-Lite/LR, now that this is confirmed for Rocket specifically.
    7 real LTU-Rocket units got this exact rejection live, all stayed
    perfectly healthy throughout (uptime unaffected, nothing flashed) -
    this is the device's own safety check working as intended, not a
    brick risk, but it only surfaces correctly because commit_upgrade()
    checks the response body, not just status_code (see its own
    docstring) - an earlier version of this method didn't, and a batch
    script polling for recovery by login-success-alone silently read
    all 7 as "recovered" with their original firmware unchanged.

    Confirmed live against a real NanoStation 5AC loco (classic
    airMAX AC, fw v8.7.11, upgrading to a real v8.7.25): a FOURTH,
    again-unrelated upgrade mechanism - check_firmware_update()/
    upload_firmware(), or upload_and_upgrade() for a blocking wrapper.
    Unlike every other mechanism on this class, the device does NOT
    fetch the image itself here - confirmed live its own device-side
    auto-fetch (api/fw/download, the same endpoint LTU uses
    successfully) reliably fails with "Firmware download failed", and
    the real web UI's own fallback - confirmed live in the exact same
    HAR, not inferred - is to fetch the image into the BROWSER and
    upload it directly (fwupl.cgi, multipart/form-data). Reuses
    commit_upgrade() unchanged for the actual flash + reboot once
    uploaded. Also confirmed live: this family's own update-check
    (dl.ubnt.com, Ubiquiti's legacy distribution host) reports a
    DIFFERENT checksum for the "same" version than firmware_catalog's
    modern catalog does - only the device's own reported file is
    confirmed to upload and flash correctly, so upload_and_upgrade()
    never uses firmware_catalog for this family (see
    FirmwareUpdateInfo's docstring). For a bulk run across many
    devices of the same board revision, see
    ubnt_automata.ui_download_catalog - a THIRD source (confirmed live
    separately, unauthenticated, labels board revision explicitly) fit
    for fetching the image client-side ONCE instead of once per
    device; upload_and_upgrade()'s firmware_data parameter still
    checks whatever it's given against this device's own reported
    checksum regardless, so using that source doesn't weaken this
    safety check.

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
        self, path: str, data=None, extra_headers: dict | None = None, files=None,
    ) -> requests.Response:
        '''Authenticated POST against a data endpoint. `files` (added
        for upload_firmware()) is passed straight through to requests,
        which then sets its own correct multipart Content-Type
        (including the boundary) regardless of any header passed here.
        '''
        return self._req_session.post(
            self._build_url(path),
            data=data,
            files=files,
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
            exceptions.WrongPassword: The device actually rejected
                these credentials (401/403).
            exceptions.UnexpectedLoginResponse: Any other non-200 -
                429 (rate limited), 5xx, etc. Confirmed live on the
                AirFiber class (which this module documents as
                sharing this exact auth mechanism): treating every
                non-200 as WrongPassword is actively harmful, since
                login()'s alternate-password retry loop only stops on
                WrongPassword - a transient rate-limit would
                previously cascade into trying every password in the
                list, each one another POST, making the rate-limiting
                worse instead of surfacing the real problem.
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

            if rez.status_code in (401, 403):
                logger.debug(f"Wrong password for {self._mgmt_ip}: {rez.status_code}")
                raise exceptions.WrongPassword()
            if rez.status_code != 200:
                logger.warning(
                    f"Unexpected (non-auth) login response from {self._mgmt_ip}: "
                    f"{rez.status_code}"
                )
                raise exceptions.UnexpectedLoginResponse(rez.status_code, rez.text)

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

        STILL not independently confirmed live: a real writecfg.cgi
        call (HAR capture, AirFiber 5X HD - this class's own docstring
        elsewhere claims AirFiber mirrors this auth/write mechanism
        byte-for-byte) was immediately followed by the device
        restarting networking on its own, with no call to
        test_mode.cgi anywhere in that flow. So at least for changes
        that set fast_restart=true in writecfg()'s result, this method
        is apparently not part of the sequence at all - left as-is
        (unverified on this class specifically) for whatever flow it
        was originally written for.
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

    def writecfg(
        self, cfgdata: dict[str, str], avoid_fast_restart: bool = False,
    ) -> airoscommon.WriteCfgResult:
        """Write config to device.

        Confirmed live (HAR capture against a real AirFiber 5X HD,
        which this module documents as sharing this exact auth/write
        mechanism with AirOSv8 byte-for-byte) - corrected from the
        prior unverified implementation on two points, NOT yet
        reconfirmed against AirOSv8 hardware specifically:

        1. writecfg.cgi replaces the ENTIRE device config, not a
           diff - the real request posts all existing keys with the
           changed ones overlaid, not just the changed ones. This
           method now does that for you: pass only the keys you want
           changed, it fetches the current config and overlays them.
        2. The real response has no "ok" key (the prior code's
           `res_data['ok']` would have raised KeyError on every real
           call - confirmed, this is exactly what happened in
           testing against the AirFiber class, which shares this
           code). Success is code == 0.

        Args:
            cfgdata: The keys to change, in the same flat key=value
                shape getcfg() returns - NOT the full config, this
                method builds that for you.
            avoid_fast_restart: If True, refuses to send the request
                at all when cfgdata contains a key already confirmed
                (see airoscommon._KNOWN_FAST_RESTART_KEYS) to make the
                device restart networking and drop the link for
                ~15-20s - raises exceptions.FastRestartRequired
                instead. This is a known-keys allowlist, not a
                guarantee: a key not yet in that set can still come
                back with fast_restart=true in the result, so check
                the return value either way.

        Returns:
            airoscommon.WriteCfgResult

        Raises:
            exceptions.FastRestartRequired: avoid_fast_restart=True and
                cfgdata contains a key known to trigger one.
        """
        if avoid_fast_restart:
            risky = set(cfgdata) & airoscommon._KNOWN_FAST_RESTART_KEYS
            if risky:
                raise exceptions.FastRestartRequired(
                    f"Refusing write to {self._mgmt_ip}: "
                    f"{sorted(risky)} is known to trigger fast_restart "
                    "(wireless link will drop ~15-20s while it applies)"
                )

        full_cfg = dict(self.getcfg())
        full_cfg.update(cfgdata)
        lines = [f"{k}={val}" for k, val in full_cfg.items()]

        logger.debug(f"Writecfg lines: {pprint.pformat(lines)}")

        cfg_output = "\r\n".join(lines)

        logger.debug(f"Cfgoutput: \n{cfg_output}")

        cfg_data = {'cfgData': cfg_output}
        rez = self._post("writecfg.cgi", data=cfg_data)

        try:
            write_result = rez.json()
        except json.decoder.JSONDecodeError:
            logger.error(f"Error decoding json in writecfg: {rez.content}")
            return airoscommon.WriteCfgResult(success=False, fast_restart=False, raw={})

        success = write_result.get('code') == 0
        fast_restart = bool(write_result.get('fast_restart'))
        if not success:
            logger.error(f"Error changing config: {write_result}")
        if fast_restart:
            logger.warning(
                f"writecfg on {self._mgmt_ip} set fast_restart=true - "
                "wireless link will drop briefly while it applies"
            )
        return airoscommon.WriteCfgResult(
            success=success, fast_restart=fast_restart, raw=write_result,
        )

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
        '''Apply a staged/downloaded image and reboot (fwflash.cgi,
        POST do_update=1).

        Confirmed live (GigaBeam LR, LTU-Lite, LTU-LR): on success this
        is the step that actually flashes the image and reboots - the
        device goes unreachable for a couple of minutes right after
        this call, then comes back running the new firmware. Uses the
        SAME X-CSRF-ID auth as every other .cgi method on this class
        (unlike start_upgrade()/get_upgrade_status(), which need the
        separate _auth_token) - reuses _post() unchanged.

        CONFIRMED LIVE HAZARD (and the reason this checks the response
        BODY, not just status_code): the device can reject the image
        itself at this step while still returning HTTP 200 - confirmed
        live against a real LTU-Rocket, whose own firmware-image
        validation refused an AFLTU-platform image built for a
        different chipset ("amesoc3", confirmed live that's what
        LTU-Lite/LTU-LR actually run) with body {"message": "Firmware
        image check failed. Error code: 99", "error_details":
        "afltu.amesoc3.v2.4.2...", "code": -1} - a working safety
        check, not a bug in the device, but one that silently looks
        identical to success if a caller only checks status_code (as
        an earlier version of this method did - it does not, treating
        a batch of these as successful recoveries to a later login
        this method's own result had not actually caused is the real
        hazard here, not the device itself). Confirmed-good responses
        (GigaBeam LR and LTU-Lite/LR alike) are {"message": "Upgrade
        initiated", "code": 0} - code is the field checked.

        Calling this with nothing staged, or before get_upgrade_status()
        reports "finished", has not been tested - do_update=1 is
        assumed to be meaningless/safe in that case, not confirmed.

        Raises:
            RuntimeError: Raised if the device rejects the request at
                the HTTP level (non-200).
            exceptions.UpgradeFailed: Raised if the device accepts the
                request (200) but its own response body reports
                failure (a non-zero `code`) - see the hazard above.
        '''
        res = self._post("fwflash.cgi", data={'do_update': '1'})
        if res.status_code != 200:
            raise RuntimeError(f"Error committing upgrade: {res.status_code} {res.text}")

        data = res.json()
        if data.get('code', 0) != 0:
            raise exceptions.UpgradeFailed(
                f"Device {self._mgmt_ip} rejected the commit: {data.get('message')!r} "
                f"({data.get('error_details')!r})"
            )

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
                non-empty failure_reason, an unrecognized status, if
                max_wait elapses first, or if staging reaches
                "finished" but commit_upgrade() itself then reports
                failure (confirmed live against a real LTU-Rocket,
                a different upgrade flow but the same shared method -
                see its docstring).

        Returns:
            AirOSv8UpgradeStatus: The "finished" (staged) status -
                commit_upgrade() has also been called successfully by
                the time this returns.
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

    def start_firmware_download(self, fw_url: str, fw_checksum: str) -> None:
        '''Start downloading a firmware image (api/fw/download, POST
        action=download) - a THIRD, distinct upgrade mechanism from
        both UispDevice's and this class's own start_upgrade(),
        confirmed live via a captured HAR of a real LTU-Lite's own web
        UI. Unlike start_upgrade()'s single url+secure body, this needs
        the image's own md5 (as fw_checksum) alongside its URL -
        confirmed live both come from the SAME firmware_catalog
        release (fw_url=download_url, fw_checksum=md5). Uses the
        ordinary X-CSRF-ID auth every other method on this class uses
        (confirmed live) - no separate _auth_token needed, unlike
        start_upgrade()/get_upgrade_status().

        Returns as soon as the device acknowledges the request - the
        actual download happens asynchronously, tracked via
        get_firmware_download_progress(). See download_and_upgrade()
        for a blocking helper that polls to completion and commits.

        CONFIRMED LIVE HAZARD: a device with a stuck prior download
        attempt rejects this (and even the read-only update-check
        step this skips, see the module docstring note on
        firmware_catalog's AFLTU entry) with a connection-level error
        whose body is {"status": 0, "error": "connection failed",
        "error_details": "Operation already in progress"} - a plain
        reboot of the device cleared this live. Not raised as a
        distinct exception here (status_code is still 200), so a
        caller that parses the body itself should watch for it.

        IMPORTANT: this writes to the device and can brick it if
        interrupted or given a bad image - there is no dry-run/undo.

        Args:
            fw_url: Firmware image URL, reachable BY THE DEVICE - see
                UispDevice.start_upgrade()'s docstring, same reasoning.
            fw_checksum: The image's MD5 checksum (firmware_catalog's
                FirmwareRelease.md5) - confirmed live the real web UI
                always sends this alongside fw_url.

        Raises:
            RuntimeError: Raised if the device rejects the request at
                the HTTP level (non-200) - NOT raised for the
                "Operation already in progress" case above, which is
                still a 200.
        '''
        res = self._post("api/fw/download", data={
            'action': 'download', 'fw_url': fw_url, 'fw_checksum': fw_checksum,
        })
        if res.status_code != 200:
            raise RuntimeError(f"Error starting firmware download: {res.status_code} {res.text}")

    def get_firmware_download_progress(self) -> FirmwareDownloadProgress:
        '''Current firmware download progress (api/fw/download, POST
        action=progress - a POST, not a GET, confirmed live).

        Confirmed live: percent climbs smoothly from 0 to 100 (unlike
        UispDevice's/this class's own get_upgrade_status(), which only
        ever reported 0 until jumping straight to 100). status is 0
        throughout an actual download, but confirmed live a device
        with nothing in flight (no download ever started, or one
        already finished) reports status=-1 instead - the same kind of
        idle-vs-failure ambiguity as UispDevice's/this class's own
        None status, and handled the same way: download_and_upgrade()
        treats both 0 and -1 as "not failed" rather than raising,
        since a transient -1 on the very first poll right after
        start_firmware_download() would otherwise abort a perfectly
        healthy download. No other status value has been observed
        live.

        Raises:
            RuntimeError: Raised if the data can't be parsed.

        Returns:
            FirmwareDownloadProgress: Current download progress.
        '''
        res = self._post("api/fw/download", data={'action': 'progress'})
        if res.status_code != 200:
            raise RuntimeError(f"Error fetching download progress: {res.status_code} {res.text}")

        data = res.json()
        return FirmwareDownloadProgress(
            status=data.get('status', 0),
            percent=data.get('percent', 0),
            bytes_downloaded=data.get('bytes', 0),
        )

    def download_and_upgrade(
        self, fw_url: str, fw_checksum: str,
        poll_interval: float = 1.0, max_wait: float = 300.0,
    ) -> FirmwareDownloadProgress:
        '''Download a firmware image, wait for it to finish, then
        commit it (flash + reboot) - the LTU-family counterpart to
        upgrade_and_wait(), for devices confirmed to use api/fw/
        download instead of api/v1.0/system/upgrade (see
        start_firmware_download()'s docstring for how to tell which
        one applies).

        See start_firmware_download() for what fw_url/fw_checksum are
        and where they come from (firmware_catalog's download_url/md5
        for "latest", or any other reachable URL plus its own real MD5
        for a specific/manually-downloaded file).

        IMPORTANT: this writes to the device and can brick it if
        interrupted or given a bad image - there is no dry-run/undo.

        Args:
            fw_url: See start_firmware_download().
            fw_checksum: See start_firmware_download().
            poll_interval: Seconds between
                get_firmware_download_progress() calls.
            max_wait: Give up and raise if the download hasn't reached
                100% within this many seconds.

        Raises:
            exceptions.UpgradeFailed: Raised if the device reports a
                status other than 0 (in-progress) or -1 (idle - see
                get_firmware_download_progress()'s docstring), if
                max_wait elapses first, or if the download reaches
                100% but commit_upgrade() itself then reports failure
                (confirmed live against a real LTU-Rocket - see its
                docstring).

        Returns:
            FirmwareDownloadProgress: The 100%-complete download
                status - commit_upgrade() has also been called
                successfully by the time this returns.
        '''
        self.start_firmware_download(fw_url, fw_checksum)

        elapsed = 0.0
        while elapsed < max_wait:
            progress = self.get_firmware_download_progress()
            if progress.status not in (0, -1):
                raise exceptions.UpgradeFailed(
                    f"Device {self._mgmt_ip} reported download status {progress.status!r}"
                )
            if progress.percent >= 100:
                self.commit_upgrade()
                return progress
            time.sleep(poll_interval)
            elapsed += poll_interval

        raise exceptions.UpgradeFailed(
            f"Device {self._mgmt_ip} did not finish downloading within {max_wait}s"
        )

    def check_firmware_update(self, force: bool = False) -> FirmwareUpdateInfo:
        '''Ask the device itself whether an update is available
        (api/fw/update-check, POST) - confirmed live this is a classic
        airMAX AC device's OWN check against Ubiquiti's legacy
        dl.ubnt.com firmware distribution, a completely different
        source from firmware_catalog's modern fw-update.ubnt.com API -
        see FirmwareUpdateInfo's docstring for why that matters.

        Args:
            force: Confirmed live the real web UI sends this (as
                force=yes) on a manual re-check; unconfirmed what, if
                anything, it actually changes server-side.

        Raises:
            RuntimeError: Raised if the data can't be parsed.

        Returns:
            FirmwareUpdateInfo: What's available, if anything.
        '''
        data_body = {'force': 'yes'} if force else None
        res = self._post("api/fw/update-check", data=data_body)
        if res.status_code != 200:
            raise RuntimeError(f"Error checking for firmware update: {res.status_code} {res.text}")

        data = res.json()
        return FirmwareUpdateInfo(
            update_available=data.get('update', False),
            version=data.get('version'),
            download_url=data.get('url'),
            checksum=data.get('checksum'),
            changelog_url=data.get('changelog'),
        )

    def upload_firmware(self, data: bytes, filename: str) -> None:
        '''Upload a firmware image directly (fwupl.cgi, POST
        multipart/form-data) - confirmed live this is what a classic
        airMAX AC device's own web UI actually falls back to, because
        its device-side auto-fetch (api/fw/download, the same
        mechanism LTU uses successfully) was confirmed live to fail
        there every time ("Firmware download failed" - the REAL web
        UI hit this exact error 3 times before falling back to this
        method, not just this library). upload_and_upgrade() always
        uses this path directly rather than attempting the unreliable
        auto-fetch first.

        Uses the SAME X-CSRF-ID auth as every other .cgi method on
        this class - reuses _post() (extended to accept `files`, see
        its docstring) rather than a special case.

        IMPORTANT: this writes to the device - there is no dry-run/
        undo once commit_upgrade() is subsequently called.

        Args:
            data: Raw firmware image bytes - see upload_and_upgrade()
                for where these should come from (check_firmware_
                update()'s own download_url, not firmware_catalog -
                see FirmwareUpdateInfo's docstring for why).
            filename: Sent as the multipart field's filename -
                confirmed live the real web UI uses the source URL's
                own last path segment (e.g.
                "WA.v8.7.25.48568.260730.1010.bin").

        Raises:
            RuntimeError: Raised if the device rejects the request at
                the HTTP level, or accepts it (200) but its own body
                reports failure (a non-zero `code` - confirmed-good
                responses look like {"isThirdParty": false, "version":
                "WA.v8.7.25", "code": 0}).
        '''
        res = self._post(
            "fwupl.cgi", files={'fwfile': (filename, data, 'application/octet-stream')},
        )
        if res.status_code != 200:
            raise RuntimeError(f"Error uploading firmware: {res.status_code} {res.text}")

        result = res.json()
        if result.get('code', 0) != 0:
            raise RuntimeError(f"Device {self._mgmt_ip} rejected the uploaded firmware: {result}")

    def upload_and_upgrade(
        self, fetch_timeout: int = 120, firmware_data: bytes | None = None,
    ) -> FirmwareUpdateInfo:
        '''Check for an update, obtain the image, upload it directly,
        then commit it (flash + reboot) - confirmed live end-to-end on
        a real NanoStation 5AC loco (classic airMAX AC).

        This is NOT the same shape as either upgrade_and_wait()
        (GigaBeam) or download_and_upgrade() (LTU), both of which hand
        the device a URL and let IT fetch the image. Confirmed live
        that the equivalent device-side fetch for this family
        (start_upgrade()/start_firmware_download() would both 404 or
        behave unpredictably here anyway - this class never exposed
        them for this hardware) reliably fails with "Firmware download
        failed" - the real web UI hits this exact error itself several
        times before falling back to fetching the file into the
        browser and uploading it, which is what this method always
        does directly, skipping the doomed attempt.

        IMPORTANT: this writes to the device and can brick it if
        interrupted or given a bad image - there is no dry-run/undo.
        By default fetches the real firmware bytes over the network
        from Ubiquiti's own legacy distribution host (dl.ubnt.com, per
        check_firmware_update()) - verifies the bytes actually used
        (fetched here, or supplied via firmware_data) against the
        checksum check_firmware_update() reported before uploading
        anything, either way.

        Args:
            fetch_timeout: Seconds to allow for fetching the firmware
                bytes (a ~10MB file, confirmed live) - separate from
                this device's own self._timeout, which governs each
                individual device-facing HTTP call instead. Unused if
                firmware_data is given.
            firmware_data: Pre-obtained firmware bytes to upload
                directly instead of fetching info.download_url again -
                e.g. a ui_download_catalog.FirmwareCache hit. Skips
                the network fetch, NOT the checksum check below, which
                still runs against whatever bytes end up used. Built
                for a bulk upgrade run across many devices of the same
                board revision, where fetching the same image once per
                device is needlessly slow at fleet scale.

        Raises:
            exceptions.UpgradeFailed: Raised if no update is available,
                or if the bytes used don't match the reported
                checksum.
            RuntimeError: Raised if fetching info.download_url fails
                (only possible when firmware_data isn't given), or if
                upload_firmware()/commit_upgrade() report failure (see
                their own docstrings).

        Returns:
            FirmwareUpdateInfo: What was just installed.
        '''
        info = self.check_firmware_update()
        if not info.update_available:
            raise exceptions.UpgradeFailed(f"Device {self._mgmt_ip} reports no update available")

        if firmware_data is None:
            fetch_res = requests.get(info.download_url, timeout=fetch_timeout)
            if fetch_res.status_code != 200:
                raise RuntimeError(
                    f"Error fetching firmware from {info.download_url}: {fetch_res.status_code}"
                )
            firmware_data = fetch_res.content

        actual_checksum = hashlib.md5(firmware_data).hexdigest()
        if info.checksum and actual_checksum != info.checksum:
            raise exceptions.UpgradeFailed(
                f"Firmware checksum {actual_checksum} does not match "
                f"the {info.checksum} {self._mgmt_ip} itself reported - refusing to upload it"
            )

        filename = info.download_url.rsplit('/', 1)[-1]
        self.upload_firmware(firmware_data, filename)
        self.commit_upgrade()
        return info

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
