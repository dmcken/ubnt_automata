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

- discovery.cgi        - POST discover=y&duration=500. Returns nearby
                         devices found via broadcast discovery (hwaddr,
                         ipv4, hostname, product, uptime, wmode,
                         fwversion) - this is the "Device Discovery"
                         feature in the UI. Confirmed via a captured
                         HAR of the real web UI.

Confirmed NOT present on AF60 HD (404) - do not call these for this
model, kept here only as breadcrumbs for other AirFiber hardware:
- antlist.cgi
- btstatus.cgi
- api/fw/update-check

Confirmed via HAR capture but NOT implemented (out of scope / low
value): both need a separate x-auth-token header rather than the
session's X-CSRF-ID - almost certainly the 'utoken' field from the
/api/auth login response (stored as self._auth_token, but unused so
far since nothing below needs it yet):
- api/v1.0/tools/unms         - UNMS/UISP cloud connection status.
                                 Mostly duplicates the same sensitive
                                 UISP key already present in getcfg()'s
                                 unms.uri.
- api/v1.0/tools/proxy/https  - A generic outbound-HTTPS relay the
                                 device uses to reach Ubiquiti's cloud
                                 (e.g. checking fw-update.ubnt.com for
                                 new firmware) - not local device
                                 telemetry, needs internet from the
                                 device.

Note: the "Excellent Link"/"Link Potential"/Gbps rate-badge labels
shown in the web UI are NOT returned by the device at all - that UI is
actually served from the external ispdesign.ui.com/linkwidget and
computes those labels client-side from the raw status.cgi fields.
There is no server-side "quality" string to fetch; getstatus()/
get_link_status() below expose the underlying raw numbers instead
(signal, capacity, linkscore, mcs) rather than guessing at a label.

Sensitive data warning: getcfg() can return device secrets in plain
text - notably radio.0.psk (the PTP link's pre-shared key) and the
embedded auth token inside unms.uri. Callers must not log/print the
full getcfg() dict.
'''

# System imports
import dataclasses
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

_MODE_LABELS = {
    'ap-ptp': 'Master',
    'sta-ptp': 'Station',
}


@dataclasses.dataclass
class AirFiberGPS:
    '''GPS fix as reported by one end of an AirFiber link.'''
    latitude: float
    longitude: float
    altitude_m: float
    satellites: int
    fix: int


@dataclasses.dataclass
class AirFiberLinkEnd:
    '''One end (local or remote) of an AirFiber PtP backhaul link.

    signal_expected_dbm/rate_expected/capacity_expected_mbps follow the
    device's dl=local/ul=remote convention (empirically confirmed: the
    web UI's "Local RX Data Rate 11 (Expected 11)" / "Remote RX Data
    Rate 11 (Expected 10)" matched dl_rate_expect=11/ul_rate_expect=10
    exactly). signal_expected_dbm's local/remote split is inferred by
    the same convention but wasn't separately confirmed (both sides
    happened to read the same expected value in testing).
    '''
    hostname: str
    device_model: str
    mac: str
    fw_version: str
    uptime_seconds: int
    cpu_load_pct: float
    memory_used_pct: float
    mode: str
    signal_dbm: int
    signal_expected_dbm: int
    snr_db: int
    rx_mcs: int
    tx_mcs: int
    capacity_mbps: int
    linkscore_pct: int
    gps: AirFiberGPS | None

    @property
    def mode_label(self) -> str:
        '''Friendly label for `mode` (e.g. "Master"/"Station"), or the raw
        value if unrecognised.'''
        return _MODE_LABELS.get(self.mode, self.mode)


@dataclasses.dataclass
class AirFiberLinkStatus:
    '''Structured view of an AirFiber PtP backhaul link (status.cgi).

    Throughput units are as reported by the device (wireless.throughput.
    tx/rx) - the exact unit scale (Kbps vs some other factor) wasn't
    confirmed against a simultaneous UI reading, so treat these as
    relative/raw rather than a confirmed Mbps value.
    '''
    distance_m: int
    local: AirFiberLinkEnd
    remote: AirFiberLinkEnd
    throughput_tx_raw: int
    throughput_rx_raw: int

    @property
    def total_capacity_mbps(self) -> int:
        '''Sum of both ends' one-directional capacity - confirmed to match
        the UI's "Total Capacity" (924 + 2156 = 3080 Mbps observed).'''
        return self.local.capacity_mbps + self.remote.capacity_mbps


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
        # From login's 'utoken' - not currently used by any implemented
        # endpoint, kept for the x-auth-token-gated endpoints noted above.
        self._auth_token = None

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
        auth_json = rez.json()
        self._dev_info = auth_json.get('boardinfo')
        self._auth_token = auth_json.get('utoken')
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

    def get_boardinfo(self) -> dict[str, str]:
        '''Parse the boardinfo blob captured at login (login_http() must
        have been called first).

        Same newline-separated key=value format as getcfg(). This is
        where the short model code (e.g. board.model=AF60HD,
        board.shortname=AF60-HD) lives - status.cgi/getcfg() only expose
        the long form ("airFiber 60 HD").

        Returns:
            dict[str,str]: Board info key=value pairs.
        '''
        board_data = {}
        for curr_line in (self._dev_info or '').split('\n'):
            curr_line = curr_line.strip()
            if not curr_line:
                continue
            try:
                key, val = curr_line.split('=', 1)
                board_data[key] = val
            except ValueError:
                logger.error(f"Unable to parse line: {curr_line}")

        return board_data

    def get_discovery(self, duration_ms: int = 500) -> list[dict]:
        '''Broadcast-discover nearby Ubiquiti devices (discovery.cgi).

        This is the "Device Discovery" feature in the web UI - confirmed
        via a captured HAR of a real session (POST discover=y&duration=500).

        Args:
            duration_ms (int, optional): How long the device should scan
                for, in milliseconds. Defaults to 500 (matching the UI).

        Raises:
            RuntimeError: Raised if the data can't be parsed.

        Returns:
            list[dict]: One entry per discovered device (hwaddr, ipv4,
                hostname, product, uptime, wmode, fwversion, addresses).
        '''
        res = self._req_session.post(
            self._build_url("discovery.cgi"),
            data={'discover': 'y', 'duration': duration_ms},
            verify=self._verify_ssl,
            timeout=self._timeout,
            headers={'X-CSRF-ID': self._csrf_id},
        )

        if res.status_code == 200:
            return res.json().get('devices', [])

        raise RuntimeError(f"Error fetching discovery data: {res.status_code} {res.text}")

    def get_link_status(self) -> AirFiberLinkStatus:
        '''Structured view of the PtP backhaul link, built from getstatus().

        Only handles the single-station case (one PtP peer) - raises if
        the device reports zero or more than one station, since this
        hasn't been observed/verified against real hardware.

        Raises:
            RuntimeError: Raised if the device isn't linked to exactly
                one station.

        Returns:
            AirFiberLinkStatus: Structured link status.
        '''
        status = self.getstatus()

        stations = status['wireless']['sta']
        if len(stations) != 1:
            raise RuntimeError(
                f"Expected exactly one PtP station, got {len(stations)}"
            )
        sta = stations[0]
        prs_local = sta['prs_sta']
        remote = sta['remote']
        prs_remote = remote['prs_remote']

        local_gps = None
        if status.get('gps', {}).get('fix'):
            local_gps = AirFiberGPS(
                latitude=status['gps']['lat'],
                longitude=status['gps']['lon'],
                altitude_m=status['gps']['alt'],
                satellites=status['gps']['sats'],
                fix=status['gps']['fix'],
            )

        remote_gps = None
        if remote.get('gps', {}).get('fix'):
            remote_gps = AirFiberGPS(
                latitude=float(remote['gps']['lat']),
                longitude=float(remote['gps']['lon']),
                altitude_m=float(remote['gps']['alt']),
                satellites=remote['gps']['sats'],
                fix=remote['gps']['fix'],
            )

        local_end = AirFiberLinkEnd(
            hostname=status['host']['hostname'],
            device_model=status['host']['devmodel'],
            mac=status['wireless']['apmac'],
            fw_version=status['host']['fwversion'],
            uptime_seconds=status['host']['uptime'],
            cpu_load_pct=status['host']['cpuload'],
            memory_used_pct=self._mem_used_pct(
                status['host']['totalram'], status['host']['freeram']
            ),
            mode=status['wireless']['mode'],
            signal_dbm=prs_local['rssi_data'],
            signal_expected_dbm=prs_local['dl_signal_expect'],
            snr_db=prs_local['snr'],
            rx_mcs=prs_local['rx_mcs'],
            tx_mcs=prs_local['tx_mcs'],
            capacity_mbps=prs_local['capacity'],
            linkscore_pct=prs_local['dl_linkscore'],
            gps=local_gps,
        )

        remote_end = AirFiberLinkEnd(
            hostname=remote['hostname'],
            device_model=remote['platform'],
            mac=sta['mac'],
            fw_version=remote['version'],
            uptime_seconds=remote['uptime'],
            cpu_load_pct=remote['cpuload'],
            memory_used_pct=self._mem_used_pct(
                remote['totalram'], remote['freeram']
            ),
            mode=remote['mode'],
            signal_dbm=prs_remote['rssi_data'],
            signal_expected_dbm=prs_local['ul_signal_expect'],
            snr_db=prs_remote['snr'],
            rx_mcs=prs_local['tx_mcs'],
            tx_mcs=prs_remote['tx_mcs'],
            capacity_mbps=prs_remote['capacity'],
            linkscore_pct=prs_local['ul_linkscore'],
            gps=remote_gps,
        )

        return AirFiberLinkStatus(
            distance_m=sta['distance'],
            local=local_end,
            remote=remote_end,
            throughput_tx_raw=status['wireless']['throughput']['tx'],
            throughput_rx_raw=status['wireless']['throughput']['rx'],
        )

    @staticmethod
    def _mem_used_pct(totalram: int, freeram: int) -> float:
        '''Memory used, as a percentage - status.cgi only gives total/free
        bytes, not a ready-made percentage (the UI computes this too).'''
        return (totalram - freeram) / totalram * 100
