'''AirFiber implementation.

Shares the same auth/session mechanism as AirOSv8 (/api/auth, X-CSRF-ID
header). Verified live against a real airFiber 60 HD (AF60HD, fw
v1.2.4, 60GHz), a real airFiber 5XHD (AF-5XHD, fw v1.5.6, 5GHz), and a
real airFiber 60 LR (AF60-LR, 60GHz). The 5GHz/AirMax generation uses a
meaningfully different status.cgi shape for the wireless link, and even
within the 60GHz/PRS generation the AF60-LR moves the link distance to
a different location than the AF60HD (see get_link_status()) - but
everything else (auth, getcfg(), discovery.cgi, ...) is identical
across all three.

Auth endpoint:
- /api/auth

Data endpoints confirmed against both a live AF60 HD and AF5XHD:
- status.cgi          - Rich JSON: host/uptime/fw, wireless link stats,
                         remote-end stats, per-interface counters, GPS.
                         The link-stats sub-shape differs by hardware
                         generation - see get_link_status().
- getcfg.cgi           - Full device config as newline-separated
                         key=value text (same format as AirOSv8).
- hist-stats.cgi       - JSON historical link-score/stat samples.
- ipscan.cgi           - Newline-separated list of IPs seen on the
                         management segment.
- api/warnings         - JSON device warnings (default password set,
                         crash report pending, etc). Field set differs
                         slightly between AF60HD/AF5XHD but both 200.
- airviewdata.cgi      - Returned an empty body on an idle AF60HD;
                         returned real spectral scan data on the
                         AF5XHD. Same shape as AirOSv8's getairview().
- discovery.cgi        - POST discover=y&duration=500. Returns nearby
                         devices found via broadcast discovery (hwaddr,
                         ipv4, hostname, product, uptime, wmode,
                         fwversion) - this is the "Device Discovery"
                         feature in the UI. Confirmed on both models.
- btstatus.cgi         - Bluetooth status (mode/name/discoverable/
                         connection_state). 404 on the AF60HD tested,
                         200 with real data on the AF5XHD.
- antlist.cgi          - Static reference table of compatible antenna
                         models and their gain, per board model. Not
                         live telemetry - bundled in firmware. 404 on
                         the AF60HD tested, 200 on the AF5XHD.

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

Also seen but not implemented (low value / static reference data, not
live telemetry): api/regdomain (regulatory frequency/power table),
api/info/public and api/info/user (pre-auth product name / SSO flag -
api/info/public's role is already covered by utils.determine_device_type()).

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
from __future__ import annotations

# System imports
import dataclasses
import logging

# External imports
import requests
import urllib3

# Local imports
from . import airoscommon, exceptions, utils

logger = logging.getLogger(__name__)

# Disable the self signed certificate warnings.
urllib3.disable_warnings()

_MODE_LABELS = {
    'ap-ptp': 'Master',
    'sta-ptp': 'Station',
}


@dataclasses.dataclass
class AirFiberLinkEnd:
    '''One end (local or remote) of an AirFiber PtP backhaul link.

    Unified across both hardware generations get_link_status() has
    seen - 60GHz (AF60HD, PRS-based, status.cgi's sta['prs_sta']) and
    5GHz (AF5XHD, AirMax-based, fields directly on sta) use genuinely
    different raw field layouts, not just different names, so this
    dataclass's values are built by variant-specific parsing rather
    than a single field-rename table. See get_link_status().

    signal_expected_dbm/rate_expected/capacity_expected_mbps follow the
    device's dl=local/ul=remote convention (empirically confirmed on
    AF60HD: the web UI's "Local RX Data Rate 11 (Expected 11)" /
    "Remote RX Data Rate 11 (Expected 10)" matched dl_rate_expect=11/
    ul_rate_expect=10 exactly). signal_expected_dbm's local/remote
    split is inferred by the same convention but wasn't separately
    confirmed (both sides happened to read the same expected value in
    testing). capacity_mbps splits the same way on AF5XHD too -
    confirmed live that local.capacity_mbps + remote.capacity_mbps
    reproduces airmax.combined_capacity exactly (downlink_capacity +
    uplink_capacity = combined_capacity).
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
    gps: airoscommon.GPSFix | None

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

    def __init__(self, management_ip: str, timeout: int | None = None) -> None:
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

    def get_gps(self) -> airoscommon.GPSFix | None:
        '''This device's own GPS location (status.cgi's top-level `gps`
        block) - this is the local end's own site GPS, distinct from
        get_link_status()'s per-end `gps` (which reports the same
        top-level block for the local end and the remote end's own
        block for the far end of the link). None if the device has no
        GPS fix (or no GPS hardware at all).

        Raises:
            RuntimeError: Raised if the data can't be parsed.

        Returns:
            airoscommon.GPSFix | None: This device's GPS location.
        '''
        return airoscommon.parse_gps_fix(self.getstatus().get('gps'))

    def getcfg(self) -> dict[str, str]:
        '''Get the device configuration (getcfg.cgi).

        Returns:
            dict[str,str]: Flat key=value config, same format as AirOSv8.
        '''
        rez = self._get("getcfg.cgi")

        return utils.parse_flat_kv_config(rez.text)

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

    def getbtstatus(self) -> dict:
        '''Get Bluetooth status (btstatus.cgi).

        Confirmed 404 on an AF60HD and 200 (with real data) on an
        AF5XHD - check for that if calling this against unknown/mixed
        hardware.

        Raises:
            RuntimeError: Raised if the data can't be parsed.

        Returns:
            dict: Bluetooth status (mode/name/discoverable/connection_state).
        '''
        res = self._get("btstatus.cgi")

        if res.status_code == 200:
            return res.json()

        raise RuntimeError(f"Error fetching bluetooth status: {res.status_code} {res.text}")

    def getantlist(self) -> dict:
        '''Get the compatible antenna reference table (antlist.cgi).

        Static data bundled in firmware (antenna model names/gains per
        board model), not live device telemetry. Confirmed 404 on an
        AF60HD and 200 on an AF5XHD.

        Raises:
            RuntimeError: Raised if the data can't be parsed.

        Returns:
            dict: {"boards": [{"model": ..., "antennas": [...]}, ...]}.
        '''
        res = self._get("antlist.cgi")

        if res.status_code == 200:
            return res.json()

        raise RuntimeError(f"Error fetching antenna list: {res.status_code} {res.text}")

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
        return utils.parse_flat_kv_config(self._dev_info or '')

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

        Branches on hardware generation, confirmed live against all
        three:
        - 60GHz/PRS (AF60HD): link stats live under sta['prs_sta'] /
          sta['remote']['prs_remote'], and total throughput is at
          wireless.throughput.{tx,rx}. distance_m comes from
          sta['distance'].
        - 60GHz/PRS (AF60-LR): same prs_sta shape as AF60HD, but
          distance_m instead lives at prs_sta.distance (sta has no
          'distance' key at all on this model, and the top-level
          wireless.distance also exists but was observed stuck at 0 -
          seemingly unused/stale on this model - so it's only used as
          a last-resort fallback, tried after prs_sta.distance).
          capacity also turned out to be in different units on this
          model - see _parse_60ghz_ends().
        - 5GHz/AirMax (AF5XHD): link stats are directly on sta /
          sta['remote'] (no prs_* wrapper) - this generation doesn't
          have wireless.throughput at all, so falls back to
          wireless.stats.{tx,rx}_throughput instead.

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
        remote = sta['remote']

        if 'prs_sta' in sta:
            local_end, remote_end = self._parse_60ghz_ends(status, sta, remote)
        else:
            local_end, remote_end = self._parse_airmax_ends(status, sta, remote)

        throughput = status['wireless'].get('throughput')
        if throughput:
            throughput_tx_raw = throughput['tx']
            throughput_rx_raw = throughput['rx']
        else:
            stats = status['wireless'].get('stats', {})
            throughput_tx_raw = stats.get('tx_throughput')
            throughput_rx_raw = stats.get('rx_throughput')

        distance_m = (
            sta.get('distance')
            or sta.get('prs_sta', {}).get('distance')
            or status['wireless'].get('distance')
        )

        return AirFiberLinkStatus(
            distance_m=distance_m,
            local=local_end,
            remote=remote_end,
            throughput_tx_raw=throughput_tx_raw,
            throughput_rx_raw=throughput_rx_raw,
        )

    def _parse_60ghz_ends(
        self, status: dict, sta: dict, remote: dict,
    ) -> tuple[AirFiberLinkEnd, AirFiberLinkEnd]:
        '''Build (local, remote) AirFiberLinkEnd for a PRS-based (60GHz,
        e.g. AF60HD) status.cgi.

        prs_sta['capacity'] turned out to not be consistently scaled
        across models: AF60HD reports it already in Mbps (e.g. 924),
        but AF60-LR reports it in Kbps (e.g. 1951000). There's no
        reliable field alongside it to detect which scale is in use,
        so this is normalized with a physical-limits heuristic instead
        (see _normalize_capacity_mbps()) rather than trusting the raw
        value as-is.
        '''
        prs_local = sta['prs_sta']
        prs_remote = remote['prs_remote']

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
            capacity_mbps=self._normalize_capacity_mbps(prs_local['capacity']),
            linkscore_pct=prs_local['dl_linkscore'],
            gps=airoscommon.parse_gps_fix(status.get('gps')),
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
            capacity_mbps=self._normalize_capacity_mbps(prs_remote['capacity']),
            linkscore_pct=prs_local['ul_linkscore'],
            gps=airoscommon.parse_gps_fix(remote.get('gps')),
        )

        return local_end, remote_end

    def _parse_airmax_ends(
        self, status: dict, sta: dict, remote: dict,
    ) -> tuple[AirFiberLinkEnd, AirFiberLinkEnd]:
        '''Build (local, remote) AirFiberLinkEnd for an AirMax-based (5GHz,
        e.g. AF5XHD) status.cgi.

        This generation has no prs_sta/prs_remote wrapper - equivalent
        fields sit directly on sta/sta['remote'], with different names:
        - signal_dbm: sta['signal'] (same meaning as prs_sta.rssi_data,
          despite AirMax confusingly naming its *own* SNR-like field
          'rssi' - confirmed live: sta['rssi'] == sta['signal'] -
          sta['noisefloor'] exactly, i.e. it's actually the SNR).
        - snr_db: sta['rssi'] (see above).
        - tx_mcs/rx_mcs: sta['tx_idx']/sta['rx_idx'] (same role, index
          into a modulation/rate table, just named 'idx' not 'mcs').
        - capacity_mbps: sta['airmax']['downlink_capacity']/
          ['uplink_capacity'], in Kbps - scaled to Mbps for consistency
          with the 60GHz variant, whose capacity fields are already in
          Mbps.
        - signal_expected_dbm: averaged from the two receive chains'
          sta['idealpwr0']/['idealpwr1'] (60GHz has one dl_signal_expect
          value; AirMax reports one per chain instead).
        '''
        airmax = sta['airmax']

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
            signal_dbm=sta['signal'],
            signal_expected_dbm=(sta['idealpwr0'] + sta['idealpwr1']) // 2,
            snr_db=sta['rssi'],
            rx_mcs=sta['rx_idx'],
            tx_mcs=sta['tx_idx'],
            capacity_mbps=airmax['downlink_capacity'] // 1000,
            linkscore_pct=round(sta['dl_score']),
            gps=airoscommon.parse_gps_fix(status.get('gps')),
        )

        remote_end = AirFiberLinkEnd(
            hostname=remote['hostname'],
            device_model=remote.get('platform', remote.get('devmodel', '')),
            mac=sta['mac'],
            fw_version=remote['version'],
            uptime_seconds=remote['uptime'],
            cpu_load_pct=remote['cpuload'],
            memory_used_pct=self._mem_used_pct(
                remote['totalram'], remote['freeram']
            ),
            mode=remote.get('mode', ''),
            signal_dbm=remote['signal'],
            signal_expected_dbm=(remote['idealpwr0'] + remote['idealpwr1']) // 2,
            snr_db=remote['rssi'],
            rx_mcs=sta['tx_idx'],
            tx_mcs=remote.get('tx_mcs', sta['rx_idx']),
            capacity_mbps=airmax['uplink_capacity'] // 1000,
            linkscore_pct=round(sta['ul_score']),
            gps=airoscommon.parse_gps_fix(remote.get('gps')),
        )

        return local_end, remote_end

    @staticmethod
    def _mem_used_pct(totalram: int, freeram: int) -> float:
        '''Memory used, as a percentage - status.cgi only gives total/free
        bytes, not a ready-made percentage (the UI computes this too).'''
        return (totalram - freeram) / totalram * 100

    @staticmethod
    def _normalize_capacity_mbps(raw_capacity: int) -> int:
        '''Normalize prs_sta/prs_remote['capacity'] to Mbps.

        Confirmed live that this field's own unit isn't consistent
        across models - AF60HD reports Mbps directly (e.g. 924),
        AF60-LR reports Kbps (e.g. 1951000, i.e. 1951 Mbps). No other
        field reliably distinguishes the two, so this uses a physical-
        limits heuristic instead: no current AirFiber 60GHz product
        exceeds ~10 Gbps of one-directional capacity, so anything
        larger than that (expressed in Mbps) must actually be Kbps.
        '''
        mbps_upper_bound = 10_000
        if raw_capacity > mbps_upper_bound:
            return raw_capacity // 1000
        return raw_capacity
