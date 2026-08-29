'''UISP-firmware device implementation.

Covers every Ubiquiti device confirmed running this generation of
firmware, regardless of product line - the Wave family (AP, Pro, Nano,
LR, ...) in either PtMP (access point) or PtP (link) mode, and now also
an AirFiber 60 XR (product "airFiber 60 XR", family "airfiber-60") -
all confirmed to share the exact same API and JSON shape
(statistics.wireless.peers is just length 1 for a PtP link instead of
many for an AP's connected clients). This was originally written as
"wave.py"/class Wave before the AF60-XR turned up using byte-for-byte
the same API despite being AirFiber-branded, at which point it was
generalized and renamed to reflect the underlying firmware rather than
any one product line.

Verified live against a real Wave AP (product "Wave AP", model
Wave-AP, fw GMC.ipq5018...) acting as an access point, a real Wave Pro
(product "Wave Pro", model Wave-Pro, fw MGMP.ipq807x...) acting as one
end of a PtP backhaul, and a real AirFiber 60 XR (model AF60-XR) also
acting as one end of a PtP backhaul - each cross-referenced against a
captured HAR of its own live web UI session.

This is a completely different API family from AirOS/AirFiber - a
modern JSON REST API under /api/v1.0/, not .cgi endpoints.

Auth:
- POST /api/v1.0/user/login, JSON body {"username":..., "password":...}.
  No CSRF header/cookie dance like AirOS - the response's x-auth-token
  header IS the credential for every subsequent request (send back as
  the same header on each call). No cookies observed for this API at
  all.

Confirmed endpoints (all need x-auth-token except public/device):
- public/device                     - Pre-auth device identification
                                       (product/model/mac/family). No
                                       login required at all.
- statistics                        - Rich JSON: this device's own info
                                       (gps/cpu/ram/uptime/
                                       temperatures), its radios, and
                                       one entry per connected peer -
                                       the other AP client(s) for a
                                       PtMP AP, or the single far end
                                       for a PtP link (identification,
                                       gps, distance, signal/mcs/
                                       linkScore for both link
                                       directions).
- statistics/historical             - Historical stat samples.
- system/alerts                     - Device alerts/warnings list.
- tools/discovery/neighbors (POST)  - Network-wide Ubiquiti device
                                       discovery (broader than just
                                       this device's own peers).
- tools/site-survey/main            - Site survey status only
                                       ({"status":"not_started"} when
                                       idle) - fetch-only, deliberately
                                       never triggers a scan (that
                                       changes wireless behaviour on
                                       the device, same reasoning as
                                       not poking AirFiber's
                                       airviewdata.cgi). Confirmed
                                       working live on a Wave AP and a
                                       PtP-configured Wave Pro, even
                                       though the latter's web UI never
                                       actually called it (that's just
                                       the nav hiding the page for PtP
                                       mode - the endpoint itself works
                                       regardless). Also present in the
                                       AF60-XR's HAR.
- tools/compose (POST)              - Batches many GET routes into one
                                       call: {"requests":[{"method":
                                       "GET","route": "/public/device"},
                                       ...],"rollback":{}} returns
                                       {"responses":[{"entity":route,
                                       "body":...,"statusCode":...},
                                       ...]}. Confirmed sub-routes:
                                       public/device, system/airos/
                                       configuration, system/airmax/
                                       regdomain, device, system,
                                       system/users, services, system/
                                       airos/countries, statistics/
                                       historical, statistics,
                                       tools/unms, system/alerts.
- tools/unms                        - UNMS/UISP cloud connection
                                       status.

Confirmed via HAR but NOT implemented (out of scope - not local
telemetry, needs internet from the device):
- tools/proxy/https (POST)   - Generic outbound-HTTPS relay to
                                Ubiquiti's cloud (e.g. firmware update
                                checks).

Sensitive data warning: several config routes return secrets in plain
text - confirmed live: wireless.interfaces[].encryption.passphrase
(under compose(['/system/airos/configuration'])) and
services.snmpAgent.community (under compose(['/services'])).
tools/unms and services.unms.key also embed the UISP auth token.
Callers must not log/print these values. Unlike AirOS's getcfg(),
system/users here does NOT include password data (just username/
readOnly/sshKeys).
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


@dataclasses.dataclass
class UispGPS:
    '''GPS fix as reported by a UISP-firmware device.'''
    latitude: float
    longitude: float
    altitude_m: float
    satellites: int
    fix: bool


@dataclasses.dataclass
class UispPeer:
    '''One connected peer - the other client for a PtMP AP, or the
    single far end for a PtP link.

    signal/mcs/linkscore are from this device's ("local") perspective
    of the link to the peer, taken from whichever of peer['local'] is
    actually connected (matched by its own 'connected' flag rather than
    assuming list order/position, since a peer could in principle be
    tracked against more than one radio).

    linkscore_dl/linkscore_ul follow the same dl=this-device-side/
    ul=peer-side convention empirically confirmed on AirFiber, but this
    pairing has NOT been separately confirmed here (no screenshots to
    cross-check against, only HARs) - treat as a reasonable assumption,
    not a verified fact.
    '''
    hostname: str
    product: str
    model: str
    mac: str
    fw_version: str
    mgmt_ip: str
    uptime_seconds: int
    distance_m: int
    signal_dbm: int | None
    signal_expected_dbm: int | None
    tx_mcs_idx: int | None
    rx_mcs_idx: int | None
    linkscore_dl: float | None
    linkscore_ul: float | None
    gps: UispGPS | None


@dataclasses.dataclass
class UispDeviceStatus:
    '''Structured view of a UISP-firmware device's own status and all
    connected peers (statistics). For a PtP link, `peers` will have
    exactly one entry - the far end.'''
    hostname: str
    uptime_seconds: int
    cpu_load_pct: float
    memory_used_pct: float
    gps: UispGPS | None
    peers: list[UispPeer]


class UispDevice(airoscommon.AirOSCommonDevice):
    '''UISP-firmware device handler - covers every product line
    confirmed running this firmware generation (Wave AP/Pro/Nano/LR,
    AirFiber 60 XR, ...) in either PtMP (access point) or PtP (link)
    mode.

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
        self._auth_token = None

    def _build_url(self, path: str) -> str:
        '''Build the final URL to pass to the request library.

        Args:
            - path: the path, relative to /api/v1.0/
        '''
        if self._is_ssl is None:
            self._determine_ssl()

        final_url = f"{'https' if self._is_ssl else 'http'}://"
        final_url += f"{self._mgmt_ip}/api/v1.0/{path}"
        return final_url

    def _get(self, path: str) -> requests.Response:
        '''Authenticated GET against a data endpoint.'''
        return self._req_session.get(
            self._build_url(path),
            verify=self._verify_ssl,
            timeout=self._timeout,
            headers={'x-auth-token': self._auth_token},
        )

    def _post(self, path: str, json_body=None) -> requests.Response:
        '''Authenticated POST against a data endpoint.'''
        return self._req_session.post(
            self._build_url(path),
            json=json_body,
            verify=self._verify_ssl,
            timeout=self._timeout,
            headers={'x-auth-token': self._auth_token},
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

        try:
            rez = self._req_session.post(
                self._build_url("user/login"),
                json={'username': curr_user, 'password': curr_pw},
                verify=self._verify_ssl,
                timeout=self._timeout,
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
        self._auth_token = rez.headers['x-auth-token']

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

    def get_public_device(self) -> dict:
        '''Pre-auth device identification (public/device).

        No login required at all - safe to call before login_http().

        Raises:
            RuntimeError: Raised if the data can't be parsed.

        Returns:
            dict: Device identification (product/model/mac/family).
        '''
        res = self._req_session.get(
            self._build_url("public/device"),
            verify=self._verify_ssl,
            timeout=self._timeout,
        )

        if res.status_code == 200:
            return res.json()

        raise RuntimeError(f"Error fetching public device info: {res.status_code} {res.text}")

    def getstatistics(self) -> dict:
        '''Get the device's raw statistics (statistics).

        The richest endpoint - this device's own info (gps/cpu/ram/
        uptime), its radios, and per-peer link stats. Only ever
        observed to return a single-element list (this device's own
        reading) - that single entry is returned directly, not the
        wrapping list.

        Raises:
            RuntimeError: Raised if the data can't be parsed.

        Returns:
            dict: Statistics data.
        '''
        res = self._get("statistics")

        if res.status_code == 200:
            data = res.json()
            return data[0] if data else {}

        raise RuntimeError(f"Error fetching statistics: {res.status_code} {res.text}")

    def gethistorical(self) -> list:
        '''Get historical statistics (statistics/historical).

        Raises:
            RuntimeError: Raised if the data can't be parsed.

        Returns:
            list: Historical stat samples, one per tracked metric.
        '''
        res = self._get("statistics/historical")

        if res.status_code == 200:
            return res.json()

        raise RuntimeError(f"Error fetching historical statistics: {res.status_code} {res.text}")

    def getalerts(self) -> list:
        '''Get device alerts/warnings (system/alerts).

        Raises:
            RuntimeError: Raised if the data can't be parsed.

        Returns:
            list: Alerts, empty if none active.
        '''
        res = self._get("system/alerts")

        if res.status_code == 200:
            return res.json()

        raise RuntimeError(f"Error fetching alerts: {res.status_code} {res.text}")

    def get_discovery(self) -> list[dict]:
        '''Network-wide Ubiquiti device discovery (tools/discovery/neighbors).

        Broader than just this device's own peers - returns whatever
        Ubiquiti gear responds to discovery on the local segment.

        Raises:
            RuntimeError: Raised if the data can't be parsed.

        Returns:
            list[dict]: One entry per discovered device.
        '''
        res = self._post("tools/discovery/neighbors")

        if res.status_code == 200:
            return res.json()

        raise RuntimeError(f"Error fetching discovery data: {res.status_code} {res.text}")

    def get_site_survey_status(self) -> dict:
        '''Site survey status only (tools/site-survey/main).

        Deliberately never triggers a scan - only reports current
        status (e.g. {"status": "not_started"}) - starting one changes
        the device's wireless behaviour, out of scope for fetch-only.
        Confirmed working on a Wave AP and a PtP-configured Wave Pro.

        Raises:
            RuntimeError: Raised if the data can't be parsed.

        Returns:
            dict: Site survey status.
        '''
        res = self._get("tools/site-survey/main")

        if res.status_code == 200:
            return res.json()

        raise RuntimeError(f"Error fetching site survey status: {res.status_code} {res.text}")

    def getunms(self) -> dict:
        '''UNMS/UISP cloud connection status (tools/unms).

        Contains the same sensitive UISP key as compose(['/services'])'s
        services.unms.key - don't log/print the full response.

        Raises:
            RuntimeError: Raised if the data can't be parsed.

        Returns:
            dict: UNMS connection status.
        '''
        res = self._get("tools/unms")

        if res.status_code == 200:
            return res.json()

        raise RuntimeError(f"Error fetching unms status: {res.status_code} {res.text}")

    def compose(self, routes: list[str]) -> dict[str, dict]:
        '''Batch several GET routes into a single request (tools/compose).

        Args:
            routes (list[str]): Routes to fetch, e.g. ['/system', '/services'].
                See the module docstring for the confirmed set.

        Raises:
            RuntimeError: Raised if the overall compose call fails.

        Returns:
            dict[str,dict]: route -> response body, one entry per
                sub-request that returned a 2xx status. Sub-requests
                that failed are logged and omitted.
        '''
        res = self._post(
            "tools/compose",
            json_body={
                'requests': [{'method': 'GET', 'route': r} for r in routes],
                'rollback': {},
            },
        )

        if res.status_code != 200:
            raise RuntimeError(f"Error composing requests: {res.status_code} {res.text}")

        result = {}
        for entry in res.json().get('responses', []):
            if 200 <= entry.get('statusCode', 0) < 300:
                result[entry['entity']] = entry['body']
            else:
                logger.error(
                    f"compose sub-request {entry.get('entity')} failed: "
                    f"{entry.get('statusCode')}"
                )
        return result

    def get_status(self) -> UispDeviceStatus:
        '''Structured view of this device's own status and all connected
        peers. For a PtP link, `peers` will have exactly one entry.

        statistics doesn't include this device's own configured
        hostname (only its peers' hostnames) - fetched separately via
        compose(['/system']), one extra request.

        Raises:
            RuntimeError: Raised if the statistics response is missing
                expected fields.

        Returns:
            UispDeviceStatus: Structured device + peer link status.
        '''
        stats = self.getstatistics()
        device = stats['device']
        wireless = stats['wireless']

        system_info = self.compose(['/system']).get('/system', {})

        # CPU usage is reported per-core - expose the average.
        cpu_cores = device.get('cpu', [])
        cpu_avg = (
            sum(c['usage'] for c in cpu_cores) / len(cpu_cores)
            if cpu_cores else 0.0
        )

        return UispDeviceStatus(
            hostname=system_info.get('hostname', ''),
            uptime_seconds=device['uptime'],
            cpu_load_pct=cpu_avg,
            memory_used_pct=device['ram']['usage'],
            gps=self._parse_gps(device.get('gps')),
            peers=[self._parse_peer(p) for p in wireless.get('peers', [])],
        )

    @staticmethod
    def _parse_gps(gps_data: dict | None) -> UispGPS | None:
        '''Parse a GPS block, returning None if there's no fix.'''
        if not gps_data or not gps_data.get('fix'):
            return None

        return UispGPS(
            latitude=gps_data['lat'],
            longitude=gps_data['lon'],
            altitude_m=gps_data['alt'],
            satellites=gps_data['sats'],
            fix=gps_data['fix'],
        )

    def _parse_peer(self, peer: dict) -> UispPeer:
        '''Parse one entry from statistics' wireless.peers list.'''
        common = peer['common']
        identification = common['identification']

        # Match the local-side link entry to whichever one is actually
        # connected - don't assume list order/position.
        local_links = peer.get('local', [])
        active_link = next(
            (link for link in local_links if link.get('connected')),
            local_links[0] if local_links else {},
        )
        link_quality = active_link.get('linkQuality', {})
        mcs = link_quality.get('mcs', {})
        linkscore = link_quality.get('linkScore', {})

        return UispPeer(
            hostname=common.get('hostname', ''),
            product=identification.get('product', ''),
            model=identification.get('model', ''),
            mac=identification.get('mac', ''),
            fw_version=identification.get('firmwareVersion', ''),
            mgmt_ip=common.get('mgmtIp', ''),
            uptime_seconds=common.get('uptime', 0),
            distance_m=common.get('distance', 0),
            signal_dbm=link_quality.get('signal'),
            signal_expected_dbm=link_quality.get('idealSignal'),
            tx_mcs_idx=mcs.get('txIdx'),
            rx_mcs_idx=mcs.get('rxIdx'),
            linkscore_dl=linkscore.get('dl'),
            linkscore_ul=linkscore.get('ul'),
            gps=self._parse_gps(common.get('gps')),
        )
