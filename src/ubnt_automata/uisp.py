'''UISP-firmware device implementation.

Covers every Ubiquiti device confirmed running this generation of
firmware, regardless of product line - the Wave family (AP, Pro, Nano,
LR, ...) in either PtMP (access point) or PtP (link) mode, an AirFiber
60 XR (product "airFiber 60 XR", family "airfiber-60"), and the
EdgePower family (family "EdgePower" - 24V-72W/54V-72W/54V-150W all
confirmed) - all confirmed to share the exact same auth mechanism and
generic tooling (public/device, discovery, compose, alerts), though
EdgePower's own statistics/device data is naturally power/battery-
focused rather than wireless-link-focused, so get_status() (which
assumes a wireless link) only makes sense for the wireless product
lines. This was originally written as "wave.py"/class Wave before the
AF60-XR turned up using byte-for-byte the same API despite being
AirFiber-branded, at which point it was generalized and renamed to
reflect the underlying firmware rather than any one product line.

Verified live against a real Wave AP (product "Wave AP", model
Wave-AP, fw GMC.ipq5018...) acting as an access point, a real Wave Pro
(product "Wave Pro", model Wave-Pro, fw MGMP.ipq807x...) acting as one
end of a PtP backhaul, a real AirFiber 60 XR (model AF60-XR) also
acting as one end of a PtP backhaul, three real EdgePower units
(EP-54V-72W, EP-54V-150W, EP-24V-72W), and a real EdgePoint S16 running
upgraded firmware that self-identifies as "EdgeSwitch S16"
(family "EdgeSwitch", model EP-S16) - each cross-referenced against a
captured HAR of its own live web UI session.

This is a completely different API family from AirOS/AirFiber - a
modern JSON REST API under /api/v1.0/, not .cgi endpoints.

Auth:
- POST /api/v1.0/user/login, JSON body {"username":..., "password":...}.
  No CSRF header/cookie dance like AirOS - the response's x-auth-token
  header IS the credential for every subsequent request (send back as
  the same header on each call). No cookies observed for this API at
  all.
- IMPORTANT: an EdgeSwitch/EdgePoint S16 was confirmed to reject login
  with a lighttpd-level 403 Forbidden (no JSON body at all) unless the
  request carries Origin/Referer headers matching the device's own
  base URL - this looks exactly like a brute-force lockout at a
  glance (and was initially misdiagnosed as one against a different
  S16), but isn't: the identical request with these two headers added
  succeeds immediately, even against a device that had never been
  logged into before. Wave/AirFiber-XR/EdgePower all worked fine
  without them. _origin_headers() now adds them to every request
  unconditionally (harmless for devices that don't require them).

Confirmed endpoints (all need x-auth-token except public/device):
- public/device                     - Pre-auth device identification
                                       (product/model/mac/family). No
                                       login required at all.
- statistics                        - Rich JSON: this device's own info
                                       (gps/cpu/ram/uptime/
                                       temperatures). For wireless
                                       product lines, also its radios
                                       and one entry per connected peer
                                       - the other AP client(s) for a
                                       PtMP AP, or the single far end
                                       for a PtP link (identification,
                                       gps, distance, signal/mcs/
                                       linkScore for both link
                                       directions). EdgePower's
                                       statistics is power/battery-
                                       focused instead - get_status()
                                       only makes sense for wireless
                                       devices, but getstatistics() (raw)
                                       works fine on EdgePower too.
- statistics/historical             - Historical stat samples.
- system/alerts                     - Device alerts/warnings list.
- tools/discovery/neighbors (GET)   - Network-wide Ubiquiti device
                                       discovery (broader than just
                                       this device's own peers). GET is
                                       used since it's confirmed to
                                       work everywhere tested; POST
                                       also works on Wave/AirFiber-XR/
                                       EdgePower but is explicitly
                                       rejected (400) by an EdgePoint
                                       S16 running older firmware. See
                                       get_discovery()'s docstring for
                                       an EdgePower/EdgePoint-specific
                                       wrinkle (results mix in raw LLDP
                                       neighbor entries).
- interfaces                         - Per-interface identification
                                       (mac/type), status (enabled/mtu/
                                       description), and addresses
                                       (static/dynamic, v4/v6, CIDR) -
                                       confirmed on EdgePower, not tried
                                       on the wireless product lines.
- tools/mac-table                   - MAC/ARP table - confirmed on
                                       EdgePower, not tried on the
                                       wireless product lines.
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
from __future__ import annotations

# System imports
import dataclasses
import logging

# External imports
import requests
import urllib3

# Local imports
from . import airoscommon, exceptions

logger = logging.getLogger(__name__)

# Disable the self signed certificate warnings.
urllib3.disable_warnings()


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
    gps: airoscommon.GPSFix | None


@dataclasses.dataclass
class UispDeviceStatus:
    '''Structured view of a UISP-firmware device's own status and all
    connected peers (statistics). For a PtP link, `peers` will have
    exactly one entry - the far end.'''
    hostname: str
    uptime_seconds: int
    cpu_load_pct: float
    memory_used_pct: float
    gps: airoscommon.GPSFix | None
    peers: list[UispPeer]


class UispDevice(airoscommon.AirOSCommonDevice):
    '''UISP-firmware device handler - covers every product line
    confirmed running this firmware generation (Wave AP/Pro/Nano/LR,
    AirFiber 60 XR, EdgePower) in either PtMP (access point) or PtP
    (link) mode, or - for EdgePower - as a plain power device with no
    wireless link at all (don't call get_status()/get_site_survey_status()
    against those; get_mac_table()/get_discovery()/get_public_device()/
    getstatistics() work fine on any of them).

    Read-only for now: change_password()/apply_changes() are
    deliberately no-ops here, never touching the device.
    '''

    _url_path_prefix = 'api/v1.0/'

    def __init__(self, management_ip: str, timeout: int | None = None) -> None:
        '''Constructor'''
        super().__init__(
            management_ip=management_ip,
            timeout=timeout,
        )
        self._req_session = requests.Session()
        self._auth_token = None

    def _origin_headers(self) -> dict:
        '''Origin/Referer headers matching this device's own base URL.

        Not needed by most UISP-firmware devices (Wave/AirFiber-XR/
        EdgePower all worked fine without them), but confirmed live
        that an EdgeSwitch/EdgePoint S16 enforces an Origin/Referer
        check as a CSRF safeguard, at least on login - a request
        without them gets a lighttpd-level 403 Forbidden (looks like a
        brute-force lockout at a glance, but isn't one: the same
        request with these headers added succeeds immediately, even
        against a device never logged into before). Sending them
        unconditionally is harmless for devices that don't require
        them.
        '''
        base = self._build_url("").rsplit('/api/v1.0/', maxsplit=1)[0]
        return {'Origin': base, 'Referer': f"{base}/"}

    def _get(self, path: str) -> requests.Response:
        '''Authenticated GET against a data endpoint.'''
        return self._req_session.get(
            self._build_url(path),
            verify=self._verify_ssl,
            timeout=self._timeout,
            headers={'x-auth-token': self._auth_token, **self._origin_headers()},
        )

    def _post(self, path: str, json_body=None) -> requests.Response:
        '''Authenticated POST against a data endpoint.'''
        return self._req_session.post(
            self._build_url(path),
            json=json_body,
            verify=self._verify_ssl,
            timeout=self._timeout,
            headers={'x-auth-token': self._auth_token, **self._origin_headers()},
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
                self._build_url("user/login"),
                json={'username': curr_user, 'password': curr_pw},
                verify=self._verify_ssl,
                timeout=self._timeout,
                headers=self._origin_headers(),
            )
        except (requests.exceptions.ConnectionError,
                requests.exceptions.ConnectTimeout) as exc:
            raise exceptions.DeviceUnavailable from exc

        if rez.status_code != 200:
            logger.debug(
                f"Error logging in to {self._mgmt_ip}: {rez.status_code} {rez.text[:200]}"
            )
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

        Usually needs no login at all - safe to call before
        login_http() on most devices confirmed so far (Wave/AirFiber-XR/
        EdgePower/newer-firmware EdgePoint). Confirmed live, though,
        that an EdgePoint S16 running older firmware returns 401 here
        even pre-login - it's not universal, so callers that need to
        support both should be prepared for this to require an active
        session on older firmware.

        Raises:
            RuntimeError: Raised if the data can't be parsed.

        Returns:
            dict: Device identification (product/model/mac/family).
        '''
        res = self._req_session.get(
            self._build_url("public/device"),
            verify=self._verify_ssl,
            timeout=self._timeout,
            headers=self._origin_headers(),
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

    def get_gps(self) -> airoscommon.GPSFix | None:
        '''This device's own GPS location (statistics' `device.gps`
        block) - works on any product line, including EdgePower (unlike
        get_status(), which assumes a wireless link). None if the
        device has no GPS fix (or no GPS hardware at all).

        Raises:
            RuntimeError: Raised if the data can't be parsed.

        Returns:
            airoscommon.GPSFix | None: This device's GPS location.
        '''
        return airoscommon.parse_gps_fix(self.getstatistics().get('device', {}).get('gps'))

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
        Ubiquiti gear responds to discovery on the local segment. Uses
        GET - Wave/AirFiber-XR's own web UI calls this via POST
        (matching AirFiber's own discovery.cgi), and that also works,
        but an EdgePoint S16 running older firmware explicitly rejects
        POST here (400 "Request is not supported") while GET works
        fine on it - and GET was confirmed to also work on Wave AP and
        EdgePower, so it's the more broadly compatible choice. On
        EdgePower/EdgePoint this list also mixes in raw LLDP neighbor
        entries (protocol=LLDP, only localInterfaceID/mac/
        remoteInterfaceID/age - no hostname/product/ip) alongside the
        usual UBNT-protocol entries, for any non-Ubiquiti neighbor gear.

        Raises:
            RuntimeError: Raised if the data can't be parsed.

        Returns:
            list[dict]: One entry per discovered device.
        '''
        res = self._get("tools/discovery/neighbors")

        if res.status_code == 200:
            return res.json()

        raise RuntimeError(f"Error fetching discovery data: {res.status_code} {res.text}")

    def get_interfaces(self) -> list[dict]:
        '''Get per-interface identification/status/addresses (interfaces).

        Confirmed live on EdgePower devices (eth0/eth1) - not tried on
        the wireless product lines, whose radio interface(s) may use a
        different `identification.type` value than the plain
        `"ethernet"` seen so far.

        Raises:
            RuntimeError: Raised if the data can't be parsed.

        Returns:
            list[dict]: One entry per interface - {"identification":
                {"id", "name", "mac", "macOverride", "type"}, "status":
                {"enabled", "description", "plugged", "speed", "mtu"},
                "addresses": [{"type": "static"/"dynamic", "version":
                "v4"/"v6", "cidr", ...}, ...]}.
        '''
        res = self._get("interfaces")

        if res.status_code == 200:
            return res.json()

        raise RuntimeError(f"Error fetching interfaces: {res.status_code} {res.text}")

    def get_mac_table(self) -> list[dict]:
        '''Get the MAC/ARP table (tools/mac-table).

        Confirmed live on EdgePower devices - lists MAC+IP pairs (IPv4
        and IPv6) seen per physical port, i.e. this is the closest
        equivalent to an ARP table this API exposes.

        Raises:
            RuntimeError: Raised if the data can't be parsed.

        Returns:
            list[dict]: One entry per learned MAC/IP pair - {"port":
                {"id", "name", "mac", "macOverride", "type"}, "mac",
                "address", "lastReachable"}.
        '''
        res = self._get("tools/mac-table")

        if res.status_code == 200:
            return res.json()

        raise RuntimeError(f"Error fetching MAC table: {res.status_code} {res.text}")

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
            gps=airoscommon.parse_gps_fix(device.get('gps')),
            peers=[self._parse_peer(p) for p in wireless.get('peers', [])],
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
            gps=airoscommon.parse_gps_fix(common.get('gps')),
        )
