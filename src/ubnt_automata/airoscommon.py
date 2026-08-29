'''Base class for common functions for all Ubnt AirOS devices'''
from __future__ import annotations

# System imports
import abc
import dataclasses
import logging

# Local imports
from . import exceptions, utils

logger = logging.getLogger(__name__)


@dataclasses.dataclass
class GPSFix:
    '''GPS fix as reported by a Ubiquiti device (AirFiber's status.cgi,
    UISP-firmware's statistics/peers) - both APIs report the exact same
    5 fields, just under different raw key names (see parse_gps_fix()).
    '''
    latitude: float
    longitude: float
    altitude_m: float
    satellites: int
    fix: int


def parse_gps_fix(gps_data: dict | None) -> GPSFix | None:
    '''Parse a GPS block, returning None if there's no fix.

    Args:
        gps_data (dict | None): Raw GPS block - {"lat", "lon", "alt",
            "sats", "fix"}. Values may come through as either numbers
            or numeric strings depending on hardware/API - always cast
            to float/int explicitly rather than trusting the source type.
    '''
    if not gps_data or not gps_data.get('fix'):
        return None

    return GPSFix(
        latitude=float(gps_data['lat']),
        longitude=float(gps_data['lon']),
        altitude_m=float(gps_data['alt']),
        satellites=int(gps_data['sats']),
        fix=int(gps_data['fix']),
    )


class AirOSCommonDevice:
    '''Base class for all AirOS device.
    '''

    # Default values
    _default_user = 'ubnt'
    _default_timeout = 30
    _verify_ssl = False

    # Path prefix _build_url() inserts between the device root and the
    # endpoint path passed in - empty for the .cgi-style APIs (AirOSv8,
    # AirFiber, EdgeRouter), overridden by UispDevice for its /api/v1.0/
    # JSON REST API.
    _url_path_prefix = ''

    def __init__(self, management_ip: str, timeout: int | None = None):
        '''Constructor
        '''
        self._mgmt_ip = management_ip
        if timeout is None:
            self._timeout = self._default_timeout
        else:
            self._timeout = timeout

        self._curr_username = None
        self._curr_password = None  # Once we login successfully will contain the current password
        self._is_ssl = None

    def login(self, passwords: list[str], username: str | None = None, auto_apply: bool = False):
        '''Login to the device.

        IMPORTANT: on a device whose change_password() actually writes
        to the device (currently only AirOSv8 - every other class here
        is read-only and treats change_password() as a no-op), a
        successful login on anything but the primary password causes
        this method to change the live device's password back to
        `passwords[0]` - never log the passwords themselves (see below),
        and be aware this is not a read-only operation on that class.
        '''
        if username is None:
            self._curr_username = self._default_user
        else:
            self._curr_username = username

        try:
            primary_pw = passwords[0]
            self.login_http(
                curr_pw=primary_pw,
                curr_user=self._curr_username,
            )
        except exceptions.WrongPassword as exc:
            logger.debug("Primary password failed, trying alternates")
            alternate_pws = passwords[1:]
            pw_found = False
            for curr_pw in alternate_pws:
                try:
                    self.login_http(
                        curr_pw=curr_pw,
                        curr_user=self._curr_username,
                    )
                    self.change_password(primary_pw)
                    if auto_apply:
                        self.apply_changes()
                    pw_found = True
                    break
                except exceptions.WrongPassword:
                    pass

            if pw_found is False:
                raise exceptions.WrongPassword(
                    f"Device {self._mgmt_ip} does not have a known password"
                ) from exc

    def _determine_ssl(self,) -> bool:
        '''Determine if the management interface has SSL enforced.
        '''
        self._is_ssl = utils.determine_ssl(self._mgmt_ip)
        return self._is_ssl

    def _build_url(self, path: str) -> str:
        '''Build the final URL to pass to the request library.

        Args:
            - path: the path, relative to the site root (or, for
              classes that set _url_path_prefix, relative to that
              prefix - e.g. UispDevice's /api/v1.0/).
        '''
        if self._is_ssl is None:
            self._determine_ssl()

        scheme = 'https' if self._is_ssl else 'http'
        return f"{scheme}://{self._mgmt_ip}/{self._url_path_prefix}{path}"

    def _parse_version_string(self, version_string):
        '''Parse the version string.
        '''
        return utils.parse_ubnt_version_string(version_string=version_string)

    @abc.abstractmethod
    def login_http(self, curr_pw:str, curr_user:str | None = None):
        '''Login to device via HTTP.'''

    @abc.abstractmethod
    def change_password(self, new_password):
        '''Change password on device.'''

    @abc.abstractmethod
    def apply_changes(self, test_mode = False):
        '''Apply changes to device.'''
