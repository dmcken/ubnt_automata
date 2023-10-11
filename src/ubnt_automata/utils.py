'''Utility functions'''

# System imports
import dataclasses
import itertools
import logging
import mimetypes
import random
import re
import socket
import sys
import urllib
import urllib3

from urllib.parse import urlparse

# External imports
import requests

# Local imports
from . import exceptions

# Disable the self signed certificate warnings.
urllib3.disable_warnings()

logger = logging.getLogger(__name__)

# Data classes
@dataclasses.dataclass
class UbntDeviceInfo:
    '''Ubiquiti model device information.'''
    # 0 - Unknown
    # 6 - AirOSv6 style kit
    # 8 - AirOSv8 style kit
    model_group: int = 0
    # Model name if known, empty string if not
    model_name: str = ''
    # Is SSL enabled on the web interface for this device.
    web_ssl: bool = True



def determine_device_type(management_ip: str) -> UbntDeviceInfo:
    '''Determine device type.

    Connect to a CPE and determine as much information as possible.

    Args:
        - management_ip: str - IP address
    '''

    is_ssl = determine_ssl(management_ip)
    if is_ssl:
        base_url = 'https'
    else:
        base_url = 'http'

    base_url += f"://{management_ip}"

    api_url = f"{base_url}/api/info/public?include_langs=false&lang="

    r_api = requests.get(
        api_url,
        timeout=10,
        allow_redirects=True,
        verify=False,
    )

    device_data = UbntDeviceInfo(web_ssl=is_ssl)

    # If we get a valid JSON object
    if r_api.headers['Content-Type'] == 'application/json; charset=utf-8':
        # The json from an AirOSv8 device looks like this
        # {"setup_complete":true,"ui_lang":"en_US","product_name":"LiteBeam 5AC"}
        device_json = r_api.json()
        device_data.model_name = device_json['product_name']
        device_data.model_group = 8
    elif urlparse(r_api.url).path[:10] == '/login.cgi':
        # This is most likely an AirOSv6 device.
        device_data.model_group = 6
    else:
        # We don't know, debug and handle any new devices
        device_data.model_group = 0

    return device_data

def determine_ssl(management_ip: str) -> bool:
    '''Determine if the management interface has SSL enforced.

    Args:
    '''
    try:
        urllib3.util.ssl_.DEFAULT_CIPHERS += 'HIGH:!DH:!aNULL'
        try:
            requests.packages.urllib3.contrib.pyopenssl.DEFAULT_SSL_CIPHER_LIST += 'HIGH:!DH:!aNULL'
        except AttributeError:
            # no pyopenssl support used / needed / available
            pass

        session = requests.Session()

        rez = session.get(
            f"http://{management_ip}/",
            verify=False,
            timeout=30,
        )
    except requests.exceptions.ConnectTimeout as exc:
        raise exceptions.DeviceUnavailable(
            f"Unable to reach {management_ip}") from exc
    except (urllib3.connection.HTTPConnection, socket.error, socket.timeout) as exc:
        # 113 - No route to host (Linux)
        # 10060 - Windows
        if exc.__class__.__name__ in ['timeout', 'BadStatusLine'] or\
             exc.errno in [10060, 113]:
            raise exceptions.DeviceUnavailable(
                f"Unable to reach {management_ip}")
        raise

    location_parse = urllib.parse.urlparse(rez.url)
    if location_parse.scheme == 'https':
        # logging.debug("SSL found")
        is_ssl = True
    else:
        is_ssl = False

    return is_ssl

def parse_ubnt_version_string(version_string: str):
    '''Parse the full version string to its parts.

    An example string looks like:


    XW.v5.6.9
    - arch: XW
    - version: v5.6.9
    - licensed: no

    XW.v5.5.9-licensed.21763.140407.1903
    - arch: XW
    - version: v5.5.9
    - licensed: yes

    XW.ar934x.v5.6.9.29546.160819.1146
    - arch: XW
    - version: v5.6.9
    - build date: 160819 (2016-12-19 - December 19th 2016)

    AF06.am1808.v3.0.2.1.27948.150717.1309
    - arch: AF06
    - version: v7.1.1

    XC.qca955x.v7.1.1.27574.150519.1505
    XC.qca955x.v7.1.1-licensed.27840.150701.0949
    XM.ar7240.v5.5.10.24241.141001.1649
    XM.ar7240.v5.6.2_licensed.28102.150805.1640
    XW.ar934x.v5.6.2_licensed.28102.150805.1456
    XM.ar7240.v5.5.8-licensed.21748.140404.1826
    XW.ar934x.v5.5.9-licensed.21763.140407.1903

    XC.qca955x.v8.6.2.41239.190822.1633
    '''
    data = {}

    parts = version_string.split('.')

    if parts[-1] == 'bin':
        parts.pop()

    data['arch'] = parts[0]

    if parts[1][0] == 'v':
        # This is a shorter version
        data['something'] = parts[-1]
        data['build-date'] = parts[-2]
        data['build-number'] = parts[-3]

        version = ''
        version_parts = parts[1:-3]
        version_parts.reverse()
        for curr_part in version_parts:
            if version == '':
                version = curr_part
            else:
                version = curr_part + '.' + version

            if curr_part[0] == 'v':
                break

        data['version'] = version

    elif parts[2][0] == 'v':
        # This is an extended version
        data['hw_model'] = parts[1]

        data['something'] = parts[-1]
        data['build-date'] = parts[-2]
        data['build-number'] = parts[-3]

        version = ''
        version_parts = parts[2:-3]
        version_parts.reverse()
        for curr_part in version_parts:
            if version == '':
                version = curr_part
            else:
                version = curr_part + '.' + version

            if curr_part[0] == 'v':
                break

        data['version'] = version

    else:
        raise ValueError(f"Unknown format for version string: '{version_string}'")

    return data

def clean_mac(mac):
    '''
    Returns a cleaned uppercase mac address with no formatting characters.
    '''

    cleaned_mac = re.sub('[^0-9A-F]', '', mac.upper())

    # Add 19 if dealing with EUI-64 (64 vs 48 bit) macs.
    if len(cleaned_mac) not in [ 12 ]:
        raise ValueError(f"Mac address '{mac}' is the wrong length")

    return cleaned_mac

def clean_mac_to_colon(mac):
    '''
    Take a cleaned mac (e.g. '001122334455') and convert to '00:11:22:33:44:55'
    '''

    chunk_n = 2

    return ":".join([mac[i:i + chunk_n] for i in range(0, len(mac), chunk_n)])

def detect_ubnt_version(management_ip: str) -> bool:
    '''Detect the major Ubnt device version.
    '''
    try:
        result = {}
        session = requests.Session()

        rez = session.get(
            f"http://{management_ip}/",
            verify=False,
            timeout=30,
        )

        # res.url will be of the format 'https://10.3.9.42/login.cgi?uri=/' for version 6
        url_parts = urllib.parse.urlparse(rez.url)
        #logger.debug(f"detect_ubnt_version - url_parts: {url_parts}")
        if url_parts.scheme == 'https':
            result['ssl'] = True
        elif url_parts.scheme == 'http':
            result['ssl'] = False
        else:
            result['ssl'] = None

        if url_parts.path == '/login.cgi':
            result['version'] = 'v6'
        elif url_parts.path == '/':
            result['version'] = 'v8'
        else:
            result['version'] = 'Unknown'

        return result
    except (urllib3.exceptions.NewConnectionError, requests.exceptions.ConnectionError) as exc:
        raise exceptions.DeviceUnavailable() from exc
    except exceptions.DeviceUnavailable:
        logger.debug(f"Device '{management_ip}' is not reachable")
        raise

class MultiPartForm(object):
    """Accumulate the data to be used when posting a form.

    Copied from: http://doughellmann.com/2009/07/pymotw-urllib2-library-for-opening-urls.html
    """

    def __init__(self):
        self.form_fields = []
        self.files = []
        self.boundary = self._make_boundary()

    def _make_boundary(self, text=None):
        # Craft a random boundary.  If text is given, ensure that the chosen
        # boundary doesn't appear in the text.
        _width = len(repr(sys.maxsize-1))
        _fmt = '%%0%dd' % _width

        token = random.randrange(sys.maxsize)
        boundary = ('=' * 15) + (_fmt % token) + '=='
        if text is None:
            return boundary
        bnd = boundary
        counter = 0
        while True:
            cre = re.compile('^--' + re.escape(bnd) + '(--)?$', re.MULTILINE)
            if not cre.search(text):
                break
            bnd = boundary + '.' + str(counter)
            counter += 1
        return bnd

    def get_content_type(self):
        '''Get content type'''
        return f'multipart/form-data; boundary={self.boundary}'

    def add_field(self, name, value):
        """Add a simple field to the form data."""
        self.form_fields.append((name, value))

    def add_file(self, fieldname, filename, file_handle, mimetype = None):
        """Add a file to be uploaded."""
        body = file_handle.read()
        if mimetype is None:
            mimetype = mimetypes.guess_type(filename)[0] or 'application/octet-stream'
        self.files.append((fieldname, filename, mimetype, body))

    def __str__(self):
        """Return a string representing the form data, including attached files."""
        # Build a list of lists, each containing "lines" of the
        # request.  Each part is separated by a boundary string.
        # Once the list is built, return a string where each
        # line is separated by '\r\n'.
        parts = []
        part_boundary = '--' + self.boundary

        # Add the form fields
        parts.extend(
            [
                part_boundary,
                f'Content-Disposition: form-data; name="{name}"',
                '',
                value,
            ]
            for name, value in self.form_fields
        )

        # Add the files to upload
        parts.extend(
            [
                part_boundary,
                f'Content-Disposition: file; name="{field_name}"; filename="{filename}"',
                f'Content-Type: {content_type}',
                '',
                body,
            ]
            for field_name, filename, content_type, body in self.files
        )

        # Flatten the list and add closing boundary marker,
        # then return CR+LF separated data
        flattened = list(itertools.chain(*parts))
        flattened.append('--' + self.boundary + '--')
        flattened.append('')
        return '\r\n'.join(flattened)
