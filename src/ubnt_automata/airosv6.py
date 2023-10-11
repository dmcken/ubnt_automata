'''Ubiquiti Common classes / functions needed for handling Ubiquiti devices.

'''
# System imports
import errno
import http # Look to remove, replace by requests
import json
import logging
import pprint
import re
import socket
import ssl
import sys
import time
import traceback
import urllib
import urllib3

# External imports
import bs4
import paramiko
import requests
import spur

# Local imports
from . import airoscommon
from . import exceptions
from . import utils

logger = logging.getLogger(__name__)

# Disable the self signed certificate warnings.
urllib3.disable_warnings()

# requests.packages.urllib3.util.ssl_.DEFAULT_CIPHERS += 'HIGH:!DH:!aNULL'
try:
    requests.packages.urllib3.contrib.pyopenssl.DEFAULT_SSL_CIPHER_LIST += 'HIGH:!DH:!aNULL'
except AttributeError:
    # no pyopenssl support used / needed / available
    pass

class UbntDevice(airoscommon.AirOSCommonDevice):
    '''Depreciated: Base device for UBNT v6 kit.
    '''

    def __init__(self, management_ip, auto_login = True, auto_apply = True):
        super().__init__(
            management_ip=management_ip,
        )

        # Default values
        self._http_conn = {}
        self._ssh_conn = None
        self._cookie_jar = None
        self._session = requests.Session()

        self._pages = {
            'ubnt': {},
            'link': {},
            'network': {},
            'advanced': {},
            'services': {},
            'system': {},
        }

        if auto_login is True:
            self.login(auto_apply)

    def login_ssh(self, passwords: list[str]):
        '''Login to device via SSH.
        '''
        try:
            curr_pw = passwords[0]
            self._ssh_conn = spur.SshShell(
                hostname = self._mgmt_ip,
                username = self._default_user,
                password = curr_pw,
                # port = 50022,
                missing_host_key = spur.ssh.MissingHostKey.accept,
            )
            self._ssh_conn._connect_ssh()
            return curr_pw
        except paramiko.ssh_exception.NoValidConnectionsError as exc:
            raise exceptions.DeviceUnavailable(
                f"Unable to connect to SSH on {self._mgmt_ip}"
            ) from exc
        except paramiko.ssh_exception.AuthenticationException:
            try:
                alt_pw_list = passwords[1:]
                for curr_alt_pw in alt_pw_list:
                    try:
                        self._ssh_conn = spur.SshShell(
                            hostname = self._mgmt_ip,
                            username = self._default_user,
                            password = curr_alt_pw,
                            port = 22,
                            missing_host_key = spur.ssh.MissingHostKey.accept,
                        )
                        self._ssh_conn._connect_ssh()
                        # Change password to currPW
                        return curr_alt_pw
                    except paramiko.ssh_exception.AuthenticationException:
                        # currAltPW failed, move onto next one.
                        continue

                # None of the passwords we know worked so can't do anything.
                raise exceptions.WrongPassword(
                    f"Device '{self._mgmt_ip}' does not have a known password."
                )
            except Exception as exc:
                raise Exception from exc

    def fetch_state(self):
        '''Fetch state of the Ubnt device.

        Primarily uses mca-status via SSH.
        '''

        rez = self._ssh_conn.run(['mca-status'])
        config_file_lines = [x.strip() for x in rez.output.strip().split(b'\n')]

        state = {}

        for curr_line in config_file_lines:
            if curr_line == b'':
                continue

            if curr_line[:11] == b'deviceName=':
                # we need to split
                parts = curr_line.split(b',')

                for curr_part in parts:
                    try:
                        name, value = curr_part.split(b'=', 1)
                    except ValueError:
                        logger.error(
                            f"Unable to split from deviceName ip '{self._mgmt_ip}' - {curr_line}"
                        )
                        continue
                    state[name] = value
            else:
                try:
                    name, value = curr_line.split(b'=', 1)
                    state[name] = value
                except ValueError:
                    logging.error(f"Error parsing line - fetchState: '{curr_line}'")

        # Convert bytes to strings
        str_state = {
            k.decode("utf-8"):v.decode("utf-8")
            for (k,v) in state.items()
        }

        return str_state

    def _get_base_url(self, relative_path: str = '') -> str:
        '''Build the base URL to request.
        '''

        # Detemine if this interface has SSL enforced.
        if self._is_ssl is None:
            self._determine_ssl()

        if self._is_ssl is False:
            access_scheme = 'http'
        elif self._is_ssl is True:
            access_scheme = 'https'
        else:
            raise RuntimeError("Reached login without determining SSL state")

        base_url = f"{access_scheme}://{self._mgmt_ip}/{relative_path}"

        return base_url

    def _parse_header(self, headers):
        '''Parse headers received, extracting cookies for cookie jar.
        '''
        for curr_header in [x for x in headers if x[0] == 'set-cookie']:
            # currHeader[0] is 'set-cookie', currHeader[1] is the data.
            cookie_sections = curr_header[1].split(';')
            for curr_section in cookie_sections:
                try:
                    cookie_name, cookie_value = curr_section.split('=', 1)
                    self._http_conn['cookieJar'][cookie_name] = cookie_value
                except ValueError:
                    pass

    def _create_cookie(self):
        '''
        Create cookie header from cookie jar.
        '''
        return "; ".join([
            f"{x[0]}={x[1]}" for x in list(self._http_conn['cookieJar'].items())
        ])

    def _fetch_fields_page(self, page):
        '''
        Fetch the lists of fields.

        '''

        result = self._session.get(self._get_base_url(page))

        soup = bs4.BeautifulSoup(result.text, "html.parser")

        form = soup.find('form', action = page)

        fields = {}

        for curr_field in form.find_all('input'):
            # print currField

            try:
                if curr_field['type'] in ['button', 'submit']:
                    continue
            except KeyError:
                # If the type is missing, then it isn't a input I want.
                continue

            try:
                curr_field['disabled']
                continue
            except KeyError:
                pass

            try:
                value = curr_field['value']
            except KeyError:
                value = ''

            if curr_field['type'] == 'checkbox':
                # If you have a checkbox the value is
                # only used if the box is checked
                try:
                    curr_field['checked']
                except KeyError:
                    value = ''

            fields[curr_field['name']] = value

        for curr_select in form.find_all('select'):
            # print currSelect

            selected = None
            for curr_option in curr_select.find_all('option'):
                try:
                    curr_option['selected']
                    selected = curr_option['value']
                except KeyError:
                    pass

            if curr_select['name'] == 'timezone' and selected is None:
                selected = 'GMT'

            fields[curr_select['name']] = selected

        # pprint.pprint(fields)

        return fields

    def login_http(self, curr_pw, curr_user = None):
        '''Login via HTTP to a UBNT device.

        '''
        try:
            if curr_user is None:
                curr_user = self._default_user

            try:
                # Session cookies get set here
                response = self._session.get(
                    self._get_base_url(),
                    verify=False,
                    timeout=self._default_timeout
                )
            except http.client.ssl.SSLError as exc:
                # Possible cases that I've seen:
                # The handshake operation timed out
                raise exceptions.DeviceUnavailable(
                    f"SSL Errors: {exc.args}"
                )
            except socket.error as exc:
                if exc.errno in [113]:
                    raise exceptions.DeviceUnavailable(
                        f"Unable to reach {self._mgmt_ip}"
                    )
                if exc.errno != errno.ECONNRESET:
                    raise
            except http.client.BadStatusLine as exc:
                raise exceptions.DeviceUnavailable(
                    "Error fetching data via HTTP connection"
                ) from exc
            except Exception as exc:
                raise exceptions.DeviceUnavailable(
                    "Connection reset by peer"
                ) from exc

            payload = {
                'username': curr_user,
                'password': curr_pw,
            }
            response = self._session.post(
                self._get_base_url('login.cgi'),
                data=payload,
            )

            result_parsed = urllib.parse.urlparse(response.url)
            if result_parsed.path == "/login.cgi":
                raise exceptions.WrongPassword(
                    f"Password '{curr_pw}' doesn't work on '{self._mgmt_ip}'"
                )

            if result_parsed.path == "/index.cgi":
                self._curr_password = curr_pw
                return
            else:
                logger.error(f"Unknown state, got url: {response.url}")
                raise RuntimeError(f"Unknown state, got url: {response.url}")
        except exceptions.WrongPassword:
            raise
        except exceptions.DeviceUnavailable:
            raise
        except Exception as exc:
            logger.debug(
                "An exception occurred 'login_http' - {0}: {1}, {2}".format(
                    self._mgmt_ip, exc.__class__, exc
                )
            )
            exc_type, exc_value, exc_traceback = sys.exc_info()
            logger.debug(repr(traceback.format_exception(exc_type, exc_value, exc_traceback)))
            raise

    def change_password(self, new_password):
        '''Change password on Ubnt device.
        '''
        try:
            logger.debug("Changing password")

            self._session.get(
                self._get_base_url('system.cgi'),
                timeout=30
            )

            fields = self._fetch_fields_page('system.cgi')

            # logger.debug(f"Change password fields: {fields}")

            field_data = {
                'OldPassword':  (None, self._curr_password),
                'NewPassword':  (None, new_password),
                'NewPassword2': (None, new_password),
                'change':       (None, 'Change'),
            }

            for field_name, field_value in list(fields.items()):
                if field_name in ['OldPassword', 'NewPassword', 'NewPassword2']:
                    continue
                field_data[field_name] = (None, field_value)

            result = self._session.post(
                url = self._get_base_url('system.cgi'),
                files = field_data,
            )

            html_data = result.text
            # Test if there is a change to apply
        except requests.exceptions.ConnectionError as exc:
            raise exceptions.DeviceUnavailable from exc

    def apply_changes(self, test_mode = False):
        '''Apply any pending changes.

        Test mode is also handled (after 120 seconds the change is rolled
        back if not confirmed).

        '''
        logger.debug("Applying changes")

        if test_mode is True:
            url = 'apply.cgi?testmode=on'
        else:
            url = 'apply.cgi'

        self._session.get(self._get_base_url(url))

        return

    def reboot(self):
        '''Reboot the device.

        v6. - Fetch the reboot.cgi page and pull the token.

        '''
        logger.debug("Rebooting")

        res = self._session.get(self._get_base_url('reboot.cgi'))

        soup = bs4.BeautifulSoup(res.text, features='html.parser')

        # We are looking for an input like this
        # <input type="hidden" name="token" value="aa7815665a132c3a12f5a3537a31804bda659f16" />

        res = soup.find('input', attrs={'name': 'token', 'type': 'hidden'})
        if res is None:
            logger.error(f"Unable to fetch token to reboot:\n{res.text}")
            return

        token = res['value']
        logger.debug(f"Token: {token}")

        reboot_request = self._session.post(
            self._get_base_url('reboot.cgi'),
            files={
                # https://stackoverflow.com/questions/12385179/how-to-send-a-multipart-form-data-with-requests-in-python
                'token': (None, token),
            },
        )

        logger.error(pprint.pformat(reboot_request.request))

        return

    def discard_changes(self):
        '''Discard pending changes.

        '''
        logging.debug("Discarding changes")
        self._http_conn['connection'].request('GET',
                                             '/discard.cgi',
                                             headers = { 'Cookie': self._create_cookie() })
        response = self._http_conn['connection'].getresponse()
        _ = response.read()
        self._http_conn['connection'].close()

        return

    def fetch_config(self, sorted_string = False):
        '''Fetch config.
        '''
        raw_config = self.fetch_config_http()

        if sorted_string:
            config_str = ''
            for curr_key in sorted(raw_config.keys()):
                config_str += f"{curr_key}={raw_config[curr_key]}\n"

            return config_str.strip()
        else:
            return raw_config


    def fetch_config_http(self):
        '''Fetch config file of UBNT device via HTTP.
        '''
        headers = {
            'Cookie': self._create_cookie(),
        }
        _, _, _, config_file = self._make_request('GET', '/cfg.cgi', headers = headers)

        data = {}
        for curr_line in [sm.strip() for sm in config_file.split('\n')]:
            if curr_line == '':
                continue

            name, value = curr_line.split('=', 1)
            data[name] = value

        return data

    def fetch_config_ssh(self, multi_layer = True):
        '''Fetch the device's config via SSH.
        '''
        rez = self._ssh_conn.run(['cat', '/tmp/system.cfg'])

        config_file_lines = [
            x.strip() for x in rez.output.strip().split('\n')
        ]

        config_dict = {}
        config_dict_breakdown = {}

        for curr_line in config_file_lines:
            key, value = curr_line.split('=', 1)
            config_dict[key] = value

            key_breakdown = key.split('.')

            dict_ptr = config_dict_breakdown
            for curr_key_part in key_breakdown:
                if curr_key_part not in dict_ptr:
                    dict_ptr[curr_key_part] = {}
                dict_ptr = dict_ptr[curr_key_part]

            dict_ptr[curr_key_part] = value

        if multi_layer:
            # logging.debug(pprint.pformat(config_dict_breakdown))
            return config_dict_breakdown
        else:
            # logging.debug(pprint.pformat(config_dict))
            return config_dict

    def _make_request(self, reqtype, path, headers, body = None, retries = 1):
        '''Make a request to the device.
        '''
        try:
            self._http_conn['connection'].request(reqtype, path, headers = headers)
            response = self._http_conn['connection'].getresponse()

            res_data = response.read()
            header_data = response.getheaders()

            return (response.status, response.reason, header_data, res_data)
        except http.client.BadStatusLine:
            if retries == 0:
                raise
            if self._is_ssl is False:
                self._http_conn['connection'] = http.client.HTTPConnection(self._mgmt_ip, 80, timeout = 30)
            else:
                try:
                    self._http_conn['connection'] = http.client.HTTPSConnection(
                        self._mgmt_ip, timeout = 30,
                        context = ssl._create_unverified_context()
                    )
                except AttributeError:
                    self._http_conn['connection'] = http.client.HTTPSConnection(self._mgmt_ip, timeout = 30)

            # Recursively re-enter function after creating connection.
            # Normally a bad thing but should only happen once.
            return self._make_request(reqtype, path, headers, body, (retries - 1))

    def _parse_ini(self, ini_str):
        '''Parse an .ini file.
        '''

        ini_data = {}
        for curr_line in [sm.strip() for sm in ini_str.split('\n')]:
            if curr_line == '':
                continue

            name, value = curr_line.split('=', 1)
            ini_data[name] = value

        return ini_data

    def fetch_site_survey(self, wait_time = 1):
        '''
        Fetch the site survery page:


        http://10.1.16.200/survey.json.cgi?iface=ath0
        '''
        headers = {
            'Cookie': self._create_cookie(),
        }

        _, _, _, json_data = self._make_request(
            'GET',
            '/survey.json.cgi?iface=ath0',
            headers = headers,
        )

        final_list = json.loads(json_data)
        time.sleep(wait_time)

        done = False
        while not done:
            _, _, _, json_data = self._make_request(
                'GET',
                '/survey.json.cgi?iface=ath0&update=last',
                headers = headers,
            )
            temp = json.loads(json_data)

            for curr_entry in temp:
                if 'scan_status' in curr_entry:
                    if curr_entry['scan_status'] == 'stopped':
                        done = True

                    continue

                found = False
                for i in range(len(final_list)):
                    if final_list[i]['mac'] == curr_entry['mac']:
                        final_list[i] = curr_entry
                        found = True

                if not found:
                    final_list.append(curr_entry)

            time.sleep(1)

        return final_list

    def change_parameter_http(self, parameter, value, page):
        '''Change parameter via HTTP.
        '''

        form = utils.MultiPartForm()
        if value is not None:
            form.add_field(parameter, value)
        # form.add_field('change', 'Change')

        # fields = self._fetchFieldsPage(page)
        # for fieldName, fieldValue in fields.items():
        #     print fieldNamepython search for dict entry
        #     if fieldName in [parameter]:
        #         continue
        #     if fieldValue == None:
        #         continue
        #     form.add_field(fieldName, fieldValue)

        headers = {
            'Content-type': form.get_content_type(),
            'Cookie': self._create_cookie()
        }

        self._http_conn['connection'].request('POST', page,
                                             body = str(form),
                                             headers = headers)
        response = self._http_conn['connection'].getresponse()
        html_data = response.read()
        # self._httpConn['connection'].close()

        '''
        print u"Code: {0}\nHeaders: {1}\nData: {2}".format(response.status,
                                                          pprint.pformat(response.getheaders()),
                                                          htmlData)
        '''

        return

    def change_parameter_ssh(self, parameters, auto_apply = False, ignore_unknown = False):
        '''
        parameters - a dictionary of config keys and the values desired.
        autoApply - should we automatically apply / reboot if changes are made.
        '''
        config = self.fetch_config_ssh(False)

        changes = {}
        additions = {}
        removals = {}

        for curr_key in list(parameters.keys()):
            if curr_key not in list(config.keys()):
                if ignore_unknown:
                    continue
                else:
                    additions[curr_key] = parameters[curr_key]
                    continue
                    # raise RuntimeError, u"Unknown parameter: '{0}'".format(currKey)

            # If the parameter is set to None it is set to be removed.
            if parameters[curr_key] is None:
                removals[curr_key] = None
                continue

            if config[curr_key] != parameters[curr_key]:
                changes[curr_key] = {'to': parameters[curr_key], 'from': config[curr_key]}

        if not changes and not additions and not removals:
            return False

        if changes:
            logger.debug(
                "SSH parameters changed: {0}".format(
                    pprint.pformat(changes)
                )
            )
            sed_strings = []
            for k,val in changes.items():
                sed_strings.append("s/{0}={1}/{0}={2}/g".format(k, val['from'], val['to']))

            #sedStrings = map(lambda (k, v): u"s/{0}={1}/{0}={2}/g".format(k, v['from'], v['to']),
            #                changes.iteritems())

            replace_command = ['sed', '-i']
            for curr_string in sed_strings:
                replace_command.append('-e')
                replace_command.append(curr_string)
            replace_command.append('/tmp/system.cfg')

            _ = self._ssh_conn.run(replace_command)

        if removals:
            logger.debug(
                f"SSH parameters removed: {0}".format(
                    pprint.pformat(removals)
                )
            )
            for key in list(removals.keys()):
                self._ssh_conn.run([
                    'sed',
                    '-i',
                    '/^{0}/d'.format(key),
                    '/tmp/system.cfg'
                ])

        if additions:
            logger.debug(
                f"SSH parameters added: {0}".format(
                    pprint.pformat(additions)
                )
            )
            for key, value in additions.items():
                self._ssh_conn.run([
                    'sed',
                    '-i',
                    f"$ a {key}={value}",
                    '/tmp/system.cfg'
                ])

        # Apply config
        _ = self._ssh_conn.run(['cfgmtd', '-f', '/tmp/system.cfg', '-w'])

        if auto_apply:
            _ = self._ssh_conn.run(['reboot'])

        return True

    def upgrade_device(self):
        '''
        wget -O /tmp/fwupdate.bin http://<sw host>/ubnt/XM.bin
        or
        wget -O /tmp/fwupdate.bin http://<sw host>/ubnt/XW.bin

        ubntbox fwupdate.real -m /tmp/fwupdate.bin


        Successful:
            XW.v5.6.9# ubntbox fwupdate.real -m /tmp/fwupdate.bin
            Current ver: 329225
            New version: 393216
            No need to fix.
            Writing 'kernel         ' to /dev/mtd2(kernel         ) ...  [%100]
            Writing 'rootfs         ' to /dev/mtd3(rootfs         ) ...  [%100]
            Done

        Errors:
            XW.v5.6.9# ubntbox fwupdate.real -m /tmp/fwupdate.bin
            Invalid version 'XM.ar7240.v6.0.30097.161219.1716'

        '''

        # logger.debug("FW Data: {0}".format(pprint.pformat(fw_data)))

        # Determine current version "ubntbox status"
        # ubntbox_status_text = self._ssh_conn.run(['ubntbox', 'status'])
        # ubntbox_status_data = json.loads(ubntbox_status_text.output)

        # device_version = self.parse_version_string(ubntbox_status_data['firmware']['version'])
        # logger.debug('Device current version: {0}{1}'.format(device_version['arch'], device_version['version']))

        # # Right before we begin the upgrade process we need to standardize a couple of parameters.

        # # fetch the appropriate firmware
        # if device_version['version'] in fw_data[device_version['arch']]\
        #     or device_version['version'] in ['v6.0.6', 'v6.0.7', 'v6.1.0', 'v6.1.3']: # Temp override due to elevate issues.
        #     # Device is running an acceptable version
        #     logger.info("Version '{0}' is acceptable, no upgrade required.".format(device_version['version']))
        #     return device_version['version']

        # upgrade_version = list(fw_data[device_version['arch']].keys())[0]

        # logger.debug("Upgrading to '{0}' from '{1}'".format(upgrade_version, device_version['version']))
        # fetch_params = ['wget', '-O', '/tmp/fwupdate.bin',
        #                 # '--timeout=120',
        #                 'http://<sw host>/ubnt/{0}'.format(fw_data[device_version['arch']][upgrade_version]['filename'])]
        # # logger.debug("Fetch: {0}".format(fetch_params))
        # _ = self._ssh_conn.run(fetch_params)

        # # Apply the firmware
        # logger.debug('Applying firmware')
        # _ = self._ssh_conn.spawn(['ubntbox', 'fwupdate.real', '-m', '/tmp/fwupdate.bin'])

        # # Seems we can't wait for the connection reset from the spur / paramiko library.
        # # Instead what I'm doing is spawining the command to burn in the new firmware
        # # (sometimes this seems to take quite some time) and then wait for the reboot.
        # # A burn in seems to take anywhere between 10-45 seconds, the reboot seems to
        # # take about a minute or two. This number is mostly from a small sampling of
        # # test cases with some extra padding to hopefully deal with weird shit.
        # # The UBNT wait time from the GUI seems to be 150 seconds.
        # # Longer term solution would be to allow a per command override of the timeout
        # # value of spur / paramiko (spur doesn't specify and paramiko's default is 1 hour).

        # # Wait 4 minutes for reboot
        # time_to_wait = 180
        # logger.debug("Starting to sleep for {0}".format(time_to_wait))
        # time.sleep(time_to_wait)
        # # Foce the old connection to close.
        # self._ssh_conn.__exit__()

        # # Re-connect to device
        # logger.debug("Attempting to re-connect")
        # self.login_ssh()

        # # confirm upgrade is completed.
        # ubntbox_status_text = self._ssh_conn.run(['ubntbox', 'status'])
        # ubntbox_status_data = json.loads(ubntbox_status_text.output)

        # device_new_version = self.parse_version_string(ubntbox_status_data['firmware']['version'])

        # if device_new_version['version'] == upgrade_version:
        #     logger.debug("Upgrade successful to '{0}'".format(upgrade_version))
        #     return upgrade_version
        # else:
        #     raise RuntimeError("Device was upgraded from '{0}' to '{1}' ended up at version '{2}'".\
        #         format(device_version['version'], upgrade_version, device_new_version['version']))

        return


class UbntSM(UbntDevice):
    '''Depreciated: Ubnt v6 SM / CPE.
    '''
    _pwClass = 'S'

    _SMFreqList = [
        # UNI-I - 20Mhz spacing
        '5180',
        '5200',
        '5220',
        '5240',
        '5260',
        '5280',
        '5300',
        '5320',

        # UNI-II - 20Mhz and 25Mhz spacing
        '5500',
        '5520',
        '5525',
        '5540',
        '5550',
        '5560',
        '5575',
        '5580',
        '5600',
        '5620',
        '5625',
        '5640',
        '5650',
        '5660',
        '5675',
        '5680',
        '5700',
    ]

    def parse_customer_config(self, cfg_data):
        '''Parse the customer config into an easier to use format.
        '''

        return_data = {}

        return_data['cpe_mode'] = cfg_data['netmode']

        if return_data['cpe_mode'] == 'bridge':
            for k, val in cfg_data.items():
                if re.search('bridge.1.port.[0-9].devname', k):
                    rez = re.search('ath[0-9].([0-9]*)', val)
                    if rez:
                        return_data['vlan'] = rez.group(1)
        elif return_data['cpe_mode'] == 'router':
            interface_data = {}
            for k, val in cfg_data.items():
                rez = re.search('netconf.([0-9]).(.*)', k)
                if rez:
                    if rez.group(1) not in interface_data:
                        interface_data[rez.group(1)] = {}
                    interface_data[rez.group(1)][rez.group(2)] = val

            return_data['vlan'] = 0
            for k, val in interface_data.items():
                if val['role'] == 'wan':
                    interface, vlan = val['devname'].split('.')
                    return_data['vlan'] = vlan
        else:
            return_data['vlan'] = 0

        # Extract the shaping data
        shaper_data = {}
        for k, val in cfg_data.items():
            rez = re.search('tshaper.([0-9]).(devname|output.rate|output.burst)', k)
            if rez:
                if rez.group(1) not in shaper_data:
                    shaper_data[rez.group(1)] = {}
                shaper_data[rez.group(1)][rez.group(2)] = val

        for k, val in shaper_data.items():
            if re.search('eth', val['devname']):
                return_data['download_rate'] = val['output.rate']
                return_data['download_burst'] = val['output.burst']
            if re.search('ath', val['devname']):
                return_data['upload_rate'] = val['output.rate']
                return_data['upload_burst'] = val['output.burst']

        if 'uploadrate' not in return_data:
            return_data['upload_rate']  = None
            return_data['upload_burst'] = None

        if 'downloadrate' not in return_data:
            return_data['download_rate']  = None
            return_data['download_burst'] = None

        return return_data

    def fetch_cust_data(self):
        '''Convenience function for fetching commonly used data from SM.


        '''
        headers = {
            'Cookie': self._create_cookie(),
        }
        return_data = {}

        # APName + IP + MAC (from sta.cgi)
        _, _, _, json_data = self._make_request('GET', '/sta.cgi?ifname=ath0', headers = headers)
        discovery_data = json.loads(json_data)

        return_data['ap_mac']  = discovery_data[0]['mac'].replace(':', '').replace('-', '')
        return_data['ap_name'] = discovery_data[0]['name']
        return_data['ap_ip']   = discovery_data[0]['lastip']

        return_data['signal_tx'] = discovery_data[0]['remote']['signal']
        return_data['signal_rx'] = discovery_data[0]['signal']

        return_data['rate_rx'] = discovery_data[0]['rx']
        return_data['rate_tx'] = discovery_data[0]['tx']

        return_data['dist_km'] = discovery_data[0]['distance']

        # SW Version + Mode (from status.cgi)
        _, _, _, json_data = self._make_request('GET', '/status.cgi', headers = headers)
        status_data = json.loads(json_data)

        return_data['cpe_mode']  = status_data['host']['netrole']
        return_data['fwprefix']  = status_data['host']['fwprefix']
        return_data['sm_ver']    = status_data['host']['fwversion']
        return_data['hostname']  = status_data['host']['hostname']
        return_data['frequency'] = status_data['wireless']['frequency']
        return_data['distance']  = status_data['wireless']['distance']
        return_data['ccq']       = status_data['wireless']['ccq']
        return_data['tx_rate']   = status_data['wireless']['txrate']
        return_data['rx_rate']   = status_data['wireless']['rxrate']
        return_data['signal']    = status_data['wireless']['signal']

        # Hardware model (from getboardinfo.sh)
        _, _, _, board_str = self._make_request(
            'GET',
            '/getboardinfo.sh',
            headers = headers
        )
        board_data = self._parse_ini(board_str)

        return_data['hardware_type'] = board_data['board.name']
        return_data['hw_addr']       = board_data['board.hwaddr']

        # VLAN + Configured BW (from getcfg.sh)
        _, _, _, cfg_str = self._make_request(
            'GET',
            '/getcfg.sh?.',
            headers = headers
        )
        cfg_data = self._parse_ini(cfg_str)

        if return_data['smmode'] == 'bridge':
            for k, val in cfg_data.items():
                if re.search('bridge.1.port.[0-9].devname', k):
                    rez = re.search('ath[0-9].([0-9]*)', val)
                    if rez:
                        return_data['vlan'] = rez.group(1)
        elif return_data['smmode'] == 'router':
            interface_data = {}
            for k, val in cfg_data.items():
                rez = re.search('netconf.([0-9]).(.*)', k)
                if rez:
                    if rez.group(1) not in interface_data:
                        interface_data[rez.group(1)] = {}
                    interface_data[rez.group(1)][rez.group(2)] = val

            return_data['vlan'] = 0
            for k, val in interface_data.items():
                if val['role'] == 'wan':
                    interface, vlan = val['devname'].split('.')
                    return_data['vlan'] = vlan
        else:
            return_data['vlan'] = 0

        # Extract the shaping data
        shaper_data = {}
        if cfg_data['tshaper.status'] == 'disabled':
            return_data['downloadrate'] = 0
            return_data['uploadrate'] = 0
        else:
            for k, val in cfg_data.items():
                rez = re.search('tshaper.([0-9]).(devname|output.rate)', k)
                if rez:
                    if rez.group(1) not in shaper_data:
                        shaper_data[rez.group(1)] = {}
                    shaper_data[rez.group(1)][rez.group(2)] = val

            for k, val in shaper_data.items():
                if re.search('eth', val['devname']):
                    return_data['downloadrate'] = val['output.rate']
                if re.search('ath', val['devname']):
                    return_data['uploadrate'] = val['output.rate']

        return return_data


class UbntAP(UbntDevice):
    '''Depreciated: Ubnt AP (v6)
    '''
    _pwClass = 'A'

    def fetch_stations_list(self):
        '''Fetch connected station list.
        '''

        headers = {
            'Cookie': self._create_cookie(),
        }

        _, _, _, json_data = self._make_request('GET', '/sta.cgi', headers = headers)

        return json.loads(json_data)

    def fetch_stations_list_ssh(self):
        '''Fetch the device's config via SSH.
        '''
        rez = self._ssh_conn.run(['wstalist'])

        return json.loads(rez.output.strip())

    def MacACLEnable(self, mode = 'deny'):
        '''Pull config of AP and check and activate the MAC ACL on the AP.

        Parameters affected:
        wireless.1.mac_acl.status=enabled
        wireless.1.mac_acl.policy=deny (or permit)
        '''
        sm_params = {
            'wireless.1.mac_acl.status': 'enabled',
            'wireless.1.mac_acl.policy': mode,
        }
        rez = self.change_parameter_ssh(sm_params, auto_apply = False)
        return rez

    def MacACLDisable(self):
        '''Pull config of AP and check and activate the MAC ACL on the AP.

        Parameters affected:
        wireless.1.mac_acl.status=disabled
        '''
        sm_params = {
            'wireless.1.mac_acl.status': 'disabled',
        }
        rez = self.change_parameter_ssh(sm_params, auto_apply = False)
        return rez

    def MacACLListSM(self):
        '''MAC ACL Lisst for CPE / SM.
        '''

        config = self.fetch_config_ssh(multi_layer = True)

        mac_list = {}
        for key in config['wireless']['1']['mac_acl']:
            if key in ['policy', 'status']:
                continue

            mac_list[key] = {
                'mac': config['wireless']['1']['mac_acl'][key]['mac']['mac'],
                'status': config['wireless']['1']['mac_acl'][key]['status']['status'],
                'comment': config['wireless']['1']['mac_acl'][key]['comment']['comment'],
            }

        return mac_list

    def MacACLAddSM(self, mac, reason):
        '''
        wireless.1.mac_acl.1.status=enabled
        wireless.1.mac_acl.1.mac=44:D9:E7:64:51:4A
        wireless.1.mac_acl.1.comment=Test
        '''
        mac_clean = utils.clean_mac(mac)
        mac_colon = utils.clean_mac_to_colon(mac_clean)

        config = self.fetch_config_ssh(multi_layer = True)

        mac_found = False
        for key in config['wireless']['1']['mac_acl']:
            if key in ['policy', 'status']:
                continue

            if config['wireless']['1']['mac_acl'][key]['mac'] == mac_colon:
                mac_found = True
                break

        if mac_found:
            logger.debug(f"Found mac '{mac_colon}' in ACL list already")
            return True

        # Ok, so the mac isn't in the existing list, determine what entry is free
        # so we can add.
        entries = [
            int(x) for x in [
                x for x in list(
                    config['wireless']['1']['mac_acl'].keys()
                ) if x not in ['policy', 'status']
            ]
        ]
        next_free = None
        for i in range(1, 256):
            if i in entries:
                continue

            next_free = i
            break

        logger.debug(
            f"Adding MAC ACL entry '{mac_colon}' to position '{next_free}'"
        )

        sm_params = {
            f'wireless.1.mac_acl.{next_free}.status'  : 'enabled',
            f'wireless.1.mac_acl.{next_free}.mac'     : mac_colon,
            f'wireless.1.mac_acl.{next_free}.comment' : reason,
        }
        rez = self.change_parameter_ssh(sm_params, auto_apply = False)
        return rez

    def MacACLDelSM(self, mac):
        '''Removes a mac from the MAC ACL list.

        '''
        mac_clean = utils.clean_mac(mac)
        mac_colon = utils.clean_mac_to_colon(mac_clean)

        config = self.fetch_config_ssh(multi_layer = True)

        mac_found = False
        for key in config['wireless']['1']['mac_acl']:
            if key in ['policy', 'status']:
                continue

            if config['wireless']['1']['mac_acl'][key]['mac']['mac'] == mac_colon:
                mac_found = key
                break


        if not mac_found:
            logger.debug(f"Mac '{mac_colon}' not found in ACL list")
            return False

        sm_params = {
            f'wireless.1.mac_acl.{mac_found}.status'  : None,
            f'wireless.1.mac_acl.{mac_found}.mac'     : None,
            f'wireless.1.mac_acl.{mac_found}.comment' : None,
        }
        rez = self.change_parameter_ssh(sm_params, auto_apply = False)
        return rez

class AirOSv6(UbntDevice):
    '''Ubnt pre-version 8 equipment handler.
    '''
    def __init__(self, managementIP, auto_login = True, auto_apply = True):
        super().__init__(
            managementIP,
            auto_login=auto_login,
            auto_apply=auto_apply,
        )


if __name__ == '__main__':
    #import pprint

    #import http.client
    #http.client.HTTPConnection.debuglevel = 1

    BASIC_FORMAT = '%(asctime)s - %(name)s - %(thread)d - %(levelname)s - %(message)s'
    logging.getLogger('paramiko.transport').setLevel(logging.ERROR)
    logging.getLogger('urllib3.connectionpool').setLevel(logging.INFO)
    logging.basicConfig(level = logging.DEBUG, format=BASIC_FORMAT)
    logging.info("Start")


