'''Tests for the pure-parsing helpers in utils.py.'''
import pytest

from ubnt_automata import exceptions, utils


class TestParseFlatKvConfig:
    def test_parses_key_value_pairs(self, load_text):
        data = utils.parse_flat_kv_config(load_text('flat_kv_config.txt'))

        assert data['radio.0.mode'] == 'ap-ptp'
        assert data['radio.0.psk'] == 'fake-psk-not-a-real-secret'
        assert data['wireless.1.mac_acl.status'] == 'disabled'

    def test_skips_blank_lines_without_logging_an_error(self, load_text, caplog):
        with caplog.at_level('ERROR'):
            data = utils.parse_flat_kv_config(load_text('flat_kv_config.txt'))

        assert not any(r.levelname == 'ERROR' for r in caplog.records)
        assert len(data) == 5

    def test_logs_and_skips_a_genuinely_malformed_line(self, caplog):
        with caplog.at_level('ERROR'):
            data = utils.parse_flat_kv_config('good.key=value\nno_equals_sign_here\n')

        assert data == {'good.key': 'value'}
        assert 'no_equals_sign_here' in caplog.text

    def test_empty_input(self):
        assert utils.parse_flat_kv_config('') == {}


class TestParseUbntVersionString:
    '''Real behavior for every example already documented in the
    function's own docstring - traced/verified directly (not hand-
    derived) before writing these, since the parsing logic is
    non-trivial.'''

    @pytest.mark.parametrize(('version_string', 'expected'), [
        (
            'XW.v5.5.9-licensed.21763.140407.1903',
            {'arch': 'XW', 'something': '1903', 'build-date': '140407',
             'build-number': '21763', 'version': 'v5.5.9-licensed'},
        ),
        (
            'XW.ar934x.v5.6.9.29546.160819.1146',
            {'arch': 'XW', 'hw_model': 'ar934x', 'something': '1146',
             'build-date': '160819', 'build-number': '29546', 'version': 'v5.6.9'},
        ),
        (
            'AF06.am1808.v3.0.2.1.27948.150717.1309',
            {'arch': 'AF06', 'hw_model': 'am1808', 'something': '1309',
             'build-date': '150717', 'build-number': '27948', 'version': 'v3.0.2.1'},
        ),
        (
            'XC.qca955x.v7.1.1.27574.150519.1505',
            {'arch': 'XC', 'hw_model': 'qca955x', 'something': '1505',
             'build-date': '150519', 'build-number': '27574', 'version': 'v7.1.1'},
        ),
        (
            'XC.qca955x.v8.6.2.41239.190822.1633',
            {'arch': 'XC', 'hw_model': 'qca955x', 'something': '1633',
             'build-date': '190822', 'build-number': '41239', 'version': 'v8.6.2'},
        ),
    ])
    def test_extended_form(self, version_string, expected):
        assert utils.parse_ubnt_version_string(version_string) == expected

    def test_short_form_does_not_actually_extract_a_version(self):
        '''KNOWN BUG: the function's own docstring claims
        "XW.v5.6.9" -> version "v5.6.9", but the short-form branch
        (parts[1][0] == 'v') slices version_parts as parts[1:-3], which
        is empty for a 4-part string - so `version` never actually gets
        set from `curr_part` and comes back as ''. Verified directly
        against the current implementation rather than assumed from
        the docstring. Locking in current behavior here since fixing
        it wasn't in scope for this test-suite pass - if this function
        is ever revisited, this test should start failing and can be
        updated to the corrected expectation.
        '''
        assert utils.parse_ubnt_version_string('XW.v5.6.9') == {
            'arch': 'XW', 'something': '9', 'build-date': '6',
            'build-number': 'v5', 'version': '',
        }

    def test_strips_trailing_bin_suffix(self):
        with_bin = utils.parse_ubnt_version_string('XC.qca955x.v8.6.2.41239.190822.1633.bin')
        without_bin = utils.parse_ubnt_version_string('XC.qca955x.v8.6.2.41239.190822.1633')
        assert with_bin == without_bin

    def test_unknown_format_raises_value_error(self):
        # Needs enough dot-separated parts to reach the else branch -
        # neither parts[1] nor parts[2] starts with 'v'.
        with pytest.raises(ValueError, match='Unknown format'):
            utils.parse_ubnt_version_string('XX.hw.notversion.1.2.3')


class TestCleanMac:
    def test_strips_separators_and_uppercases(self):
        assert utils.clean_mac('aa:bb:cc:dd:ee:ff') == 'AABBCCDDEEFF'
        assert utils.clean_mac('AA-BB-CC-DD-EE-FF') == 'AABBCCDDEEFF'
        assert utils.clean_mac('aabbccddeeff') == 'AABBCCDDEEFF'

    def test_wrong_length_raises(self):
        with pytest.raises(ValueError, match='wrong length'):
            utils.clean_mac('aa:bb:cc')

    def test_clean_mac_to_colon_round_trips(self):
        cleaned = utils.clean_mac('aa:bb:cc:dd:ee:ff')
        assert utils.clean_mac_to_colon(cleaned) == 'AA:BB:CC:DD:EE:FF'


class TestDetermineSsl:
    def test_https_redirect_means_ssl(self, requests_mock):
        requests_mock.get('http://192.0.2.1/', status_code=302,
                           headers={'Location': 'https://192.0.2.1/'})
        requests_mock.get('https://192.0.2.1/', status_code=200)

        assert utils.determine_ssl('192.0.2.1') is True

    def test_plain_http_means_no_ssl(self, requests_mock):
        requests_mock.get('http://192.0.2.1/', status_code=200)

        assert utils.determine_ssl('192.0.2.1') is False

    def test_connect_timeout_raises_device_unavailable(self, requests_mock):
        import requests as requests_lib
        requests_mock.get('http://192.0.2.1/', exc=requests_lib.exceptions.ConnectTimeout)

        with pytest.raises(exceptions.DeviceUnavailable):
            utils.determine_ssl('192.0.2.1')

    def test_connection_error_raises_device_unavailable(self, requests_mock):
        '''requests.exceptions.ConnectionError (e.g. "No route to host",
        "Connection refused") is what a real closed/filtered port
        actually raises through requests/urllib3 - it isn't an OSError
        or urllib3.exceptions.* by the time it reaches this function,
        so the except clause further down never saw it (regression:
        a live sweep of ~400 devices treated every one of these as a
        crash instead of DeviceUnavailable).
        '''
        import requests as requests_lib
        requests_mock.get('http://192.0.2.1/', exc=requests_lib.exceptions.ConnectionError)

        with pytest.raises(exceptions.DeviceUnavailable):
            utils.determine_ssl('192.0.2.1')


class TestDetermineDeviceType:
    def test_airosv8_json_response(self, requests_mock):
        requests_mock.get('http://192.0.2.1/', status_code=200)
        requests_mock.get(
            'http://192.0.2.1/api/info/public',
            json={'setup_complete': True, 'ui_lang': 'en_US', 'product_name': 'LiteBeam 5AC'},
            headers={'Content-Type': 'application/json; charset=utf-8'},
        )

        result = utils.determine_device_type('192.0.2.1')

        assert result.model_group == 8
        assert result.model_name == 'LiteBeam 5AC'
        assert result.web_ssl is False

    def test_missing_content_type_header_does_not_crash(self, requests_mock):
        '''Some devices respond to /api/info/public with no Content-Type
        header at all (regression: this used to KeyError on
        headers['Content-Type'] instead of falling through to
        model_group 0, and hit ~1 in 6 devices in a live sweep).
        '''
        requests_mock.get('http://192.0.2.1/', status_code=200)
        requests_mock.get(
            'http://192.0.2.1/api/info/public',
            status_code=200,
            headers={},
        )
        requests_mock.get('http://192.0.2.1/api/v1.0/public/device', status_code=404)

        result = utils.determine_device_type('192.0.2.1')

        assert result.model_group == 0

    def test_uisp_firmware_public_device(self, requests_mock):
        '''Wave AP/Pro/Nano/LR, AirFiber 60 XR, EdgePower, and newer-
        firmware EdgePoint switches all share this pre-auth device-
        identification endpoint -- checked once AirOSv8/v6 have both
        already been ruled out.
        '''
        requests_mock.get('http://192.0.2.1/', status_code=200)
        requests_mock.get('http://192.0.2.1/api/info/public', status_code=404)
        requests_mock.get(
            'http://192.0.2.1/api/v1.0/public/device',
            json={'product': 'Wave AP', 'model': 'Wave-AP', 'family': 'wave'},
        )

        result = utils.determine_device_type('192.0.2.1')

        assert result.model_group == 9
        assert result.model_name == 'Wave AP'

    def test_uisp_public_device_unreachable_falls_back_to_unknown(self, requests_mock):
        import requests as requests_lib
        requests_mock.get('http://192.0.2.1/', status_code=200)
        requests_mock.get('http://192.0.2.1/api/info/public', status_code=404)
        requests_mock.get(
            'http://192.0.2.1/api/v1.0/public/device',
            exc=requests_lib.exceptions.ConnectionError,
        )

        result = utils.determine_device_type('192.0.2.1')

        assert result.model_group == 0

    def test_older_edgepoint_firmware_401_falls_back_to_unknown(self, requests_mock):
        '''An EdgePoint S16 running older firmware was confirmed to
        401 on public/device even pre-login -- not universal, so this
        one case can't be identified without a working password,
        which this function deliberately never tries.
        '''
        requests_mock.get('http://192.0.2.1/', status_code=200)
        requests_mock.get('http://192.0.2.1/api/info/public', status_code=404)
        requests_mock.get(
            'http://192.0.2.1/api/v1.0/public/device',
            status_code=401,
            text='Unauthorized',
        )

        result = utils.determine_device_type('192.0.2.1')

        assert result.model_group == 0

    def test_airosv6_login_redirect(self, requests_mock):
        requests_mock.get('http://192.0.2.1/', status_code=200)
        # A real AirOSv6 CPE redirects api/info/public to its login page -
        # determine_device_type() checks the *final*, post-redirect URL's
        # path, so mock the actual redirect chain rather than the target
        # URL directly.
        requests_mock.get(
            'http://192.0.2.1/api/info/public',
            status_code=302,
            headers={'Location': 'http://192.0.2.1/login.cgi'},
        )
        requests_mock.get(
            'http://192.0.2.1/login.cgi',
            status_code=200,
            headers={'Content-Type': 'text/html'},
        )

        result = utils.determine_device_type('192.0.2.1')

        assert result.model_group == 6
