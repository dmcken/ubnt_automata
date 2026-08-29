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
