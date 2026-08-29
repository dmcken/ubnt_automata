'''Tests for AirOSv8 - the X-CSRF-ID session flow, its _get()/_post()
helpers (added in the dedup pass, replacing 8 inline header blocks),
and the shared flat key=value config parser.'''
import pytest

from ubnt_automata import airoscommon, exceptions
from ubnt_automata.airosv8 import AirOSv8


class TestLoginHttp:
    def test_success_stores_csrf_id_and_boardinfo(self, requests_mock):
        requests_mock.get('http://192.0.2.1/', status_code=200)
        requests_mock.post(
            'http://192.0.2.1/api/auth',
            status_code=200,
            json={'boardinfo': 'board.model=RP5AC\n'},
            headers={'X-CSRF-ID': 'fake-csrf-id'},
        )
        dev = AirOSv8('192.0.2.1')
        dev._is_ssl = False

        dev.login_http('fake-password', 'ubnt')

        assert dev._csrf_id == 'fake-csrf-id'
        assert dev._dev_info == 'board.model=RP5AC\n'
        assert dev._curr_password == 'fake-password'

    def test_non_200_raises_wrong_password(self, requests_mock):
        requests_mock.get('http://192.0.2.1/', status_code=200)
        requests_mock.post(
            'http://192.0.2.1/api/auth',
            status_code=401,
            json={'error': 'bad credentials'},
        )
        dev = AirOSv8('192.0.2.1')
        dev._is_ssl = False

        with pytest.raises(exceptions.WrongPassword):
            dev.login_http('wrong-password', 'ubnt')

    def test_connection_error_raises_device_unavailable(self, requests_mock):
        import requests as requests_lib
        requests_mock.get('http://192.0.2.1/', exc=requests_lib.exceptions.ConnectionError)
        dev = AirOSv8('192.0.2.1')
        dev._is_ssl = False

        with pytest.raises(exceptions.DeviceUnavailable):
            dev.login_http('any-password', 'ubnt')


class TestGetAndPostHelpers:
    '''The dedup pass added these to remove 8 repeated inline
    `headers={"X-CSRF-ID": ...}` blocks - confirm the CSRF header (and
    an extra per-call header, used by change_password()) actually make
    it onto the wire.'''

    def test_get_sends_csrf_header(self, requests_mock):
        requests_mock.get('http://192.0.2.1/status.cgi', json={'ok': True})
        dev = AirOSv8('192.0.2.1')
        dev._is_ssl = False
        dev._csrf_id = 'fake-csrf-id'

        dev._get('status.cgi')

        assert requests_mock.request_history[0].headers['X-CSRF-ID'] == 'fake-csrf-id'

    def test_post_merges_extra_headers_with_csrf(self, requests_mock):
        requests_mock.post('http://192.0.2.1/pwd.cgi', json={'success': True})
        dev = AirOSv8('192.0.2.1')
        dev._is_ssl = False
        dev._csrf_id = 'fake-csrf-id'

        dev._post('pwd.cgi', extra_headers={'Accept': 'application/json'})

        sent = requests_mock.request_history[0].headers
        assert sent['X-CSRF-ID'] == 'fake-csrf-id'
        assert sent['Accept'] == 'application/json'


class TestGetcfg:
    def test_uses_shared_flat_kv_parser(self, requests_mock, load_text):
        requests_mock.get('http://192.0.2.1/getcfg.cgi', text=load_text('flat_kv_config.txt'))
        dev = AirOSv8('192.0.2.1')
        dev._is_ssl = False
        dev._csrf_id = 'fake-csrf-id'

        cfg = dev.getcfg()

        assert cfg['radio.0.mode'] == 'ap-ptp'

    def test_trailing_newline_does_not_log_a_parse_error(self, requests_mock, caplog):
        '''Regression test: getcfg() used to split on '\\n' with no
        blank-line guard, so a response with a trailing newline logged
        a spurious "Unable to parse line: " error on every single call.
        Now routed through the shared parser, which guards against it.
        '''
        requests_mock.get(
            'http://192.0.2.1/getcfg.cgi',
            text='radio.0.mode=ap-ptp\nradio.0.psk=fake-psk\n',
        )
        dev = AirOSv8('192.0.2.1')
        dev._is_ssl = False
        dev._csrf_id = 'fake-csrf-id'

        with caplog.at_level('ERROR'):
            cfg = dev.getcfg()

        assert cfg == {'radio.0.mode': 'ap-ptp', 'radio.0.psk': 'fake-psk'}
        assert not any(r.levelname == 'ERROR' for r in caplog.records)


class TestChangePassword:
    def test_success_sends_old_and_new_password(self, requests_mock):
        requests_mock.post('http://192.0.2.1/pwd.cgi', json={'success': True})
        dev = AirOSv8('192.0.2.1')
        dev._is_ssl = False
        dev._csrf_id = 'fake-csrf-id'
        dev._curr_password = 'old-password'

        dev.change_password('new-password')

        sent = requests_mock.request_history[0]
        assert 'oldPwd=old-password' in sent.text
        assert 'pwd=new-password' in sent.text

    def test_device_reported_failure_is_logged_not_raised(self, requests_mock, caplog):
        requests_mock.post('http://192.0.2.1/pwd.cgi', json={'success': False})
        dev = AirOSv8('192.0.2.1')
        dev._is_ssl = False
        dev._csrf_id = 'fake-csrf-id'
        dev._curr_password = 'old-password'

        with caplog.at_level('ERROR'):
            dev.change_password('new-password')  # must not raise

        assert 'Error changing password' in caplog.text

    def test_non_json_response_is_logged_not_raised(self, requests_mock, caplog):
        requests_mock.post('http://192.0.2.1/pwd.cgi', text='not json')
        dev = AirOSv8('192.0.2.1')
        dev._is_ssl = False
        dev._csrf_id = 'fake-csrf-id'
        dev._curr_password = 'old-password'

        with caplog.at_level('ERROR'):
            dev.change_password('new-password')  # must not raise

        assert 'Error decoding json' in caplog.text


class TestApplyChanges:
    def test_active_zero_or_one_is_success(self, requests_mock):
        requests_mock.get('http://192.0.2.1/test_mode.cgi', json={'active': 0})
        dev = AirOSv8('192.0.2.1')
        dev._is_ssl = False
        dev._csrf_id = 'fake-csrf-id'

        dev.apply_changes()  # must not raise


class TestWritecfg:
    def test_success(self, requests_mock):
        requests_mock.post('http://192.0.2.1/writecfg.cgi', json={'ok': True})
        dev = AirOSv8('192.0.2.1')
        dev._is_ssl = False
        dev._csrf_id = 'fake-csrf-id'

        dev.writecfg({'radio.0.mode': 'ap-ptp'})

        sent = requests_mock.request_history[0]
        assert 'radio.0.mode%3Dap-ptp' in sent.text or 'radio.0.mode=ap-ptp' in sent.text

    def test_failure_is_logged_not_raised(self, requests_mock, caplog):
        requests_mock.post('http://192.0.2.1/writecfg.cgi', json={'ok': False})
        dev = AirOSv8('192.0.2.1')
        dev._is_ssl = False
        dev._csrf_id = 'fake-csrf-id'

        with caplog.at_level('ERROR'):
            dev.writecfg({'radio.0.mode': 'ap-ptp'})  # must not raise

        assert 'Error changing config' in caplog.text


class TestGetDiscovery:
    def test_posts_discover_and_duration(self, requests_mock):
        requests_mock.post(
            'http://192.0.2.1/discovery.cgi',
            json={'devices': [{'hostname': 'neighbor-1'}]},
        )
        dev = AirOSv8('192.0.2.1')
        dev._is_ssl = False
        dev._csrf_id = 'fake-csrf-id'

        result = dev.getdiscovery()

        assert result == [{'hostname': 'neighbor-1'}]
        sent = requests_mock.request_history[0]
        assert sent.method == 'POST'
        assert 'discover=y' in sent.text
        assert 'duration=500' in sent.text


class TestGetGps:
    def test_returns_gps_fix(self, requests_mock):
        requests_mock.get(
            'http://192.0.2.1/status.cgi',
            json={'gps': {'lat': -33.36753, 'lon': 148.016417, 'alt': 260.5,
                           'sats': 11, 'fix': 1}},
        )
        dev = AirOSv8('192.0.2.1')
        dev._is_ssl = False
        dev._csrf_id = 'fake-csrf-id'

        gps = dev.get_gps()

        assert gps == airoscommon.GPSFix(
            latitude=-33.36753, longitude=148.016417, altitude_m=260.5,
            satellites=11, fix=1,
        )

    def test_no_fix_returns_none(self, requests_mock):
        requests_mock.get(
            'http://192.0.2.1/status.cgi',
            json={'gps': {'lat': 0, 'lon': 0, 'alt': 0, 'sats': 0, 'fix': False}},
        )
        dev = AirOSv8('192.0.2.1')
        dev._is_ssl = False
        dev._csrf_id = 'fake-csrf-id'

        assert dev.get_gps() is None

    def test_no_gps_key_at_all_returns_none(self, requests_mock):
        requests_mock.get('http://192.0.2.1/status.cgi', json={})
        dev = AirOSv8('192.0.2.1')
        dev._is_ssl = False
        dev._csrf_id = 'fake-csrf-id'

        assert dev.get_gps() is None
