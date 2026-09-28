'''Tests for AirOSv6 - the classic lighttpd-served, HTML-form/cookie-
based web UI still running on older-generation gear (e.g. an
AirFiber 11FX on fw v4.1.0), distinct from AirOSv8's JSON API.'''
import pytest

from ubnt_automata import exceptions
from ubnt_automata.airosv6 import AirOSv6


def _device_with_status(status):
    '''A real AirOSv6 instance with getstatus() monkeypatched to return
    a fixture payload instead of making an HTTP call - avoids needing
    to fake the whole session/cookie flow just to exercise the pure
    parsing logic in get_gps()/get_wireless().'''
    dev = AirOSv6('192.0.2.1')
    dev.getstatus = lambda: status
    return dev


class TestLoginHttp:
    def test_success_lands_on_index_html(self, requests_mock):
        requests_mock.get('http://192.0.2.1/', status_code=200)
        requests_mock.post(
            'http://192.0.2.1/login.cgi',
            status_code=302,
            headers={'Location': 'http://192.0.2.1/index.html'},
        )
        requests_mock.get('http://192.0.2.1/index.html', status_code=200)
        dev = AirOSv6('192.0.2.1')
        dev._is_ssl = False

        dev.login_http('fake-password', 'ubnt')

        assert dev._curr_password == 'fake-password'
        sent = requests_mock.request_history[1]
        assert sent.method == 'POST'
        assert sent.url == 'http://192.0.2.1/login.cgi'
        assert 'username=ubnt' in sent.text
        assert 'password=fake-password' in sent.text

    def test_wrong_password_redirects_back_to_login(self, requests_mock):
        requests_mock.get('http://192.0.2.1/', status_code=200)
        requests_mock.post(
            'http://192.0.2.1/login.cgi',
            status_code=302,
            headers={'Location': 'http://192.0.2.1/login.cgi'},
        )
        # A 302 to the same URL is auto-followed as a GET to complete
        # the redirect chain - the login page itself, landed on again.
        requests_mock.get('http://192.0.2.1/login.cgi', status_code=200)
        dev = AirOSv6('192.0.2.1')
        dev._is_ssl = False

        with pytest.raises(exceptions.WrongPassword):
            dev.login_http('wrong-password', 'ubnt')

    def test_connection_error_raises_device_unavailable(self, requests_mock):
        import requests as requests_lib
        requests_mock.get('http://192.0.2.1/', exc=requests_lib.exceptions.ConnectionError)
        dev = AirOSv6('192.0.2.1')
        dev._is_ssl = False

        with pytest.raises(exceptions.DeviceUnavailable):
            dev.login_http('any-password', 'ubnt')


class TestGetcfg:
    def test_uses_shared_flat_kv_parser(self, requests_mock, load_text):
        requests_mock.get('http://192.0.2.1/getcfg.sh', text=load_text('flat_kv_config.txt'))
        dev = AirOSv6('192.0.2.1')
        dev._is_ssl = False

        cfg = dev.getcfg()

        assert cfg['radio.0.mode'] == 'ap-ptp'


class TestGetBoardinfo:
    def test_uses_shared_flat_kv_parser(self, requests_mock, load_text):
        requests_mock.get(
            'http://192.0.2.1/getboardinfo.sh', text=load_text('airosv6_boardinfo.txt'),
        )
        dev = AirOSv6('192.0.2.1')
        dev._is_ssl = False

        info = dev.get_boardinfo()

        assert info['board.name'] == 'airFiber 11FX'
        assert info['board.shortname'] == 'AF11FX'


class TestGetstatus:
    def test_returns_parsed_json(self, requests_mock, load_json):
        requests_mock.get('http://192.0.2.1/status.cgi', json=load_json('airosv6_status.json'))
        dev = AirOSv6('192.0.2.1')
        dev._is_ssl = False

        status = dev.getstatus()

        assert status['host']['devmodel'] == 'airFiber 11FX '
        assert status['airfiber']['remote_ip'] == '192.0.2.2'

    def test_non_200_raises_runtime_error(self, requests_mock):
        requests_mock.get('http://192.0.2.1/status.cgi', status_code=500, text='boom')
        dev = AirOSv6('192.0.2.1')
        dev._is_ssl = False

        with pytest.raises(RuntimeError):
            dev.getstatus()


class TestGetDiscovery:
    def test_returns_devices_list(self, requests_mock, load_json):
        requests_mock.get(
            'http://192.0.2.1/discovery.cgi', json=load_json('airosv6_discovery.json'),
        )
        dev = AirOSv6('192.0.2.1')
        dev._is_ssl = False

        devices = dev.get_discovery()

        assert len(devices) == 1
        assert devices[0]['hostname'] == 'TEST-LINK-B'
        assert devices[0]['product'] == 'AF11FX'

    def test_sends_discover_and_duration_query_params(self, requests_mock, load_json):
        requests_mock.get(
            'http://192.0.2.1/discovery.cgi', json=load_json('airosv6_discovery.json'),
        )
        dev = AirOSv6('192.0.2.1')
        dev._is_ssl = False

        dev.get_discovery(duration_ms=1000)

        sent = requests_mock.request_history[0]
        assert sent.qs == {'discover': ['y'], 'duration': ['1000']}

    def test_non_200_raises_runtime_error(self, requests_mock):
        requests_mock.get('http://192.0.2.1/discovery.cgi', status_code=500, text='boom')
        dev = AirOSv6('192.0.2.1')
        dev._is_ssl = False

        with pytest.raises(RuntimeError):
            dev.get_discovery()


class TestGetGps:
    def test_no_fix_returns_none(self, load_json):
        dev = _device_with_status(load_json('airosv6_status.json'))
        assert dev.get_gps() is None


class TestGetWireless:
    def test_returns_single_radio(self, load_json):
        dev = _device_with_status(load_json('airosv6_status.json'))

        radios = dev.get_wireless()

        assert len(radios) == 1
        assert radios[0].frequency_mhz == 11155
        assert radios[0].ssid == 'TEST-LINK'


class TestNoOpWrites:
    '''change_password()/apply_changes() must never touch the device -
    see the class docstring on why (AirOSCommonDevice.login()'s
    alternate-password path calls change_password() automatically).'''

    def test_change_password_is_a_noop(self, requests_mock):
        dev = AirOSv6('192.0.2.1')
        dev.change_password('anything')
        assert len(requests_mock.request_history) == 0

    def test_apply_changes_is_a_noop(self, requests_mock):
        dev = AirOSv6('192.0.2.1')
        dev.apply_changes()
        assert len(requests_mock.request_history) == 0
