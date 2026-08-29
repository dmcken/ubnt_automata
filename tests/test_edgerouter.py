'''Tests for EdgeRouter - the classic EdgeMAX/EdgeOS web UI (303-
redirect + PHPSESSID login), a third API family distinct from both
AirOS/AirFiber and the UISP-firmware JSON REST API.'''
import pytest

from ubnt_automata import exceptions
from ubnt_automata.edgerouter import EdgeRouter


class TestLoginHttp:
    def test_303_redirect_with_phpsessid_is_success(self, requests_mock):
        '''login_http() checks the *session's* cookie jar (not the
        response's) for a fresh PHPSESSID - requests_mock is known not
        to propagate Set-Cookie into the session jar the way a real
        transport does, so the jar is seeded directly here to exercise
        the same check login_http() actually makes.'''
        requests_mock.post('http://192.0.2.1/', status_code=303)
        dev = EdgeRouter('192.0.2.1')
        dev._is_ssl = False
        dev._req_session.cookies.set('PHPSESSID', 'fake-session-id')

        dev.login_http('fake-password', 'ubnt')

        assert dev._curr_password == 'fake-password'

    def test_non_303_is_treated_as_wrong_password(self, requests_mock):
        requests_mock.post('http://192.0.2.1/', status_code=200)
        dev = EdgeRouter('192.0.2.1')
        dev._is_ssl = False

        with pytest.raises(exceptions.WrongPassword):
            dev.login_http('wrong-password', 'ubnt')

    def test_303_without_phpsessid_is_treated_as_wrong_password(self, requests_mock):
        '''A 303 alone isn't sufficient - the module docstring notes
        this failure-mode check was never empirically confirmed live,
        so both halves of the condition are covered here.'''
        requests_mock.post('http://192.0.2.1/', status_code=303)
        dev = EdgeRouter('192.0.2.1')
        dev._is_ssl = False

        with pytest.raises(exceptions.WrongPassword):
            dev.login_http('some-password', 'ubnt')


class TestGetData:
    def test_success_returns_output(self, requests_mock):
        requests_mock.get(
            'http://192.0.2.1/api/edge/data.json',
            json={'success': '1', 'output': {'sw_ver': '2.0.9'}},
        )
        dev = EdgeRouter('192.0.2.1')
        dev._is_ssl = False

        assert dev.get_sys_info() == {'sw_ver': '2.0.9'}

    def test_device_reported_failure_raises(self, requests_mock):
        requests_mock.get(
            'http://192.0.2.1/api/edge/data.json',
            json={'success': '0'},
        )
        dev = EdgeRouter('192.0.2.1')
        dev._is_ssl = False

        with pytest.raises(RuntimeError, match='reported failure'):
            dev.get_sys_info()

    def test_non_200_raises(self, requests_mock):
        requests_mock.get('http://192.0.2.1/api/edge/data.json', status_code=500, text='error')
        dev = EdgeRouter('192.0.2.1')
        dev._is_ssl = False

        with pytest.raises(RuntimeError, match='500'):
            dev.get_routes()

    def test_is_default_config(self, requests_mock):
        requests_mock.get(
            'http://192.0.2.1/api/edge/data.json',
            json={'success': '1', 'output': {'is_default': '1'}},
        )
        dev = EdgeRouter('192.0.2.1')
        dev._is_ssl = False

        assert dev.is_default_config() is True


class TestHeartbeat:
    def test_alive_session(self, requests_mock):
        requests_mock.get(
            'http://192.0.2.1/api/edge/heartbeat.json',
            json={'SESSION': True, 'PING': True},
        )
        dev = EdgeRouter('192.0.2.1')
        dev._is_ssl = False

        assert dev.heartbeat() is True

    def test_dead_session(self, requests_mock):
        requests_mock.get(
            'http://192.0.2.1/api/edge/heartbeat.json',
            json={'SESSION': False, 'PING': True},
        )
        dev = EdgeRouter('192.0.2.1')
        dev._is_ssl = False

        assert dev.heartbeat() is False


class TestGetConfig:
    def test_returns_get_key_contents(self, requests_mock):
        requests_mock.get(
            'http://192.0.2.1/api/edge/get.json',
            json={'GET': {'interfaces': {'eth0': {}}}},
        )
        dev = EdgeRouter('192.0.2.1')
        dev._is_ssl = False

        assert dev.get_config() == {'interfaces': {'eth0': {}}}
