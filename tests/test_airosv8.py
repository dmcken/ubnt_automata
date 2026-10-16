'''Tests for AirOSv8 - the X-CSRF-ID session flow, its _get()/_post()
helpers (added in the dedup pass, replacing 8 inline header blocks),
the shared flat key=value config parser, and the firmware-upgrade trio
(start_upgrade()/get_upgrade_status()/commit_upgrade(), plus the
blocking upgrade_and_wait() wrapper) confirmed live against a real
GigaBeam LR - a genuine hybrid using the SAME /api/v1.0/system/upgrade
path as UispDevice, but a different credential (_auth_token, not
_csrf_id) and a different two-stage shape (system/upgrade only stages
the image; fwflash.cgi commits it).'''
import unittest.mock

import pytest

from ubnt_automata import airoscommon, exceptions
from ubnt_automata.airosv8 import AirOSv8, AirOSv8UpgradeStatus


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

    def test_success_also_stores_separate_auth_token_when_present(self, requests_mock):
        '''Confirmed live (GigaBeam LR): the api/auth response's JSON
        body carries its own `utoken`, a DIFFERENT value from the
        X-CSRF-ID response header - needed separately for the
        /api/v1.0/ surface (see _get_v1()/_post_v1()).'''
        requests_mock.get('http://192.0.2.1/', status_code=200)
        requests_mock.post(
            'http://192.0.2.1/api/auth',
            status_code=200,
            json={'boardinfo': 'board.model=GigaBeam LR\n', 'utoken': 'fake-utoken'},
            headers={'X-CSRF-ID': 'fake-csrf-id'},
        )
        dev = AirOSv8('192.0.2.1')
        dev._is_ssl = False

        dev.login_http('fake-password', 'ubnt')

        assert dev._csrf_id == 'fake-csrf-id'
        assert dev._auth_token == 'fake-utoken'

    def test_missing_utoken_defaults_to_none(self, requests_mock):
        '''Not every AirOSv8 device's api/auth response has been
        confirmed to include utoken (only GigaBeam LR has) - must not
        KeyError on devices that don't send it.'''
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

        assert dev._auth_token is None

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


class TestGetWireless:
    '''Pure parsing coverage via monkeypatched getstatus() - avoids
    faking the whole HTTP/auth flow just to test wireless parsing.'''

    def _device_with_status(self, status):
        dev = AirOSv8('192.0.2.1')
        dev.getstatus = lambda: status
        return dev

    def test_parses_the_one_radio(self, load_json):
        dev = self._device_with_status(load_json('airosv8_status_wireless.json'))

        radios = dev.get_wireless()

        assert len(radios) == 1
        radio = radios[0]
        assert radio.radio_id == 'main'
        assert radio.connected is True
        assert radio.frequency_mhz == 5765
        assert radio.channel_width_mhz == 20
        assert radio.ssid == 'TEST-SITE-PTMP'
        assert radio.security == 'WPA2'

    def test_no_wireless_key_returns_disconnected_radio(self):
        dev = self._device_with_status({})

        radios = dev.get_wireless()

        assert len(radios) == 1
        assert radios[0].connected is False
        assert radios[0].frequency_mhz is None
        assert radios[0].channel_width_mhz is None


class TestStartUpgrade:
    def test_sends_url_and_secure_via_auth_token_not_csrf(self, requests_mock):
        '''Confirmed live: the real request body has no `timeout` key
        (unlike UispDevice's), and uses x-auth-token, not X-CSRF-ID.'''
        requests_mock.post(
            'http://192.0.2.1/api/v1.0/system/upgrade',
            json={'statusCode': 200, 'error': 0, 'message': 'Success'},
        )
        dev = AirOSv8('192.0.2.1')
        dev._is_ssl = False
        dev._csrf_id = 'fake-csrf-id'
        dev._auth_token = 'fake-utoken'

        dev.start_upgrade('https://example.invalid/fw.bin')

        sent = requests_mock.request_history[0]
        assert sent.json() == {'url': 'https://example.invalid/fw.bin', 'secure': False}
        assert sent.headers['x-auth-token'] == 'fake-utoken'
        assert 'X-CSRF-ID' not in sent.headers

    def test_non_200_raises_runtime_error(self, requests_mock):
        requests_mock.post(
            'http://192.0.2.1/api/v1.0/system/upgrade',
            status_code=400, text='bad request',
        )
        dev = AirOSv8('192.0.2.1')
        dev._is_ssl = False
        dev._auth_token = 'fake-utoken'

        with pytest.raises(RuntimeError, match='400'):
            dev.start_upgrade('https://example.invalid/fw.bin')


class TestGetUpgradeStatus:
    def test_parses_in_progress(self, requests_mock):
        requests_mock.get(
            'http://192.0.2.1/api/v1.0/system/upgrade',
            json={
                'status': 'in_progress', 'progressPercent': 0,
                'remainingTime': 0, 'failureReason': '',
            },
        )
        dev = AirOSv8('192.0.2.1')
        dev._is_ssl = False
        dev._auth_token = 'fake-utoken'

        status = dev.get_upgrade_status()

        assert status == AirOSv8UpgradeStatus(
            status='in_progress', progress_percent=0, remaining_time=0, failure_reason='',
        )

    def test_parses_finished(self, requests_mock):
        '''Confirmed live: unlike UispDevice, "finished" here carries
        no version confirmation at all - it means staged, not applied
        (see commit_upgrade()).'''
        requests_mock.get(
            'http://192.0.2.1/api/v1.0/system/upgrade',
            json={
                'status': 'finished', 'progressPercent': 100,
                'remainingTime': 0, 'failureReason': '',
            },
        )
        dev = AirOSv8('192.0.2.1')
        dev._is_ssl = False
        dev._auth_token = 'fake-utoken'

        status = dev.get_upgrade_status()

        assert status.status == 'finished'
        assert status.progress_percent == 100

    def test_non_200_raises_runtime_error(self, requests_mock):
        requests_mock.get(
            'http://192.0.2.1/api/v1.0/system/upgrade',
            status_code=500, text='error',
        )
        dev = AirOSv8('192.0.2.1')
        dev._is_ssl = False
        dev._auth_token = 'fake-utoken'

        with pytest.raises(RuntimeError, match='500'):
            dev.get_upgrade_status()


class TestCommitUpgrade:
    def test_sends_do_update_via_csrf_not_auth_token(self, requests_mock):
        '''Confirmed live: fwflash.cgi uses the SAME X-CSRF-ID auth as
        every other .cgi method on this class - reuses _post()
        unchanged, unlike start_upgrade()/get_upgrade_status().'''
        requests_mock.post('http://192.0.2.1/fwflash.cgi', json={'ok': True, 'code': 0})
        dev = AirOSv8('192.0.2.1')
        dev._is_ssl = False
        dev._csrf_id = 'fake-csrf-id'

        dev.commit_upgrade()

        sent = requests_mock.request_history[0]
        assert 'do_update=1' in sent.text
        assert sent.headers['X-CSRF-ID'] == 'fake-csrf-id'

    def test_non_200_raises_runtime_error(self, requests_mock):
        requests_mock.post('http://192.0.2.1/fwflash.cgi', status_code=500, text='error')
        dev = AirOSv8('192.0.2.1')
        dev._is_ssl = False
        dev._csrf_id = 'fake-csrf-id'

        with pytest.raises(RuntimeError, match='500'):
            dev.commit_upgrade()


class TestUpgradeAndWait:
    '''Pure orchestration coverage via monkeypatched start_upgrade()/
    get_upgrade_status()/commit_upgrade() - avoids faking the HTTP/
    polling timing. time.sleep is patched to a no-op.'''

    def _device(self, monkeypatch, statuses):
        from ubnt_automata import airosv8 as airosv8_module
        monkeypatch.setattr(airosv8_module.time, 'sleep', lambda seconds: None)

        dev = AirOSv8('192.0.2.1')
        dev.start_upgrade = lambda url, secure=False: None
        dev.commit_upgrade = unittest.mock.MagicMock()

        calls = iter(statuses)
        dev.get_upgrade_status = lambda: next(calls, statuses[-1])
        return dev

    def test_commits_once_staging_finishes(self, monkeypatch):
        finished = AirOSv8UpgradeStatus(
            status='finished', progress_percent=100, remaining_time=0, failure_reason='',
        )
        dev = self._device(monkeypatch, [
            AirOSv8UpgradeStatus(
                status='in_progress', progress_percent=0, remaining_time=0, failure_reason='',
            ),
            finished,
        ])

        result = dev.upgrade_and_wait('https://example.invalid/fw.bin')

        assert result is finished
        dev.commit_upgrade.assert_called_once()

    def test_none_status_is_not_treated_as_failure(self, monkeypatch):
        '''Same defensive handling as UispDevice - no live evidence
        this device's idle status is None too, but cheap insurance
        against the same race if it is.'''
        finished = AirOSv8UpgradeStatus(
            status='finished', progress_percent=100, remaining_time=0, failure_reason='',
        )
        dev = self._device(monkeypatch, [
            AirOSv8UpgradeStatus(
                status=None, progress_percent=0, remaining_time=0, failure_reason='',
            ),
            finished,
        ])

        result = dev.upgrade_and_wait('https://example.invalid/fw.bin')

        assert result is finished

    def test_non_empty_failure_reason_raises_regardless_of_status(self, monkeypatch):
        failed = AirOSv8UpgradeStatus(
            status='in_progress', progress_percent=40, remaining_time=0, failure_reason='disk full',
        )
        dev = self._device(monkeypatch, [failed])

        with pytest.raises(exceptions.UpgradeFailed, match='disk full'):
            dev.upgrade_and_wait('https://example.invalid/fw.bin')
        dev.commit_upgrade.assert_not_called()

    def test_unexpected_status_raises_upgrade_failed(self, monkeypatch):
        weird = AirOSv8UpgradeStatus(
            status='something_else', progress_percent=0, remaining_time=0, failure_reason='',
        )
        dev = self._device(monkeypatch, [weird])

        with pytest.raises(exceptions.UpgradeFailed):
            dev.upgrade_and_wait('https://example.invalid/fw.bin')

    def test_timeout_raises_upgrade_failed(self, monkeypatch):
        in_progress = AirOSv8UpgradeStatus(
            status='in_progress', progress_percent=0, remaining_time=0, failure_reason='',
        )
        dev = self._device(monkeypatch, [in_progress])

        with pytest.raises(exceptions.UpgradeFailed, match='did not finish'):
            dev.upgrade_and_wait('https://example.invalid/fw.bin', poll_interval=1, max_wait=2)
