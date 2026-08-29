'''Tests for the shared AirOSCommonDevice base class: GPS parsing,
_build_url()'s prefix handling, and the multi-password login() retry
loop (including a regression test for the password-in-logs bug fixed
in this same pass).'''
import pytest

from ubnt_automata import airoscommon, exceptions


class TestParseGpsFix:
    def test_no_fix_returns_none(self):
        assert airoscommon.parse_gps_fix(None) is None
        assert airoscommon.parse_gps_fix({}) is None
        assert airoscommon.parse_gps_fix({'fix': 0}) is None
        assert airoscommon.parse_gps_fix({'fix': False}) is None

    def test_airfiber_style_numeric_fix(self):
        gps = airoscommon.parse_gps_fix({
            'lat': 10.5, 'lon': 20.5, 'alt': 100.0, 'sats': 12, 'fix': 1,
        })
        assert gps == airoscommon.GPSFix(
            latitude=10.5, longitude=20.5, altitude_m=100.0, satellites=12, fix=1,
        )

    def test_uisp_style_boolean_fix_is_lossless(self):
        '''UISP's API reports 'fix' as a JSON boolean rather than
        AirFiber's numeric fix-quality value - confirmed against real
        statistics captures. int(True) == 1, so unifying both APIs onto
        one dataclass doesn't lose the "has a lock" meaning.'''
        gps = airoscommon.parse_gps_fix({
            'lat': 10.5, 'lon': 20.5, 'alt': 100.0, 'sats': 12, 'fix': True,
        })
        assert gps.fix == 1

    def test_string_values_are_cast(self):
        '''Values can arrive as numeric strings depending on hardware
        generation - always cast explicitly rather than trust the type.'''
        gps = airoscommon.parse_gps_fix({
            'lat': '10.5', 'lon': '20.5', 'alt': '100.0', 'sats': '12', 'fix': '1',
        })
        assert gps == airoscommon.GPSFix(
            latitude=10.5, longitude=20.5, altitude_m=100.0, satellites=12, fix=1,
        )


class _StubDevice(airoscommon.AirOSCommonDevice):
    '''Minimal concrete subclass for exercising login()'s retry loop
    without any real network I/O.'''

    def __init__(self, working_password, changes_device=False):
        super().__init__(management_ip='192.0.2.1')
        self._working_password = working_password
        self._changes_device = changes_device
        self.change_password_calls = []
        self.apply_changes_called = False

    def login_http(self, curr_pw, curr_user=None):
        if curr_pw != self._working_password:
            raise exceptions.WrongPassword()
        self._curr_username = curr_user
        self._curr_password = curr_pw

    def change_password(self, new_password):
        self.change_password_calls.append(new_password)
        if self._changes_device:
            # Simulates AirOSv8: change_password() is a real device
            # mutation, not a no-op.
            self._working_password = new_password

    def apply_changes(self, test_mode=False):
        self.apply_changes_called = True


class TestLogin:
    def test_primary_password_succeeds_without_retry(self):
        dev = _StubDevice(working_password='correct-horse')
        dev.login(['correct-horse', 'unused-alt'])
        assert dev._curr_password == 'correct-horse'
        assert dev.change_password_calls == []

    def test_falls_back_to_alternate_password(self):
        dev = _StubDevice(working_password='alternate-pw')
        dev.login(['primary-pw', 'alternate-pw'])
        assert dev._curr_password == 'alternate-pw'

    def test_no_known_password_raises_wrong_password(self):
        dev = _StubDevice(working_password='only-this-works')
        with pytest.raises(exceptions.WrongPassword, match='does not have a known password'):
            dev.login(['a', 'b', 'c'])

    def test_alternate_success_triggers_change_password_back_to_primary(self):
        '''Documents the existing (not newly introduced) behavior: a
        successful login on an alternate password calls
        change_password(primary_pw) - a no-op on read-only classes, but
        a real device mutation for a class like AirOSv8 where it isn't.
        '''
        dev = _StubDevice(working_password='alternate-pw', changes_device=True)
        dev.login(['primary-pw', 'alternate-pw'])
        assert dev.change_password_calls == ['primary-pw']

    def test_auto_apply_calls_apply_changes_only_after_alternate_success(self):
        dev = _StubDevice(working_password='alternate-pw')
        dev.login(['primary-pw', 'alternate-pw'], auto_apply=True)
        assert dev.apply_changes_called is True

        dev2 = _StubDevice(working_password='primary-pw')
        dev2.login(['primary-pw'], auto_apply=True)
        assert dev2.apply_changes_called is False

    def test_passwords_never_appear_in_logs(self, caplog):
        '''Regression test for the cleartext-password-logging bug fixed
        in this pass (airoscommon.py's login() used to log
        f"Trying: {curr_pw}" and f"Primary password '{primary_pw}'
        failed" at debug level).'''
        secret_passwords = ['s3cr3t-primary', 's3cr3t-alternate', 's3cr3t-unused']
        dev = _StubDevice(working_password='s3cr3t-alternate')

        with caplog.at_level('DEBUG'):
            dev.login(secret_passwords)

        for pw in secret_passwords:
            assert pw not in caplog.text

    def test_passwords_never_appear_in_logs_even_on_total_failure(self, caplog):
        secret_passwords = ['s3cr3t-a', 's3cr3t-b']
        dev = _StubDevice(working_password='not-in-the-list')

        with caplog.at_level('DEBUG'), pytest.raises(exceptions.WrongPassword):
            dev.login(secret_passwords)

        for pw in secret_passwords:
            assert pw not in caplog.text


class _PrefixedDevice(airoscommon.AirOSCommonDevice):
    _url_path_prefix = 'api/v1.0/'

    def login_http(self, curr_pw, curr_user=None):
        pass

    def change_password(self, new_password):
        pass

    def apply_changes(self, test_mode=False):
        pass


class TestBuildUrl:
    def test_default_prefix_is_empty(self):
        dev = _StubDevice(working_password='x')
        dev._is_ssl = False
        assert dev._build_url('status.cgi') == 'http://192.0.2.1/status.cgi'

    def test_https_when_ssl_detected(self):
        dev = _StubDevice(working_password='x')
        dev._is_ssl = True
        assert dev._build_url('status.cgi') == 'https://192.0.2.1/status.cgi'

    def test_subclass_can_override_path_prefix(self):
        dev = _PrefixedDevice(management_ip='192.0.2.1')
        dev._is_ssl = True
        assert dev._build_url('user/login') == 'https://192.0.2.1/api/v1.0/user/login'
