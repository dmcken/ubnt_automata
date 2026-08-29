'''Tests for UispDevice - the UISP-firmware JSON REST API family
(Wave/AirFiber-XR/EdgePower/newer EdgePoint switches). Covers login's
Origin/Referer header requirement, the GET-not-POST discovery choice,
and get_status()'s statistics/peer parsing.'''
from ubnt_automata import exceptions
from ubnt_automata.uisp import UispDevice


class TestBuildUrl:
    def test_uses_api_v1_prefix(self):
        dev = UispDevice('192.0.2.1')
        dev._is_ssl = True
        assert dev._build_url('user/login') == 'https://192.0.2.1/api/v1.0/user/login'


class TestOriginHeaders:
    def test_matches_the_devices_own_base_url(self):
        dev = UispDevice('192.0.2.1')
        dev._is_ssl = True
        headers = dev._origin_headers()
        assert headers == {'Origin': 'https://192.0.2.1', 'Referer': 'https://192.0.2.1/'}


class TestLoginHttp:
    def test_success_stores_auth_token_and_sends_origin_headers(self, requests_mock):
        requests_mock.post(
            'https://192.0.2.1/api/v1.0/user/login',
            json={'status': 'ok'},
            headers={'x-auth-token': 'fake-token-abc'},
        )
        dev = UispDevice('192.0.2.1')
        dev._is_ssl = True

        dev.login_http('fake-password', 'ubnt')

        assert dev._auth_token == 'fake-token-abc'
        sent = requests_mock.request_history[0]
        assert sent.headers['Origin'] == 'https://192.0.2.1'
        assert sent.headers['Referer'] == 'https://192.0.2.1/'

    def test_403_without_origin_header_is_reported_as_wrong_password(self, requests_mock):
        '''This is the exact failure mode that was originally
        misdiagnosed as a brute-force lockout - a bare 403 with no JSON
        body, from a device that actually just needed the Origin/
        Referer headers this code now always sends. This test locks in
        that those headers get sent (see test above); this one just
        confirms a genuine auth failure still surfaces as
        WrongPassword rather than crashing on the non-JSON body.'''
        requests_mock.post(
            'https://192.0.2.1/api/v1.0/user/login',
            status_code=403,
            text='<html>Forbidden</html>',
        )
        dev = UispDevice('192.0.2.1')
        dev._is_ssl = True

        try:
            dev.login_http('wrong-password', 'ubnt')
            raise AssertionError('expected WrongPassword')
        except exceptions.WrongPassword:
            pass

    def test_password_never_appears_in_logs(self, requests_mock, caplog):
        requests_mock.post('https://192.0.2.1/api/v1.0/user/login', status_code=403, text='no')
        dev = UispDevice('192.0.2.1')
        dev._is_ssl = True

        with caplog.at_level('DEBUG'):
            try:
                dev.login_http('super-secret-password', 'ubnt')
            except exceptions.WrongPassword:
                pass

        assert 'super-secret-password' not in caplog.text


class TestGetDiscovery:
    def test_uses_get_not_post(self, requests_mock):
        '''An EdgePoint S16 on older firmware rejects POST here (400)
        while GET works everywhere tested - confirmed the method
        actually sent matches that choice.'''
        requests_mock.get(
            'https://192.0.2.1/api/v1.0/tools/discovery/neighbors',
            json=[{'hostname': 'neighbor-1'}],
        )
        dev = UispDevice('192.0.2.1')
        dev._is_ssl = True
        dev._auth_token = 'fake-token'

        result = dev.get_discovery()

        assert result == [{'hostname': 'neighbor-1'}]
        assert requests_mock.request_history[0].method == 'GET'

    def test_non_200_raises_runtime_error(self, requests_mock):
        requests_mock.get(
            'https://192.0.2.1/api/v1.0/tools/discovery/neighbors',
            status_code=400,
            json={'message': 'Request is not supported'},
        )
        dev = UispDevice('192.0.2.1')
        dev._is_ssl = True
        dev._auth_token = 'fake-token'

        try:
            dev.get_discovery()
            raise AssertionError('expected RuntimeError')
        except RuntimeError as exc:
            assert '400' in str(exc)


class TestGetPublicDevice:
    def test_pre_auth_no_token_needed(self, requests_mock):
        requests_mock.get(
            'https://192.0.2.1/api/v1.0/public/device',
            json={'product': 'Wave AP', 'model': 'Wave-AP', 'family': 'wave'},
        )
        dev = UispDevice('192.0.2.1')
        dev._is_ssl = True

        result = dev.get_public_device()

        assert result['product'] == 'Wave AP'

    def test_older_edgepoint_firmware_401_raises(self, requests_mock):
        requests_mock.get(
            'https://192.0.2.1/api/v1.0/public/device',
            status_code=401,
            text='Unauthorized',
        )
        dev = UispDevice('192.0.2.1')
        dev._is_ssl = True

        try:
            dev.get_public_device()
            raise AssertionError('expected RuntimeError')
        except RuntimeError as exc:
            assert '401' in str(exc)


class TestGetInterfaces:
    def test_returns_identification_status_and_addresses(self, requests_mock, load_json):
        requests_mock.get(
            'https://192.0.2.1/api/v1.0/interfaces',
            json=load_json('uisp_interfaces.json'),
        )
        dev = UispDevice('192.0.2.1')
        dev._is_ssl = True
        dev._auth_token = 'fake-token'

        result = dev.get_interfaces()

        assert len(result) == 2
        eth1 = next(i for i in result if i['identification']['id'] == 'eth1')
        assert eth1['identification']['mac'] == 'aa:bb:cc:dd:ee:01'
        assert eth1['status']['mtu'] == 1500
        static_v4 = next(a for a in eth1['addresses'] if a['type'] == 'static')
        assert static_v4['cidr'] == '192.0.2.10/24'

    def test_non_200_raises_runtime_error(self, requests_mock):
        requests_mock.get(
            'https://192.0.2.1/api/v1.0/interfaces',
            status_code=500,
            text='error',
        )
        dev = UispDevice('192.0.2.1')
        dev._is_ssl = True
        dev._auth_token = 'fake-token'

        try:
            dev.get_interfaces()
            raise AssertionError('expected RuntimeError')
        except RuntimeError as exc:
            assert '500' in str(exc)


class TestGetMacTable:
    def test_returns_parsed_entries(self, requests_mock):
        requests_mock.get(
            'https://192.0.2.1/api/v1.0/tools/mac-table',
            json=[{'mac': 'aa:bb:cc:dd:ee:ff', 'address': '192.0.2.50'}],
        )
        dev = UispDevice('192.0.2.1')
        dev._is_ssl = True
        dev._auth_token = 'fake-token'

        result = dev.get_mac_table()

        assert result == [{'mac': 'aa:bb:cc:dd:ee:ff', 'address': '192.0.2.50'}]


class TestCompose:
    def test_returns_body_per_successful_sub_request(self, requests_mock):
        requests_mock.post(
            'https://192.0.2.1/api/v1.0/tools/compose',
            json={'responses': [
                {'entity': '/system', 'body': {'hostname': 'test'}, 'statusCode': 200},
                {'entity': '/services', 'body': {'snmpAgent': {}}, 'statusCode': 500},
            ]},
        )
        dev = UispDevice('192.0.2.1')
        dev._is_ssl = True
        dev._auth_token = 'fake-token'

        result = dev.compose(['/system', '/services'])

        # The failed sub-request (500) is logged and omitted, not raised.
        assert result == {'/system': {'hostname': 'test'}}

    def test_overall_failure_raises(self, requests_mock):
        requests_mock.post(
            'https://192.0.2.1/api/v1.0/tools/compose',
            status_code=500,
            text='error',
        )
        dev = UispDevice('192.0.2.1')
        dev._is_ssl = True
        dev._auth_token = 'fake-token'

        try:
            dev.compose(['/system'])
            raise AssertionError('expected RuntimeError')
        except RuntimeError:
            pass


class TestGetStatus:
    '''Pure parsing coverage via monkeypatched getstatistics()/compose()
    - avoids faking the whole HTTP/auth flow just to test statistics
    parsing.'''

    def _device_with_stats(self, stats_body, hostname='test-device'):
        dev = UispDevice('192.0.2.1')
        dev.getstatistics = lambda: (stats_body[0] if stats_body else {})
        dev.compose = lambda routes: {'/system': {'hostname': hostname}}
        return dev

    def test_parses_device_and_peer_fields(self, load_json):
        stats = load_json('uisp_statistics_wireless.json')
        dev = self._device_with_stats(stats)

        status = dev.get_status()

        assert status.hostname == 'test-device'
        assert status.uptime_seconds == 654321
        assert status.cpu_load_pct == 15.0  # average of [10, 20]
        assert status.memory_used_pct == 35
        assert status.gps.latitude == 50.111111

        assert len(status.peers) == 1
        peer = status.peers[0]
        assert peer.hostname == 'test-peer-1'
        assert peer.product == 'Wave Pro'
        assert peer.mac == 'aa:bb:cc:dd:ee:01'
        assert peer.distance_m == 5000
        assert peer.gps.latitude == 50.333333

    def test_uses_the_connected_local_link_not_list_order(self, load_json):
        '''The fixture's first 'local' entry is NOT connected and has
        different signal/mcs/linkscore values than the second (which
        is connected) - proves the code matches by the 'connected' flag
        rather than assuming index 0.'''
        stats = load_json('uisp_statistics_wireless.json')
        dev = self._device_with_stats(stats)

        peer = dev.get_status().peers[0]

        assert peer.signal_dbm == -60
        assert peer.tx_mcs_idx == 9
        assert peer.rx_mcs_idx == 9
        assert peer.linkscore_dl == 95.5

    def test_zero_cpu_cores_does_not_divide_by_zero(self, load_json):
        stats = load_json('uisp_statistics_wireless.json')
        stats[0]['device']['cpu'] = []
        dev = self._device_with_stats(stats)

        status = dev.get_status()

        assert status.cpu_load_pct == 0.0


class TestGetGps:
    def test_returns_the_devices_own_gps(self, load_json):
        stats = load_json('uisp_statistics_wireless.json')
        dev = UispDevice('192.0.2.1')
        dev.getstatistics = lambda: stats[0]

        gps = dev.get_gps()

        assert gps.latitude == 50.111111
        assert gps.fix == 1

    def test_no_fix_returns_none(self, load_json):
        stats = load_json('uisp_statistics_power.json')  # gps: null
        dev = UispDevice('192.0.2.1')
        dev.getstatistics = lambda: stats[0]

        assert dev.get_gps() is None
