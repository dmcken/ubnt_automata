'''Tests for AirFiber - both hardware generations' status.cgi parsing
(get_link_status()), config parsing, and the capacity-unit heuristic.'''
import pytest

from ubnt_automata.airfiber5x import AirFiber


def _device_with_status(status):
    '''A real AirFiber instance with getstatus() monkeypatched to
    return a fixture payload instead of making an HTTP call - avoids
    needing to fake the whole session/auth flow just to exercise the
    pure parsing logic in get_link_status().'''
    dev = AirFiber('192.0.2.1')
    dev.getstatus = lambda: status
    return dev


class TestGetLinkStatus60GhzHd:
    '''AF60HD-style: sta['prs_sta']/remote['prs_remote'], distance on
    sta itself, capacity already in Mbps, wireless.throughput present.'''

    def test_parses_local_and_remote_ends(self, load_json):
        dev = _device_with_status(load_json('airfiber_status_60ghz.json'))
        link = dev.get_link_status()

        assert link.local.hostname == 'test-af60hd-local'
        assert link.local.device_model == 'airFiber 60 HD'
        assert link.local.signal_dbm == -50
        assert link.local.rx_mcs == 12
        assert link.local.tx_mcs == 12
        assert link.local.capacity_mbps == 924

        assert link.remote.hostname == 'test-af60hd-remote'
        assert link.remote.signal_dbm == -49
        assert link.remote.capacity_mbps == 924

        assert link.distance_m == 610
        assert link.throughput_tx_raw == 924
        assert link.throughput_rx_raw == 2156
        assert link.total_capacity_mbps == 924 + 924

    def test_gps_is_parsed_for_both_ends(self, load_json):
        dev = _device_with_status(load_json('airfiber_status_60ghz.json'))
        link = dev.get_link_status()

        assert link.local.gps.latitude == 10.1
        assert link.remote.gps.latitude == 10.111111

    def test_mode_label(self, load_json):
        dev = _device_with_status(load_json('airfiber_status_60ghz.json'))
        link = dev.get_link_status()
        assert link.local.mode_label == 'Master'
        assert link.remote.mode_label == 'Station'


class TestGetLinkStatus60GhzLr:
    '''AF60-LR variant: no top-level sta['distance'] (falls back to
    prs_sta['distance']), capacity reported in Kbps rather than Mbps,
    no GPS fix on either end.'''

    def test_distance_falls_back_to_prs_sta(self, load_json):
        dev = _device_with_status(load_json('airfiber_status_60ghz_lr.json'))
        link = dev.get_link_status()
        assert link.distance_m == 291

    def test_capacity_kbps_is_normalized_to_mbps(self, load_json):
        dev = _device_with_status(load_json('airfiber_status_60ghz_lr.json'))
        link = dev.get_link_status()
        # Raw prs_sta.capacity is 1951000 (Kbps) -> 1951 Mbps.
        assert link.local.capacity_mbps == 1951

    def test_no_gps_fix_is_none(self, load_json):
        dev = _device_with_status(load_json('airfiber_status_60ghz_lr.json'))
        link = dev.get_link_status()
        assert link.local.gps is None
        assert link.remote.gps is None


class TestGetLinkStatusAirmax:
    '''AF5XHD-style: fields directly on sta (no prs_sta wrapper),
    capacity in Kbps under sta['airmax'], throughput via
    wireless.stats.{tx,rx}_throughput rather than wireless.throughput.'''

    def test_parses_local_and_remote_ends(self, load_json):
        dev = _device_with_status(load_json('airfiber_status_airmax.json'))
        link = dev.get_link_status()

        assert link.local.signal_dbm == -55
        assert link.local.snr_db == 40
        assert link.local.rx_mcs == 4  # sta['rx_idx']
        assert link.local.tx_mcs == 3  # sta['tx_idx']
        # downlink_capacity 193280 Kbps -> 193 Mbps (integer division).
        assert link.local.capacity_mbps == 193

        # remote.tx_mcs comes from the remote object's own 'tx_mcs' field
        # (a different raw key name to sta's 'tx_idx'/'rx_idx') - verified
        # against a real capture before relying on this, since it initially
        # looked like it might be a wrong-key bug. remote.rx_mcs has no
        # equivalent raw field at all, so it's mirrored from local's own
        # tx_idx (what local transmits is what remote receives).
        assert link.remote.tx_mcs == 5
        assert link.remote.rx_mcs == 3  # == sta['tx_idx'], mirrored

    def test_throughput_falls_back_to_wireless_stats(self, load_json):
        dev = _device_with_status(load_json('airfiber_status_airmax.json'))
        link = dev.get_link_status()
        assert link.throughput_tx_raw == 193
        assert link.throughput_rx_raw == 49

    def test_signal_expected_is_averaged_across_chains(self, load_json):
        dev = _device_with_status(load_json('airfiber_status_airmax.json'))
        link = dev.get_link_status()
        # (idealpwr0 + idealpwr1) // 2 = (-50 + -52) // 2 = -51
        assert link.local.signal_expected_dbm == -51


class TestGetLinkStatusErrors:
    def test_raises_if_zero_stations(self, load_json):
        status = load_json('airfiber_status_60ghz.json')
        status['wireless']['sta'] = []
        dev = _device_with_status(status)

        with pytest.raises(RuntimeError, match='Expected exactly one PtP station'):
            dev.get_link_status()

    def test_raises_if_more_than_one_station(self, load_json):
        status = load_json('airfiber_status_60ghz.json')
        status['wireless']['sta'] = status['wireless']['sta'] * 2
        dev = _device_with_status(status)

        with pytest.raises(RuntimeError, match='Expected exactly one PtP station'):
            dev.get_link_status()


class TestNormalizeCapacityMbps:
    def test_values_already_in_mbps_pass_through(self):
        assert AirFiber._normalize_capacity_mbps(924) == 924

    def test_large_values_are_treated_as_kbps(self):
        assert AirFiber._normalize_capacity_mbps(1951000) == 1951

    def test_boundary_value_is_not_rescaled(self):
        assert AirFiber._normalize_capacity_mbps(10_000) == 10_000

    def test_just_above_boundary_is_rescaled(self):
        assert AirFiber._normalize_capacity_mbps(10_001) == 10


class TestConfigParsing:
    def test_getcfg_uses_shared_flat_kv_parser(self, requests_mock, load_text):
        dev = AirFiber('192.0.2.1')
        dev._is_ssl = False
        dev._csrf_id = 'fake-csrf-id'
        requests_mock.get('http://192.0.2.1/getcfg.cgi', text=load_text('flat_kv_config.txt'))

        cfg = dev.getcfg()

        assert cfg['radio.0.mode'] == 'ap-ptp'

    def test_get_boardinfo_parses_dev_info_captured_at_login(self, load_text):
        dev = AirFiber('192.0.2.1')
        dev._dev_info = 'board.model=AF60HD\nboard.shortname=AF60-HD\n'

        board = dev.get_boardinfo()

        assert board == {'board.model': 'AF60HD', 'board.shortname': 'AF60-HD'}

    def test_get_boardinfo_before_login_returns_empty_dict(self):
        dev = AirFiber('192.0.2.1')
        assert dev.get_boardinfo() == {}
