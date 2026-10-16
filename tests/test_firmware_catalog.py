'''Tests for firmware_catalog - a direct client for Ubiquiti's public
firmware catalog (fw-update.ubnt.com). Not any device's own API, so
unlike every other test module here, these mock a fixed public URL
rather than a device's management IP.'''
from ubnt_automata import firmware_catalog


class TestQueryLatest:
    def test_parses_embedded_firmware_list(self, requests_mock):
        requests_mock.get(
            firmware_catalog.CATALOG_BASE_URL,
            json={'_embedded': {'firmware': [
                {
                    'version': 'v4.1.1', 'file_size': 27333691,
                    'md5': 'fake-md5', 'sha256_checksum': 'fake-sha256',
                    'created': '2026-05-28T13:08:23Z',
                    '_links': {
                        'data': {'href': 'https://fw-download.ubnt.com/data/GMC/fake.bin'},
                        'changelog': {'href': 'https://fw-download.ubnt.com/changelog/GMC/fake'},
                    },
                },
            ]}},
        )

        releases = firmware_catalog.query_latest(platform='wave', product='GMC')

        assert len(releases) == 1
        release = releases[0]
        assert release.version == 'v4.1.1'
        assert release.file_size == 27333691
        assert release.download_url == 'https://fw-download.ubnt.com/data/GMC/fake.bin'
        assert release.changelog_url == 'https://fw-download.ubnt.com/changelog/GMC/fake'

    def test_missing_changelog_link_is_none(self, requests_mock):
        '''Not every catalog entry is confirmed to carry a changelog
        link - download_url is the one this library actually acts on
        (start_upgrade()'s url), so that's required in all the tests
        above; changelog_url degrades to None instead of KeyError.'''
        requests_mock.get(
            firmware_catalog.CATALOG_BASE_URL,
            json={'_embedded': {'firmware': [
                {
                    'version': 'v4.1.1', 'file_size': 1, 'md5': 'x', 'sha256_checksum': 'y',
                    'created': '2026-05-28T13:08:23Z',
                    '_links': {'data': {'href': 'https://fw-download.ubnt.com/data/GMC/fake.bin'}},
                },
            ]}},
        )

        release = firmware_catalog.query_latest(platform='wave', product='GMC')[0]

        assert release.changelog_url is None

    def test_missing_data_link_defaults_to_empty_string(self, requests_mock):
        '''No live evidence this ever happens, but fail soft rather
        than KeyError if a future catalog entry omits it.'''
        requests_mock.get(
            firmware_catalog.CATALOG_BASE_URL,
            json={'_embedded': {'firmware': [
                {
                    'version': 'v4.1.1', 'file_size': 1, 'md5': 'x', 'sha256_checksum': 'y',
                    'created': '2026-05-28T13:08:23Z', '_links': {},
                },
            ]}},
        )

        release = firmware_catalog.query_latest(platform='wave', product='GMC')[0]

        assert release.download_url == ''

    def test_sends_platform_product_and_channel_filters(self, requests_mock):
        requests_mock.get(firmware_catalog.CATALOG_BASE_URL, json={'_embedded': {'firmware': []}})

        firmware_catalog.query_latest(platform='wave', product='GMC', channel='release', limit=4)

        sent_url = requests_mock.request_history[0].url.lower()
        assert 'eq~~platform~~wave' in sent_url
        assert 'eq~~product~~gmc' in sent_url
        assert 'eq~~channel~~release' in sent_url
        assert 'sort=-version' in sent_url
        assert 'limit=4' in sent_url

    def test_non_200_raises_runtime_error(self, requests_mock):
        requests_mock.get(firmware_catalog.CATALOG_BASE_URL, status_code=500, text='error')

        try:
            firmware_catalog.query_latest(platform='wave', product='GMC')
            raise AssertionError('expected RuntimeError')
        except RuntimeError as exc:
            assert '500' in str(exc)

    def test_unexpected_shape_raises_runtime_error(self, requests_mock):
        requests_mock.get(firmware_catalog.CATALOG_BASE_URL, json={'unexpected': True})

        try:
            firmware_catalog.query_latest(platform='wave', product='GMC')
            raise AssertionError('expected RuntimeError')
        except RuntimeError:
            pass

    def test_empty_results_returns_empty_list(self, requests_mock):
        requests_mock.get(firmware_catalog.CATALOG_BASE_URL, json={'_embedded': {'firmware': []}})

        assert firmware_catalog.query_latest(platform='wave', product='GMC') == []
