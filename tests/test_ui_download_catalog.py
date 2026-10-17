'''Tests for ui_download_catalog - a direct client for Ubiquiti's
public download-page catalog (download.svc.ui.com), the backend behind
ui.com/download/<family>. Like firmware_catalog, this mocks a fixed
public URL rather than a device's management IP - a DIFFERENT public
URL though, and a different response shape entirely (a flat
`downloads` list mixing firmware in with datasheets/guides, not
firmware_catalog's `_embedded.firmware`).'''
from ubnt_automata import ui_download_catalog


def _entry(**overrides):
    entry = {
        'id': 4715, 'name': 'airOS8 for XC board firmware 8.7.25', 'version': '8.7.25',
        'category': {'id': 12, 'name': 'Firmware', 'slug': 'firmware'},
        'filename': 'XC.v8.7.25.48568.260730.1009.bin',
        'file_url': 'https://ui.com/downloads/firmwares/XC-fw/v8.7.25/XC.v8.7.25.48568.260730.1009.bin',
        'date_published': '2026-08-06',
    }
    entry.update(overrides)
    return entry


class TestListFirmware:
    def test_parses_firmware_entry(self, requests_mock):
        requests_mock.get(
            ui_download_catalog.DOWNLOADS_BY_SLUG_URL.format(slug='nbe-5ac-gen2'),
            json={'product': {}, 'downloads': [_entry()]},
        )

        releases = ui_download_catalog.list_firmware('nbe-5ac-gen2')

        assert len(releases) == 1
        release = releases[0]
        assert release.version == '8.7.25'
        assert release.board == 'XC'
        assert release.filename == 'XC.v8.7.25.48568.260730.1009.bin'
        assert release.file_url == (
            'https://ui.com/downloads/firmwares/XC-fw/v8.7.25/XC.v8.7.25.48568.260730.1009.bin'
        )
        assert release.date_published == '2026-08-06'

    def test_wa_filename_prefix_is_wa_board(self, requests_mock):
        requests_mock.get(
            ui_download_catalog.DOWNLOADS_BY_SLUG_URL.format(slug='nbe-5ac-gen2'),
            json={'downloads': [_entry(filename='WA.v8.7.25.48568.260730.1010.bin')]},
        )

        release = ui_download_catalog.list_firmware('nbe-5ac-gen2')[0]

        assert release.board == 'WA'

    def test_unrecognized_filename_prefix_is_none(self, requests_mock):
        requests_mock.get(
            ui_download_catalog.DOWNLOADS_BY_SLUG_URL.format(slug='nbe-5ac-gen2'),
            json={'downloads': [_entry(filename='firmware.bin')]},
        )

        release = ui_download_catalog.list_firmware('nbe-5ac-gen2')[0]

        assert release.board is None

    def test_non_firmware_category_is_excluded(self, requests_mock):
        '''Confirmed live: most entries under a product are datasheets/
        guides, not firmware - sharing the same list.'''
        requests_mock.get(
            ui_download_catalog.DOWNLOADS_BY_SLUG_URL.format(slug='nbe-5ac-gen2'),
            json={'downloads': [
                _entry(),
                {
                    'name': 'NanoBeam® AC Gen2 Datasheet',
                    'category': {'id': 3, 'name': 'Datasheets', 'slug': 'datasheets'},
                    'filename': 'NanoBeam_AC_Gen2_DS.pdf',
                    'file_url': None,
                    'version': '',
                    'date_published': '2017-03-08',
                },
            ]},
        )

        releases = ui_download_catalog.list_firmware('nbe-5ac-gen2')

        assert len(releases) == 1
        assert releases[0].filename == 'XC.v8.7.25.48568.260730.1009.bin'

    def test_missing_file_url_is_excluded(self, requests_mock):
        '''No live evidence a firmware-category entry ever lacks
        file_url, but skip rather than hand back an unusable entry.'''
        requests_mock.get(
            ui_download_catalog.DOWNLOADS_BY_SLUG_URL.format(slug='nbe-5ac-gen2'),
            json={'downloads': [_entry(file_url=None)]},
        )

        assert ui_download_catalog.list_firmware('nbe-5ac-gen2') == []

    def test_non_200_raises_runtime_error(self, requests_mock):
        requests_mock.get(
            ui_download_catalog.DOWNLOADS_BY_SLUG_URL.format(slug='nbe-5ac-gen2'),
            status_code=500, text='error',
        )

        try:
            ui_download_catalog.list_firmware('nbe-5ac-gen2')
            raise AssertionError('expected RuntimeError')
        except RuntimeError as exc:
            assert '500' in str(exc)

    def test_unexpected_shape_raises_runtime_error(self, requests_mock):
        requests_mock.get(
            ui_download_catalog.DOWNLOADS_BY_SLUG_URL.format(slug='nbe-5ac-gen2'),
            json={'unexpected': True},
        )

        try:
            ui_download_catalog.list_firmware('nbe-5ac-gen2')
            raise AssertionError('expected RuntimeError')
        except RuntimeError:
            pass

    def test_empty_results_returns_empty_list(self, requests_mock):
        requests_mock.get(
            ui_download_catalog.DOWNLOADS_BY_SLUG_URL.format(slug='nbe-5ac-gen2'),
            json={'downloads': []},
        )

        assert ui_download_catalog.list_firmware('nbe-5ac-gen2') == []


class TestFirmwareCache:
    DOWNLOAD = ui_download_catalog.FirmwareDownload(
        name='airOS8 for XC board firmware 8.7.25', version='8.7.25', board='XC',
        filename='XC.v8.7.25.bin', file_url='https://dl.ui.com/firmwares/XC-fw/v8.7.25/XC.v8.7.25.bin',
        date_published='2026-08-06',
    )

    def test_cache_miss_fetches_and_saves(self, tmp_path, requests_mock):
        requests_mock.get(self.DOWNLOAD.file_url, content=b'fake-firmware-bytes')
        cache = ui_download_catalog.FirmwareCache(tmp_path)

        data = cache.fetch(self.DOWNLOAD)

        assert data == b'fake-firmware-bytes'
        assert (tmp_path / 'XC.v8.7.25.bin').read_bytes() == b'fake-firmware-bytes'

    def test_cache_hit_does_not_refetch(self, tmp_path, requests_mock):
        (tmp_path / 'XC.v8.7.25.bin').write_bytes(b'already-cached-bytes')
        cache = ui_download_catalog.FirmwareCache(tmp_path)

        data = cache.fetch(self.DOWNLOAD)

        assert data == b'already-cached-bytes'
        assert requests_mock.request_history == []

    def test_non_200_raises_runtime_error(self, tmp_path, requests_mock):
        requests_mock.get(self.DOWNLOAD.file_url, status_code=404)
        cache = ui_download_catalog.FirmwareCache(tmp_path)

        try:
            cache.fetch(self.DOWNLOAD)
            raise AssertionError('expected RuntimeError')
        except RuntimeError as exc:
            assert '404' in str(exc)
        assert not (tmp_path / 'XC.v8.7.25.bin').exists()

    def test_path_for_does_not_require_the_file_to_exist(self, tmp_path):
        cache = ui_download_catalog.FirmwareCache(tmp_path)

        assert cache.path_for('XC.v8.7.25.bin') == tmp_path / 'XC.v8.7.25.bin'

    def test_creates_cache_dir_if_missing(self, tmp_path):
        cache_dir = tmp_path / 'nested' / 'firmware'

        ui_download_catalog.FirmwareCache(cache_dir)

        assert cache_dir.is_dir()
