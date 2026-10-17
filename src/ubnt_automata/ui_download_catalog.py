'''Ubiquiti's public download-page catalog (download.svc.ui.com) - a
THIRD, independent catalog backend, separate from both firmware_catalog
(fw-update.ubnt.com) and a device's own check_firmware_update() (api/
fw/update-check). This is what https://ui.com/download/<family> itself
queries client-side - confirmed live via a captured HAR of a real
browser session on https://ui.com/download/airmax-ac (NanoBeam 5AC
Gen2), then independently confirmed again with a direct curl from the
jump host: no cookie, no session, no CSRF wall (unlike community.ui.com,
which sits behind an Apollo GraphQL endpoint that rejected an
unauthenticated query outright).

Confirmed query shape (GET /v1/downloads/products/slugs/<slug>, no
auth) returning {"product": {...}, "downloads": [...]} - `downloads` is
EVERY download Ubiquiti publishes for that product (datasheets, user
guides, quick-start guides - not just firmware), each entry carrying a
`category` block ({"id", "name", "slug"} - this module only keeps
category.slug == "firmware") and a `file_url` pointing directly at the
real binary. Confirmed live that `file_url` 301s once (ui.com ->
dl.ui.com, the successor to the legacy dl.ubnt.com host) before landing
on a plain, unauthenticated S3/CloudFront object - requests' default
redirect-following handles that with no special-casing needed.
Confirmed live (NBE-5AC-Gen2, 63 firmware entries spanning v8.1.4 to
v8.7.25) that entries come back newest-`date_published`-first; also
confirmed live that `version` is occasionally blank on an entry whose
`name`/`filename` clearly carry one anyway (a real "airOS8 for WA board
firmware v8.5.4" entry) - don't rely on `version` alone to pick a
specific release out of a list.

This is the ONE source confirmed to explicitly label which board
revision a given firmware entry is for - unlike firmware_catalog (one
entry per platform/product code, no board distinction at all) and
unlike a device's own check_firmware_update() (correctly resolves its
OWN board, but only tells you about the one device you asked), this
catalog lists BOTH "airOS8 for WA board firmware X" and "airOS8 for XC
board firmware X" side by side for the same product and version -
confirmed live (NBE-5AC-Gen2, v8.7.25) these are two genuinely
different binaries (different build numbers, different byte content),
not the same image under two names.

CONFIRMED LIMITATION: no entry here carries a checksum of any kind -
every field was inventoried from a real response and there is nothing
resembling md5/sha256. Treat every file_url/bytes from this module as
UNVERIFIED until checked against a specific device's own
check_firmware_update().checksum - airosv8.AirOSv8.upload_and_upgrade()
does exactly that for whatever firmware_data it's given, regardless of
whether it came from here, so routing a FirmwareCache hit through it
(rather than calling upload_firmware() directly) gets this check for
free.

`slug` is the product's own URL slug (e.g. "nbe-5ac-gen2" for
https://ui.com/download/software/nbe-5ac-gen2) - GET /v1/products (also
unauthenticated, unconfirmed live beyond a bare 200/JSON check) lists
every product Ubiquiti publishes downloads for, each with its own
`slug`, if a model's isn't already known.
'''
from __future__ import annotations

# System imports
import dataclasses
import pathlib

# External imports
import requests

PRODUCTS_URL = 'https://download.svc.ui.com/v1/products'
DOWNLOADS_BY_SLUG_URL = 'https://download.svc.ui.com/v1/downloads/products/slugs/{slug}'


@dataclasses.dataclass
class FirmwareDownload:
    '''One firmware entry from a product's download-page catalog - see
    the module docstring for what's confirmed and what isn't.'''
    name: str
    version: str
    board: str | None
    filename: str
    file_url: str
    date_published: str


def list_firmware(slug: str, timeout: int = 30) -> list[FirmwareDownload]:
    '''Query a product's download-page catalog directly (NOT via
    ui.com/download/<slug> itself, and NOT via any device).

    Args:
        slug: The product's own URL slug, e.g. "nbe-5ac-gen2" - see
            the module docstring for where this comes from.
        timeout: HTTP request timeout, seconds.

    Raises:
        RuntimeError: Raised if the query fails or the response can't
            be parsed.

    Returns:
        list[FirmwareDownload]: Every entry under this product whose
            category is "firmware" - datasheets/guides/etc excluded.
            Confirmed live newest-date_published-first; not otherwise
            filtered, so callers wanting one specific release match on
            filename/date_published themselves (see the module
            docstring for why `version` alone isn't reliable enough).
    '''
    res = requests.get(DOWNLOADS_BY_SLUG_URL.format(slug=slug), timeout=timeout)
    if res.status_code != 200:
        raise RuntimeError(
            f"Error querying download catalog for {slug!r}: {res.status_code} {res.text}"
        )

    try:
        entries = res.json()['downloads']
    except (KeyError, ValueError) as exc:
        raise RuntimeError(f"Unexpected download catalog response shape: {res.text[:200]}") from exc

    releases = []
    for entry in entries:
        if entry.get('category', {}).get('slug') != 'firmware':
            continue
        if not entry.get('file_url'):
            continue
        filename = entry.get('filename', '')
        if filename.startswith('WA.'):
            board = 'WA'
        elif filename.startswith('XC.'):
            board = 'XC'
        else:
            board = None
        releases.append(FirmwareDownload(
            name=entry.get('name', ''),
            version=entry.get('version', ''),
            board=board,
            filename=filename,
            file_url=entry['file_url'],
            date_published=entry.get('date_published', ''),
        ))
    return releases


class FirmwareCache:
    '''Disk-backed cache of firmware bytes, keyed by filename - built
    for a bulk upgrade run across many devices of the same board
    revision, where fetching the same ~10MB image once per device (as
    airosv8.AirOSv8.upload_and_upgrade() does by default) is needlessly
    slow at fleet scale. Persists to disk, not just this process's
    memory, so a batch that's stopped and resumed later - or a second,
    separate run - doesn't refetch what's already local.

    Makes no integrity claim of its own, cached or freshly fetched -
    see fetch()'s docstring.
    '''

    def __init__(self, cache_dir: str | pathlib.Path) -> None:
        self._dir = pathlib.Path(cache_dir)
        self._dir.mkdir(parents=True, exist_ok=True)

    def path_for(self, filename: str) -> pathlib.Path:
        '''Where `filename` would be (or already is) cached.'''
        return self._dir / filename

    def fetch(self, download: FirmwareDownload, timeout: int = 120) -> bytes:
        '''Return this entry's bytes, from disk if already cached
        here, otherwise fetching and saving it first.

        Makes no integrity claim of its own, cached or freshly fetched
        - airosv8.AirOSv8.upload_and_upgrade()'s firmware_data
        parameter checks whatever bytes it's given against a specific
        device's own check_firmware_update().checksum regardless of
        where they came from; that check, not this one, is what's
        confirmed live to matter. Run it yourself if calling
        upload_firmware() directly instead.

        Args:
            download: Which entry to fetch - see list_firmware().
            timeout: HTTP request timeout, seconds, for a cache miss.

        Raises:
            RuntimeError: Raised if a cache miss's fetch fails.

        Returns:
            bytes: The firmware image's raw bytes.
        '''
        path = self.path_for(download.filename)
        if path.exists():
            return path.read_bytes()

        res = requests.get(download.file_url, timeout=timeout)
        if res.status_code != 200:
            raise RuntimeError(
                f"Error fetching firmware from {download.file_url}: {res.status_code}"
            )

        path.write_bytes(res.content)
        return res.content
