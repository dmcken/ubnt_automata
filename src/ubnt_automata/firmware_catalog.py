'''Ubiquiti's own firmware catalog (fw-update.ubnt.com) - NOT any one
device's own API. This is a public, unauthenticated REST service that
Ubiquiti's own web UIs query to check for updates - confirmed live
(HAR of a real Wave Nano's own web UI) that the UISP-firmware web UI
reaches it through its own device's tools/proxy/https relay, since a
browser can't make this cross-origin call itself. An ordinary Python
caller doesn't need a device as a relay for that - this module queries
the catalog directly instead, with no device involved in the lookup at
all. See uisp.UispDevice.start_upgrade() for actually applying a
release this returns (or any other firmware URL, for a specific/
manually-downloaded file instead of whatever this catalog calls
"latest").

Confirmed query shape (GET /api/firmware):
    ?filter=eq~~platform~~<platform>&filter=eq~~product~~<product>
    &filter=eq~~channel~~release&sort=-version&limit=4
returning {"_embedded": {"firmware": [...]}}, newest first, each entry
carrying version/file_size/md5/sha256_checksum and `_links.upload`
(name "data"/"changelog" -> download URLs).

`platform` matches a device's own public/device identification.family
exactly (e.g. "wave"). `product`, however, is an internal hardware
code (e.g. "GMC" for a Wave Nano) with no relation to the device's own
self-reported identification.product ("Wave Nano") - there's no known
API to look this code up from the device, so PRODUCT_CODES below is a
plain mapping, built up one confirmed model at a time, not derived.

IMPORTANT - download_url is NOT `_links.upload.data.href` directly:
confirmed live that href (fw-update.ui.com/api/firmware/<id>/data) is
itself just a 302 to a time-limited, presigned fw-download.svc.ui.com
URL (?Expires=<unix-ts>&Signature=...) - fine for a browser, but a bad
choice to hand to a device that might take a while to fetch a ~27MB
file over a slow/congested link, only for the signed URL to expire
mid-download. Confirmed live (HAR of a real upgrade) that the actual
web UI instead ends up using a STABLE, non-expiring URL on
fw-download.ubnt.com with the exact same path and no query string at
all, confirmed to serve the byte-identical object (same ETag/
Content-Length, no signature needed). _resolve_stable_download_url()
reproduces that: follow the redirect without downloading the body,
then substitute the stable host for the signed one. Confirmed live
for two distinct releases/products (Wave Nano/GMC/v4.1.1, GigaBeam LR/
GBE/v1.5.1) - assumed, not separately confirmed, to generalize to
every other release this catalog serves.

`platform` is also not always the device's own device-class family -
confirmed live GigaBeam LR (whose own public/device-equivalent reports
family "airmax" via AirOSv8's status.cgi, not a UispDevice at all)
uses platform "airmax" here too, so this one case happens to still
line up; not yet confirmed whether that holds for every AirOSv8-class
device or is specific to GigaBeam.
'''
from __future__ import annotations

# System imports
import dataclasses
import urllib.parse

# External imports
import requests

CATALOG_BASE_URL = 'https://fw-update.ubnt.com/api/firmware'

# Confirmed live: the catalog's own upload/data link redirects to this
# host with a presigned, expiring URL - STABLE_DOWNLOAD_HOST serves the
# identical object at the same path with no signature/expiry at all.
STABLE_DOWNLOAD_HOST = 'https://fw-download.ubnt.com'

# Device's own model name -> catalog product code. The exact source
# field varies by device class (UispDevice's identification.model;
# AirOSv8's status.cgi host.devmodel / api/auth boardinfo's
# board.model, confirmed identical values for GigaBeam LR) - there's
# no known API to look this code up from the device itself, so this
# is a plain mapping, built up one confirmed model at a time, not
# derived, and deliberately small rather than guessed at for
# unconfirmed models.
PRODUCT_CODES = {
    'Wave-Nano': 'GMC',
    'GigaBeam LR': 'GBE',
    # Not independently confirmed via its own catalog entry - inferred
    # from a real GigaBeam Plus reporting the exact same byte-for-byte
    # firmware build string as a real GigaBeam LR
    # (v1.5.1.3f54e8e6.250725.1224), implying they ship the identical
    # image and so share GBE's catalog entry.
    'GigaBeam Plus': 'GBE',
}


@dataclasses.dataclass
class FirmwareRelease:
    '''One firmware release, as reported by Ubiquiti's own catalog.'''
    version: str
    file_size: int
    md5: str
    sha256_checksum: str
    download_url: str
    changelog_url: str | None
    created: str


def _resolve_stable_download_url(upload_href: str, timeout: int) -> str:
    '''Follow the catalog's upload/data link one hop, without
    downloading the body, and substitute the stable host for whatever
    presigned/expiring one it redirects to - see the module docstring.

    Raises:
        RuntimeError: Raised if the link doesn't redirect as expected,
            or has no Location header.
    '''
    with requests.get(upload_href, timeout=timeout, allow_redirects=False, stream=True) as res:
        if res.status_code not in (301, 302, 303, 307, 308):
            raise RuntimeError(
                f"Expected a redirect resolving {upload_href}, got {res.status_code}"
            )
        location = res.headers.get('Location')
        if not location:
            raise RuntimeError(f"Redirect from {upload_href} had no Location header")

    path = urllib.parse.urlsplit(location).path
    return f'{STABLE_DOWNLOAD_HOST}{path}'


def _parse_release(entry: dict, timeout: int) -> FirmwareRelease:
    upload_links = {
        link['name']: link['href'] for link in entry.get('_links', {}).get('upload', [])
    }
    upload_href = upload_links.get('data', '')
    download_url = _resolve_stable_download_url(upload_href, timeout=timeout) if upload_href else ''
    return FirmwareRelease(
        version=entry['version'],
        file_size=entry['file_size'],
        md5=entry['md5'],
        sha256_checksum=entry['sha256_checksum'],
        download_url=download_url,
        changelog_url=upload_links.get('changelog'),
        created=entry.get('created', ''),
    )


def query_latest(
    platform: str, product: str, channel: str = 'release', limit: int = 4,
    timeout: int = 15,
) -> list[FirmwareRelease]:
    '''Query Ubiquiti's firmware catalog directly (NOT via any device).

    Args:
        platform: e.g. "wave" - matches a device's own public/device
            identification.family exactly.
        product: Catalog hardware code, e.g. "GMC" for a Wave Nano -
            see PRODUCT_CODES; this is NOT the device's own
            identification.product string.
        channel: Release channel - "release" confirmed live; other
            values untested.
        limit: Max releases to return, newest first.
        timeout: Per-HTTP-request timeout, seconds - applied to the
            catalog query itself and, separately, to each returned
            release's download-URL resolution (see
            _resolve_stable_download_url()).

    Raises:
        RuntimeError: Raised if the catalog call fails, the response
            can't be parsed, or a release's download link doesn't
            resolve the way _resolve_stable_download_url() expects.

    Returns:
        list[FirmwareRelease]: Newest-first matching releases.
    '''
    res = requests.get(
        CATALOG_BASE_URL,
        params=(
            ('filter', f'eq~~platform~~{platform}'),
            ('filter', f'eq~~product~~{product}'),
            ('filter', f'eq~~channel~~{channel}'),
            ('sort', '-version'),
            ('limit', str(limit)),
        ),
        timeout=timeout,
    )
    if res.status_code != 200:
        raise RuntimeError(f"Error querying firmware catalog: {res.status_code} {res.text}")

    try:
        entries = res.json()['_embedded']['firmware']
    except (KeyError, ValueError) as exc:
        raise RuntimeError(f"Unexpected firmware catalog response shape: {res.text[:200]}") from exc

    return [_parse_release(entry, timeout=timeout) for entry in entries]
