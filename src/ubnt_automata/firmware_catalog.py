'''Ubiquiti's own firmware catalog (fw-update.ubnt.com) - NOT any one
device's own API. This is a public, unauthenticated REST service that
Ubiquiti's own web UIs query to check for updates. Confirmed live via
three independent HARs (a real Wave Nano, GigaBeam LR, and LTU-Lite,
each applying an official release through its own web UI) that every
device family relays this query through itself rather than the
browser querying it directly - UISP-firmware devices via their own
tools/proxy/https (a browser can't make the cross-origin call itself),
AirOSv8 devices (GigaBeam, LTU) via their own dedicated api/fw/
update-check. An ordinary Python caller doesn't need a device as a
relay for any of that - this module queries the catalog directly
instead, with no device involved in the lookup at all. See
uisp.UispDevice.start_upgrade() / airosv8.AirOSv8's upgrade methods for
actually applying a release this returns (or any other firmware URL,
for a specific/manually-downloaded file instead of whatever this
catalog calls "latest").

Confirmed query shape (GET /api/firmware):
    ?filter=eq~~platform~~<platform>&filter=eq~~product~~<product>
    &filter=eq~~channel~~release&sort=-version&limit=4
returning {"_embedded": {"firmware": [...]}}, newest first, each entry
carrying version/file_size/md5/sha256_checksum and, directly under
`_links`, both `data.href` and `changelog.href` - confirmed live
(curl, all three platforms above) these are stable, non-expiring
fw-download.ubnt.com URLs, safe to hand to a device even over a slow
link. (`_links.upload` lists the same two hrefs again under a
different host, fw-update.ui.com - confirmed live those are each a 302
to a time-limited, presigned fw-download.svc.ui.com URL instead; an
earlier version of this module followed that redirect and substituted
the stable host by hand before noticing `_links.data` already gives
the same stable URL directly, with no extra request needed.)

`platform`/`product` are internal hardware codes with no reliable
relation to the device's own self-reported family/model strings, and
no known API to look them up from the device itself - confirmed
"wave"/"GMC" for a Wave Nano, "airmax"/"GBE" for GigaBeam LR/Plus
(sharing one image - see CATALOG_IDENTITY), and "airfiber"/"AFLTU" for
LTU-Lite. That LTU case also confirmed (via its own changelog text,
"LTU PTMP FW support for: LTU-Rocket, LTU-Lite, LTU-Pro, LTU-LR,
LTU-XR, LTU-Instant") that every LTU PTMP model shares the same
"AFLTU" image too - CATALOG_IDENTITY maps the ones actually seen live
in this fleet; the rest are a reasonable inference from that changelog
line, not separately confirmed.
'''
from __future__ import annotations

# System imports
import dataclasses

# External imports
import requests

CATALOG_BASE_URL = 'https://fw-update.ubnt.com/api/firmware'

# Device's own model name -> (catalog platform, catalog product). The
# exact source field for "model" varies by device class (UispDevice's
# identification.model; AirOSv8's status.cgi host.devmodel / api/auth
# boardinfo's board.model, confirmed identical values for GigaBeam LR)
# - there's no known API to derive either catalog value from the
# device itself, so this is a plain mapping, built up one confirmed
# model at a time, deliberately small rather than guessed at for
# unconfirmed models.
CATALOG_IDENTITY = {
    'Wave-Nano': ('wave', 'GMC'),
    'GigaBeam LR': ('airmax', 'GBE'),
    # Not independently confirmed via its own catalog entry - inferred
    # from a real GigaBeam Plus reporting the exact same byte-for-byte
    # firmware build string as a real GigaBeam LR
    # (v1.5.1.3f54e8e6.250725.1224), implying they ship the identical
    # image and so share GBE's catalog entry.
    'GigaBeam Plus': ('airmax', 'GBE'),
    'LTU-Lite': ('airfiber', 'AFLTU'),
    # Not independently confirmed - inferred from LTU-Lite's own
    # changelog text listing all of these as sharing one firmware line
    # (see module docstring).
    'LTU-LR': ('airfiber', 'AFLTU'),
    'LTU-Rocket': ('airfiber', 'AFLTU'),
    'LTU-Pro': ('airfiber', 'AFLTU'),
    'LTU-XR': ('airfiber', 'AFLTU'),
    'LTU-Instant': ('airfiber', 'AFLTU'),
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


def _parse_release(entry: dict) -> FirmwareRelease:
    links = entry.get('_links', {})
    return FirmwareRelease(
        version=entry['version'],
        file_size=entry['file_size'],
        md5=entry['md5'],
        sha256_checksum=entry['sha256_checksum'],
        download_url=links.get('data', {}).get('href', ''),
        changelog_url=links.get('changelog', {}).get('href'),
        created=entry.get('created', ''),
    )


def query_latest(
    platform: str, product: str, channel: str = 'release', limit: int = 4,
    timeout: int = 15,
) -> list[FirmwareRelease]:
    '''Query Ubiquiti's firmware catalog directly (NOT via any device).

    Args:
        platform: Catalog hardware-family code, e.g. "wave" - see
            CATALOG_IDENTITY; not reliably derivable from the device's
            own self-reported family/model.
        product: Catalog hardware code, e.g. "GMC" for a Wave Nano -
            see CATALOG_IDENTITY; also not reliably derivable from the
            device's own self-reported family/model.
        channel: Release channel - "release" confirmed live; other
            values untested.
        limit: Max releases to return, newest first.
        timeout: HTTP request timeout, seconds.

    Raises:
        RuntimeError: Raised if the catalog call fails or the
            response can't be parsed.

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

    return [_parse_release(entry) for entry in entries]
