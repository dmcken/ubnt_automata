'''Top level module of this package'''
# Classes accessible from import


# Exceptions
from . import exceptions

# Classes
from .airfiber5x import AirFiber
from .airosv8 import AirOSv8
from .edgerouter import EdgeRouter
from .uisp import UispDevice
from .utils import determine_device_type, parse_ubnt_version_string

# AirOSv6 needs the 'legacy' extra (beautifulsoup4/paramiko/spur) - every
# other class here is HTTP-only via requests alone. Degrade to None
# rather than making the whole package unimportable for callers who
# don't have that extra installed and don't need this frozen/historical
# class.
try:
    from .airosv6 import AirOSv6
except ImportError:
    AirOSv6 = None

# Versions should comply with PEP 440:
# https://www.python.org/dev/peps/pep-0440/
__version__ = "0.1.0"

__all__ = [
    'AirFiber',
    'AirOSv6',
    'AirOSv8',
    'EdgeRouter',
    'UispDevice',
    'determine_device_type',
    'exceptions',
    'parse_ubnt_version_string',
]
