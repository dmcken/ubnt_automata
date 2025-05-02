'''Top level module of this package'''
# Classes accessible from import


# Exceptions
from . import exceptions

# Classes
from .airosv8 import AirOSv8
from .airosv6 import AirOSv6
from .utils import determine_device_type, parse_ubnt_version_string


# Versions should comply with PEP 440:
# https://www.python.org/dev/peps/pep-0440/
__version__ = "0.0.7"

__all__ = [
    'AirOSv6',
    'AirOSv8',
    'determine_device_type',
    'exceptions',
    'parse_ubnt_version_string',
]
