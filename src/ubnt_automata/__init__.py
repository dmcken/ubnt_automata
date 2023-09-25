'''Top level module of this package'''
# Classes accessible from import


# Exceptions
from . import exceptions

# Classes
from .airosv8 import AirOSv8
from .airosv6 import AirOSv6
from .utils import determine_device_type


__all__ = [
    'AirOSv6',
    'AirOSv8',
    'determine_device_type',
    'exceptions',
]
