'''General exceptions'''


class DeviceUnavailable(Exception):
    '''Exception to handle a device being unavailable'''
class WrongPassword(Exception):
    '''Exception to handle a wrong password'''
class UpgradeFailed(Exception):
    '''Exception to handle a firmware upgrade that failed, or didn't
    reach "finished" within the allotted wait time'''
class FastRestartRequired(Exception):
    '''Raised by writecfg() when avoid_fast_restart=True and the
    config being written contains a key already known (see
    _KNOWN_FAST_RESTART_KEYS in airoscommon.py) to make the device
    set fast_restart=true in its writecfg.cgi response.

    This is NOT a power-cycle reboot - confirmed live (HAR capture,
    AirFiber 5X HD, enabling ame.net.jumbo): the device's management
    UI starts returning errors/404s for ~15-20s immediately after the
    write while networking restarts, then recovers on its own. But
    that is still a real wireless link drop on a live backhaul, which
    is exactly what this exception lets a caller avoid opting into
    unknowingly.'''
