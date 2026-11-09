'''General exceptions'''


class DeviceUnavailable(Exception):
    '''Exception to handle a device being unavailable'''
class WrongPassword(Exception):
    '''Exception to handle a wrong password'''
class UpgradeFailed(Exception):
    '''Exception to handle a firmware upgrade that failed, or didn't
    reach "finished" within the allotted wait time'''
class UnexpectedLoginResponse(Exception):
    '''Raised by login_http() for a non-200 /api/auth response that
    ISN'T a real credential rejection (401/403) - e.g. 429 (rate
    limited), 5xx, or anything else. Deliberately NOT a WrongPassword
    subclass/sibling caught by login()'s alternate-password retry loop:
    confirmed live that treating every non-200 as "wrong password" (the
    prior behavior) makes a transient problem like rate-limiting worse,
    since login() would then cascade through every password in the
    list - each one another POST - instead of surfacing the real cause
    immediately. Carries the actual status_code and response body so a
    caller (or a human reading the exception message) can tell "bad
    credentials" from "device is rate-limiting/erroring" without
    needing to read this library's source to find out.'''
    def __init__(self, status_code: int, body: str = ''):
        self.status_code = status_code
        self.body = body
        super().__init__(
            f"Unexpected non-200 response from /api/auth: "
            f"{status_code} - this is NOT necessarily a wrong "
            f"password, see UnexpectedLoginResponse's docstring "
            f"(body: {body[:200]!r})"
        )
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
