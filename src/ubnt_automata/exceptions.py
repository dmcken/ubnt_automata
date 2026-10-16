'''General exceptions'''


class DeviceUnavailable(Exception):
    '''Exception to handle a device being unavailable'''
class WrongPassword(Exception):
    '''Exception to handle a wrong password'''
class UpgradeFailed(Exception):
    '''Exception to handle a firmware upgrade that failed, or didn't
    reach "finished" within the allotted wait time'''
