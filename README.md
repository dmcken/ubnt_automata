# Ubiquiti Automations
Automate the interfaces of various Ubiquiti products.

## Modules / Hardware Platforms:
- AirOSv8
- AirOS (pre-v8) - Planned
- AirFiber (fetch-only - verified against a real AirFiber 60 HD, AirFiber 5X HD, and AirFiber 60 LR)
- UISP-firmware devices (Wave AP/Pro/Nano/LR, AirFiber 60 XR, EdgePower, some EdgePoint switches like the S16, ...) - fetch-only, verified against real Wave AP/Pro, AirFiber 60 XR, three EdgePower units, and an EdgePoint S16
- EdgeRouter - classic EdgeMAX/EdgeOS web UI, NOT the same API as the UISP-firmware devices above despite similar branding (fetch-only - verified against a real EdgeRouter ER-6P)
- EdgeSwitch - some models use the UISP-firmware API above (e.g. EdgePoint S16); others may still run the classic EdgeMAX UI like EdgeRouter - check which before assuming
- Camera / Door Access - Planned

## Install

See [INSTALL](INSTALL.md)


## Examples

Login and fetch config:
```python
import pprint
import ubnt_automata

dev = ubnt_automata.AirOSv8('10.0.0.1')
dev.login_http('ubnt') # Default to using 'ubnt' as the username
# full version
# dev.login_http('ubnt','ubnt')
device_config = dev.getcfg()

pprint.pprint(device_config)
```

Login and change password:
```python
import pprint
import ubnt_automata

dev = ubnt_automata.AirOSv8('10.0.0.1')
dev.login_http('old-password')
dev.change_password('new-password')
```
