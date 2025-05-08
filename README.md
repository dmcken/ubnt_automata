# Ubiquiti Automations
Automate the interfaces of various Ubiquiti products.

## Modules / Hardware Platforms:
- AirOSv8
- AirOS (pre-v8) - Planned
- AirFiber - Planned
- EdgeRouter - Planned
- EdgeSwitch - Planned
- EdgePower - Planned
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
