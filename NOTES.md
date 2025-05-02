


## Ubnt v6 upgrade process

```
wget -O /tmp/fwupdate.bin http://<sw host>/ubnt/XM.bin
or
wget -O /tmp/fwupdate.bin http://<sw host>/ubnt/XW.bin

ubntbox fwupdate.real -m /tmp/fwupdate.bin


Successful:
    XW.v5.6.9# ubntbox fwupdate.real -m /tmp/fwupdate.bin
    Current ver: 329225
    New version: 393216
    No need to fix.
    Writing 'kernel         ' to /dev/mtd2(kernel         ) ...  [%100]
    Writing 'rootfs         ' to /dev/mtd3(rootfs         ) ...  [%100]
    Done

Errors:
    XW.v5.6.9# ubntbox fwupdate.real -m /tmp/fwupdate.bin
    Invalid version 'XM.ar7240.v6.0.30097.161219.1716'
```

```
# logger.debug("FW Data: {0}".format(pprint.pformat(fw_data)))

# Determine current version "ubntbox status"
# ubntbox_status_text = self._ssh_conn.run(['ubntbox', 'status'])
# ubntbox_status_data = json.loads(ubntbox_status_text.output)

# device_version = self.parse_version_string(
#     ubntbox_status_data['firmware']['version']
# )
# logger.debug('Device current version: {0}{1}'.format(
#     device_version['arch'], device_version['version']
# ))

# # Right before we begin the upgrade process we need to standardize a couple of parameters.

# # fetch the appropriate firmware
# if device_version['version'] in fw_data[device_version['arch']]\
#     # Temp override due to elevate issues.
#     or device_version['version'] in ['v6.0.6', 'v6.0.7', 'v6.1.0', 'v6.1.3']:
#     # Device is running an acceptable version
#     logger.info("Version '{0}' is acceptable, no upgrade required.".format(
#       device_version['version']
#     ))
#     return device_version['version']

# upgrade_version = list(fw_data[device_version['arch']].keys())[0]

# logger.debug("Upgrading to '{0}' from '{1}'".format(
#   upgrade_version, device_version['version']
# ))
# fetch_params = ['wget', '-O', '/tmp/fwupdate.bin',
#                 # '--timeout=120',
#                 'http://<sw host>/ubnt/{0}'.format(
#                     fw_data[device_version['arch']][upgrade_version]['filename']
#               )]
# # logger.debug("Fetch: {0}".format(fetch_params))
# _ = self._ssh_conn.run(fetch_params)

# # Apply the firmware
# logger.debug('Applying firmware')
# _ = self._ssh_conn.spawn(['ubntbox', 'fwupdate.real', '-m', '/tmp/fwupdate.bin'])

# # Seems we can't wait for the connection reset from the spur / paramiko library.
# # Instead what I'm doing is spawining the command to burn in the new firmware
# # (sometimes this seems to take quite some time) and then wait for the reboot.
# # A burn in seems to take anywhere between 10-45 seconds, the reboot seems to
# # take about a minute or two. This number is mostly from a small sampling of
# # test cases with some extra padding to hopefully deal with weird shit.
# # The UBNT wait time from the GUI seems to be 150 seconds.
# # Longer term solution would be to allow a per command override of the timeout
# # value of spur / paramiko (spur doesn't specify and paramiko's default is 1 hour).

# # Wait 4 minutes for reboot
# time_to_wait = 180
# logger.debug("Starting to sleep for {0}".format(time_to_wait))
# time.sleep(time_to_wait)
# # Foce the old connection to close.
# self._ssh_conn.__exit__()

# # Re-connect to device
# logger.debug("Attempting to re-connect")
# self.login_ssh()

# # confirm upgrade is completed.
# ubntbox_status_text = self._ssh_conn.run(['ubntbox', 'status'])
# ubntbox_status_data = json.loads(ubntbox_status_text.output)

# device_new_version = self.parse_version_string(ubntbox_status_data['firmware']['version'])

# if device_new_version['version'] == upgrade_version:
#     logger.debug("Upgrade successful to '{0}'".format(upgrade_version))
#     return upgrade_version
# else:
#     raise RuntimeError("Device was upgraded from '{0}' to '{1}' ended up at version '{2}'".\
#         format(device_version['version'], upgrade_version, device_new_version['version']))
```