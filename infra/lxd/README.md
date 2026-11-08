# LXD host: USB camera re-pass (Issue #301 item 1)

For the LXD VM environment (`server/docs/REMOTE_LIVE_VIEW_SETUP.md`, D2) only.
These files are installed **on the LXD host** by the Owner, as root. They are
not part of the ServerSentinel release, ServerSentinel never runs them, and
neither ServerSentinel nor `media-capture-agent` gets root, a capability or
LXD access for them.

## What it does

LXD 5.21 does not pass a camera that the host re-enumerated (`USB disconnect`
and reconnect, even within a second and without anyone touching it) back to
the running VM. QEMU keeps the old, deleted `/dev/bus/usb` node open and the
guest keeps a device that delivers nothing, so the source stays `offline`
(observed 2026-10-19; on 2026-11-08 a read-only check found both passed
cameras in that state after host re-enumerations on 2026-11-06 and
2026-11-08).

`usb_repass.py` (Python standard library only) checks, for each LXD `usb`
device named in its configuration:

| Check | Result |
| --- | --- |
| the instance's own device has `vendorid`, `productid` and `serial`, and no `busnum` / `devnum` | otherwise `unidentified`: never touched (identical non-serial cameras are not rebound automatically; a device pinned to a bus or device number would be re-added with numbers of an enumeration that is gone) |
| no other configured device names the same camera | otherwise both are `ambiguous`: neither is touched |
| exactly one host USB device has those three values, unchanged across two samples 2 s apart after a 5 s settle | none: `absent`; more than one: `ambiguous`; changed: `unsettled`; nothing is done |
| the VM's QEMU process holds that device's current node open | `held`: nothing is done |
| otherwise | `needs_repass`: the device is removed and added again with exactly the same configuration, as the documented recovery does by hand |

It decides from host facts only (LXD's instance configuration and state over
its unix socket, sysfs, `/proc/<qemu pid>/fd`), never from `/dev/videoN`, and
never trusts anything from the guest. It judges nothing while the VM is not
running or its QEMU process is younger than 120 s.

The remove and the add are two `PUT /1.0/instances/<vm>` requests with the
instance's ETag on the LXD unix socket (what `lxc config device remove` /
`add` send), each sent only while the device is still exactly as judged
(remove) or absent (add); an Owner edit in between is left as it is
(`usb_repass_changed`). A failed or unanswered request is decided by reading
the device again, so a remove that did happen is always followed by its add,
and an add that did happen is not repeated. Before the remove the device's
configuration is written to `/var/lib/server-sentinel-usb-repass/state.json`
(root-only, fsynced with its directory), so a run that dies between the two
restores the device on its next run, also while the VM is stopped
(`usb_repass_restored`). A state file that cannot be read refuses every run
(`usb_repass_state_unreadable`) and is kept as it is: it may hold the only
copy of a removed device's configuration (restore it by hand, then move the
file away). Each device is re-passed at most once per 60 s and five times per
rolling hour (`usb_repass_rate_limited`), so a camera that keeps
re-enumerating cannot make it loop. All cameras found not passed are
re-passed in one pass and verified together afterwards (the two C960 reset
each other), each counted once.

A run ends within 900 s (`RUN_LIMIT_SECONDS`; the unit's `TimeoutStartSec=960`
adds 60 s for the interpreter start). Each LXD request has a 30 s timeout and
an operation is polled for up to 60 s, so a remove takes at most 180 s and an
add (three attempts, each read first, and a final read) at most 574 s. A
remove starts only while that remove, its add and the final verification
(20 s) still fit (`usb_repass_deferred` otherwise; the timer runs again within
about two minutes), so a run is never cut between a remove and its add.

Triggers: `90-server-sentinel-usb-repass.rules` starts
`server-sentinel-usb-repass.service` on every USB device add (the service
ignores devices it is not configured for), and
`server-sentinel-usb-repass.timer` runs it 3 minutes after boot and every
2 minutes after the last run, for a missed event.

Journal lines (`journalctl -u server-sentinel-usb-repass.service`) are fixed
words plus the configured device label, for example
`usb_repass_done device=cam1`; no serial, vendor/product id, bus or device
number is printed. The service fails (`systemctl --failed`) when a remove,
add or restore failed, or a re-passed camera was not held by QEMU afterwards
(`usb_repass_unverified`).

What it does not do:

- It does not tell the Owner. ServerSentinel's own `camera_offline`
  notification and dashboard notice (`REMOTE_LIVE_VIEW_SETUP.md`) stay the
  signal and work as before; a re-pass may end the outage before
  `after_seconds`, and then there is nothing to notify.
- It cannot recover a camera the host itself lost (unplugged, failed, or
  still enumerating): that stays `absent`.
- It does not pass a camera by vendor/product only, by bus or device number,
  or one whose LXD device lacks `serial` or pins `busnum` / `devnum`.
- The source returns to `online` only when ServerSentinel's own UVC identity
  check rebinds the serial-identified camera; an ambiguous reconnect still
  needs the Owner's re-approval.

## Install (Owner, on the LXD host, as root)

```sh
sudo install -d -m 0755 /usr/local/lib/server-sentinel-usb-repass
sudo install -m 0644 infra/lxd/usb_repass.py /usr/local/lib/server-sentinel-usb-repass/usb_repass.py
sudo install -m 0644 infra/lxd/server-sentinel-usb-repass.service infra/lxd/server-sentinel-usb-repass.timer /etc/systemd/system/
sudo install -m 0644 infra/lxd/90-server-sentinel-usb-repass.rules /etc/udev/rules.d/
# the VM name and the LXD usb device names of the cameras (Step 2), no serials
sudo install -m 0600 /dev/null /etc/server-sentinel-usb-repass.json
sudoedit /etc/server-sentinel-usb-repass.json   # {"instance": "<vm>", "devices": ["cam1", "cam2"]}
```

Check before enabling (changes nothing; prints one line per device):

```sh
sudo /usr/bin/python3 -I -S /usr/local/lib/server-sentinel-usb-repass/usb_repass.py \
  --config /etc/server-sentinel-usb-repass.json --check
```

`usb_repass_held` for every device is the normal state. `usb_repass_needs_repass`
means that camera is not passed now and the first run will re-pass it.
Then enable:

```sh
sudo systemctl daemon-reload && sudo udevadm control --reload && \
  sudo systemctl enable --now server-sentinel-usb-repass.timer && \
  sudo systemctl start server-sentinel-usb-repass.service
sudo journalctl -u server-sentinel-usb-repass.service -n 20
```

The configuration must be a regular file owned by root and writable by
nobody else (`usb_repass_config_unsafe` otherwise). Optional key `socket`:
the LXD unix socket (default `/var/snap/lxd/common/lxd/unix.socket`).

## Remove

```sh
sudo systemctl disable --now server-sentinel-usb-repass.timer
sudo rm /etc/udev/rules.d/90-server-sentinel-usb-repass.rules \
  /etc/systemd/system/server-sentinel-usb-repass.service \
  /etc/systemd/system/server-sentinel-usb-repass.timer
sudo systemctl daemon-reload && sudo udevadm control --reload
```

Check `sudo lxc config device show <vm>` afterwards: every camera device is
still there (a re-pass in progress at removal is restored only by a later
run, so add it by hand as in `REMOTE_LIVE_VIEW_SETUP.md` if one is missing).

Tests: `tests/unit/test_lxd_usb_repass.py` (synthetic sysfs, `/proc` and LXD;
no host is touched).
