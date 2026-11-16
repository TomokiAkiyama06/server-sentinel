# LXD host: check for USB cameras not passed to the VM (Issue #301, #405)

For the LXD VM environment (`server/docs/REMOTE_LIVE_VIEW_SETUP.md`, D2) only.
These files are installed **on the LXD host** by the Owner, as root. They are
not part of the ServerSentinel release, ServerSentinel never runs them, and
neither ServerSentinel nor `media-capture-agent` gets root, a capability or
LXD access for them.

**It never changes the VM** (Owner decision 2026-11-16, Issue #405). The
first version (PR #399) removed and added the LXD `usb` device by itself. On
the real host on 2026-11-08 it judged both healthy cameras not passed,
removed them, and QEMU then refused every add (`/dev/fdset`) until the VM was
stopped, so the cameras were out of the VM twice. The check now only reports
a camera that *looks* not passed; the re-pass is done by hand ("Manual
re-pass" below), after verifying.

## What it checks

LXD 5.21 does not pass a camera that the host re-enumerated (`USB disconnect`
and reconnect, even within a second and without anyone touching it) back to
the running VM. QEMU keeps the old, deleted `/dev/bus/usb` node open and the
guest keeps a device that delivers nothing, so the source stays `offline`
(observed 2026-10-19).

`usb_repass.py` (Python standard library only) checks, for each LXD `usb`
device named in its configuration:

| Check | Line |
| --- | --- |
| the instance has a device of that name | otherwise `usb_repass_not_configured` (asks for attention) |
| the device has `vendorid`, `productid` and `serial`, and no `busnum` / `devnum` | otherwise `usb_repass_unidentified`: not judged (identical non-serial cameras are never matched) |
| no other configured device names the same camera | otherwise both `usb_repass_ambiguous` |
| exactly one host USB device has those three values, unchanged across two samples 2 s apart after a 5 s settle | none: `usb_repass_absent`; more than one: `usb_repass_ambiguous`; changed: `usb_repass_unsettled` |
| the VM's QEMU process holds that device's current node open (`/proc/<qemu pid>/fd`, deleted nodes excluded) | `usb_repass_held`: the normal state |
| otherwise | `usb_repass_looks_unpassed` (asks for attention) |

When one first sample already finds every configured camera held, the
settle and the second sample are skipped. Otherwise the judgement ends with
`usb_repass_qemu_usb_fds live=<n> deleted=<m>`: how many `/dev/bus/usb` fds
QEMU holds on live and on deleted nodes (counts only, for the manual
verification).

**The judgement can be wrong.** On 2026-11-08 it reported both cameras
`needs_repass` (the old word) while they were passed; after the VM restart
QEMU held four live USB nodes for two cameras, and why (one fd per
interface, or a second open through LXD's `/dev/fdset`) is not known (Issue
#405). Treat `usb_repass_looks_unpassed` as "verify by hand", never as a
reason to remove a device.

It decides from host facts only (LXD's instance configuration and state over
its unix socket, sysfs, `/proc/<qemu pid>/fd`), never from `/dev/videoN`, and
never trusts anything from the guest. It judges nothing while the VM is not
running or its QEMU process is younger than 300 s (the VM start's own USB
resets re-enumerate on the host for a while; Issue #405 saw them after
120 s).

It is read-only: the LXD client sends only `GET /1.0/instances/<vm>` and
`GET /1.0/instances/<vm>/state` (no method parameter, no request body), and
nothing is written anywhere. The unit has `ProtectSystem=strict`, no state
directory, `PrivateNetwork=yes` and `RestrictAddressFamilies=AF_UNIX`.

Leftover pending records: the old version wrote a device's configuration to
`/var/lib/server-sentinel-usb-repass/state.json` before each remove. The
check reads that file (never writes it) and prints, for each record,
`usb_repass_pending_record device=<label>` first (also while LXD does not
answer), then one of:

- `usb_repass_pending_device_missing`: the instance has no device of that
  name; the record may be its only configuration. Asks for attention; restore
  it by hand ("Leftover pending records" below).
- `usb_repass_pending_device_present`: the device is there exactly as
  recorded; the record is stale.
- `usb_repass_pending_device_differs`: a device of that name is there with
  another configuration (an Owner edit); check it by hand.

A state file that cannot be read prints `usb_repass_state_unreadable`, asks
for attention and is kept as it is.

## How the Owner is told

- **The notification is ServerSentinel's own `camera_offline`** (inside the
  VM, Slack, `camera_offline_notification.after_seconds`, default 5 minutes;
  or the Owner's dashboard notice without Slack;
  `REMOTE_LIVE_VIEW_SETUP.md`). A camera that is really not passed delivers no
  frames, so its source goes `offline` and that notice is sent. It does not
  say why.
- **The host check is the diagnosis**, on the LXD host only. A run that asks
  for attention prints `usb_repass_attention see=infra/lxd/README.md#manual-re-pass`
  and exits 1, so the unit shows in `systemctl --failed` until a later run
  finds nothing (the timer runs it every 5 minutes):
  ```sh
  systemctl --failed
  sudo journalctl -u server-sentinel-usb-repass.service -n 20
  ```
- The host sends nothing itself: no network, no Slack webhook or other
  secret on the host. A suspicion that ServerSentinel does not share (the
  source stays `online`) is therefore visible on the host only; it is most
  likely the wrong judgement above.

Journal lines are fixed words plus the configured device label and counts;
no serial, vendor/product id, bus or device number is printed.

## Manual re-pass

Only for cameras passed by `vendorid` + `productid` + `serial`
(`REMOTE_LIVE_VIEW_SETUP.md` Step 2). Changing an LXD device on the
production host needs the Owner. One camera at a time; keep serials and
bus/device numbers in the private record, not in GitHub. `<vm>` is the VM
(`ss-main`), `<camN>` the LXD device.

1. **Verify before anything is removed.** All four must agree; if one does
   not, do not remove the device (record what was seen in Issue #405):
   1. [Web] the source of that camera is `offline` (or a `camera_offline`
      notice arrived).
   2. [host] the instance has the device with the three values:
      ```sh
      sudo lxc config device show <vm>
      ```
   3. [host] exactly one host node has that serial (prints one line, e.g.
      `/dev/bus/usb/001/019`):
      ```sh
      for d in /sys/bus/usb/devices/*; do [ "$(cat "$d/serial" 2>/dev/null)" = '<serial N>' ] && \
        printf '/dev/bus/usb/%03d/%03d\n' "$(cat "$d/busnum")" "$(cat "$d/devnum")"; done
      ```
   4. [host] QEMU does **not** hold that node (only `(deleted)` entries, or
      other numbers):
      ```sh
      pid=$(sudo lxc info <vm> | awk '/^PID:/ {print $2}')
      sudo ls -l /proc/"$pid"/fd | grep /dev/bus/usb
      ```
      The node of step 3 listed without `(deleted)` means the camera **is**
      passed: stop here.
   5. [guest] the guest lacks the camera, or lists it while the source is
      `offline`:
      ```sh
      sudo lxc exec <vm> -- v4l2-ctl --list-devices
      sudo lxc exec <vm> -- ls -l /dev/v4l/by-id/
      ```
2. **Save the configuration**, then remove and add again **in one command**,
   with every key `lxc config device show` printed for that device except
   `type` (for example `required=false` too):
   ```sh
   sudo lxc config device show <vm> | sudo tee /root/<vm>-devices-$(date +%Y%m%dT%H%M%S).yaml >/dev/null
   sudo lxc config device remove <vm> <camN> && \
     sudo lxc config device add <vm> <camN> usb vendorid=<vvvv> productid=<pppp> serial=<serial N>
   ```
3. **Verify** within about a minute: step 1.4 lists the new node without
   `(deleted)`, step 1.5 lists the camera, the source is `online` again (no VM
   or service restart needed; ServerSentinel rebinds the serial-identified
   camera), and `--check` (below) prints `usb_repass_held` for it. Only then
   re-pass another camera.
4. **If the `add` fails** (e.g. `Failed to add device: GenericError: failed to
   open host usb device /dev/fdset/N`), do not run it in a loop and do not
   re-pass any other camera: in that state QEMU refuses every hot-plug until
   the VM restarts (Issue #405). With the Owner's approval (every camera
   stops recording during the restart), add the device while the VM is
   stopped:
   ```sh
   sudo lxc stop <vm>
   sudo lxc config device add <vm> <camN> usb vendorid=<vvvv> productid=<pppp> serial=<serial N>
   sudo lxc config device show <vm>    # every camera device is there, as in the saved copy
   sudo lxc start <vm>
   ```
   Then follow "After a host or VM reboot" in `REMOTE_LIVE_VIEW_SETUP.md`
   (the passed disk may be numbered differently) and verify every camera as
   in step 3.
5. If the source does not return to `online`, or shows
   `manual_intervention_required`, the reconnect was not unambiguous and
   needs the Owner's re-approval (`DEPLOYMENT.md`). Never pass a camera by
   vendor/product only or by bus/device number to get it back.

## Leftover pending records (2026-11-08)

Restoring a record is a manual `lxc config device add`, not a flag of the
check: the check stays without any write path, the add is the very operation
that failed on 2026-11-08 and needs the judgement of step 4 above when it
fails again, and only the records of that one incident exist.

1. `--check` (below). For each `usb_repass_pending_device_missing device=<camN>`:
   read the record (root-only; it holds the serial, keep it out of GitHub):
   ```sh
   sudo python3 -I -c 'import json; print(json.dumps(json.load(open("/var/lib/server-sentinel-usb-repass/state.json"))["pending"], indent=1))'
   ```
   and add it as recorded, with every key except `type`, as in "Manual
   re-pass" step 2 (only the `add` line) and step 4 if it fails.
2. For `usb_repass_pending_device_differs`, compare the record with
   `sudo lxc config device show <vm>` and keep whichever is right by hand.
3. When `--check` prints no `usb_repass_pending_device_missing` any more,
   move the file away so it is no longer reported:
   ```sh
   sudo mv /var/lib/server-sentinel-usb-repass/state.json /root/usb-repass-state-20261108.json
   sudo rm -r /var/lib/server-sentinel-usb-repass
   ```

## Install or update (Owner, on the LXD host, as root; not executed)

On the production host the old version is installed and disabled (Issue
#405: timer stopped, udev rule renamed to
`90-server-sentinel-usb-repass.rules.disabled`). From a checkout of this
repository:

```sh
# 1. make sure nothing of the old version can start, and drop its udev rule
sudo systemctl disable --now server-sentinel-usb-repass.timer
sudo systemctl stop server-sentinel-usb-repass.service
sudo rm -f /etc/udev/rules.d/90-server-sentinel-usb-repass.rules \
  /etc/udev/rules.d/90-server-sentinel-usb-repass.rules.disabled
sudo udevadm control --reload
# 2. the read-only version (same paths as before)
sudo install -d -m 0755 /usr/local/lib/server-sentinel-usb-repass
sudo install -m 0644 infra/lxd/usb_repass.py /usr/local/lib/server-sentinel-usb-repass/usb_repass.py
sudo install -m 0644 infra/lxd/server-sentinel-usb-repass.service infra/lxd/server-sentinel-usb-repass.timer /etc/systemd/system/
sudo systemctl daemon-reload
# 3. the configuration, if it is not there yet: the VM and the LXD usb device
#    names of the cameras, no serials
sudo install -m 0600 /dev/null /etc/server-sentinel-usb-repass.json
sudoedit /etc/server-sentinel-usb-repass.json   # {"instance": "<vm>", "devices": ["cam1", "cam2"]}
```

Check (changes nothing; prints one line per device, always exits 0):

```sh
sudo /usr/bin/python3 -I -S /usr/local/lib/server-sentinel-usb-repass/usb_repass.py \
  --config /etc/server-sentinel-usb-repass.json --check
```

`usb_repass_held` for every device is the normal state. Handle any pending
record first ("Leftover pending records"). A `usb_repass_looks_unpassed` is
verified by hand ("Manual re-pass" step 1) before anything is changed. Then
enable the timer and run it once:

```sh
sudo systemctl enable --now server-sentinel-usb-repass.timer && \
  sudo systemctl start server-sentinel-usb-repass.service; \
  sudo journalctl -u server-sentinel-usb-repass.service -n 20
```

(`systemctl start` returns non-zero when the run asks for attention; that is
the signal, not an install failure.)

Triggers: `server-sentinel-usb-repass.timer` only, 10 minutes after boot and
every 5 minutes after each start. There is no udev rule any more: a
read-only check does not need to react to a USB add within seconds (the
`camera_offline` notice comes after 5 minutes anyway), and the old rule
started runs on the VM start's own USB resets (Issue #405, 19:56). A run that
starts within 180 s of the host's boot (a manual one) waits up to 60 s for
LXD and ends without failing (`usb_repass_lxd_not_ready`) if it still does
not answer; a later run fails on `usb_repass_lxd_unreachable`.

The configuration must be a regular file owned by root and writable by
nobody else (`usb_repass_config_unsafe` otherwise). Optional key `socket`:
the LXD unix socket (default `/var/snap/lxd/common/lxd/unix.socket`).

## Remove

```sh
sudo systemctl disable --now server-sentinel-usb-repass.timer
sudo rm /etc/systemd/system/server-sentinel-usb-repass.service \
  /etc/systemd/system/server-sentinel-usb-repass.timer
sudo systemctl daemon-reload
sudo rm -r /usr/local/lib/server-sentinel-usb-repass /etc/server-sentinel-usb-repass.json
```

The check never changed the instance, so nothing else is left behind. A
`/var/lib/server-sentinel-usb-repass` from the old version is handled as in
"Leftover pending records" before it is removed.

Tests: `tests/unit/test_lxd_usb_repass.py` (synthetic sysfs, `/proc` and LXD;
no host is touched).
