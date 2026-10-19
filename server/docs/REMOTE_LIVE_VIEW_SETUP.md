# Remote live view: dedicated environment setup (Owner procedure)

This is the step-by-step procedure the Owner runs so that the live camera view
of the Main Server can be opened from viewer devices (phone, Mac, desktop) on
Tailscale. It follows the Owner decisions of 2026-10-16 (Issue #10, Issue
#205):

- **D1**: `tailscaled`'s peerAPI TCP listener on the reserved addresses is
  accepted as one recorded listener exception (`tailscaled.service`, uid 0,
  not the HTTPS port); ADR-0003 records it. Its cookie and port behaviour is
  verified on the hardware (`MANUAL_TEST.md`).
- **D2**: the shared GPU Main host is **not** declared `single_purpose_node`.
  ServerSentinel runs in a dedicated environment (a VM) with its own
  `tailscaled`, `"isolation": "dedicated_network_identity"`, and USB camera
  passthrough.
- **D3**: listener exceptions and camera create/approve are done with host
  CLIs as the service account (controlling-terminal confirmation, audited, no
  WebAuthn step-up).
- **D6**: the Tailscale node gets a neutral name before any HTTPS certificate
  is issued for it, because the name is published in the public Certificate
  Transparency logs.

Steps 0-9 were run once on the real Main host on 2026-10-19 (partial record
in `MANUAL_TEST.md`, section J, "Issue #205 remote live view in the dedicated
environment"); step 10 and most verification items are still unrun. A step
counts as verified only where that record says so. The commands are
written for an Ubuntu 24.04 LTS or later host and an Ubuntu 24.04 LTS guest.

This document orders and connects the existing procedures; it does not
replace them. The details of each step stay in `server/docs/DEPLOYMENT.md`, and
the security model is in ADR-0003, ADR-0004, `SECURITY.md` and
`server/app/auth/README.md`.

## What this gives, and what it does not (yet)

After this procedure:

- the **Owner** can open `https://<neutral name>.<tailnet>.ts.net/` from a
  phone, Mac or desktop that is logged in to the lab Tailnet, sign in with
  their own passkey, and watch the interim live view (Issue #10 S7, at most
  5 fps per viewer) of the `local_uvc` cameras (the 2 x C960 passed into the
  VM);
- the Main Server keeps recording, running the startup/daily hardware check
  and the daily recording self-test inside the VM;
- the capture host (`media-capture-agent`) can reach the VM's private LAN
  address for pairing, without Tailscale.

Not available yet (未実装 in the current code; do not work around them):

- **Inviting other viewers.** The server has the Owner administration routes
  (`/api/admin/principals`: invite, permissions, revocation; Issue #10 S4b),
  but the Web UI has no Owner administration screen yet (S6 second part / S15),
  and the local CLI only lists and revokes (`bootstrap_cli list |
  revoke-principal | revoke-credential`, Owner decision S4-6). There is no
  supported way to issue an invitation code for a non-owner today. Until that
  screen exists, only the Owner can watch.
- **Live view of `remote_agent` sources.** The Main Server does not start the
  capture-ingest listener yet (Issues #14/#15), and the interim live view is
  attached to the `local_uvc` sources only. Pairing a capture node works; its
  video does not reach the dashboard yet.
- **Physical-host hardware integrity.** Inside a VM the startup/daily
  hardware integrity check sees the VM's virtual CPU, memory, disks and
  display device plus the passed-through devices, not the physical host. A
  change of the host's GPU, memory or disks that is not passed into the VM is
  not detected by ServerSentinel. This is a consequence of D2 that needs an
  Owner decision (accept and record it, or add a host-side check later); it
  is listed in the PR as an open item.
- **Moving an existing host deployment into the VM.** There is no migration
  tool for the database, recordings, passkeys or the capture CA. This
  procedure sets up a new deployment in the VM; the host deployment (if any)
  is stopped and kept untouched for rollback.

## Choice of environment: a VM managed by LXD (recommended)

D2 allows a VM or LXD. LXD can run both system containers and VMs; this
procedure uses **an LXD virtual machine** (`lxc launch ... --vm`), not an LXD
container.

Why a VM:

1. **Cameras keep their own identity.** For a VM, LXD passes the whole USB
   device through ("When a device is passed to the instance, it vanishes from
   the host"), and selects it by `vendorid`, `productid` and `serial`. The
   guest kernel loads `uvcvideo` and the guest's udev creates the video
   nodes, so ServerSentinel's own discovery and serial-based approval work
   exactly as on bare metal: the camera is selected by its serial both at the
   passthrough and in the Owner approval, never by `/dev/videoN`. For a
   container, LXD's `usb` device only passes the libusb node
   (`/dev/bus/usb/...`); a V4L2 camera would have to be passed as a
   `unix-char` path such as `/dev/video0`, which is the unstable identity the
   product forbids.
2. **The upstream socket can be verified.** The hostname reservation check
   needs cgroup v2 with cgroup-BPF so that systemd creates
   `server-sentinel-upstream.socket` in that unit's own cgroup (Issue #157).
   A VM has its own kernel and systemd and meets this like a bare host. An
   unprivileged container normally cannot attach cgroup-BPF programs, so the
   socket would be created in `/init.scope` and human access would never open
   (`UPSTREAM_CREATED_IN_INIT_SCOPE`). (Expected from the documented
   behaviour; not tested on this host.)
3. **Own network identity.** The VM has its own network stack, its own
   `tailscaled` and its own Tailscale node. Nothing on the host, including
   the GPU benchmark sessions, can bind the VM's Tailscale addresses. This is
   what `"dedicated_network_identity"` states.
4. **The GPU stays on the host.** The only person detector implementation is
   the CPU one (`rtdetr-v2-r18vd-onnx-cpu`), so the VM needs no GPU
   passthrough, and the other sessions keep using the GPU. Give the VM a
   fixed number of vCPUs so that detection does not compete without bound
   with the host's work.
5. **LXD over plain libvirt.** LXD's `usb` device takes a `serial` key, which
   is needed to tell the two identical C960 apart. Plain libvirt USB hostdev
   selects by vendor/product or by bus address (to our knowledge; not
   re-verified here), and a bus address changes on re-plug. Use LXD unless
   the Owner already runs libvirt and verifies an equivalent serial-based
   selection.

Costs of the VM: some memory and CPU overhead; the hardware check sees
virtual hardware (above); the host cannot open the cameras while the VM holds
them.

## Conventions

Each step is marked with where it runs and with which privilege:

- **[host, sudo]**: on the Main host, needs `sudo` (the Owner runs it).
  `lxc` commands are written as `sudo lxc ...`; membership in the `lxd` group
  is equivalent to root and is not needed for this procedure.
- **[host]**: on the Main host, no privilege.
- **[guest, root]**: inside the VM, in a root shell opened with
  `sudo lxc exec <vm> -- bash` (a host `sudo` step that opens a root shell in
  the guest; the commands inside run as the guest's root).
- **[guest, service account]**: inside the VM, as the ServerSentinel service
  account (`sudo -u server-sentinel ...` from the guest root shell, which
  keeps the controlling terminal the D3 CLIs require).
- **[viewer]**: on the phone, Mac or desktop.

Placeholders: `<vm>` is the LXD instance name (for example `ss-main`; it is
local to the host and never published), `<neutral name>` is the Tailscale
node name (see step 5), `<lan nic>` is the host's network interface on
the private LAN (`<lan subnet>`), `<vm lan ip>` is the address the Owner reserves for the VM
on that LAN. Keep real names, addresses, serials and disk identifiers in the
private operations record only, never in GitHub.

## Step 0. Before starting

1. [host] Confirm hardware virtualization is available:
   ```sh
   test -c /dev/kvm && echo kvm-present
   lscpu | grep -i virtualization
   ```
2. [host] Check whether LXD is installed and already initialized. If it is,
   **do not run `lxd init` again** (other work on the host may use it):
   ```sh
   snap list lxd
   sudo lxc storage list
   sudo lxc profile show default
   ```
   If it is not installed:
   ```sh
   sudo snap install lxd
   sudo lxd init --minimal
   ```
   `--minimal` creates a `dir` storage pool on the host root filesystem and
   the `lxdbr0` bridge. The VM's operating system disk lives in that pool; the
   recordings do **not** (step 3).
3. [host] If ServerSentinel already runs on the host itself, plan a window:
   the cameras leave the host in step 2. Stop and disable the host service
   before attaching the cameras, and keep its configuration, runtime root and
   CA directory untouched (they are the rollback):
   ```sh
   sudo systemctl disable --now server-sentinel-upstream.socket server-sentinel.service
   ```
   Never run two deployments against the same cameras.
4. Tailnet prerequisites (outside ServerSentinel). MagicDNS and HTTPS
   Certificates must be enabled for the Tailnet, which is a DNS setting of the
   Tailnet, not an ACL/Grants change. ServerSentinel neither performs nor asks
   for it and stores no Tailscale credential. If they are not enabled, the
   Owner decides whether to enable them as the holder of the shared account;
   this procedure does not change any Tailnet policy.

## Step 1. Create the VM

[host, sudo] Create (not yet start) an Ubuntu 24.04 VM. Size CPU and memory
from the detector measurements of Issue #20; the values below are
placeholders, not recommendations:

```sh
sudo lxc init ubuntu:24.04 <vm> --vm \
  --config limits.cpu=<vCPUs> \
  --config limits.memory=<n>GiB \
  --device root,size=<n>GiB
sudo lxc config set <vm> boot.autostart=true
```

`boot.autostart=true` starts the VM at host boot so that recording resumes
without the Owner.

### LAN interface for capture agents (macvlan)

The capture agents on the private LAN must reach the VM directly, without
Tailscale. Give the VM its own address on that LAN with a macvlan NIC on the
host's LAN interface. A local device named `eth0` replaces the `eth0` of the
default profile:

```sh
ip -br addr            # [host] find <lan nic>: the interface on <lan subnet>
sudo lxc config device add <vm> eth0 nic nictype=macvlan parent=<lan nic>
```

- The VM gets its own MAC address (LXD keeps it in
  `volatile.eth0.hwaddr`). If the lab LAN filters MAC addresses or uses DHCP
  reservations, register that MAC (`sudo lxc config get <vm>
  volatile.eth0.hwaddr` after the first start).
- macvlan does not work on a Wi-Fi parent interface; use the wired NIC.
- LXD documents that with macvlan "communication between the LXD host and
  the instances is not possible". This is acceptable here: the Owner
  administers the VM with `lxc exec`, and the capture host is a different
  machine. The VM reaches the Internet (Tailscale coordination, Ubuntu
  updates) through the LAN gateway.
- Do not add an LXD `proxy` device or host DNAT towards the VM: the
  reservation check cannot see kernel forwarding, and none is needed.

## Step 2. Pass the two C960 cameras through by serial

1. [host] With both cameras plugged in, list the USB devices with their
   vendor id, product id and serial (sysfs is world-readable; no `sudo`).
   Record the serials only in the private record:
   ```sh
   for d in /sys/bus/usb/devices/*; do
     [ -r "$d/idVendor" ] || continue
     printf '%s %s:%s serial=%s %s\n' "${d##*/}" "$(cat "$d/idVendor")" \
       "$(cat "$d/idProduct")" "$(cat "$d/serial" 2>/dev/null || echo -)" \
       "$(cat "$d/product" 2>/dev/null)"
   done
   ```
   Both C960 must show the same `vendor:product` and two different, non-empty
   serials. If a camera shows no serial, or both show the same serial, stop:
   it cannot be selected unambiguously (and ServerSentinel's `approve` would
   refuse it as `camera_without_serial` / `camera_serial_not_unique`). Do not
   fall back to passing it by vendor/product or by bus/device number.
2. [host, sudo] Add one `usb` device per camera, each with `serial`:
   ```sh
   sudo lxc config device add <vm> cam1 usb vendorid=<vvvv> productid=<pppp> serial=<serial 1>
   sudo lxc config device add <vm> cam2 usb vendorid=<vvvv> productid=<pppp> serial=<serial 2>
   ```
   `required` stays at its default `false`: the VM also starts without a
   camera, and LXD hotplugs the camera when it is plugged in. The serial
   stays in the host's LXD configuration (readable by root and the `lxd`
   group); keep it out of GitHub.

   Observed on the real host (2026-10-19, Issue #301): when the host
   re-enumerated one camera (`USB disconnect` and reconnect in the same
   second, no unplug), LXD did **not** pass it back to the running VM; the
   guest lost the camera and its source stayed `offline` until the device was
   re-added. Until #301 is resolved, recover with
   `sudo lxc config device remove <vm> <camN>` (the device whose serial
   belongs to the offline source) followed by its
   `lxc config device add` line (no VM restart; the service rebinds the
   serial-identified camera by itself), and watch the source state.
3. Up to 4 cameras are supported by ServerSentinel; add `cam3` / `cam4` the
   same way if more `local_uvc` cameras are used. Nothing in this procedure
   assumes exactly two.

## Step 3. Recording filesystem on a dedicated disk

ServerSentinel refuses a runtime root on the operating system's root
filesystem and identifies its recording filesystem by UUID and device
numbers. In the VM, give it a separate block device:

- **Recommended**: a whole host disk or partition that the host does not
  mount, passed as a block device by its stable `/dev/disk/by-id/` path.
  Then the recordings do not consume the host root filesystem, and capacity
  exhaustion stays on that disk.
- An LXD custom block volume in the default `dir` pool would sit on the host
  root filesystem; do not use it for recordings unless the pool is on a
  dedicated disk. On a dedicated data filesystem (for example a `dir` pool
  under the host's `/data`) it works, but the volume file is sparse: the
  guest then sees free space the host filesystem may not have. Preallocate
  it on the host (`sudo fallocate -l <size> <pool dir>/custom/default_<volume>/root.img`,
  then `du -h` shows the full size), format it in step 4 with
  `mkfs.ext4 -E nodiscard`, and disable `fstrim.timer` in the guest
  (`systemctl disable --now fstrim.timer`): a discard deallocates the file
  again (observed 2026-10-19: `mkfs` discard left 4.2G of 2 TiB allocated).
- A shared host directory (`disk source=<directory>`, 9p/virtiofs) has no
  filesystem UUID in `/dev/disk/by-uuid` inside the guest and is expected to
  be refused by the runtime identity check; do not use it.

[host] Find the disk. **Make sure it holds nothing that must be kept and is
not mounted on the host** (formatting in step 4 destroys its contents; never
use the disk behind the host's existing data mount while the host deployment
is the rollback):

```sh
ls -l /dev/disk/by-id/
lsblk -o NAME,SIZE,TYPE,MOUNTPOINTS,FSTYPE,MODEL
```

[host, sudo]

```sh
sudo lxc config device add <vm> recdisk disk source=/dev/disk/by-id/<disk id>
```

## Step 4. First start and base system of the VM

[host, sudo]

```sh
sudo lxc start <vm>
sudo lxc list <vm>                 # wait for RUNNING
sudo lxc exec <vm> -- bash         # opens the guest root shell for the steps below
```

[guest, root]

1. Update and install what the installer and the checks need
   (`python3-venv` for the release virtual environment, `dmidecode` for the
   hardware inventory; `v4l-utils` only for the manual checks):
   ```sh
   apt-get update && apt-get -y full-upgrade
   apt-get install -y python3-venv dmidecode v4l-utils
   python3 --version                       # 3.12.x on 24.04 (supported: >=3.12,<3.15, not 3.13)
   modinfo uvcvideo >/dev/null || apt-get install -y linux-generic "linux-modules-extra-$(uname -r)"
   modprobe uvcvideo
   ```
2. Neutral OS hostname (the same name as the Tailscale node in step 5):
   ```sh
   hostnamectl set-hostname <neutral name>
   ```
3. Fixed LAN address. Either reserve `<vm lan ip>` for the MAC in the LAN's
   DHCP server, or set it statically. Static example (find the interface name
   with `ip -br link`; it is usually `enp5s0` in an LXD VM):
   ```sh
   printf 'network: {config: disabled}\n' > /etc/cloud/cloud.cfg.d/99-disable-network-config.cfg
   cat > /etc/netplan/60-lan.yaml <<'EOF'
   network:
     version: 2
     ethernets:
       enp5s0:
         dhcp4: false
         addresses: [<vm lan ip>/24]
         routes:
           - to: default
             via: <lan gateway>
         nameservers:
           addresses: [<lan dns>]
   EOF
   chmod 600 /etc/netplan/60-lan.yaml
   rm -f /etc/netplan/50-cloud-init.yaml
   netplan try                              # confirm within the timeout, or it reverts
   ip -br addr show enp5s0
   ```
   The address must not be in `100.64.0.0/10` or `fd7a:115c:a1e0::/48`: the
   capture enrollment and ingest refuse Tailscale-range addresses.
4. SSH inside the VM is not needed (administration goes through
   `lxc exec`). Disabling it removes a wildcard listener that would otherwise
   need a `tcp/22` exception:
   ```sh
   systemctl disable --now ssh.socket ssh.service 2>/dev/null; systemctl is-active ssh.socket ssh.service
   ```
5. Time synchronization before start (`DEPLOYMENT.md`, "Clock
   synchronization before start"). Ubuntu 24.04 uses `systemd-timesyncd` by
   default; check and enable the matching wait service:
   ```sh
   systemctl is-active chrony.service systemd-timesyncd.service
   systemctl enable systemd-time-wait-sync.service      # or chrony-wait.service with chrony
   timedatectl show -p NTPSynchronized
   ```
6. Recording filesystem. Identify the passed disk (its `/dev/disk/by-id/`
   name in the guest ends in `lxd_recdisk`; confirm by size), format it once,
   and mount it by UUID:
   ```sh
   lsblk -o NAME,SIZE,TYPE,MOUNTPOINTS,FSTYPE
   ls -l /dev/disk/by-id/ | grep lxd_recdisk
   mkfs.ext4 -E nodiscard -L ss-recordings /dev/disk/by-id/<…lxd_recdisk>   # destroys the disk's contents
   blkid /dev/disk/by-id/<…lxd_recdisk>                          # note UUID=
   mkdir -p /srv/ss-data
   echo 'UUID=<uuid> /srv/ss-data ext4 defaults,nofail 0 2' >> /etc/fstab
   systemctl daemon-reload && mount /srv/ss-data && findmnt /srv/ss-data
   ```
   With `nofail` a missing disk does not stop the VM from booting; the empty
   `/srv/ss-data` directory on the root filesystem is then refused by
   ServerSentinel (UUID and device mismatch) instead of being written to.
7. Cameras are visible in the guest:
   ```sh
   v4l2-ctl --list-devices
   ```

## Step 5. Tailscale inside the VM, neutral name first (D6)

The VM is a **new Tailscale node** of the lab Tailnet, separate from the
host's node. The reserved dashboard name is this node's MagicDNS name.

1. Choose `<neutral name>`: it is published in Certificate Transparency logs
   as `<neutral name>.<tailnet>.ts.net` as soon as the first certificate is
   issued, and it becomes the WebAuthn relying-party id (changing it later
   invalidates every registered passkey). Do not use "sentinel", "camera",
   "monitor", the lab, room or a person's name. Decide it before step 5.2.
2. [guest, root] Install `tailscaled` from Tailscale's package repository for
   Ubuntu 24.04 (noble) and join with that name:
   ```sh
   curl -fsSL https://pkgs.tailscale.com/stable/ubuntu/noble.noarmor.gpg \
     -o /usr/share/keyrings/tailscale-archive-keyring.gpg
   curl -fsSL https://pkgs.tailscale.com/stable/ubuntu/noble.tailscale-keyring.list \
     -o /etc/apt/sources.list.d/tailscale.list
   apt-get update && apt-get install -y tailscale
   tailscale up --hostname=<neutral name>
   ```
   `tailscale up` prints a login URL; open it and log in with the lab's
   shared account. Do not add `--ssh`, `--advertise-routes`,
   `--advertise-exit-node`, `--shields-up` or Funnel: they add answers on
   the node or block Serve.
3. [guest, root] Confirm the final name **before** anything requests a
   certificate:
   ```sh
   tailscale status --json | python3 -c 'import json,sys; print(json.load(sys.stdin)["Self"]["DNSName"])'
   tailscale ip -4; tailscale ip -6
   ```
   If the printed name is not `<neutral name>.<tailnet>.ts.net.` (for example
   a `-1` suffix because the name was taken), rename it now with
   `tailscale set --hostname=<another neutral name>` and check again.
4. Do **not** run `tailscale cert`: it is not needed (Tailscale Serve obtains
   the certificate itself at step 8) and it would issue a certificate before
   the name is final. Do not run `tailscale serve` yet either.
5. Note the node key expiry of the Tailnet: when the VM's node key expires,
   the name stops answering until the Owner re-authenticates the node
   (`tailscale up` again); recording continues meanwhile.

## Step 6. Install ServerSentinel in the VM

Follow `server/docs/DEPLOYMENT.md` inside the guest. VM-specific points:

1. [host] Build the release artifact and installer from a tagged checkout as
   in "Release artifact" (on the host or a build machine, not in the VM), and
   copy them in with their published SHA-256:
   ```sh
   sudo lxc file push /path/to/server-sentinel-main-<ver>.tar.gz <vm>/tmp/
   sudo lxc file push /path/to/server-sentinel-installer-<ver>.pyz <vm>/tmp/
   sudo lxc file push infra/systemd/server-sentinel-upstream.socket <vm>/tmp/
   ```
2. [guest, root] Service account and runtime tree ("One-time deployment
   preparation"):
   ```sh
   useradd --system --user-group --no-create-home --shell /usr/sbin/nologin server-sentinel
   usermod -aG video server-sentinel          # UVC nodes are root:video; never add audio
   id server-sentinel                         # groups include video, not audio
   for v in /dev/video*; do sudo -u server-sentinel test -r "$v" -a -w "$v" && echo "$v rw-ok"; done
   install -d -o server-sentinel -g server-sentinel -m 0700 \
     /srv/ss-data/server-sentinel /srv/ss-data/server-sentinel/state \
     /srv/ss-data/server-sentinel/recordings /srv/ss-data/server-sentinel/audit
   install -d -o root -g root -m 0755 /etc/server-sentinel
   id -u server-sentinel                      # "service_uid"
   findmnt -no MAJ:MIN,UUID /srv/ss-data      # decimal major:minor and the UUID
   ```
   `runtime_device` and `monitoring.recording_filesystem.device` take the
   major and minor numbers as two decimal integers, for example `[8, 16]`.
3. [guest, root] Write `/etc/server-sentinel/deployment.json` (owner `root`,
   group `server-sentinel`, mode `0640`) with the shape in "One-time
   deployment preparation": `runtime_root` `/srv/ss-data/server-sentinel`,
   `runtime_mount_point` `/srv/ss-data`, the UUID and decimal device numbers
   from step 4.6, `service_uid`, `"human_host": "127.0.0.1"`,
   `"human_port": 880`, the `monitoring` section sized for the disk,
   `"capture_ca_directory": null` (the release refuses a configured CA
   path that does not exist yet; step 10 creates the CA account and
   directory and then sets the path), and
   `"web_assets_directory": "/opt/server-sentinel-main/current/web"`. Leave
   `human_access` and `local_uvc` out for now.
4. [guest, root] Human upstream socket ("Human upstream through socket
   activation"):
   ```sh
   install -o root -g root -m 0644 /tmp/server-sentinel-upstream.socket /etc/systemd/system/
   grep '^ListenStream=' /etc/systemd/system/server-sentinel-upstream.socket   # 127.0.0.1:880
   systemctl daemon-reload
   ```
5. [guest, root] Install ("Install, update, and rollback"; the installer
   verifies the artifact hash):
   ```sh
   python3 /tmp/server-sentinel-installer-<ver>.pyz \
     --destination /opt/server-sentinel-main \
     --config /etc/server-sentinel/deployment.json \
     --unit /etc/systemd/system/server-sentinel.service \
     install --version <ver> \
     --artifact /tmp/server-sentinel-main-<ver>.tar.gz --sha256 <published sha256>
   systemctl enable --now server-sentinel-upstream.socket
   systemctl enable server-sentinel.service    # the installer does not enable it; without this it does not start at boot
   systemctl restart server-sentinel.service
   systemctl status server-sentinel.service --no-pager
   ss -ltn --cgroup 'sport = :880'     # expect cgroup:/system.slice/server-sentinel-upstream.socket
   ```
   `cgroup:/init.scope` here means the VM lacks cgroup-BPF support; stop and
   fix the VM rather than weakening the check.

## Step 7. Cameras as `local_uvc` sources (D3)

[guest, service account] Follow "Creating sources and approving cameras
locally" in `DEPLOYMENT.md`, **inside the VM** (from the host the command
cannot see the guest's service). In short, from the guest root shell:

```sh
cd /opt/server-sentinel-main/current
systemctl stop server-sentinel.service
sudo -u server-sentinel ./venv/bin/python -m app.cameras.uvc.admin_cli \
  create-source --config /etc/server-sentinel/deployment.json \
  --name "<display name>" --profile 1920x1080@30/MJPG          # type CREATE; repeat per camera
# add the printed UUIDs to "local_uvc": {"source_ids": [...]} in deployment.json
sudo -u server-sentinel ./venv/bin/python -m app.deployment \
  --config /etc/server-sentinel/deployment.json --check
sudo -u server-sentinel ./venv/bin/python -m app.cameras.uvc.admin_cli \
  candidates --config /etc/server-sentinel/deployment.json        # two cam-… labels, serial=present
sudo -u server-sentinel ./venv/bin/python -m app.cameras.uvc.admin_cli \
  approve --config /etc/server-sentinel/deployment.json <source uuid> cam-<label>   # type APPROVE; per camera
systemctl start server-sentinel.service
```

`candidates` never prints a serial or device path. The approval binds each
source to a camera by its serial; the passthrough of step 2 selected the
same cameras by the same serials.

## Step 8. Tailscale Serve and human access

1. [guest, root] Map the reserved name to the loopback upstream, and nothing
   else on that name ("Enabling human access through Tailscale Serve"):
   ```sh
   tailscale serve --bg --https=443 http://127.0.0.1:880
   tailscale serve status
   ```
   The first HTTPS request to the name makes Tailscale issue its certificate
   (the Certificate Transparency entry of D6). No other Serve path, port, TCP
   forward or Funnel.
2. [guest, service account] Confirm the backend can read Serve status
   without any environment (the backend runs exactly this):
   ```sh
   sudo -u server-sentinel env -i /usr/bin/tailscale serve status --json
   ```
   If this needs anything else (for example operator rights), stop: do not
   make the service account a Tailscale operator; record the result in
   `MANUAL_TEST.md` and ask for a follow-up decision.
3. [guest, root] Inventory every listener the reservation check will see:
   ```sh
   ss -ltnup --cgroup
   getent ahosts <neutral name>.<tailnet>.ts.net
   nft list ruleset; iptables-save -t nat 2>/dev/null
   ```
   Expected on the reserved addresses or wildcard: `tailscaled`'s WireGuard
   UDP port (wildcard, `cgroup:/system.slice/tailscaled.service`), its
   peerAPI TCP port on the Tailscale addresses (same cgroup), possibly a
   Serve socket on port 443, and nothing else. Loopback-only listeners
   (`127.0.0.1:880`, `systemd-resolved` on `127.0.0.53/54`) are not on the
   reserved addresses. Any other wildcard or reserved-address listener must
   be removed, not excepted. No NAT/DNAT/REDIRECT rule may target the
   Tailscale addresses.
4. [guest, root] Run the peerAPI checks of `MANUAL_TEST.md` (section
   "ADR-0003 follow-up", `tailscaled` peerAPI reserved-address exception)
   before recording the exception (D1).
5. [guest, root] Add the `human_access` section to `deployment.json`
   (`DEPLOYMENT.md` lists every key; values here are placeholders):
   ```json
   "human_access": {
     "enabled": true,
     "hostname": "<neutral name>.<tailnet>.ts.net",
     "port": 443,
     "reserved_addresses": ["<tailscale ip -4>", "<tailscale ip -6>"],
     "isolation": "dedicated_network_identity",
     "tailscale_executable": "/usr/bin/tailscale",
     "proxy_listeners": [],
     "proxy_owner": null,
     "require_device_bound": false
   }
   ```
   If step 3 showed a Serve socket on a reserved address at port 443, list
   those addresses in `proxy_listeners` and set
   `"proxy_owner": {"unit": "tailscaled.service", "uid": 0}`.
   Do not use `"single_purpose_node"` (D2).
   `reserved_addresses` must equal the address set `getent ahosts` printed
   in step 3: when the name resolves to IPv4 only (observed 2026-10-19),
   list only the IPv4 address. Moving the node to another Tailnet changes
   the name, the addresses and usually the peerAPI port: repeat steps 3-7.
6. [guest, service account] Record the listener exceptions (D3; "Recording
   listener exceptions"). `set` replaces the whole set; type `CHANGE`:
   ```sh
   cd /opt/server-sentinel-main/current
   sudo -u server-sentinel ./venv/bin/python -m app.deployment \
     --config /etc/server-sentinel/deployment.json --check
   sudo -u server-sentinel ./venv/bin/python -m app.auth.reservation_cli \
     set --config /etc/server-sentinel/deployment.json \
     protocol=udp,port=<wireguard port>,unit=tailscaled.service,uid=0 \
     scope=reserved_address,protocol=tcp,port=<peerAPI port>,unit=tailscaled.service,uid=0
   systemctl restart server-sentinel.service
   ```
   Use one `reserved_address` exception without `family` when IPv4 and IPv6
   use the same peerAPI port, or one with `family=ipv4` and one with
   `family=ipv6` when they differ (at most one per family). Add
   `protocol=tcp,port=22,unit=ssh.socket,uid=0` only if SSH was kept in the
   VM.
7. [guest, root] Confirm the startup check passed: no
   `human_access_check_failed` or `human_access_composition_failed` in
   `journalctl -u server-sentinel.service`, and no `human_access_fault`
   notification to the Owner.

## Step 9. Owner passkey and live view

1. [guest, service account] Issue the Owner's single-use code ("Owner
   bootstrap and recovery"):
   ```sh
   cd /opt/server-sentinel-main/current
   sudo -u server-sentinel ./venv/bin/python -m app.auth.bootstrap_cli \
     bootstrap --config /etc/server-sentinel/deployment.json
   ```
   The code appears only on this terminal and is valid for
   `invitation_lifetime_hours` (default 24). Copy it rather than retyping
   it: every refusal is the same generic message, and a code takes at most
   5 redemption attempts. A lost or exhausted code is replaced with
   `bootstrap_cli recover` (before any passkey exists it revokes nothing).
2. [viewer] On a phone, Mac or desktop logged in to the lab Tailnet, open
   `https://<neutral name>.<tailnet>.ts.net/` (only this `https` origin
   works; there is no `http://localhost` Owner route), enter the code and
   register the Owner's passkey on an authenticator the Owner personally
   controls, with user verification (not a passkey in a shared OS account).
3. [viewer] Sign in and open Live: the approved `local_uvc` cameras appear
   and the picture updates.

Reaching the name over the shared Tailscale account identifies nobody: every
person needs a ServerSentinel invitation and their own passkey. Inviting
non-owners is 未実装 (see the top of this document).

## Step 10. Capture agents over the private LAN (pairing only)

Pairing works now; the ingest of their video is 未実装 (#14/#15). Follow
"Capture-node CA and Main listener certificate" in `DEPLOYMENT.md` inside the
VM. In order: stop the service, create the CA account `serversentinel-ca`
and `/var/lib/serversentinel-ca` in the guest and run `serversentinel-pairing
init` as described there, then set `"capture_ca_directory":
"/var/lib/serversentinel-ca"` in `deployment.json`, run the release's
`--check` as the service account and start the service again (the check
refuses a missing CA directory, and one the service account can reach).
Pair with `approve --listen <vm lan ip>:<port>` and
`export-bundle --endpoint <vm lan ip>:<port>`, a port at or above
`ip_unprivileged_port_start`. On the capture host, the bundle endpoint is the
VM's LAN IP literal (not a MagicDNS name; no Tailscale on the capture host is
needed). A capture node paired with a previous host deployment trusts that
deployment's CA, not the VM's, and must be re-paired with the VM.

## Verification checklist

Record each item in `MANUAL_TEST.md` (section J, "Issue #205 remote live view
in the dedicated environment"), without private values:

- [ ] `test -c /dev/kvm`; the VM is an LXD VM (`sudo lxc info <vm>` shows
  `Type: virtual-machine`) with `boot.autostart=true`;
- [ ] each camera is passed by `vendorid` + `productid` + `serial`; the host
  no longer lists the passed cameras; the guest lists both; re-plugging one
  camera brings it back in the guest only (hotplug) and the other is
  untouched;
- [ ] the runtime filesystem is the passed disk (not the guest root), and
  with the disk detached the service refuses to start instead of writing to
  `/srv/ss-data` on the root filesystem;
- [ ] `ss -ltn --cgroup 'sport = :880'` in the guest shows
  `cgroup:/system.slice/server-sentinel-upstream.socket`;
- [ ] the Tailscale node name was neutral before the first certificate
  (record the order of the `tailscale status` and `tailscale serve` runs);
  the host's own node is a different node;
- [ ] the startup check opens human access with `"isolation":
  "dedicated_network_identity"`, the single Serve mapping and the recorded
  exceptions, and closes it (generic denial, one `human_access_fault`) with
  `"isolation": null`, an extra Serve path or port, or `tailscaled` stopped;
- [ ] from a process **on the host**, the VM's Tailscale addresses cannot be
  bound (`python3 -c 'import socket; s=socket.socket(); s.bind(("<vm tailscale ip>", 8443))'`
  fails with "Cannot assign requested address"), which is what the dedicated
  network identity provides;
- [ ] the D1 peerAPI checks (plain HTTP only, no `__Host-session` cookie
  sent, port stability across `tailscaled` restart, `down`/`up` and reboot);
- [ ] the Owner registers a passkey from a viewer device at the `https`
  origin and watches live from phone, Mac and desktop;
- [ ] the capture host reaches `<vm lan ip>:<port>` for pairing without
  Tailscale; the human dashboard is not reachable on the LAN address (the
  upstream is loopback-only);
- [ ] the hardware integrity baseline taken in the VM is recorded, with the
  note that it describes the VM's view (open Owner decision above);
- [ ] ServerSentinel asked for no Tailscale ACL/Grants change and no
  Tailscale administrative credential at any step.

## Rollback

The VM is self-contained; rolling back does not touch the host's data.

1. [guest, root] Close human access first: set `"enabled": false` in
   `human_access` (or remove Serve with `tailscale serve reset`) and
   `systemctl restart server-sentinel.service`. To remove the node from the
   Tailnet, run `tailscale logout` in the guest; otherwise it stays as an
   offline node.
2. [host, sudo] Stop the VM and give the cameras back to the host:
   ```sh
   sudo lxc stop <vm>
   sudo lxc config set <vm> boot.autostart=false
   sudo lxc config device remove <vm> cam1
   sudo lxc config device remove <vm> cam2
   ```
3. [host, sudo] If a host deployment existed (step 0.3), start it again:
   ```sh
   sudo systemctl enable --now server-sentinel-upstream.socket server-sentinel.service
   ```
   Confirm its sources with `admin_cli sources` and the camera state on the
   host (`DEPLOYMENT.md`, "Creating sources and approving cameras locally");
   re-approve a source that reports `approval_required` or
   `manual_intervention_required` instead of assuming the old binding.
4. Keep the VM, its recording disk and its database until the Owner decides
   what to do with the recordings and audit log made there (retention
   applies; do not delete them as part of a rollback). Deleting the VM
   (`sudo lxc delete <vm>`) does not erase the passed host disk; the disk is
   erased only by an explicit Owner action.
5. Passkeys registered for `<neutral name>.<tailnet>.ts.net` stay valid only
   for a deployment that keeps that name and database; a deployment under
   another name needs a new Owner bootstrap.
