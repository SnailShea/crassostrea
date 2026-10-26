# Installation ISO

A bootable ISO installs the gateway on bare metal or a VM: AlmaLinux 10
from the ISO itself, and this repository in `/opt/crassostrea`. At the first
boot, once the machine is on its network, a console wizard runs
`setup.sh`.

## Building

```bash
iso/build.sh                       # the checked-out branch -> iso/out/
iso/build.sh --ref v1.4.0 --origin https://github.com/SnailShea/crassostrea.git
```

- **Base image:** the newest AlmaLinux 10 **minimal** ISO is downloaded to
  `iso/cache/` (about 1.6 GB, reused by later builds). It is checked against
  AlmaLinux's signed `CHECKSUM`, using the pinned AlmaLinux 10 key.
- **Gateway source:** a clone of `--ref` with its git history, so `update.sh`
  works on the installed gateway. `--origin` is the remote it pulls from;
  the default is this repository's `origin`.
- **Assembly:** `iso/assemble.sh` adds the kickstart and the gateway with
  xorriso and mtools. It needs no root, loop devices or mounts, so a
  rootless podman or docker is enough. It runs in an `almalinux:10`
  container unless xorriso, mtools, isomd5sum and pykickstart are installed.
- **Output:** `crassostrea-<version>-alma<release>-x86_64.iso` and its
  `.sha256`.
- **Requirements:** git, curl, gpg and sha256sum, plus podman or docker.

The GitHub workflow `.github/workflows/iso.yml` builds the ISO in two cases:

- **Run workflow** (Actions tab): the ISO is kept as an artifact for 7 days.
- **Pushing a tag `v*`:** the ISO is attached to the tag's release. A
  release asset can be at most 2 GiB; the ISO is about 1.6 GB.

On pull requests that change `iso/`, the workflow only checks the scripts
and the kickstart.

## Installing

Write the ISO to a USB stick (`dd if=crassostrea-....iso of=/dev/sdX bs=4M`)
or attach it to a VM, then boot it in BIOS or UEFI mode. Secure Boot should work,
because the signed shim, GRUB and kernel of AlmaLinux are kept (not tested yet).

- **Interactive** (the default): the installer asks for the disk, the root
  password or an administrator account, and optionally the network and time
  zone. At the first boot, the console shows:
  1. set up the gateway now (`setup.sh`, which asks for the hostname);
  2. configure the network first (`nmtui`): a gateway wants a fixed
     address;
  3. skip, and run `/opt/crassostrea/setup.sh` later over SSH.
- **Unattended:** press `e` on the boot entry and add parameters to the
  `linux` line:

  | Parameter | Effect |
  | --- | --- |
  | `crassostrea.hostname=FQDN` | The first boot runs `setup.sh --hostname FQDN --yes`, and retries at each boot until it succeeds |
  | `crassostrea.wipe=sda` | **Erases** that disk and partitions it automatically; `first` = the first disk that is not the installation medium |
  | `crassostrea.sshkey="ssh-ed25519 AAAA... me@host"` | Root logs in with this key only; there is no root password |
  | `crassostrea.timezone=Europe/Berlin` | Time zone (default UTC) |

  With `wipe` and `sshkey` the installer asks nothing at all and reboots when
  it is done.

  For automation, a PXE or virtual-media setup can pass the same parameters
  together with
  `inst.ks=hd:LABEL=<volume label>:/crassostrea.ks`.

The first boot needs Internet access (EPEL and Rspamd repositories, PyPI,
ClamAV signatures). Its output is in `/var/log/crassostrea-firstboot.log`.
The installer's logs are in `/root/crassostrea-install*.log`.

## Files

| File | Purpose |
| --- | --- |
| `build.sh` | Stages the source, fetches and verifies the base ISO, runs `assemble.sh` |
| `assemble.sh` | Kickstart, GRUB entries (BIOS and UEFI, including the EFI image) and payload into the ISO |
| `crassostrea.ks` | The kickstart: base system, boot parameters (`%pre`), source and first-boot unit (`%post`) |
| `firstboot.sh`, `crassostrea-firstboot.service` | The first-boot wizard on tty1 |
