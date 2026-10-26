# Kickstart of the Crassostrea installation ISO (iso/build.sh adds it with
# iso/assemble.sh). Installs AlmaLinux 10 from the ISO itself (no network needed) and
# the gateway's source in /opt/crassostrea; the gateway is set up at the first
# boot (crassostrea-firstboot), when the machine is on its network.
#
# Interactive by default: the installer asks for the disk, the root password
# or an administrator account, and may change the network and time zone.
# Boot parameters (edit the boot entry: "e" in GRUB) make it unattended:
#   crassostrea.hostname=FQDN    the gateway's hostname; the first boot then
#                                runs setup.sh without questions
#   crassostrea.wipe=DISK        erase DISK (e.g. sda, nvme0n1, or "first")
#                                and partition it automatically
#   crassostrea.sshkey="KEY"     root logs in with this SSH key only; with
#                                crassostrea.wipe nothing is asked at all
#   crassostrea.timezone=ZONE    time zone (default UTC)

lang en_US.UTF-8
keyboard us
network --bootproto=dhcp --device=link --activate --onboot=on
selinux --enforcing
firewall --enabled --service=ssh
firstboot --disable
cdrom
%include /tmp/crassostrea-generated.ks

%pre --interpreter=/usr/bin/bash --log=/tmp/crassostrea-pre.log
# Boot parameters -> kickstart commands for the unattended parts
param() {
  local value
  value=$(sed -nE "s/.*(^| )$1=(\"([^\"]*)\"|([^ ]*)).*/\3\4/p" /proc/cmdline)
  printf '%s' "${value}"
}
out=/tmp/crassostrea-generated.ks
: > "${out}"
zone=$(param crassostrea.timezone)
if [[ -n ${zone} && -f /usr/share/zoneinfo/${zone} && ${zone} =~ ^[A-Za-z0-9_/+-]+$ ]]; then
  echo "timezone ${zone} --utc" >> "${out}"
else
  echo "timezone Etc/UTC --utc" >> "${out}"
fi
wipe=$(param crassostrea.wipe)
if [[ -n ${wipe} ]]; then
  if [[ ${wipe} == first ]]; then
    # the first disk that is not the installation medium
    media=$(findmnt -no SOURCE /run/install/repo 2> /dev/null | sed 's|/dev/||; s/[0-9]*$//')
    wipe=$(lsblk -dno NAME,TYPE | awk -v m="${media}" '$2 == "disk" && $1 != m && $1 !~ /^(loop|zram|sr)/ {print $1; exit}')
  fi
  if [[ ${wipe} =~ ^[a-z0-9]+$ && -b /dev/${wipe} ]]; then
    {
      echo "ignoredisk --only-use=${wipe}"
      echo "clearpart --all --initlabel --drives=${wipe}"
      echo "zerombr"
      echo "autopart --type=lvm"
      echo "bootloader --boot-drive=${wipe}"
    } >> "${out}"
  else
    echo "crassostrea.wipe: no disk '${wipe}', asking for the storage instead" >&2
  fi
fi
key=$(param crassostrea.sshkey)
key_re='^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(256|384|521)|sk-ssh-ed25519@openssh\.com) [A-Za-z0-9+/=]+( [^"]*)?$'
if [[ ${key} =~ ${key_re} ]]; then
  echo "rootpw --lock" >> "${out}"
  printf 'sshkey --username=root "%s"\n' "${key}" >> "${out}"
fi
# unattended only when nothing is left to ask
if grep -q '^autopart' "${out}" && grep -q '^sshkey' "${out}"; then
  echo "reboot --eject" >> "${out}"
fi
param crassostrea.hostname > /tmp/crassostrea-hostname
%end

%packages
@^minimal-environment
tar
%end

# The gateway's source from the ISO (iso/build.sh puts it in /crassostrea)
%post --nochroot --interpreter=/usr/bin/bash --log=/mnt/sysimage/root/crassostrea-install.log
set -e
media=/run/install/repo/crassostrea
mkdir -p /mnt/sysimage/opt
tar -xzf "${media}/crassostrea.tar.gz" -C /mnt/sysimage/opt
install -m 0755 "${media}/firstboot.sh" /mnt/sysimage/usr/local/sbin/crassostrea-firstboot
install -m 0644 "${media}/crassostrea-firstboot.service" /mnt/sysimage/etc/systemd/system/
mkdir -p /mnt/sysimage/etc/crassostrea
install -m 0644 "${media}/VERSION" /mnt/sysimage/etc/crassostrea/iso-version
hostname=$(cat /tmp/crassostrea-hostname 2> /dev/null || true)
if [[ ${hostname} =~ ^[A-Za-z0-9.-]{1,253}$ ]]; then
  echo "HOSTNAME=${hostname}" > /mnt/sysimage/etc/crassostrea/firstboot.conf
fi
echo "Copied the gateway $(cat "${media}/VERSION") to /opt/crassostrea"
%end

%post --interpreter=/usr/bin/bash --log=/root/crassostrea-install-chroot.log
set -e
chown -R root:root /opt/crassostrea
restorecon -R /opt/crassostrea /usr/local/sbin/crassostrea-firstboot /etc/systemd/system/crassostrea-firstboot.service \
  /etc/crassostrea 2> /dev/null || true
systemctl enable crassostrea-firstboot.service
%end
