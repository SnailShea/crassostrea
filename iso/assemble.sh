#!/usr/bin/env bash
# Puts the kickstart and the gateway into the AlmaLinux ISO (run by
# iso/build.sh, in an almalinux:10 container or on EL10 with xorriso, mtools,
# isomd5sum and pykickstart). No root, loop devices or mounts needed:
#   1. the GRUB entries (BIOS: boot/grub2/grub.cfg, UEFI: EFI/BOOT/grub.cfg)
#      get inst.ks=hd:LABEL=<volume>:/crassostrea.ks;
#   2. the UEFI GRUB configuration inside images/efiboot.img (the FAT image
#      UEFI firmware starts from) is replaced with mtools;
#   3. xorriso writes the new ISO with the boot setup of the original, as
#      xorriso reports it, except that the UEFI boot image is the patched
#      images/efiboot.img, both as El Torito image and as GPT EFI partition.
#      (xorriso's own "replay" cannot do this for the AlmaLinux 10 ISOs, whose
#      UEFI El Torito image is no file; neither can mkksiso.)
#   4. the media checksum for "Test this media" (implantisomd5).
#
#   assemble.sh BASE_ISO KICKSTART PAYLOAD_DIR OUTPUT_ISO
set -o pipefail

die() { echo "ERROR: $*" >&2; exit 1; }

[[ $# -eq 4 ]] || die "usage: $0 BASE_ISO KICKSTART PAYLOAD_DIR OUTPUT_ISO"
base=$1 ks=$2 payload=$3 output=$4
for tool in xorriso mtype mcopy implantisomd5 ksvalidator; do
  command -v "${tool}" > /dev/null || die "${tool} is missing (xorriso, mtools, isomd5sum, pykickstart)"
done

tmp=$(mktemp -d) || die "Cannot create a temporary directory"
trap 'rm -rf "${tmp}"' EXIT

# The kickstart's %include is written at install time by its %pre
grep -v '^%include ' "${ks}" > "${tmp}/validate.ks"
ksvalidator -v RHEL10 "${tmp}/validate.ks" || die "The kickstart is not valid"

xorriso -osirrox on -indev "${base}" \
  -extract /EFI/BOOT/grub.cfg "${tmp}/efi-grub.cfg" \
  -extract /boot/grub2/grub.cfg "${tmp}/bios-grub.cfg" \
  -extract /images/efiboot.img "${tmp}/efiboot.img" > /dev/null 2>&1 \
  || die "${base} has no EFI/BOOT/grub.cfg, boot/grub2/grub.cfg or images/efiboot.img"
chmod u+w "${tmp}"/*

volid=$(xorriso -indev "${base}" -pvd_info 2> /dev/null | sed -n "s/^Volume Id *: //p")
[[ ${volid} =~ ^[A-Za-z0-9._-]+$ ]] || die "Unexpected volume label '${volid}'"
add="inst.ks=hd:LABEL=${volid}:/crassostrea.ks"

# 1. the installer's entries (the ones with inst.stage2) load the kickstart
for cfg in "${tmp}/efi-grub.cfg" "${tmp}/bios-grub.cfg"; do
  sed -i -E \
    -e "/^[[:space:]]*linux(efi)?[[:space:]].*inst\.stage2=/ s|\$| ${add}|" \
    -e "s/menuentry 'Install AlmaLinux/menuentry 'Install Crassostrea on AlmaLinux/" \
    -e "s/menuentry 'Test this media \& install AlmaLinux/menuentry 'Test this media \& install Crassostrea on AlmaLinux/" \
    "${cfg}"
  grep -q "${add}" "${cfg}" || die "No installer entry in $(basename "${cfg}")"
done

# 2. the same configuration in the FAT image of the UEFI boot
mtype -i "${tmp}/efiboot.img" ::/EFI/BOOT/grub.cfg > /dev/null || die "images/efiboot.img has no EFI/BOOT/grub.cfg"
mcopy -o -i "${tmp}/efiboot.img" "${tmp}/efi-grub.cfg" ::/EFI/BOOT/grub.cfg || die "Cannot update images/efiboot.img"

# 3. the original boot setup, with the UEFI image as a file of the ISO
xorriso -indev "${base}" -report_el_torito cmd 2> /dev/null > "${tmp}/boot.cmd"
grep -q "bin_path='/images/eltorito.img'" "${tmp}/boot.cmd" || die "Unexpected BIOS boot setup of ${base}"
boot=()
while IFS= read -r line; do
  case ${line} in
    # replaced below; the volume date gives the new image a new UUID
    *efi_boot_part=*|*efi_path=*|*"-boot_image any next"*|-volume_date*|-volid*) continue ;;
    -boot_image\ *)
      # "-boot_image any partition_table=on" -> three words; values have no spaces
      read -r -a words <<< "${line}"
      words=("${words[@]//\'/}")
      boot+=("${words[@]}") ;;
  esac
done < "${tmp}/boot.cmd"

rm -f "${output}"
xorriso -indev "${base}" -outdev "${output}" \
  -volid "${volid}" \
  "${boot[@]}" \
  -boot_image any next \
  -boot_image any efi_path=/images/efiboot.img \
  -boot_image any platform_id=0xef \
  -boot_image any emul_type=no_emulation \
  -boot_image any efi_boot_part=--efi-boot-image \
  -update "${tmp}/efiboot.img" /images/efiboot.img \
  -update "${tmp}/efi-grub.cfg" /EFI/BOOT/grub.cfg \
  -update "${tmp}/bios-grub.cfg" /boot/grub2/grub.cfg \
  -map "${payload}" /crassostrea \
  -map "${ks}" /crassostrea.ks \
  -end > "${tmp}/xorriso.log" 2>&1 \
  || { cat "${tmp}/xorriso.log" >&2; die "xorriso failed"; }
grep -E "SORRY|FAILURE" "${tmp}/xorriso.log" >&2 && die "xorriso reported problems"

# the result must boot both ways
report=$(xorriso -indev "${output}" -report_el_torito plain -report_system_area plain 2> /dev/null)
grep -qE "El Torito boot img : +1 +BIOS" <<< "${report}" || die "The new ISO lost its BIOS boot image"
grep -qE "El Torito boot img : +2 +UEFI" <<< "${report}" || die "The new ISO has no UEFI boot image"
grep -q "GPT type GUID .*28732ac11ff8d211ba4b00a0c93ec93b" <<< "${report}" || die "The new ISO has no EFI partition"

# 4. "Test this media"
implantisomd5 --force "${output}" > /dev/null || die "implantisomd5 failed"
echo "Assembled ${output}"
