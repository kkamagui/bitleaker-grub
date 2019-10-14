# Make
make -j

# Standalone build
#grub-mkstandalone -d grub-core -o grubx64.efi -O x86_64-efi "boot/grub/grub.cfg=/boot/grub/grub.cfg"

# Normal build
cd grub-core
../grub-mkimage -d . -o grubx64.efi -O x86_64-efi -p "" boot part_gpt part_msdos fat ext2 normal configfile lspci ls reboot datetime time loadenv search lvm help gfxmenu gfxterm gfxterm_menu gfxterm_background all_video png gettext sleep linux linuxefi chain
