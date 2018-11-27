losetup /dev/loop0 filesystem.img
insmod minix.ko key="123456789abcdef1"
mount -t minix /dev/loop0 /mnt/filesystem
