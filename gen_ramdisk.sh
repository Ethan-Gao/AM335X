#!/bin/sh

# ref : http://blog.csdn.net/dean_gdp/article/details/51713139

# check root
if [ `whoami` != "root" ]
then
        echo "run as root or with sudo ..."
        exit
fi

# make ramdisk
mkdir loop
dd if=/dev/zero of=ramdisk bs=1k count=65536
mke2fs -F -v -m 0 ramdisk
sudo mount -o loop ramdisk ./loop/
sudo cp -r target/* ./loop/
sync && sleep 1
sudo umount ./loop/

gzip -9 -c ramdisk > ramdisk.gz
mkimage -n 'uboot ext2 ramdisk rootfs' -A arm -O linux -T ramdisk -C gzip -d ramdisk.gz ramdisk.img
