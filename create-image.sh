#!/usr/bin/env bash
# Copy and simplify from syzkaller/tools/create-image.sh

set -eux

# Create a minimal Debian distribution in a directory.
PREINSTALL_PKGS=openssh-server,curl,tar,gcc,libc6-dev,time,strace,sudo,less,psmisc,selinux-utils,policycoreutils,checkpolicy,selinux-policy-default,firmware-atheros,debian-ports-archive-keyring,make,sysbench,git,vim,tmux,usbutils,tcpdump

# Variables affected by options
ARCH=$(uname -m)
RELEASE=bullseye
SEEK=2047

# Handle cases where qemu and Debian use different arch names
case "$ARCH" in
    x86_64)
        DEBARCH=amd64
        ;;
    *)
        DEBARCH=$ARCH
        ;;
esac

# Double check KERNEL when PERF is enabled
if [ -z ${KERNEL+x} ]; then
    echo "Please set KERNEL environment variable"
    exit 1
fi

DIR=$RELEASE
sudo rm -rf $DIR
sudo mkdir -p $DIR
sudo chmod 0755 $DIR

# 1. debootstrap stage
DEBOOTSTRAP_PARAMS="--arch=$DEBARCH --include=$PREINSTALL_PKGS --components=main,contrib,non-free,non-free-firmware $RELEASE $DIR"

# debootstrap may fail for EoL Debian releases
RET=0
sudo --preserve-env=http_proxy,https_proxy,ftp_proxy,no_proxy debootstrap $DEBOOTSTRAP_PARAMS || RET=$?

if [ $RET != 0 ]; then
    echo "Debootstrap failed, trying again"
    exit 1
fi

# Set some defaults and enable promtless ssh to the machine for root.
sudo sed -i '/^root/ { s/:x:/::/ }' $DIR/etc/passwd
echo 'T0:23:respawn:/sbin/getty -L ttyS0 115200 vt100' | sudo tee -a $DIR/etc/inittab
printf '\nauto eth0\niface eth0 inet dhcp\n' | sudo tee -a $DIR/etc/network/interfaces
echo '/dev/root / ext4 defaults 0 0' | sudo tee -a $DIR/etc/fstab
echo 'debugfs /sys/kernel/debug debugfs defaults 0 0' | sudo tee -a $DIR/etc/fstab
echo 'securityfs /sys/kernel/security securityfs defaults 0 0' | sudo tee -a $DIR/etc/fstab
echo 'configfs /sys/kernel/config/ configfs defaults 0 0' | sudo tee -a $DIR/etc/fstab
echo 'binfmt_misc /proc/sys/fs/binfmt_misc binfmt_misc defaults 0 0' | sudo tee -a $DIR/etc/fstab
echo -en "127.0.0.1\tlocalhost\n" | sudo tee $DIR/etc/hosts
echo "nameserver 8.8.8.8" | sudo tee -a $DIR/etc/resolv.conf
echo "schedtest" | sudo tee $DIR/etc/hostname
ssh-keygen -f $RELEASE.id_rsa -t rsa -N ''
sudo mkdir -p $DIR/root/.ssh/
cat $RELEASE.id_rsa.pub | sudo tee $DIR/root/.ssh/authorized_keys


cp -r $KERNEL $DIR/tmp/
BASENAME=$(basename $KERNEL)
sudo chroot $DIR /bin/bash -c "apt-get update; apt-get install -y flex bison python-dev libelf-dev libunwind8-dev libaudit-dev libslang2-dev libperl-dev binutils-dev liblzma-dev libnuma-dev"
sudo chroot $DIR /bin/bash -c "apt-get install -y make pkg-config systemtap-sdt-dev libssl-dev libdw-dev libpfm4-dev libtraceevent-dev"
sudo chroot $DIR /bin/bash -c "apt-get install -y python3-setuptools python3-nitime"
sudo chroot $DIR /bin/bash -c "cd /tmp/$BASENAME/tools/perf/; make"
sudo chroot $DIR /bin/bash -c "cp /tmp/$BASENAME/tools/perf/perf /usr/bin/"
sudo rm -rf $DIR/tmp/$BASENAME


# Add udev rules for custom drivers.
# Create a /dev/vim2m symlink for the device managed by the vim2m driver
echo 'ATTR{name}=="vim2m", SYMLINK+="vim2m"' | sudo tee -a $DIR/etc/udev/rules.d/50-udev-default.rules

# Build a disk image
dd if=/dev/zero of=$RELEASE.img bs=1M seek=$SEEK count=1
sudo mkfs.ext4 -F $RELEASE.img
sudo mkdir -p /mnt/$DIR
sudo mount -o loop $RELEASE.img /mnt/$DIR
sudo cp -a $DIR/. /mnt/$DIR/.
sudo umount /mnt/$DIR