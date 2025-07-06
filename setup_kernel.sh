#!/usr/bin/env bash
# $1: target directory
# $2: commit hash
# Example: ./setup_kernel.sh aa3ee4f0b7541382c9f6f43f7408d73a5d4f4042 
# option: --skip-download
set -eux

# load config/.env
source config/.env

export IMAGE=$IMAGE
export KERNEL=$KERNEL
# Check if the target directory is provided
if [ -z "$1" ]; then
    echo "Usage: $0 <commit_hash>"
    exit 1
fi

SchedTestDir=$(pwd)
commit_hash=$1
ARCH=$(uname -m)

echo "Target directory: $KERNEL"
echo "Commit hash: $commit_hash"

# Check if --skip-download is provided, if not, install dependencies, init kernel repo
if [[ ! "$*" =~ "--skip-download" ]]; then
    sudo apt update
    sudo apt install -y make gcc flex bison libncurses-dev libelf-dev libssl-dev

    if [ -d $KERNEL ]; then
        rm -rf $KERNEL
    fi

    git init $KERNEL && cd $KERNEL
    git remote add origin https://github.com/torvalds/linux.git
    git fetch --depth 1 origin $commit_hash
    git checkout FETCH_HEAD

else
    echo "Skipping download"
    cd $KERNEL
fi

make defconfig
make kvm_guest.config

# update kernel config to the new configs
python $SchedTestDir/update_kernel_config.py $KERNEL/.config $SchedTestDir/config/kernel_config.cfg
make olddefconfig
python $SchedTestDir/check_kernel_config.py $KERNEL/.config $SchedTestDir/config/kernel_config.cfg # check if the updated kernel config is reverted by  `make olddefconfig`

make -j$(nproc)

# check if the kernel is built
if [ -f $KERNEL/arch/x86/boot/bzImage ] && [ -f $KERNEL/vmlinux ]; then
    echo "Kernel is built"
else
    echo "Kernel is not built"
    exit 1
fi
