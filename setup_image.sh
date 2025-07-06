#!/usr/bin/env bash
# Example: ./setup_image.sh
set -eux

source config/.env

echo "IMAGE: $IMAGE"
echo "KERNEL: $KERNEL"

export IMAGE=$IMAGE
export KERNEL=$KERNEL

SchedTestDir=$(pwd)


if [ -d $IMAGE ]; then
    sudo rm -rf $IMAGE
fi

mkdir $IMAGE

# if mkdir failed, exit
if [ $? -ne 0 ]; then
    echo "Failed to create image directory"
    exit 1
fi

sudo apt update
sudo apt install debootstrap -y

cd $IMAGE

cp $SchedTestDir/create-image.sh $IMAGE/
chmod +x $IMAGE/create-image.sh
./create-image.sh --add-perf