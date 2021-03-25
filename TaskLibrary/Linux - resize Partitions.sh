#!/bin/bash
set -ex

# the root volume has aleady been grown, so now we need to add space to the lvm partition
sudo growpart /dev/sda 2

# Resize the partition
sudo pvresize /dev/sda2

# add the space to the logical volume
sudo lvextend -l +100%FREE /dev/mapper/centos-root

# grow the root file system
sudo xfs_growfs /dev/centos/root

