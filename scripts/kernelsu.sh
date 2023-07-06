#!/bin/bash

#
# Copyright (C) 2023-2025 Unitrix Kernel
#

#
# Set environment variable
#
set -e

#
# Filter in precise actions
#
function parse_parameters()
{
    while (($#)); do
        case $1 in
		stable | devel | v*) action=$1 ;;
		*) exit 33 ;;
	esac
	shift
    done
}

#
# Checkout branch of last release
#
function do_stable()
{
   if ! [ -d $KERNELSU ]; then
       git clone https://github.com/tiann/KernelSU.git $KERNELSU > /dev/null 2>&1
       git -C $KERNELSU checkout $(git -C $KERNELSU describe --abbrev=0 --tags) > /dev/null 2>&1
   fi
}

#
# Checkout main development branch
#
function do_devel()
{
   if ! [ -d $KERNELSU ]; then
       git clone https://github.com/tiann/KernelSU.git $KERNELSU > /dev/null 2>&1
   fi
}

#
# Checkout any specific older release
#
function do_older()
{
   if ! [ -d $KERNELSU ]; then
       git clone https://github.com/tiann/KernelSU.git $KERNELSU > /dev/null 2>&1
       git -C $KERNELSU checkout $action > /dev/null 2>&1
   fi
}

#
# Remove existing KernelSU directory
#
rm -rf $KERNELSU

#
# Parse user parameters
#
parse_parameters $@

#
# Check action and call appropriate function
#
if [ $action = "stable" ] || [ $action = "devel" ]; then
do_$action
else
do_older
fi

#
# Fix compile errors on kernel v4.4
#
if [ $(git -C $KERNELSU describe --abbrev=0 --tags) = "v0.6.6" ]; then
    git -C $KERNELSU cherry-pick -n --no-gpg-sign 0b1bab5b01d346ed4ad1b00d4ba974e27a20f5fb
fi

#
# Fix compile errors on kernel v4.4
#
if [ $(git -C $KERNELSU describe --abbrev=0 --tags) = "v0.9.4" ]; then
    git -C $KERNELSU cherry-pick -n --no-gpg-sign 7af4f338e56cce386ba0dccdc0871b687cd697b1
fi

#
# Add Non-GKI Support onwards v1.0.0
#
for release in "v1.0.0" "v1.0.1" "v1.0.2" "v1.0.3"; do
if [ $(git -C $KERNELSU describe --abbrev=0 --tags) = $release ]; then
    git -C $KERNELSU revert -n --no-gpg-sign 898e9d4f8ca9b2f46b0c6b36b80a872b5b88d899
fi
done

#
# AOSP sepolicy does not allow appdomain to open pts. Hence, convert
# devpts domain to ksu_file to allow any access.
#
for release in "v0.9.4" "v0.9.5" "1.0.0"; do
if [ $(git -C $KERNELSU describe --abbrev=0 --tags) = $release ]; then
    git -C $KERNELSU cherry-pick -n --no-gpg-sign 78bf2493bf2b92a12636a4ec64ded21e33644441
fi
done
