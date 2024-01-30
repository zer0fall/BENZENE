#!/bin/bash

apt-get update
apt-get install git  ccache cmake make g++-multilib gdb \
  pkg-config coreutils python3-pexpect manpages-dev git \
  ninja-build capnproto libcapnp-dev zlib1g-dev libgmp-dev linux-tools-common linux-tools-generic linux-tools-`uname -r` wget autoconf automake libtool curl make g++ unzip pip python-setuptools libpng-dev libxml2-dev -y

pip3 install setuptools pandas scikit-learn protobuf capstone
