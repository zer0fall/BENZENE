#!/bin/bash

set -e

BENZENE_HOME=$(pwd)

# install Mozilla's RR debugger
cd $BENZENE_HOME
git clone https://github.com/rr-debugger/rr
mkdir rr-build && cd rr-build
cmake ../rr && make -j$(nproc)
# sudo make install

# install dynamorio
cd $BENZENE_HOME
git clone --recursive https://github.com/DynamoRIO/dynamorio dynamorio
pushd dynamorio && git reset --hard bb2ff609c65cf2cf541be331d7cd29da086d3cac # before droption change
popd
mkdir -p dr-build
cd dr-build && cmake ../dynamorio && make -j$(nproc)

# install Intel PIN
cd $BENZENE_HOME
wget https://software.intel.com/sites/landingpage/pintool/downloads/pin-3.21-98484-ge7cd811fd-gcc-linux.tar.gz
tar -xvf pin-3.21-98484-ge7cd811fd-gcc-linux.tar.gz && mv pin-3.21-98484-ge7cd811fd-gcc-linux pin-3.21
export PIN_ROOT=$BENZENE_HOME/pin-3.21

# build libdft64
cd $BENZENE_HOME/libdft64/src && make -j$(nproc)

# Build a Pin-related tool
cd $BENZENE_HOME/src/dynvfg
make vfg -j$(nproc)

# Build a DynamoRIO-related tool
mkdir $BENZENE_HOME/src/fuzz/build
cd $BENZENE_HOME/src/fuzz/build
cmake .. -DDynamoRIO_DIR=$BENZENE_HOME/dr-build/cmake
make -j$(nproc)

# install gdb 11.2
cd $BENZENE_HOME
wget https://ftp.gnu.org/gnu/gdb/gdb-11.2.tar.gz
tar -xvf gdb-11.2.tar.gz
cd gdb-11.2
# export PATH=$PATH:$(pwd)
ln -s /usr/bin/python3 python # make our gdb use python3, not python2
./configure --with-python=$BENZENE_HOME/gdb-11.2 --with-separate-debug-dir=/usr/lib/debug && make -j$(nproc)
make -j$(nproc)
ln -s $BENZENE_HOME/gdb-11.2/gdb/gdb $BENZENE_HOME/tools/gdb

