FROM ubuntu:20.04

ARG DEBIAN_FRONTEND=noninteractive

ENV PIN_ROOT "/Benzene/pin-3.21"
ENV BENZENE_HOME "/Benzene"
ENV DR_BUILD "/Benzene/dr-build"

RUN apt-get update
RUN apt-get install git -y

RUN mkdir Benzene
WORKDIR /Benzene

COPY src src
COPY libdft64 libdft64

# install Mozilla's RR debugger
RUN git clone https://github.com/rr-debugger/rr
RUN apt-get install ccache cmake make g++-multilib gdb \
  pkg-config coreutils python3-pexpect manpages-dev git \
  ninja-build capnproto libcapnp-dev zlib1g-dev -y
RUN mkdir rr-build

# build RR debugger
WORKDIR /Benzene/rr-build
RUN cmake ../rr
RUN make -j$(nproc) install

# install dynamorio
WORKDIR /Benzene
RUN git clone --recursive https://github.com/DynamoRIO/dynamorio dynamorio
RUN mkdir -p dr-build
WORKDIR /Benzene/dr-build
RUN cmake ../dynamorio
RUN make -j$(nproc)

# install Intel PIN
WORKDIR /Benzene
RUN apt-get install wget -y
RUN wget https://software.intel.com/sites/landingpage/pintool/downloads/pin-3.21-98484-ge7cd811fd-gcc-linux.tar.gz
RUN tar -xvf pin-3.21-98484-ge7cd811fd-gcc-linux.tar.gz && mv pin-3.21-98484-ge7cd811fd-gcc-linux pin-3.21

# build libdft64
WORKDIR /Benzene/libdft64
RUN make

# Google protobuf
WORKDIR /Benzene
RUN apt-get install autoconf automake libtool curl make g++ unzip -y
RUN git clone https://github.com/protocolbuffers/protobuf

WORKDIR /Benzene/protobuf
RUN git submodule update --init --recursive
RUN ./autogen.sh && ./configure
RUN make -j$(nproc) install
RUN ldconfig

# static build
RUN make clean
RUN ./configure --disable-shared CXXFLAGS="-fPIC"
RUN make -j$(nproc)

WORKDIR /Benzene/protobuf/python
RUN apt-get install pip python-setuptools -y
RUN pip install setuptools
RUN python3 setup.py install

# Build a Pin-related tool
WORKDIR /Benzene/src/DynVFG
RUN make chain -j$(nproc)

# Build a DynamoRIO-related tool
RUN mkdir -p /Benzene/src/explorer/build
WORKDIR /Benzene/src/explorer/build
RUN protoc -I=../ benzene.proto --cpp_out=../ --python_out=../../../src
RUN cmake .. -DDynamoRIO_DIR=${DR_BUILD}/cmake
RUN cp /Benzene/protobuf/src/.libs/libprotobuf.a ./
RUN make -j$(nproc)

RUN pip3 install pandas sklearn protobuf capstone

RUN apt-get install linux-tools-common linux-tools-generic linux-tools-`uname -r` -y

WORKDIR /Benzene
COPY eval eval

# install gdb 11.2
RUN apt-get install libgmp-dev python3-dev -y
RUN ln -s /usr/bin/python3 /usr/local/bin/python
RUN wget https://ftp.gnu.org/gnu/gdb/gdb-11.2.tar.gz
RUN tar -xvf gdb-11.2.tar.gz
WORKDIR /Benzene/gdb-11.2
RUN ./configure --with-python=yes --with-separate-debug-dir=/usr/lib/debug && make -j$(nproc)
RUN make install


# build testcase CVE-2013-7226
WORKDIR /Benzene/eval/php/cve-2013-7226
RUN apt-get install libpng-dev libxml2-dev -y
RUN wget http://museum.php.net/php5/php-5.5.0.tar.gz && tar xvfz php-5.5.0.tar.gz
WORKDIR  /Benzene/eval/php/cve-2013-7226/php-5.5.0
RUN ./configure --with-gd && make -j$(nproc)


WORKDIR /Benzene