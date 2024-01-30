FROM ubuntu:20.04

ARG DEBIAN_FRONTEND=noninteractive

ENV BENZENE_HOME "/benzene"
ENV PIN_ROOT "/benzene/pin-3.21"
ENV DR_BUILD "/benzene/dr-build"

RUN apt-get update
RUN apt-get install git -y

RUN mkdir benzene
WORKDIR /benzene

COPY benzene /benzene/benzene
COPY src src
COPY libdft64 libdft64
COPY setup.sh setup.sh

RUN apt-get update
RUN apt-get install git  ccache cmake make g++-multilib gdb \
  pkg-config coreutils python3-pexpect manpages-dev git \
  ninja-build capnproto libcapnp-dev zlib1g-dev libgmp-dev linux-tools-common linux-tools-generic linux-tools-`uname -r` wget autoconf automake libtool curl make g++ unzip pip python-setuptools libpng-dev libxml2-dev -y

RUN pip3 install setuptools pandas scikit-learn protobuf capstone


RUN /benzene/setup.sh

# build testcase CVE-2013-7226
COPY example /benzene/example
WORKDIR /benzene/example/cve-2013-7226
RUN apt-get install libpng-dev libxml2-dev -y
RUN wget http://museum.php.net/php5/php-5.5.0.tar.gz && tar xvfz php-5.5.0.tar.gz
WORKDIR  /benzene/example/cve-2013-7226/php-5.5.0
RUN ./configure --with-gd && make -j$(nproc)

WORKDIR /benzene