# BENZENE: A Practical Root Cause Analysis System with an Under-Constrained State Mutation

BENZENE is an automated root cause analysis tool for a software crash.

This repository is a prototype implementation of our IEEE S&P '24 (Oakland) [paper](https://sp2024.ieee-security.org/accepted-papers.html).

```
@inproceedings{park2023benzene,
  title={BENZENE: A Practical Root Cause Analysis System with an Under-Constrained State Mutation},
  author={Park, Younggi and Lee, Hwiwon and Jung, Jinho and Koo, Hyungjoon and Kim, Huy Kang},
  booktitle={2024 IEEE Symposium on Security and Privacy (SP)},
  pages={74--74},
  year={2023},
  organization={IEEE Computer Society}
}
```


## Structure

```
BENZENE
|-- src
|   |-- backtracer: RR debugger based target function extraction scripts
|   |
|   |-- dynvfg: libdft-based dynamic binary analysis module
|   |
|   |-- fuzz: program behavior generator based on dynamorio
|   |
|   |-- benzene.py: main python script for BENZENE
|
|-- benzene: shell script wrapper for running BENZENE
|
|-- dependency.sh: shell script for installing required libraries
|
|-- setup.sh: build script for BENZENE
|
|-- libdft64: external taint analysis library that supports dynamic binary analysis
|
|-- README.md
```

## Setup

BENZENE is currently tested on Ubuntu 20.04 LTS environment.
To build BENZENE, we provide the setup scripts as follows.

```sh
./dependency.sh # it may requires sudo privilege
./setup.sh
```


## Run Command

To run BENZENE properly, three environment variables (`BENZENE_HOME`, `PIN_ROOT`, `DR_BUILD`) should be set first.

`BENZENE_HOME` contains the repository path, `PIN_ROOT` contains the path of Intel Pin's home directory and `DR_BUILD` contains the path of DynamoRIO's build directory.

If BENZENE is built using the `setup.sh` script in above, those variables can be easily set as follows.

```sh
export BENZENE_HOME=/path/to/BENZENE/repository
export PIN_ROOT=$BENZENE_HOME/pin-3.21
export DR_BUILD=$BENZENE_HOME/dr-build
```

After setting the environment variables, there are some system configurations to be set.

```sh
sudo sysctl kernel.perf_event_paranoid=1
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
```

Then, one can execute BENZENE as follows.

```sh
# print usage
$BENZENE_HOME/benzene --help

# crash analysis
$BENZENE_HOME/benzene --cmd [<crashing-cmd>] --proc [<number-of-process>]
```

For example, if the crashing command is `/some/path/crashme poc`, then BENZENE's commandline will be like:

```sh
$BENZENE_HOME/benzene --cmd '/some/path/crashme poc' --proc -j$(nproc)
```

### Example: CVE-2013-7226

The following commands present how to run BENZENE against CVE-2013-7226, the type confusion vulnerability in PHP.

To get started, one first need to build PHP project as follows:

```sh
# build the testcase CVE-2013-7226
cd $BENZENE_HOME/example/cve-2013-7226
wget http://museum.php.net/php5/php-5.5.0.tar.gz && tar xvfz php-5.5.0.tar.gz
cd $BENZENE_HOME/example/cve-2013-7226/php-5.5.0
./configure --with-gd && make -j$(nproc)
```

In this scenario, target executable is located in `$BENZENE_HOME/example/cve-2013-7226/php-5.5.0/sapi/cli/php` and the crashing input is `poc.php`.

To analyze the given crash (`poc.php`), run the following command.

```sh
cd $BENZENE_HOME/example/cve-2013-7226
$BENZENE_HOME/benzene --cmd 'php-5.5.0/sapi/cli/php poc.php' --proc $(nproc)
```

After the analysis, one can check the results as below.

```
***** Root Cause Analysis Result *****
#Rank       | Module               | Offset               | Predicate           
------------------------------------------------------------------------------------------
#1          | php                  | 0x1da38a             | geq(eax,0xb151a001) 
#2          | php                  | 0x1da387             | geq(mem,0x1)        
#3          | php                  | 0x3a44b1             | leq(eax,0x0)        
#4          | php                  | 0x1dddba             | exist(r15,0x50)     
#5          | php                  | 0x351eab             | ~exist(r12,0x7ffff6e7e81c)
#6          | php                  | 0x35e2a9             | leq(eax,0x8)        
#7          | php                  | 0x1e39e4             | geq(esi,0x1)        
#8          | php                  | 0x351efb             | greater_exist(mem,0x7ffff6e78d88)
#9          | php                  | 0x350242             | ~exist(r12,0x60)    
#10         | php                  | 0x351eae             | leq(rsi,0x8c0004)   
#11         | php                  | 0x1ddd64             | less_exist(ebx,0x4e080a)
#12         | php                  | 0x1f0416             | geq(mem,0xa)        
    ...         ...                     ...                     ...
```

The top ranked predicate (#1) suspects that CVE-2013-7226's root cause is located in the offset `0x1da38a` when the condition `eax >= 0xb151a001` satisfies.

To further inspect the analysis result, one can use RR (or gdb) and debug symbols as follows.

Note that the base address of PHP is `0x555555554000`.

```sh
$BENZENE_HOME/rr-build/bin/rr replay $BENZENE_HOME/example/php/cve-2013-7226/benzene.out/rr-trace
...
# in RR terminal
(rr) b * 0x555555554000 + 0x1da38a
(rr) c
Continuing.

Breakpoint 1, 0x000055555572e38a in zif_imagecrop (ht=<optimized out>, return_value=0x7ffff5b245f0, return_value_ptr=<optimized out>, this_ptr=<optimized out>, return_value_used=<optimized out>) at /home/user/work/Benzene/eval/php/cve-2013-7226/php-5.5.0/ext/gd/gd.c:4975
4975			rect.x = Z_LVAL_PP(tmp);
...
```

As shown above, the offset `0x1da38a` corresponds to the source line `rect.x = Z_LVAL_PP(tmp);`, which is the root cause of the type confusion bug, CVE-2013-7226.


## Docker

To setup BENZENE environment easily, we recommend using the docker.

Before running BENZENE with docker, docker image should be built by the following command.

```sh
# In the BENEZENE repository containing `Dockerfile`
docker build -t benzene .
```

After building the image, you can run a container with the following commands.

Please make sure that `--cap-add=SYS_PTRACE --security-opt seccomp=unconfined` options are included in your command.
Those options are required to run BENZENE under the docker.

```sh
# system configuration
sudo sysctl kernel.perf_event_paranoid=1
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space

# launch docker container
docker run --cap-add=SYS_PTRACE --security-opt seccomp=unconfined -it benzene:latest
```

Then, you can get a terminal environment to work with.

### Example

The following commands present how to run BENZENE against CVE-2013-7226, PHP's type confustion vulnerability in the docker environment.

```sh
# In the docker container
cd /benzene/example/cve-2013-7226
/benzene/benzene --cmd 'php-5.5.0/sapi/cli/php poc.php' --proc $(nproc)
```


