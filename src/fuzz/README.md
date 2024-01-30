# DRErnest: In-Memory Fuzzing Framework for Crash Exploration

## Build

### Build DynamoRIO

```sh
$ git clone https://github.com/DynamoRIO/dynamorio
$ pushd dynamorio && mkdir build
$ cd build
$ cmake ..
$ make
$ popd
```

### Build Main Client

```sh
$ mkdir build && cd build
$ cmake .. -DDynamoRIO_DIR=path/to/dynamorio/cmake
$ make
```


## Run

```sh
$ # run client
$ drrun -root [DynamoRIO build dir] -c libdrern.so -offset [target offset] -- [exe] [args]

```






