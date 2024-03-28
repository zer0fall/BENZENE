cmake_minimum_required(VERSION 2.6)

if (${USE_COLOR})
    add_definitions(-DUSE_COLOR)
endif()


project(sqlite3)

set(libtype STATIC)

add_library(sqlite3 ${libtype}
            sqlite3.c
            sqlite3.h)

target_compile_options(sqlite3 PUBLIC -O2)
target_compile_options(sqlite3 PUBLIC -g)
# option : -DSQLITE_THREADSAFE=0
target_compile_definitions(sqlite3 PUBLIC SQLITE_THREADSAFE=0)
# option : -ldl 
target_link_libraries(sqlite3 PUBLIC dl)
set_property(TARGET sqlite3 PROPERTY POSITION_INDEPENDENT_CODE ON)


project(bfuzz)

find_package(DynamoRIO)
if (NOT DynamoRIO_FOUND)
  message(FATAL_ERROR "DynamoRIO package required to build")
endif(NOT DynamoRIO_FOUND)

if (STATIC_LIBRARY)
  set(libtype STATIC)
else()
  set(libtype SHARED)
endif ()

add_library(bfuzz ${libtype}
            benzene_fuzz.cpp
            benzene_proc.cpp
            benzene_op.cpp
            benzene_inst.cpp
            benzene_mutation.cpp
            benzene_shared.cpp
            benzene_modules.cpp
            bfuzz.cpp)

target_compile_options(bfuzz PUBLIC -O2)
target_link_libraries(bfuzz sqlite3)

configure_DynamoRIO_client(bfuzz)
use_DynamoRIO_extension(bfuzz drmgr)
use_DynamoRIO_extension(bfuzz drx)
use_DynamoRIO_extension(bfuzz drcontainers)
use_DynamoRIO_extension(bfuzz drreg)
use_DynamoRIO_extension(bfuzz droption)
use_DynamoRIO_extension(bfuzz drutil)
use_DynamoRIO_extension(bfuzz drsyms)
use_DynamoRIO_extension(bfuzz drwrap)

add_custom_command(TARGET bfuzz POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:bfuzz> ${PROJECT_BINARY_DIR}/../../../tools/bfuzz.so
)


project(bfuzz_server)

add_executable(bfuzz_server
               bfuzz_server.cpp
               bfuzz_corpus.cpp
               benzene_mutation.cpp
               )

target_compile_options(bfuzz_server PUBLIC -O2)
set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)
target_link_libraries(bfuzz_server PRIVATE Threads::Threads)
target_link_libraries(bfuzz_server sqlite3)

add_custom_command(TARGET bfuzz_server POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:bfuzz_server> ${PROJECT_BINARY_DIR}/../../../tools/bfuzz_server
)