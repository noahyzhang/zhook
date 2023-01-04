cmake_minimum_required(VERSION 2.8.0)

project(zhook)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -Wall -Werror -fPIC")

include_directories(
    ./include
    ./src
)

file(GLOB SRCS
    ./src/*.cpp
)

add_library(zhook SHARED ${SRCS})

target_link_libraries(zhook
    dl
    bfd
    pthread
)

add_subdirectory(test)
