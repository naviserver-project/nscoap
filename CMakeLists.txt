cmake_minimum_required(VERSION 2.8.4)
project(ns_coap)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

set(SOURCE_FILES coap2http.c)
add_executable(ns_coap ${SOURCE_FILES})