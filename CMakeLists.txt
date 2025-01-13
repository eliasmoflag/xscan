
cmake_minimum_required(VERSION 3.10)

project(xscan LANGUAGES CXX)

add_library(xscan INTERFACE)
add_library(xscan::xscan ALIAS xscan)

target_include_directories(xscan INTERFACE ${CMAKE_CURRENT_LIST_DIR}/include)
