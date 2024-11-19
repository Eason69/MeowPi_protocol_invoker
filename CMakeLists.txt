cmake_minimum_required(VERSION 3.16)
project(MeowPi_protocol_invoker)

set(CMAKE_CXX_STANDARD 20)

add_executable(MeowPi_protocol_invoker main.cpp cat_net.cpp)

include(${CMAKE_SOURCE_DIR}/3rdparty/3rdparty.cmake)

target_link_libraries(MeowPi_protocol_invoker PRIVATE ws2_32)
