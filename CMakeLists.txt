cmake_minimum_required(VERSION 3.16)
project(MeowPi_protocol_invoker)

set(CMAKE_CXX_STANDARD 20)

add_executable(MeowPi_protocol_invoker main.cpp cat_net.cpp)

find_package(asio CONFIG REQUIRED)
find_package(OpenSSL REQUIRED)

target_link_libraries(MeowPi_protocol_invoker PRIVATE ws2_32 asio::asio OpenSSL::SSL OpenSSL::Crypto)
