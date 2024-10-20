# asio
include_directories(${CMAKE_SOURCE_DIR}/3rdparty/asio)

# websocketpp
include_directories(${CMAKE_SOURCE_DIR}/3rdparty/websocketpp)

# openssl
set(OPENSSL_ROOT_DIR "${CMAKE_SOURCE_DIR}/3rdparty/openssl")
include_directories(${OPENSSL_ROOT_DIR}/include)
link_directories(${OPENSSL_ROOT_DIR}/lib)