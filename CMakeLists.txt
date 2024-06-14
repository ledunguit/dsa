cmake_minimum_required(VERSION 3.28)
project(DigitalSignature)

set(CMAKE_CXX_STANDARD 17)

include_directories("include")
link_directories("lib/cryptopp")
link_directories("lib/openssl")
link_libraries("libcryptopp.a")
link_libraries("libcrypto.a")

add_executable(DSA DSA.cpp DSA.h)
add_executable(SIGN sign.cpp sign.h)
add_executable(VERIFY verify.cpp verify.h)

add_library(DSADLL SHARED DSA.cpp)

