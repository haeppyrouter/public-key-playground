cmake_minimum_required(VERSION 3.16)
project(rsa_keypair_demo LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(OpenSSL REQUIRED)

add_executable(rsa_keypair_demo rsa_keypair_demo.cpp)
target_link_libraries(rsa_keypair_demo PRIVATE OpenSSL::Crypto)
