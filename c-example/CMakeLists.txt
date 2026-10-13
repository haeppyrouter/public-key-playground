cmake_minimum_required(VERSION 3.16)
project(rsa_keypair_demo_c LANGUAGES C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

find_package(OpenSSL REQUIRED)

add_executable(rsa_keypair_demo rsa_keypair_demo.c)
target_link_libraries(rsa_keypair_demo PRIVATE OpenSSL::Crypto)
