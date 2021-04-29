cmake_minimum_required(VERSION 3.2)
project(oblivira)

list(APPEND CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake")

find_package(SGX REQUIRED)

set(WOLFSSL_ROOT ${CMAKE_SOURCE_DIR}/Lib/wolfssl)
set(WOLFSSL_INC ${WOLFSSL_ROOT})
set(WOLFSSL_LIB ${WOLFSSL_ROOT}/IDE/LINUX-SGX)
set(WOLFSSL_STATIC_LIB_FILE wolfssl.sgx.static.lib)
set(WOLFSSL_STATIC_LIB_FILE_FULL_PATH ${WOLFSSL_LIB}/libwolfssl.sgx.static.lib.a)


set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_subdirectory(App)
add_subdirectory(Enclave)

message(STATUS "=> SGX_MODE: " ${SGX_MODE})
message(STATUS "=> SGX_HW: " ${SGX_HW})
