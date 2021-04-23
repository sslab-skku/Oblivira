set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${SGX_COMMON_CFLAGS} -fPIC -Wno-attributes")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${CMAKE_C_FLAGS} -std=c++11")

if(EXISTS "${SGX_PATH}/include/sgx_uae_launch.h")
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DHAVE_SGX_UAE_LAUNCH_H")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DHAVE_SGX_UAE_LAUNCH_H")
endif(EXISTS "${SGX_PATH}/include/sgx_uae_launch.h")


set_directory_properties(PROPERTIES
        ADDITIONAL_MAKE_CLEAN_FILES "Enclave_u.c; Enclave_u.h")

add_custom_command(
        OUTPUT Enclave_u.c Enclave_u.h
        COMMAND ${SGX_EDGER8R} --untrusted Enclave.edl
        --search-path ${CMAKE_CURRENT_SOURCE_DIR}/../enclave/ # enclave.edl
        --search-path ${SGX_PATH}/include
        --search-path ${CMAKE_SOURCE_DIR}/trusted # mbedtls_sgx.edl
        COMMENT "Generating Enclave_u.{c,h}"
)

# add_executable(s_server Enclave_u.c s_server.cpp Utils.cpp)
add_executable(oblivira Oblivira.cpp)

include_directories(
        ${SGX_INCLUDE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}
	${CMAKE_SOURCE_DIR}/include
	${WOLFSSL_INC}
        ${CMAKE_SOURCE_DIR}/trusted/config
        ${CMAKE_SOURCE_DIR}/trusted/include
        ${CMAKE_CURRENT_BINARY_DIR}
        ${JSONCPP_SRC_DIR}/json
)


# target_link_libraries(s_server
#         -L${SGX_LIBRARY_PATH} -l${SGX_URTS_LIB} -l${SGX_USVC_LIB}
#         ${MBEDTLS_SGX_LIB_U} -lcurl -lpthread )

target_link_libraries(oblivira
        -L${SGX_LIBRARY_PATH} -l${SGX_URTS_LIB} -l${SGX_USVC_LIB}
         -lcurl -lpthread )

# add_dependencies(s_server enclave)
add_dependencies(oblivira enclave)
