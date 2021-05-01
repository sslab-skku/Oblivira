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
    --search-path ${SGX_PATH}/include
    --search-path ${CMAKE_SOURCE_DIR}/Enclave/
    COMMENT "Generating Enclave_u.{c,h}"
)

add_executable(oblivira
  Oblivira_v2.cpp
  ServiceServer.cpp
  Enclave_u.c
  sgx_init.cpp
  ocalls.cpp
  jsoncpp.cpp
  localstorage.cpp
  )

include_directories(
        ${SGX_INCLUDE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}
	${CMAKE_SOURCE_DIR}/Include
	${WOLFSSL_INC}
        ${CMAKE_CURRENT_BINARY_DIR}
	)

	# ${CMAKE_CURRENT_SOURCE_DIR}/json
	# ${CMAKE_CURRENT_SOURCE_DIR}/oram
	# ${CMAKE_CURRENT_SOURCE_DIR}/threadpool
	# ${CMAKE_CURRENT_SOURCE_DIR}/sgx
      
# file(GLOB_RECURSE SRC_FILE ${CMAKE_CURRENT_SOURCE_DIR}/src "*.cpp" "*.cc" "*.c")
# add_executable(oblivira ${SRC_FILE} Enclave_u.c)
# include_directories(
#     ${SGX_INCLUDE_DIR}
#     ${CMAKE_CURRENT_SOURCE_DIR}/include
# 	${CMAKE_SOURCE_DIR}/Include
# 	${WOLFSSL_INC}
#     ${CMAKE_CURRENT_BINARY_DIR}
#     ${JSONCPP_SRC_DIR}/json
# )


target_link_libraries(oblivira
        -L${SGX_LIBRARY_PATH} -l${SGX_URTS_LIB} -l${SGX_USVC_LIB}
        -lcurl -lpthread
)
