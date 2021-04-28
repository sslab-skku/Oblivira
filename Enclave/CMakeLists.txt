set(COMMON_C_CPP_FLAGS "-O2 -nostdinc -fvisibility=hidden -fpie -fstack-protector -fno-builtin -fno-builtin-printf -I.")

set(WOLFSSL_C_EXTRA_FLAGS "-DWOLFSSL_SGX -DDEBUG_WOLFSSL -DHAVE_SUPPORTED_CURVES -DHAVE_TLS_EXTENSIONS")                                 

set(CMAKE_C_FLAGS "${COMMON_C_CPP_FLAGS} ${WOLFSSL_C_EXTRA_FLAGS} -Wno-implicit-function-declaration -std=c11")

set(CMAKE_CXX_FLAGS "${COMMON_C_CPP_FLAGS} ${WOLFSSL_C_EXTRA_FLAGS} -std=c++11 -nostdinc++")


# HAVE_WOLFSSL_TEST=1 HAVE_WOLFSSL_BENCHMARK=1 HAVE_WOLFSSL_SP=1

# set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${SGX_COMMON_CFLAGS} -std=c11 -nostdinc -fvisibility=hidden -fpie -fstack-protector -Wno-implicit-function-declaration ${WOLFSSL_C_EXTRA_FLAGS}")

# set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${CMAKE_C_FLAGS} -std=c++11 -nostdinc++")

set_directory_properties(PROPERTIES
    ADDITIONAL_MAKE_CLEAN_FILES "Enclave_t.c; Enclave_t.h")
add_custom_command(
    OUTPUT Enclave_t.c Enclave_t.h
    COMMAND ${SGX_EDGER8R} --trusted Enclave.edl
    --search-path ${SGX_PATH}/include
    --search-path ${CMAKE_CURRENT_SOURCE_DIR}/sgx/edl
    COMMENT "Generating Enclave_t.{c,h}"
)

enable_language(C CXX ASM_NASM)

file(GLOB_RECURSE SRC_FILES ${CMAKE_CURRENT_SOURCE_DIR}/src "*.cpp" "*.cc" "*.c" "*.asm")
add_library(enclave SHARED ${SRC_FILES} Enclave_t.c)
include_directories(
    ${CMAKE_SOURCE_DIR}/Include
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_BINARY_DIR}
    ${SGX_PATH}/include
    ${SGX_PATH}/include/tlibc
    ${SGX_PATH}/include/libcxx
    ${WOLFSSL_INC}
    ${WOLFSSL_INC}/wolfcrypt
)


set_target_properties(enclave PROPERTIES PREFIX "")
target_link_libraries(enclave "${SGX_COMMON_CFLAGS} \
    -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L${SGX_LIBRARY_PATH} \
    -L${WOLFSSL_LIB} -l${WOLFSSL_STATIC_LIB_FILE} \
    -Wl,--whole-archive -l${SGX_TRTS_LIB} -Wl,--no-whole-archive \
    -Wl,--start-group -lsgx_tstdc -lsgx_tcxx -lsgx_tcrypto -l${SGX_TSVC_LIB} -lsgx_pthread -lpthread -Wl,--end-group \
    -Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
    -Wl,-pie,-eenclave_entry -Wl,--export-dynamic \
    -Wl,--defsym,__ImageBase=0 \
    -Wl,-v\
    -Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/sgx/Enclave.lds"
)


add_custom_command(TARGET enclave
    POST_BUILD
    COMMAND ${SGX_ENCLAVE_SIGNER} sign
    -key ${CMAKE_CURRENT_SOURCE_DIR}/sgx/Enclave_private.pem
    -config ${CMAKE_CURRENT_SOURCE_DIR}/sgx/Enclave.config.xml
    -enclave enclave.so
    -out enclave.signed.so
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    COMMENT "Signing the enclave => ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/enclave.signed.so"
)
